// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/valyala/fasthttp"
)

// testWalletAttestation mints a WIA signed by the test issuer's private key
// (extracted from ATTESTATION_CERTIFICATE, which testAppWithIssuer sets) and a PoP
// signed by a freshly generated wallet EC key. The WIA cnf.jwk holds the
// wallet's public key so VerifyAttestationPoP can verify the PoP.
func testWalletAttestation(t testing.TB) (wia, pop string) {
	t.Helper()

	// --- 1. Recover the issuer signing key from the PEM set by testAppWithIssuer ---
	certPEM := os.Getenv("ATTESTATION_CERTIFICATE")
	if certPEM == "" {
		t.Fatal("ATTESTATION_CERTIFICATE env var not set — call testAppWithIssuer before testWalletAttestation")
	}

	var issuerKey *ecdsa.PrivateKey

	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type == "PRIVATE KEY" {
			raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			qt.Assert(t, qt.IsNil(err))

			var ok bool
			issuerKey, ok = raw.(*ecdsa.PrivateKey)
			qt.Assert(t, qt.IsTrue(ok))
			break
		}
	}

	qt.Assert(t, qt.IsTrue(issuerKey != nil))

	// --- 2. Generate a fresh wallet key pair ---
	walletKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	pub := &walletKey.PublicKey
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	// Pad to 32 bytes for P-256
	for len(xBytes) < 32 {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < 32 {
		yBytes = append([]byte{0}, yBytes...)
	}

	cnfJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}

	// --- 3. Build and sign the WIA ---
	walletPublicURL := os.Getenv("WALLET_API_PUBLIC_URL")
	if walletPublicURL == "" {
		walletPublicURL = "http://wallet:8080"
	}

	now := time.Now()
	wiaToken := jwt.New(jwt.SigningMethodES256)
	wiaToken.Header["typ"] = "oauth-client-attestation+jwt"
	wiaToken.Claims = jwt.MapClaims{
		"iss": walletPublicURL,
		"sub": walletPublicURL,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": cnfJWK},
	}

	wia, err = wiaToken.SignedString(issuerKey)
	qt.Assert(t, qt.IsNil(err))

	// --- 4. Build and sign the PoP ---
	popToken := jwt.New(jwt.SigningMethodES256)
	popToken.Header["typ"] = "oauth-client-attestation-pop+jwt"
	popToken.Claims = jwt.MapClaims{
		"iss": walletPublicURL,
		"aud": walletPublicURL + "/token",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"jti": "test-jti-" + time.Now().Format("20060102150405"),
	}

	pop, err = popToken.SignedString(walletKey)
	qt.Assert(t, qt.IsNil(err))

	return wia, pop
}

func TestToken_AuthCodeGrantForwardsAttestationHeadersToIDAuth(t *testing.T) {
	var gotWIA, gotPoP, gotDPoP string

	fakeIDAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotWIA = r.Header.Get("OAuth-Client-Attestation")
		gotPoP = r.Header.Get("OAuth-Client-Attestation-PoP")
		gotDPoP = r.Header.Get("DPoP")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"DPoP","expires_in":600}`))
	}))
	defer fakeIDAuth.Close()

	fakeIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer fakeIssuer.Close()

	app := testAppWithIssuer(t, fakeIssuer.URL, fakeIDAuth.URL)
	wia, pop := testWalletAttestation(t)

	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostForm(
		"/token", map[string]any{
			"grant_type":    "authorization_code",
			"code":          "code-1",
			"code_verifier": "verifier-verifier-verifier-verifier-verifier",
			"redirect_uri":  "https://wallet.example.com/cb",
		},
		client.WithHeader("OAuth-Client-Attestation", wia),
		client.WithHeader("OAuth-Client-Attestation-PoP", pop),
		client.WithHeader("DPoP", "dummy-proof-forwarded-verbatim"),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	qt.Check(t, qt.Equals(gotWIA, wia))
	qt.Check(t, qt.Equals(gotPoP, pop))
	qt.Check(t, qt.Equals(gotDPoP, "dummy-proof-forwarded-verbatim"))
}
