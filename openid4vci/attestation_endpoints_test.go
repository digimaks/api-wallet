// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"azugo.io/azugo"
	"azugo.io/core"
	"github.com/digimaks/api-wallet/issuer"
	"github.com/go-quicktest/qt"
	"github.com/lx-lib/lx-go-jsondb"
)

// stubStore implements jsondb.Store for unit tests; only Exec is exercised.
type stubStore struct{}

func (s *stubStore) Start(_ context.Context) error { return nil }
func (s *stubStore) IsReady() bool                 { return true }
func (s *stubStore) Close()                        {}
func (s *stubStore) AddTask(_ core.Tasker)         {}
func (s *stubStore) Ping(_ context.Context) error  { return nil }
func (s *stubStore) Begin(_ context.Context) (*jsondb.Tx, error) {
	return nil, nil
}

func (s *stubStore) Exec(_ context.Context, method string, _ interface{}, data interface{}) error {
	switch method {
	case "wallet_provider.get_public_key":
		if data != nil {
			b, _ := json.Marshal(map[string]interface{}{
				"publicKey": "test-public-key",
				"account": map[string]interface{}{
					"code":       "10345678901",
					"givenName":  "Test",
					"familyName": "User",
				},
			})
			_ = json.Unmarshal(b, data)
		}

		return nil
	case "wallet_provider.get_revocation_status":
		return jsondb.ExecError{Code: "not_found"}
	default:
		return nil
	}
}

// testServiceCertificatePEM generates a throwaway self-signed EC certificate
// for use in unit tests; matches the pattern in credential_forward_test.go.
func testServiceCertificatePEM(t testing.TB) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	qt.Assert(t, qt.IsNil(err))

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	qt.Assert(t, qt.IsNil(err))

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return string(certPEM) + string(keyPEM)
}

// newTestWUAService builds a minimal Service for unit tests: in-memory cache,
// stub DB store, and a mock status-list HTTP server.
func newTestWUAService(t testing.TB) (*Service, *azugo.TestApp) {
	t.Helper()

	statusSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status_list": map[string]interface{}{
				"idx": 1,
				"uri": "http://statuslist:8080/test",
			},
		})
	}))
	t.Cleanup(statusSrv.Close)

	conf := &issuer.Configuration{
		NonceTTL:                   10 * time.Minute,
		NonceSharedSecret:          "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
		AttestationCertificate:     testServiceCertificatePEM(t),
		APIURL:                     "http://issuer:5000",
		TxCodeCacheTTL:             10 * time.Minute,
		StatusListAPIURL:           statusSrv.URL,
		StatusListAPIKey:           "test-key",
		WalletSolutionProviderName: "test-provider",
		WalletSolutionID:           "test.wallet",
		WalletSolutionVersion:      "1.0",
	}

	testApp := azugo.NewTestApp()

	svc, err := New(testApp.App, &stubStore{}, conf, nil, "http://wallet:8080")
	qt.Assert(t, qt.IsNil(err))

	return svc, testApp
}

func TestIssueWalletUnitAttestation_EmbedsHardwareKeyTag(t *testing.T) {
	svc, testApp := newTestWUAService(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}

	const hardwareKeyTag = "tag-test-abc-123"

	// Register a test route that calls IssueWalletUnitAttestation with a
	// proper HTTP context (avoids nil-fasthttp-context panic in MockContext).
	testApp.Post("/test-wua", func(ctx *azugo.Context) {
		wua, wuaErr := svc.IssueWalletUnitAttestation(ctx, []map[string]any{jwk}, "", hardwareKeyTag)
		if wuaErr != nil {
			ctx.StatusCode(500)
			ctx.Raw([]byte(wuaErr.Error()))

			return
		}

		ctx.Raw([]byte(wua))
	})
	testApp.Start(t)
	defer testApp.Stop()

	resp, err := testApp.TestClient().Post("/test-wua", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	wua := string(body)
	qt.Assert(t, qt.IsTrue(len(wua) > 0))

	parts := strings.Split(wua, ".")
	qt.Assert(t, qt.HasLen(parts, 3))

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	qt.Assert(t, qt.IsNil(err))

	var claims map[string]interface{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(payloadBytes, &claims)))

	qt.Check(t, qt.Equals(claims["hardware_key_tag"], hardwareKeyTag))
}

// TestIssueWalletUnitAttestation_HeaderCarriesX5COnly guards against the WUA
// JOSE header carrying both kid and x5c (spec forbids both) or neither.
// Issuer-go's ValidateWUA trusts the embedded x5c leaf cert exclusively —
// it doesn't resolve kid via jwks_uri — so kid must be absent.
func TestIssueWalletUnitAttestation_HeaderCarriesX5COnly(t *testing.T) {
	svc, testApp := newTestWUAService(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}

	testApp.Post("/test-wua-header", func(ctx *azugo.Context) {
		wua, wuaErr := svc.IssueWalletUnitAttestation(ctx, []map[string]any{jwk}, "", "tag-header-test")
		if wuaErr != nil {
			ctx.StatusCode(500)
			ctx.Raw([]byte(wuaErr.Error()))

			return
		}

		ctx.Raw([]byte(wua))
	})
	testApp.Start(t)
	defer testApp.Stop()

	resp, err := testApp.TestClient().Post("/test-wua-header", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	parts := strings.Split(string(body), ".")
	qt.Assert(t, qt.HasLen(parts, 3))

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	qt.Assert(t, qt.IsNil(err))

	var header map[string]interface{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(headerBytes, &header)))

	_, hasKid := header["kid"]
	qt.Check(t, qt.IsFalse(hasKid))

	x5c, hasX5C := header["x5c"].([]interface{})
	qt.Check(t, qt.IsTrue(hasX5C))
	qt.Check(t, qt.IsTrue(len(x5c) > 0))
}
