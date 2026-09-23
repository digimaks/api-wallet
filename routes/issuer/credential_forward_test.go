// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	wallet "github.com/digimaks/api-wallet"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-platform-kit/correlation"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// testAttestationCertificatePEM generates a throwaway self-signed EC certificate
// and unencrypted PKCS8 private key, PEM-encoded and concatenated as expected
// by issuer.Configuration's ATTESTATION_CERTIFICATE env var (see
// azugo.io/core/cert.LoadPEMFromReader). issuer.Configuration.Validate loads
// and parses this certificate eagerly, so wallet.New fails without one.
func testAttestationCertificatePEM(t testing.TB) string {
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

// testAppWithIssuer mirrors wallet.TestApp but points ISSUER_API_URL at a
// caller-supplied address (a local httptest server standing in for issuer-go),
// since wallet.TestApp itself hardcodes an unreachable placeholder URL. It
// also fills in the remaining configuration wallet.New requires (Postgres
// connection shape, issuer certificate, wallet solution metadata) that
// wallet.TestApp does not set - no existing test exercises wallet.New to
// completion, they all t.SkipNow() beforehand.
// testAppWithIssuer mirrors wallet.TestApp but points ISSUER_API_URL at a
// caller-supplied address. Pass an optional idauthURL to override the default
// stub address — needed by tests that intercept the idauth backend.
func testAppWithIssuer(t testing.TB, issuerURL string, idauthURL ...string) *azugo.TestApp {
	t.Helper()

	idauth := "http://idauth:8080"
	if len(idauthURL) > 0 && idauthURL[0] != "" {
		idauth = idauthURL[0]
	}

	t.Setenv("METRICS_ENABLED", "false")
	t.Setenv("IDAUTH_URL", idauth)
	t.Setenv("IDAUTH_CLIENT_ID", "digimaks.self-service.portal")
	t.Setenv("IDAUTH_CLIENT_SECRET", "secret")
	t.Setenv("ISSUER_NONCE_SHARED_SECRET", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	t.Setenv("ISSUER_API_URL", issuerURL)

	t.Setenv("POSTGRES_HOST", "localhost")
	t.Setenv("POSTGRES_PORT", "5432")
	t.Setenv("POSTGRES_USER", "test")
	t.Setenv("POSTGRES_PASSWORD", "test")
	t.Setenv("POSTGRES_DB", "test")

	t.Setenv("ATTESTATION_CERTIFICATE", testAttestationCertificatePEM(t))
	t.Setenv("STATUS_LIST_API_URL", "http://statuslist:8080")
	t.Setenv("STATUS_LIST_API_KEY", "test")
	t.Setenv("WALLET_SOLUTION_PROVIDER_NAME", "test-provider")
	t.Setenv("WALLET_SOLUTION_ID", "test.wallet")
	t.Setenv("WALLET_SOLUTION_VERSION", "1.0")

	t.Setenv("QR_API_DEEP_LINK", "openid-credential-offer")
	t.Setenv("PID_SERVICE_TYPE", "local")
	t.Setenv("SIMPLE_SIGN_SERVICE", "http://simple-sign:8080")
	t.Setenv("SIMPLE_SIGN_PUBLIC_URL", "http://simple-sign-public:8080")
	t.Setenv("SIMPLE_SIGN_API_KEY", "test")
	t.Setenv("WALLET_API_PUBLIC_URL", "http://wallet:8080")

	app, err := wallet.New(nil, "1.0.0-test")
	qt.Assert(t, qt.IsNil(err))

	err = Bind(app, app)
	qt.Assert(t, qt.IsNil(err))

	return azugo.NewTestApp(app.App)
}

// forwardablePayload deliberately omits credential_configuration_id: the
// production handler routes any payload that HAS that key into
// credentialJWT() instead of the plain forward path this test targets.
var forwardablePayload = map[string]any{
	"proof": map[string]any{"proof_type": "jwt", "jwt": "test-jwt"},
}

func TestCredential_ForwardsCorrelationID(t *testing.T) {
	var gotCorrelationID string

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCorrelationID = r.Header.Get(correlation.HeaderCorrelationID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"credentials":[{"credential":"fake-cred"}]}`))
	}))
	defer fake.Close()

	app := testAppWithIssuer(t, fake.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/credential", forwardablePayload,
		app.TestClient().WithHeader("Authorization", "Bearer test-token"))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	qt.Check(t, qt.Not(qt.Equals(gotCorrelationID, "")))
}

func TestCredential_TransportFailure(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	fake.Close() // closed before use: any request will hit connection refused

	app := testAppWithIssuer(t, fake.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/credential", forwardablePayload,
		app.TestClient().WithHeader("Authorization", "Bearer test-token"))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadGateway))
	// The old X-Error-Code header must never reappear - this is the leak fix's
	// regression guard.
	qt.Check(t, qt.Equals(string(resp.Header.Peek("X-Error-Code")), ""))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	body := map[string]string{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["error"], "server_error"))
	qt.Check(t, qt.Equals(body["error_description"], "issuer service unreachable"))
}

func TestCredential_DownstreamProblemTranslated(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"err:credential:proofInvalid","title":"Invalid proof","status":400,"source":"EUDIW PID Credential Issuer","trace_id":"test-trace"}`))
	}))
	defer fake.Close()

	app := testAppWithIssuer(t, fake.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/credential", forwardablePayload,
		app.TestClient().WithHeader("Authorization", "Bearer test-token"))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	// Neither the internal code nor the internal source may reach the wire.
	qt.Check(t, qt.Equals(string(resp.Header.Peek("X-Error-Code")), ""))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Not(qt.StringContains(string(buf), "err:credential:proofInvalid")))
	qt.Check(t, qt.Not(qt.StringContains(string(buf), "EUDIW PID Credential Issuer")))

	body := map[string]string{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["error"], "invalid_proof"))
	qt.Check(t, qt.Equals(body["error_description"], "proof verification failed"))
}

func TestCredential_ForwardsDPoPHeader(t *testing.T) {
	var gotDPoP string

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDPoP = r.Header.Get("DPoP")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"credentials":[{"credential":"fake-cred"}]}`))
	}))
	defer fake.Close()

	app := testAppWithIssuer(t, fake.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/credential", forwardablePayload,
		app.TestClient().WithHeader("Authorization", "******"),
		app.TestClient().WithHeader("DPoP", "test-proof-jwt"))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	qt.Check(t, qt.Equals(gotDPoP, "test-proof-jwt"))
}

func TestCredential_TracksIssuanceOnFlowAPath(t *testing.T) {
	idauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/1.0/session" {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"code":        "10345678902",
			"given_name":  "Arturs",
			"family_name": "Testeris",
		})
	}))
	defer idauthServer.Close()

	const issuerBody = `{"credentials":[{"credential":"fake-cred","format":"mso_mdoc","expires_at":"2026-07-15T08:46:11Z","status_list_uri":"http://statuslist:8080/x","status_list_idx":5905}]}`

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(issuerBody))
	}))
	defer fake.Close()

	app := testAppWithIssuer(t, fake.URL, idauthServer.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/credential", forwardablePayload,
		app.TestClient().WithHeader("Authorization", "DPoP the-token"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	// The response body forwarded to the client must be byte-identical to
	// what issuer-go returned — tracking must not have altered it.
	buf, bufErr := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(bufErr))
	qt.Check(t, qt.Equals(string(buf), issuerBody))
}
