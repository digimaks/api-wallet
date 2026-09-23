// SPDX-License-Identifier: EUPL-1.2

package wallet

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

	"github.com/go-quicktest/qt"
)

// TestApp for unit testing.
func TestApp(tb testing.TB) *App {
	tb.Helper()

	tb.Setenv("METRICS_ENABLED", "false")

	tb.Setenv("IDAUTH_URL", "http://idauth:8080")
	tb.Setenv("IDAUTH_CLIENT_ID", "digimaks.self-service.portal")
	tb.Setenv("IDAUTH_CLIENT_SECRET", "secret")

	tb.Setenv("ISSUER_NONCE_SHARED_SECRET", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	tb.Setenv("ISSUER_API_URL", "http://issuer:5000")

	// Database configuration
	tb.Setenv("POSTGRES_HOST", "localhost")
	tb.Setenv("POSTGRES_PORT", "5432")
	tb.Setenv("POSTGRES_USER", "test")
	tb.Setenv("POSTGRES_PASSWORD", "test")
	tb.Setenv("POSTGRES_DB", "test")

	// Issuer configuration - generate certificate dynamically
	tb.Setenv("ATTESTATION_CERTIFICATE", testAttestationCertificatePEM(tb))
	tb.Setenv("STATUS_LIST_API_URL", testStatusListServer(tb).URL)
	tb.Setenv("STATUS_LIST_API_KEY", "test")
	tb.Setenv("WALLET_SOLUTION_PROVIDER_NAME", "test-provider")
	tb.Setenv("WALLET_SOLUTION_ID", "test.wallet")
	tb.Setenv("WALLET_SOLUTION_VERSION", "1.0")

	// Wallet configuration
	tb.Setenv("QR_API_DEEP_LINK", "openid-credential-offer")
	tb.Setenv("PID_SERVICE_TYPE", "local")
	tb.Setenv("WALLET_API_PUBLIC_URL", "http://wallet:8080")

	// Simple Sign configuration
	tb.Setenv("SIMPLE_SIGN_SERVICE", "http://simple-sign:8080")
	tb.Setenv("SIMPLE_SIGN_PUBLIC_URL", "http://simple-sign-public:8080")
	tb.Setenv("SIMPLE_SIGN_API_KEY", "test")

	app, err := New(nil, "1.0.0-test")
	qt.Assert(tb, qt.IsNil(err))

	return app
}

// testAttestationCertificatePEM generates a throwaway self-signed EC certificate
// and unencrypted PKCS8 private key, PEM-encoded and concatenated as expected
// by issuer.Configuration's ATTESTATION_CERTIFICATE env var.
func testAttestationCertificatePEM(tb testing.TB) string {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(tb, qt.IsNil(err))

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-issuer"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	qt.Assert(tb, qt.IsNil(err))

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	qt.Assert(tb, qt.IsNil(err))

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return string(certPEM) + string(keyPEM)
}

// testStatusListServer stubs the status-list-go "/take" endpoint so tests
// don't depend on the "statuslist" hostname being resolvable (e.g. via
// docker-compose networking) or reachable over the network.
func testStatusListServer(tb testing.TB) *httptest.Server {
	tb.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status_list": map[string]any{
				"idx": 1,
				"uri": "http://statuslist:8080/test",
			},
		})
	}))
	tb.Cleanup(srv.Close)

	return srv
}
