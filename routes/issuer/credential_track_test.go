// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wallet "github.com/digimaks/api-wallet"
	"github.com/digimaks/api-wallet/openid4vci"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
)

func TestStripAuthScheme(t *testing.T) {
	qt.Check(t, qt.Equals(stripAuthScheme("DPoP 01KX0EFRSZGWBFMMA1XHF6M8PA"), "01KX0EFRSZGWBFMMA1XHF6M8PA"))
	qt.Check(t, qt.Equals(stripAuthScheme("Bearer some-token"), "some-token"))
	qt.Check(t, qt.Equals(stripAuthScheme("some-token"), "some-token"))
}

func TestExtractFormatAndExpiry_UsesRealValuesWhenPresent(t *testing.T) {
	fallbackExpiry := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	response := map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{
				"credential": "fake-cred",
				"format":     "dc+sd-jwt",
				"expires_at": "2026-07-06T11:19:11Z",
			},
		},
	}

	format, expiresAt := extractFormatAndExpiry(response, "mso_mdoc", fallbackExpiry)

	qt.Check(t, qt.Equals(format, "dc+sd-jwt"))
	qt.Check(t, qt.Equals(expiresAt, time.Date(2026, 7, 6, 11, 19, 11, 0, time.UTC)))
}

func TestExtractFormatAndExpiry_FallsBackWhenCredentialsMissing(t *testing.T) {
	fallbackExpiry := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	format, expiresAt := extractFormatAndExpiry(map[string]interface{}{}, "mso_mdoc", fallbackExpiry)

	qt.Check(t, qt.Equals(format, "mso_mdoc"))
	qt.Check(t, qt.Equals(expiresAt, fallbackExpiry))
}

func TestExtractFormatAndExpiry_FallsBackWhenResponseNil(t *testing.T) {
	fallbackExpiry := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	format, expiresAt := extractFormatAndExpiry(nil, "mso_mdoc", fallbackExpiry)

	qt.Check(t, qt.Equals(format, "mso_mdoc"))
	qt.Check(t, qt.Equals(expiresAt, fallbackExpiry))
}

func TestExtractFormatAndExpiry_FallsBackPerFieldWhenExpiryUnparseable(t *testing.T) {
	fallbackExpiry := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	response := map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{
				"credential": "fake-cred",
				"format":     "mso_mdoc",
				"expires_at": "not-a-date",
			},
		},
	}

	format, expiresAt := extractFormatAndExpiry(response, "mso_mdoc", fallbackExpiry)

	qt.Check(t, qt.Equals(format, "mso_mdoc"))
	qt.Check(t, qt.Equals(expiresAt, fallbackExpiry))
}

func TestResolveIdentityFromAuthHeader_UsesIntrospection(t *testing.T) {
	idauthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/introspection" {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		qt.Check(t, qt.Equals(r.Method, http.MethodPost))
		qt.Check(t, qt.IsTrue(strings.HasPrefix(r.Header.Get("Authorization"), "Basic ")))
		qt.Assert(t, qt.IsNil(r.ParseForm()))
		qt.Check(t, qt.Equals(r.FormValue("token"), "01KX0EFRSZGWBFMMA1XHF6M8PA"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active":      true,
			"sub":         "10345678902",
			"given_name":  "Arturs",
			"family_name": "Testeris",
		})
	}))
	defer idauthSrv.Close()

	t.Setenv("METRICS_ENABLED", "false")
	t.Setenv("IDAUTH_URL", idauthSrv.URL)
	t.Setenv("IDAUTH_CLIENT_ID", "digimaks.self-service.portal")
	t.Setenv("IDAUTH_CLIENT_SECRET", "secret")
	t.Setenv("ISSUER_NONCE_SHARED_SECRET", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	t.Setenv("ISSUER_API_URL", "http://unused:5000")
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

	walletApp, err := wallet.New(nil, "1.0.0-test")
	qt.Assert(t, qt.IsNil(err))

	r := &router{App: walletApp}

	var person *openid4vci.AttestationPerson
	var identErr error
	r.Get("/__test/resolve-identity", func(ctx *azugo.Context) {
		person, identErr = r.resolveIdentityFromAuthHeader(ctx, ctx.Header.Get("Authorization"))
		ctx.StatusCode(http.StatusOK)
	})

	testAzugoApp := azugo.NewTestApp(walletApp.App)
	testAzugoApp.Start(t)
	defer testAzugoApp.Stop()

	client := testAzugoApp.TestClient()
	resp, err := client.Get("/__test/resolve-identity", client.WithHeader("Authorization", "DPoP 01KX0EFRSZGWBFMMA1XHF6M8PA"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), http.StatusOK))

	qt.Assert(t, qt.IsNil(identErr))
	qt.Check(t, qt.Equals(person.Code, "10345678902"))
	qt.Check(t, qt.Equals(person.GivenName, "Arturs"))
	qt.Check(t, qt.Equals(person.FamilyName, "Testeris"))
}

func TestExtractHardwareKeyTag_ReadsClaimFromKeyAttestationHeader(t *testing.T) {
	// Build a minimal KA JWT carrying hardware_key_tag — signature is never
	// checked by extractAccessContextKey/peekJWT (decode only).
	kaHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	kaPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"hardware_key_tag":"tag-abc-123"}`))
	ka := kaHeader + "." + kaPayload + ".sig"

	// Build a proof JWT whose header embeds the KA JWT in key_attestation.
	proofHeaderJSON := `{"alg":"ES256","key_attestation":"` + ka + `"}`
	proofHeader := base64.RawURLEncoding.EncodeToString([]byte(proofHeaderJSON))
	proofPayload := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	proof := proofHeader + "." + proofPayload + ".sig"

	payload := map[string]interface{}{
		"proofs": map[string]interface{}{"jwt": []interface{}{proof}},
	}

	qt.Check(t, qt.Equals(extractHardwareKeyTag(payload), "tag-abc-123"))
}

func TestExtractHardwareKeyTag_EmptyWhenNoAttestation(t *testing.T) {
	payload := map[string]interface{}{
		"proofs": map[string]interface{}{"jwt": []interface{}{"not-a-jwt"}},
	}

	qt.Check(t, qt.Equals(extractHardwareKeyTag(payload), ""))
}
