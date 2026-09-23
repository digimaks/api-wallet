// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

func fetchASMeta(t *testing.T) map[string]any {
	t.Helper()

	fakeIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"https://backend.example.com"}`))
	}))
	defer fakeIssuer.Close()

	app := testAppWithIssuer(t, fakeIssuer.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/.well-known/oauth-authorization-server")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	meta := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &meta)))

	return meta
}

func TestASMeta_AuthorizationEndpointPointsAtIDAuthWhenConfigured(t *testing.T) {
	t.Setenv("IDAUTH_PUBLIC_URL", "https://sso.example.com/auth")

	meta := fetchASMeta(t)

	qt.Check(t, qt.Equals(meta["authorization_endpoint"],
		"https://sso.example.com/auth/authorizationV3"))
}

func TestASMeta_AuthorizationEndpointFallsBackToSelfWhenUnset(t *testing.T) {
	meta := fetchASMeta(t)

	endpoint, _ := meta["authorization_endpoint"].(string)
	qt.Check(t, qt.IsTrue(len(endpoint) > 0))
	qt.Check(t, qt.StringContains(endpoint, "/authorizationV3"))
	qt.Check(t, qt.Not(qt.StringContains(endpoint, "sso.example.com")))
}

func TestASMeta_AdvertisesPARWhenIDAuthConfigured(t *testing.T) {
	t.Setenv("IDAUTH_PUBLIC_URL", "https://sso.example.com/auth")

	meta := fetchASMeta(t)

	qt.Check(t, qt.Equals(meta["pushed_authorization_request_endpoint"],
		"https://sso.example.com/auth/par"))
}

func TestASMeta_OmitsPARWhenIDAuthNotConfigured(t *testing.T) {
	meta := fetchASMeta(t)

	_, present := meta["pushed_authorization_request_endpoint"]
	qt.Check(t, qt.IsFalse(present))
}

func TestASMeta_AdvertisesRefreshTokenGrant(t *testing.T) {
	meta := fetchASMeta(t)

	grants, _ := meta["grant_types_supported"].([]any)
	found := false

	for _, g := range grants {
		if g == "refresh_token" {
			found = true
		}
	}

	qt.Check(t, qt.IsTrue(found))
}
