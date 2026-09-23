// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestToken_RefreshGrantForwardsDPoPToIDAuth(t *testing.T) {
	var gotGrantType, gotRefreshToken, gotDPoP string

	fakeIDAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotGrantType = r.PostForm.Get("grant_type")
		gotRefreshToken = r.PostForm.Get("refresh_token")
		gotDPoP = r.Header.Get("DPoP")

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-tok","token_type":"DPoP","expires_in":600,"refresh_token":"new-refresh"}`))
	}))
	defer fakeIDAuth.Close()

	fakeIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer fakeIssuer.Close()

	app := testAppWithIssuer(t, fakeIssuer.URL, fakeIDAuth.URL)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostForm("/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": "original-refresh-token",
	}, client.WithHeader("DPoP", "dummy-proof-forwarded-verbatim"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	qt.Check(t, qt.Equals(gotGrantType, "refresh_token"))
	qt.Check(t, qt.Equals(gotRefreshToken, "original-refresh-token"))
	qt.Check(t, qt.Equals(gotDPoP, "dummy-proof-forwarded-verbatim"))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(buf), `"refresh_token":"new-refresh"`))
}

func TestToken_RefreshGrantDoesNotRequireAttestation(t *testing.T) {
	// Unlike authorization_code/pre-authorized_code, refresh_token must
	// succeed with ONLY a DPoP header and no OAuth-Client-Attestation —
	// idauth's refresh_token handler authenticates via DPoP-key binding alone, not
	// a fresh WIA. Requiring attestation here would reject every
	// legitimate refresh call.
	fakeIDAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostForm("/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": "some-refresh-token",
	}, client.WithHeader("DPoP", "some-proof"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
}
