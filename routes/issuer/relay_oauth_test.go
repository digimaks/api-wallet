// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestCredential_DownstreamOAuthErrorRelayedVerbatim(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_dpop_proof","error_description":"Invalid DPoP proof: missing, malformed, expired, replayed, or bound to a different request"}`))
	}))
	defer fake.Close()

	app := testAppWithIssuer(t, fake.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/credential", forwardablePayload,
		app.TestClient().WithHeader("Authorization", "Bearer test-token"))
	qt.Assert(t, qt.IsNil(err))

	// The downstream status and OAuth error pair must reach the wallet
	// unchanged — NOT a 502 server_error.
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	body := map[string]string{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["error"], "invalid_dpop_proof"))
	qt.Check(t, qt.StringContains(body["error_description"], "Invalid DPoP proof"))
}

func TestCredential_DownstreamOAuthErrorExtraFieldsNotLeaked(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"expired","internal_hint":"session 01ABC in cache digimaks","stack":"..."}`))
	}))
	defer fake.Close()

	app := testAppWithIssuer(t, fake.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/credential", forwardablePayload,
		app.TestClient().WithHeader("Authorization", "Bearer test-token"))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Not(qt.StringContains(string(buf), "internal_hint")))
	qt.Check(t, qt.Not(qt.StringContains(string(buf), "stack")))
}

func TestCredential_DownstreamGarbageBodyStill502(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`<html>nginx error page</html>`))
	}))
	defer fake.Close()

	app := testAppWithIssuer(t, fake.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/credential", forwardablePayload,
		app.TestClient().WithHeader("Authorization", "Bearer test-token"))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadGateway))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	body := map[string]string{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["error"], "server_error"))
}
