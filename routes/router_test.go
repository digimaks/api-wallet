// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"strings"
	"testing"

	api "github.com/digimaks/api-wallet"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func testApp(t testing.TB) *azugo.TestApp {
	app := api.TestApp(t)

	err := Init(app)
	qt.Assert(t, qt.IsNil(err))

	return azugo.NewTestApp(app.App)
}

func TestVersionInfo(t *testing.T) {
	// TODO: Requires full app configuration setup for testing
	// For now, verify that the route compiles and the handler exists
	t.Skip("Requires full app configuration with database and external services")

	app := testApp(t)

	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/.well-known/appspecific/version.json")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), 200))

	// Check that the response contains expected version data
	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	body := string(buf)
	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"version"`)))
	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"platforms"`)))
	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"ios"`)))
	qt.Assert(t, qt.IsTrue(strings.Contains(body, `"android"`)))

	fasthttp.ReleaseResponse(resp)
}
