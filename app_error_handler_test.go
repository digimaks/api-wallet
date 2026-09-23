// SPDX-License-Identifier: EUPL-1.2

package wallet

import (
	"testing"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestErrorHandler_RendersPublicProblemJSON(t *testing.T) {
	app := TestApp(t)

	app.Post("/__test_smoke_error", func(ctx *azugo.Context) {
		ctx.Error(pkerrors.NewProblem("err:test:smoke", pkerrors.WithStatus(fasthttp.StatusTeapot)))
	})

	testApp := azugo.NewTestApp(app.App)
	testApp.Start(t)
	defer testApp.Stop()

	resp, err := testApp.TestClient().Post("/__test_smoke_error", nil)
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusTeapot))
	qt.Check(t, qt.Equals(string(resp.Header.ContentType()), pkerrors.ContentTypeProblemJSON))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(body), `"code":"err:test:smoke"`))
	qt.Check(t, qt.Not(qt.StringContains(string(body), `"source"`)))
}
