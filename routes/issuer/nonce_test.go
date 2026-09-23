// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

func TestNonce_Request(t *testing.T) {
	// TODO: Needs mock IDAuth server
	t.SkipNow()

	app, a := testApp(t)

	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Post("/nonce", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	nonce := struct {
		Nonce string `json:"c_nonce"`
	}{}

	err = json.Unmarshal(buf, &nonce)
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.Not(qt.Equals(nonce.Nonce, "")))

	app.Get("/test", func(ctx *azugo.Context) {
		aud, err := a.OpenID4VCI().ValidateNonce(ctx, nonce.Nonce)
		if err != nil {
			ctx.Text("nonce rejected")
			ctx.StatusCode(fasthttp.StatusBadRequest)
		}

		ctx.Text(aud)
		ctx.StatusCode(fasthttp.StatusOK)
	})

	resp, _ = app.TestClient().Get("/test")
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	fasthttp.ReleaseResponse(resp)
}

func TestNonce_ReplyAttack(t *testing.T) {
	// TODO: Needs mock IDAuth server
	t.SkipNow()

	app, a := testApp(t)

	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Post("/nonce", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))

	nonce := struct {
		Nonce string `json:"c_nonce"`
	}{}

	err = json.Unmarshal(buf, &nonce)
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.Not(qt.Equals(nonce.Nonce, "")))

	app.Get("/test", func(ctx *azugo.Context) {
		var aud string
		var err error

		if aud, err = a.OpenID4VCI().ValidateNonce(ctx, nonce.Nonce); err != nil {
			ctx.Text("nonce rejected")
			ctx.StatusCode(fasthttp.StatusBadRequest)

			return
		}

		ctx.Text(aud)
		ctx.StatusCode(fasthttp.StatusOK)
	})

	resp, err = app.TestClient().Get("/test")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)

	resp, err = app.TestClient().Get("/test")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	buf, err = resp.BodyUncompressed()
	fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(buf), "nonce rejected"))
}
