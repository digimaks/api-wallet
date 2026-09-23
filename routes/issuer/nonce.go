// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"azugo.io/azugo"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"go.uber.org/zap"
)

func (r *router) nonce(ctx *azugo.Context) {
	nonce, err := r.OpenID4VCI().Nonce(ctx)
	if err != nil {
		ctx.Log().Error("failed to mint nonce", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:nonce:mintFailed"))

		return
	}

	ctx.Header.Set("Cache-Control", "no-store")
	ctx.JSON(struct {
		Nonce string `json:"c_nonce"` //nolint: tagliatelle
	}{
		Nonce: nonce,
	})
}
