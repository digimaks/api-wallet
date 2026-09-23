// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"errors"

	"azugo.io/azugo"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"go.uber.org/zap"
)

type walletInstanceAttestationRequest struct {
	JWK      map[string]any `json:"jwk"`
	ClientID string         `json:"clientId,omitempty"`
	// KeyAttestation is a placeholder for a future hardware/device attestation
	// proof (e.g. Android Keystore key attestation). Not yet validated —
	// tracked in docs/plans/2026-07-28-wua-dpop-fixes-api-wallet.md (A2).
	KeyAttestation string `json:"keyAttestation,omitempty"`
}

type walletUnitAttestationRequest struct {
	JWKSet struct {
		Keys []map[string]any `json:"keys"`
	} `json:"jwkSet"`
	Nonce          string `json:"nonce,omitempty"`
	HardwareKeyTag string `json:"hardwareKeyTag,omitempty"`
}

func (r *router) walletInstanceAttestationJWK(ctx *azugo.Context) {
	var req walletInstanceAttestationRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	wia, err := r.OpenID4VCI().IssueWalletInstanceAttestation(ctx, req.JWK, req.ClientID)
	if err != nil {
		ctx.Log().Error("failed to issue wallet instance attestation", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:attestation:walletInstanceAttestationFailed"))

		return
	}

	ctx.JSON(struct {
		WalletInstanceAttestation string `json:"walletInstanceAttestation"`
	}{
		WalletInstanceAttestation: wia,
	})
}

func (r *router) walletUnitAttestationJWKSet(ctx *azugo.Context) {
	var req walletUnitAttestationRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	wua, err := r.OpenID4VCI().IssueWalletUnitAttestation(ctx, req.JWKSet.Keys, req.Nonce, req.HardwareKeyTag)
	if err != nil {
		ctx.Log().Error("failed to issue wallet unit attestation", zap.Error(err))

		var badReq azugo.BadRequestError
		if errors.As(err, &badReq) {
			ctx.Error(pkerrors.NewProblem("err:attestation:instanceNotRegistered"))

			return
		}

		ctx.Error(pkerrors.NewProblem("err:attestation:walletUnitAttestationFailed"))

		return
	}

	ctx.JSON(struct {
		WalletUnitAttestation string `json:"walletUnitAttestation"`
	}{
		WalletUnitAttestation: wua,
	})
}
