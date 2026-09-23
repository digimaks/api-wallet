// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/digimaks/api-wallet/attestation"
	"github.com/digimaks/api-wallet/routes/request"

	"azugo.io/azugo"
	"azugo.io/core/http"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/valyala/fasthttp"
)

var b64 = base64.RawURLEncoding.Strict()

// @operationId WalletInstance
// @title Initialize wallet instance
// @description Initialize wallet instance using attestation key.
// @param AttestationRequest body request.AttestationRequest true "Attestation key request"
// @success 201 {empty} "Created"
// @failure 400 string string "Bad request"
// @failure 422 string string "Invalid request"
// @failure 500 string string "Internal server error"
// @resource Instance
// @route /instance [post].
func (r *router) attestation(ctx *azugo.Context) {
	req := request.AttestationRequest{}

	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	// Validate deviceIdentifiers array - each entry must have manufacturer and/or model
	for i, identifier := range req.DeviceIdentifiers {
		if identifier.Manufacturer == "" && identifier.Model == "" {
			ctx.Error(azugo.ParamInvalidError{
				Name: "deviceIdentifiers",
				Tag:  "invalid",
				Err:  fmt.Errorf("deviceIdentifiers[%d] must contain manufacturer and/or model", i),
			})

			return
		}
	}

	buf, err := b64.DecodeString(req.Challenge)
	if err != nil {
		ctx.Error(azugo.ParamInvalidError{
			Name: "challenge",
			Tag:  "invalid",
			Err:  err,
		})

		return
	}

	// TODO - remove this log when we fix ios problem
	logLen := len(buf)
	if logLen > 32 {
		logLen = 32
	}

	ctx.Log().Debug("attestation verification",
		zap.String("challenge_b64", req.Challenge),
		zap.Int("challenge_len", len(buf)),
		zap.String("challenge_hex", fmt.Sprintf("%x", buf[:logLen])))

	// For iOS, pass the base64url string as bytes (iOS hashes the string, not decoded bytes)
	// For Android, pass the decoded bytes (Android uses decoded bytes directly)
	attest, err := r.Attestation().Verify(req.KeyAttestation, buf, req.HardwareKeyTag, req.Challenge)
	if err != nil {
		var pie azugo.ParamInvalidError

		logFields := []zap.Field{
			zap.Error(err),
			zap.String("hardware_key_tag", req.HardwareKeyTag),
			zap.Int("key_attestation_len", len(req.KeyAttestation)),
			zap.Any("device_identifiers", req.DeviceIdentifiers),
		}

		if errors.As(err, &pie) {
			logFields = append(logFields, zap.String("param", pie.Name), zap.String("param_tag", pie.Tag))
		}

		ctx.Log().Error("wallet instance attestation verification failed", logFields...)

		var certErr attestation.CertError
		if errors.As(err, &certErr) {
			ctx.StatusCode(fasthttp.StatusUnprocessableEntity)
			ctx.JSON(certErr)

			return
		}

		if errors.As(err, &pie) {
			switch pie.Name {
			case "challenge":
				ctx.Error(pkerrors.NewProblem("err:attestation:challengeMismatch"))
			case "hardware_key_tag":
				ctx.Error(pkerrors.NewProblem("err:attestation:keyTagMismatch"))
			case "certificate:extension":
				ctx.Error(pkerrors.NewProblem("err:attestation:extensionMissing"))
			default:
				ctx.Error(pkerrors.NewProblem("err:attestation:verificationFailed"))
			}

			return
		}

		ctx.Error(pkerrors.NewProblem("err:attestation:verificationFailed"))

		return
	}

	// Populate device information from request
	attest.DeviceLabel = req.DeviceLabel
	if len(req.DeviceIdentifiers) > 0 {
		attest.DeviceIdentifiers = make([]attestation.DeviceIdentifier, len(req.DeviceIdentifiers))
		for i, identifier := range req.DeviceIdentifiers {
			attest.DeviceIdentifiers[i] = attestation.DeviceIdentifier{
				Manufacturer: identifier.Manufacturer,
				Model:        identifier.Model,
			}
		}
	}

	logInstancePublicKey(ctx, attest.HardwareKeyTag, attest.PublicKey)

	token, err := r.OpenID4VCI().ValidateNonce(ctx, req.Challenge)
	if err != nil {
		ctx.Log().Error("failed to validate nonce for wallet instance", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:attestation:nonceInvalid"))

		return
	}

	if token == "anonymous" {
		if err := r.Store().Exec(ctx, "wallet_provider.create_instance", &struct {
			*attestation.Result `json:",inline"`

			Person any `json:"person"`
		}{
			Result: attest,
			Person: struct {
				Code          string `json:"code"`
				RequesterCode string `json:"requesterCode"`
			}{
				Code:          token,
				RequesterCode: token,
			},
		}, nil); err != nil {
			ctx.Log().Error("failed to create anonymous wallet instance", zap.Error(err))
			ctx.Error(pkerrors.NewProblem("err:attestation:instanceCreateFailed"))

			return
		}

		ctx.StatusCode(fasthttp.StatusCreated)

		return
	}

	session, err := r.IDAuth().UserInfo(ctx, http.WithHeader(fasthttp.HeaderAuthorization, "Bearer "+token))
	if err != nil {
		ctx.Log().Error("failed to fetch user info from idauth for wallet instance", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:auth:userInfoLookupFailed"))

		return
	}

	if err := r.Store().Exec(ctx, "wallet_provider.create_instance", &struct {
		*attestation.Result `json:",inline"`

		Person any `json:"person"`
	}{
		Result: attest,
		Person: struct {
			Code          string `json:"code"`
			GivenName     string `json:"givenName"`
			FamilyName    string `json:"familyName"`
			RequesterCode string `json:"requesterCode"`
		}{
			Code:          session.Code,
			GivenName:     session.GivenName,
			FamilyName:    session.FamilyName,
			RequesterCode: session.Code,
		},
	}, nil); err != nil {
		ctx.Log().Error("failed to create authenticated wallet instance", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:attestation:instanceCreateFailed"))

		return
	}

	ctx.StatusCode(fasthttp.StatusCreated)
}

func logInstancePublicKey(ctx *azugo.Context, hardwareKeyTag, pemStr string) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		ctx.Log().Warn("attestation: failed to decode public key PEM",
			zap.String("hardwareKeyTag", hardwareKeyTag))

		return
	}

	sum := sha256.Sum256(block.Bytes)
	previewLen := 16

	if len(block.Bytes) < previewLen {
		previewLen = len(block.Bytes)
	}

	ctx.Log().Info(
		"attestation: verified device public key",
		zap.String("hardwareKeyTag", hardwareKeyTag),
		zap.String("pubkey_sha256_b64", base64.StdEncoding.EncodeToString(sum[:])),
		zap.String("pubkey_der_preview_b64", base64.StdEncoding.EncodeToString(block.Bytes[:previewLen])),
	)
}
