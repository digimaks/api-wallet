// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"errors"

	"github.com/digimaks/api-wallet/models"
	"github.com/digimaks/api-wallet/routes/object"
	"github.com/digimaks/api-wallet/routes/request"

	"azugo.io/azugo"
	"azugo.io/core/http"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/gmb-lib/go-platform-kit/httpclient"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

func (r *router) qrCodeInternal(ctx *azugo.Context) {
	requestType := ctx.Params.String("requestType")

	r.qrCodeData(ctx, requestType)
}

// @operationId GenerateQRCode
// @title Generate QR code
// @description Generates qr code
// @param requestType path string true "options: `pid`"
// @success 200 GenerateCredentialOfferResponse models.GenerateCredentialOfferResponse "pid result"
// @failure 400 string string "Bad request"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @failure 422 string string "Invalid request"
// @failure 500 string string "Internal server error"
// @resource QRCode
// @route /1.0/{requestType} [post].
func (r *router) qrCode(ctx *azugo.Context) {
	requestType := ctx.Params.String("requestType")

	r.qrCodeData(ctx, requestType)
}

func (r *router) qrCodeData(ctx *azugo.Context, requestType string) {
	personCodeClaim := ctx.User().Claim("code")

	var (
		gcoReq any

		err error
	)

	if len(personCodeClaim) == 0 || personCodeClaim[0] == "" {
		ctx.StatusCode(fasthttp.StatusUnauthorized)

		return
	}

	switch requestType {
	case "pid":
		gcoReq, err = r.getPIDData(ctx)
		if err != nil {
			if errors.Is(err, http.NotFoundError{}) {
				ctx.Error(err)
				ctx.Text("Data about person not found")

				return
			}

			ctx.Log().Error("failed to call PID service", zap.Error(err), zap.String("request_type", requestType))
			ctx.Error(pkerrors.NewProblem("err:pid:pidServiceCallFailed"))

			return
		}
	default:
		ctx.StatusCode(fasthttp.StatusNotFound)

		return
	}

	issuerRes := &models.GenerateCredentialOffer{}
	client := ctx.HTTPClient().WithBaseURL(r.Config().Issuer.APIURL)

	err = client.PostJSON("/generate_credential_offer", &gcoReq, issuerRes, httpclient.CorrelationOptions(ctx)...)
	if err != nil {
		ctx.Log().Error("failed to generate credential offer from issuer", zap.Error(err), zap.String("request_type", requestType))
		ctx.Error(pkerrors.NewProblem("err:pid:credentialOfferGenerationFailed"))

		return
	}

	ctx.JSON(issuerRes)
}

func (r *router) getPIDData(ctx *azugo.Context) (any, error) {
	switch r.Config().PidServiceType {
	case "local":
		return r.getIDAuthPIDData(ctx)
	default:
		return nil, http.NotFoundError{Resource: "PID type"}
	}
}

func (r *router) getIDAuthPIDData(ctx *azugo.Context) (any, error) {
	gcoReq := &request.PIDCredentialOfferRequest{
		GenericCredentialOffer: object.GenericCredentialOffer{
			CredentialIDS:      []string{"eu.europa.ec.eudi.pid_digimaks_pid_mdoc"},
			CodeGrant:          "pre_auth_code",
			CredentialOfferURI: r.Config().QRAPIDeepLink + "://",
			ReturnInHTML:       false,
		},
		Form: &request.PIDCredentialOfferForm{},
	}

	gcoReq.Form.FamilyName = ctx.User().FamilyName()
	gcoReq.Form.GivenName = ctx.User().GivenName()
	gcoReq.Form.PersonalAdministrativeNumber = ctx.User().ID()

	return gcoReq, nil
}
