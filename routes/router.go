// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	wallet "github.com/digimaks/api-wallet"
	"github.com/digimaks/api-wallet/openapi"
	"github.com/digimaks/api-wallet/routes/issuer"

	"azugo.io/azugo"
	"azugo.io/azugo/token"
	"azugo.io/azugo/user"
	"azugo.io/core/http"
	"github.com/digimaks/go-idauth"
	"github.com/digimaks/go-idauth/authorization"
	oa "github.com/lx-lib/go-openapi"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

type router struct {
	*wallet.App
	openapi *oa.OpenAPI
}

func Init(a *wallet.App) error {
	r := &router{
		App: a,
	}
	r.openapi = oa.NewDefaultOpenAPIHandler(openapi.OpenAPIDefinition, a.App)

	a.Get("/healthz", r.healthz)

	a.Get("/.well-known/appspecific/version.json", r.versionInfo)

	if err := authorization.Bind(r, a.Config().IDAuth); err != nil {
		return err
	}

	if err := issuer.Bind(a, a); err != nil {
		return err
	}

	a.Post("/wallet-instance-attestation/jwk", r.walletInstanceAttestationJWK)

	a.Post("/instance", r.attestation)

	a.Post("/eparaksts/{type}", r.eparakstsPrepare)
	a.Get("/eparaksts/download/{requestID}", r.eparakstsDownload)
	a.Delete("/eparaksts/{type}/{requestID}", r.eparakstsCloseSession)
	a.Post("/eparaksts/validate", r.eparakstsValidate)

	a.Get("/eparaksts/identities", r.eparakstsIdentities)
	a.Get("/eparaksts/identities/{id}", r.eparakstsIdentitiesUlid)

	authorize := a.Group("")
	{
		authorize.Use(idauth.Authentication(a.App, a.Config().IDAuth))
		authorize.Post("/wallet-unit-attestation/jwk-set", idauth.UserHasScope("citizen", r.walletUnitAttestationJWKSet))
	}

	portal := a.Group("/1.0/internal")
	{
		portal.Use(idauth.Authentication(a.App, a.Config().IDAuth))
		portal.Post("/{requestType}", idauth.UserHasScope("citizen", r.qrCodeInternal))
	}

	v1 := a.Group("/1.0")
	{
		v1.Use(idauth.Authentication(a.App, a.Config().IDAuth))
		v1.Post("/{requestType}", r.qrCode)
	}

	return nil
}

// for now version.json is a static file in ./static/version.json
// added to docker image via build.yaml in woodpecker pipeline
func (r *router) versionInfo(ctx *azugo.Context) {
	data, err := os.ReadFile("static/version.json")
	if err != nil {
		ctx.StatusCode(fasthttp.StatusNotFound)
		ctx.JSON(map[string]string{"error": "version file not found"})

		return
	}

	var versionData interface{}
	if err := json.Unmarshal(data, &versionData); err != nil {
		ctx.StatusCode(fasthttp.StatusInternalServerError)
		ctx.JSON(map[string]string{"error": "failed to parse version file"})

		return
	}

	ctx.JSON(versionData)
}

// todo: might use for future
//
//nolint:unused
func (r *router) authentication(next azugo.RequestHandler) azugo.RequestHandler {
	return func(ctx *azugo.Context) {
		auth := ctx.Header.Get(fasthttp.HeaderAuthorization)
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			ctx.Error(http.UnauthorizedError{})

			return
		}

		tok := strings.TrimPrefix(auth, "Bearer ")

		instanceID, person, err := r.App.OpenID4VCI().VerifyAttestation(ctx, tok)
		if err != nil {
			if errors.Is(err, azugo.BadRequestError{}) || errors.Is(err, http.NotFoundError{}) {
				ctx.Error(http.UnauthorizedError{})

				return
			}

			ctx.Log().Error("failed to verify wallet attestation token", zap.Error(err))
			ctx.Error(err)

			return
		}

		ctx.SetUser(user.New(map[string]token.ClaimStrings{
			"sub":         {instanceID},
			"code":        {person.Code},
			"given_name":  {person.GivenName},
			"family_name": {person.FamilyName},
			"scope":       {"citizen"},
		}))

		next(ctx)
	}
}
