// SPDX-License-Identifier: EUPL-1.2

package wallet

import (
	"slices"

	"azugo.io/azugo"
	"azugo.io/azugo/user"
	"azugo.io/core/http"
	"github.com/digimaks/go-idauth"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"go.uber.org/zap"
)

// TryAuthenticate middleware checks if the user is authentificated and has the required session state, if not will set to anonymous.
func TryAuthenticate(_ *azugo.App, config *idauth.Configuration, states ...string) azugo.RequestHandlerFunc {
	client, err := idauth.NewClient(config)
	if err != nil {
		panic(err)
	}

	if len(states) == 0 {
		states = []string{"authorized"}
	}

	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			// Get the Authorization header
			authHeader := ctx.Header.Get("Authorization")

			// Check if authorization header is empty or anonymous
			if authHeader == "" || authHeader == "anonymous" {
				// Continue without setting user
				next(ctx)

				return
			}

			userinfo, err := client.UserInfo(ctx, ctx.Header.InheritAuthorization())
			if err != nil {
				ctx.Log().Error("failed to fetch user info from idauth", zap.Error(err))
				ctx.Error(pkerrors.NewProblem("err:auth:userInfoLookupFailed"))

				return
			}

			if !userinfo.Active {
				ctx.Error(http.UnauthorizedError{})

				return
			}

			if !slices.Contains(states, userinfo.State) {
				ctx.Error(http.ForbiddenError{})

				return
			}

			ctx.SetUser(user.New(userinfo.ToClaims()))

			next(ctx)
		}
	}
}
