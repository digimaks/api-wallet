// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	wallet "github.com/digimaks/api-wallet"

	"azugo.io/azugo"
)

type router struct {
	*wallet.App
}

func Bind(a *wallet.App, g azugo.Router) error {
	r := &router{
		App: a,
	}

	g.Get("/.well-known/openid-credential-issuer", r.openIDCredentialIssuer)
	g.Get("/.well-known/openid-configuration", r.openIDConfiguration)
	g.Get("/.well-known/oauth-authorization-server", r.oauthAuthorizationServer)
	g.Get("/.well-known/jwks", r.openIDJWKS)
	g.Post("/credential", r.credential)
	g.Post("/token", r.token)
	g.Post("/credential/{id}/acknowledge", r.credentialAcknowledge)

	// Nonce support
	auth := g.Group("")
	auth.Use(wallet.TryAuthenticate(a.App, a.Config().IDAuth))
	auth.Post("/nonce", r.nonce)

	return nil
}
