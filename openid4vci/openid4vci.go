// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/digimaks/api-wallet/attestation"
	"github.com/digimaks/api-wallet/issuer"

	"aidanwoods.dev/go-paseto"
	"azugo.io/azugo"
	"azugo.io/core/cache"
	"github.com/lx-lib/lx-go-jsondb"
)

type AccessContext struct {
	AccessToken  string
	Person       *AttestationPerson
	AttestedKeys []JWK
}

type Service struct {
	app         *azugo.App
	config      *issuer.Configuration
	store       jsondb.Store
	attestation *attestation.Service

	nonceCache cache.Instance[bool]
	nonceLock  sync.Mutex
	nonceKey   paseto.V4SymmetricKey

	wuaCache cache.Instance[AccessContext]
	wuaLock  sync.RWMutex

	walletPublicURL   string
	walletInstanceURL string
}

func New(app *azugo.App, store jsondb.Store, config *issuer.Configuration, att *attestation.Service, publicBaseURL string) (*Service, error) {
	b, err := base64.StdEncoding.DecodeString(config.NonceSharedSecret)
	if err != nil {
		return nil, err
	}

	key, err := paseto.V4SymmetricKeyFromBytes(b)
	if err != nil {
		return nil, err
	}

	nonceCache, err := cache.Create[bool](app.Cache(), "nonce-reuse", cache.DefaultTTL(config.NonceTTL))
	if err != nil {
		return nil, err
	}

	wuaCache, err := cache.Create[AccessContext](app.Cache(), "wua-access-token", cache.DefaultTTL(config.NonceTTL))
	if err != nil {
		return nil, err
	}

	walletInstanceURL, err := url.JoinPath(publicBaseURL, "instance")
	if err != nil {
		return nil, fmt.Errorf("failed to generate instance ID: %w", err)
	}

	return &Service{
		app:         app,
		config:      config,
		store:       store,
		attestation: att,

		nonceCache: nonceCache,
		nonceKey:   key,

		wuaCache: wuaCache,

		walletPublicURL:   strings.TrimSuffix(publicBaseURL, "/"),
		walletInstanceURL: walletInstanceURL,
	}, nil
}
