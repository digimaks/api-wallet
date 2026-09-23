// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/digimaks/api-wallet/models"

	"azugo.io/azugo"
	"azugo.io/core/cache"
)

type Issuer struct {
	ch              cache.Instance[int]
	mu              sync.Mutex
	walletPublicURL string
}

const issuerCache = "digimaks-wallet-api-issuer"

type CacheProvider interface {
	Cache() *cache.Cache
}

func NewIssuer(app CacheProvider, verifyTTL time.Duration, walletPublicURL string) (*Issuer, error) {
	sid := &Issuer{
		walletPublicURL: walletPublicURL,
	}

	var err error

	sid.ch, err = cache.Create[int](app.Cache(), issuerCache, cache.DefaultTTL(verifyTTL))
	if err != nil {
		return nil, err
	}

	return sid, nil
}

func (i *Issuer) ParseCredentialOffer(ctx *azugo.Context, credentialOffer models.GenerateCredentialOffer, showTXCode bool) (*models.GenerateCredentialOffer, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	urlData := credentialOffer.URLData

	u, err := url.Parse(urlData)
	if err != nil {
		return nil, fmt.Errorf("error parsing URL data: %w", err)
	}

	q := u.Query()

	var offer models.CredentialOffer

	err = json.Unmarshal([]byte(q.Get("credential_offer")), &offer)
	if err != nil {
		return nil, fmt.Errorf("error parsing JSON string: %w", err)
	}

	if !showTXCode {
		if err := i.ch.Set(ctx, offer.Grants.PreAuthorizedCode.PreAuthorizedCode, *credentialOffer.TXCode); err != nil {
			return nil, err
		}

		offer.Grants.PreAuthorizedCode.TXCode = nil
		credentialOffer.TXCode = nil
	}

	offer.CredentialIssuer = i.walletPublicURL

	buf, err := json.Marshal(&offer)
	if err != nil {
		return nil, fmt.Errorf("error parsing JSON string: %w", err)
	}

	q.Set("credential_offer", string(buf))
	u.RawQuery = q.Encode()

	result := models.GenerateCredentialOffer{
		URLData: u.String(),
		TXCode:  credentialOffer.TXCode,
	}

	return &result, nil
}

func (i *Issuer) GetTXCode(ctx *azugo.Context, preAuthorizedCode string) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	txCode, err := i.ch.Get(ctx, preAuthorizedCode)
	if err != nil {
		return "", err
	}

	return strconv.Itoa(txCode), nil
}
