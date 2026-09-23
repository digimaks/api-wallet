// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"errors"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
	"azugo.io/azugo"
	"azugo.io/core/cache"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

var errInvalidNonce = errors.New("invalid nonce")

func (s *Service) Nonce(ctx *azugo.Context) (string, error) {
	now := time.Now().UTC()

	t := paseto.NewToken()
	t.SetIssuer(s.walletPublicURL)
	t.SetIssuedAt(now)
	t.SetNotBefore(now)
	t.SetExpiration(now.Add(s.config.NonceTTL))
	t.SetSubject(ulid.Make().String())

	sid := ctx.User().ClaimValue("sid")
	if sid == "" {
		sid = "anonymous"
	}

	t.SetAudience(sid)

	return strings.TrimPrefix(t.V4Encrypt(s.nonceKey, nil), "v4.local."), nil
}

func (s *Service) ValidateNonce(ctx *azugo.Context, nonce string) (string, error) {
	now := time.Now().UTC()

	parser := paseto.NewParser()
	parser.AddRule(paseto.IssuedBy(s.walletPublicURL))
	parser.AddRule(paseto.ValidAt(now))

	t, err := parser.ParseV4Local(s.nonceKey, "v4.local."+nonce, nil)
	if err != nil {
		return "", err
	}

	id, err := t.GetSubject()
	if err != nil {
		return "", errInvalidNonce
	}

	exp, err := t.GetExpiration()
	if err != nil {
		return "", errInvalidNonce
	}

	s.nonceLock.Lock()
	defer s.nonceLock.Unlock()

	ok, err := s.nonceCache.Get(ctx, id)
	if err != nil {
		// Log error but continue
		ctx.Log().Error("failed to check nonce cache", zap.Error(err))
	}

	if ok {
		ctx.Log().Warn("nonce reuse detected", zap.String("nonce", id))

		return "", errInvalidNonce
	}

	if err := s.nonceCache.Set(ctx, id, true, cache.TTL[bool](exp.Sub(now))); err != nil {
		// Log error but continue
		ctx.Log().Error("failed to set nonce cache", zap.Error(err))
	}

	return t.GetAudience()
}
