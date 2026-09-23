// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"azugo.io/azugo"
	"github.com/lx-lib/lx-go-jsondb"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// IssueWalletInstanceAttestation signs a key-bound WIA for OAuth attestation-based client auth.
// clientID is the OAuth client_id this WIA attests (e.g. "digimaks.wallet.instance"). Empty means
// the caller predates this field — sub falls back to the wallet-provider's own URL, matching
// this endpoint's original (pre-attest_jwt_client_auth) behavior, so existing callers are
// unaffected until they're updated to send it.
func (s *Service) IssueWalletInstanceAttestation(ctx *azugo.Context, jwk map[string]any, clientID string) (string, error) {
	if len(jwk) == 0 {
		return "", azugo.ParamRequiredError{Name: "jwk"}
	}

	if _, err := s.publicKeyFromJWK(map[string]any{"jwk": jwk}); err != nil {
		return "", azugo.ParamInvalidError{
			Name: "jwk",
			Tag:  "invalid",
			Err:  err,
		}
	}

	jwk = publicJWKFields(jwk)

	x5c, err := s.SigningCertificateX5C()
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)

	statusInfo, err := s.StatusList(ctx, "wia", "LV", exp.Format("2006-01-02"))
	if err != nil {
		ctx.Log().Error("failed to allocate status list slot for WIA", zap.Error(err))

		return "", err
	}

	sub := s.walletPublicURL
	if clientID != "" {
		sub = clientID
	}

	token := jwt.New(jwt.SigningMethodES256)
	token.Header["typ"] = "oauth-client-attestation+jwt"
	token.Header["x5c"] = x5c
	token.Claims = jwt.MapClaims{
		"iss": s.walletPublicURL,
		"sub": sub,
		"iat": now.Unix(),
		"exp": exp.Unix(),
		"cnf": map[string]any{
			"jwk": jwk,
		},
		"client_status": map[string]any{
			"status": statusInfo,
			"exp":    exp.Unix(),
		},
		"wallet_name":    s.config.WalletSolutionProviderName,
		"wallet_version": s.config.WalletSolutionVersion,
		"wallet_link":    s.config.WalletLink,
		"wallet_solution_certification_information": s.config.WalletSolutionCertificationInformation,
	}

	cert, err := s.SigningCertificate()
	if err != nil {
		return "", err
	}

	return token.SignedString(cert.PrivateKey)
}

// IssueWalletUnitAttestation signs a WUA (key attestation JWT) for provided credential keys.
func (s *Service) IssueWalletUnitAttestation(ctx *azugo.Context, keys []map[string]any, nonce string, hardwareKeyTag string) (string, error) {
	if len(keys) == 0 {
		return "", azugo.ParamRequiredError{Name: "jwkSet.keys"}
	}

	// Always store AccessContext so the credential endpoint can retrieve it
	var person *AttestationPerson

	resp := struct {
		PublicKey string             `json:"publicKey"`
		Person    *AttestationPerson `json:"account"`
	}{}

	if err := s.store.Exec(ctx, "wallet_provider.get_public_key", &struct {
		Type           string `json:"type"`
		HardwareKeyTag string `json:"hardwareKeyTag"`
	}{
		Type:           "instance",
		HardwareKeyTag: hardwareKeyTag,
	}, &resp); err != nil {
		ctx.Log().Warn(
			"failed to look up wallet instance public key for WUA; proceeding without person context",
			zap.Error(err),
			zap.String("hardware_key_tag", hardwareKeyTag),
		)

		if eerr, ok := errors.AsType[jsondb.ExecError](err); ok && eerr.Code == "err:public_key:not_found" {
			return "", azugo.BadRequestError{Description: "wallet instance not registered - call POST /instance first"}
		}
	}

	person = resp.Person
	// check if WU is not revoked
	if revoked, err := s.isWalletRevoked(ctx, hardwareKeyTag); err != nil {
		ctx.Log().Error(
			"failed to check wallet revocation status",
			zap.Error(err),
			zap.String("hardware_key_tag", hardwareKeyTag),
		)

		return "", err
	} else if revoked {
		ctx.Log().Warn("WUA issuance rejected: wallet is revoked", zap.String("hardware_key_tag", hardwareKeyTag))
		return "", azugo.BadRequestError{Description: "wallet is revoked"}
	}

	attestedKeys := make([]map[string]any, 0, len(keys))

	for i, key := range keys {
		if _, err := s.publicKeyFromJWK(map[string]any{"jwk": key}); err != nil {
			return "", azugo.ParamInvalidError{
				Name: "jwkSet.keys",
				Tag:  "invalid",
				Err:  fmt.Errorf("invalid key at index %d: %w", i, err),
			}
		}

		cloned := publicJWKFields(key)

		if _, ok := cloned["kid"]; !ok {
			cloned["kid"] = strconv.Itoa(i)
		}

		if _, ok := cloned["use"]; !ok {
			cloned["use"] = "sig"
		}

		attestedKeys = append(attestedKeys, cloned)
	}

	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)
	expFormatted := exp.Format("2006-01-02")

	statusInfo, err := s.StatusList(ctx, "wua", "LV", expFormatted)
	if err != nil {
		ctx.Log().Error(
			"failed to allocate status list slot for WUA",
			zap.Error(err),
			zap.String("hardware_key_tag", hardwareKeyTag),
		)

		return "", err
	}

	if err := s.storeWUARevocationInfo(ctx, hardwareKeyTag, statusInfo, exp); err != nil {
		ctx.Log().Warn("Failed to store WUA revocation info", zap.Error(err))
		// Don't fail the WUA issuance, just log the error
	}

	token := jwt.New(jwt.SigningMethodES256)
	token.Header["typ"] = "key-attestation+jwt"
	token.Header["alg"] = "ES256"
	claims := jwt.MapClaims{
		"iat":                 now.Unix(),
		"exp":                 exp.Unix(),
		"certification":       s.config.WSCDCertificationInformation,
		"attested_keys":       attestedKeys,
		"key_storage":         []string{"iso_18045_high"},
		"user_authentication": []string{"iso_18045_high"},
		"key_storage_status": map[string]any{
			"status": statusInfo,
			"exp":    exp.Unix(),
		},
		"hardware_key_tag": hardwareKeyTag,
	}

	if nonce != "" {
		claims["c_nonce"] = nonce
	}

	token.Claims = claims

	x5c, err := s.SigningCertificateX5C()
	if err != nil {
		return "", err
	}

	token.Header["x5c"] = x5c

	cert, err := s.SigningCertificate()
	if err != nil {
		return "", err
	}

	tok, err := token.SignedString(cert.PrivateKey)
	if err != nil {
		ctx.Log().Error("failed to sign WUA JWT", zap.Error(err))
		return "", err
	}

	authHeader := strings.TrimPrefix(ctx.Header.Get("Authorization"), "Bearer ")
	_ = s.SetAccessContext(ctx, tok, AccessContext{
		AccessToken:  authHeader,
		Person:       person,
		AttestedKeys: nil,
	}, time.Until(exp))

	return tok, nil
}
