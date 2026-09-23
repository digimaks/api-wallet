// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

func isJWTError(err error) bool {
	return errors.Is(err, jwt.ErrInvalidKey) ||
		errors.Is(err, jwt.ErrInvalidKeyType) ||
		errors.Is(err, jwt.ErrHashUnavailable) ||
		errors.Is(err, jwt.ErrTokenMalformed) ||
		errors.Is(err, jwt.ErrTokenUnverifiable) ||
		errors.Is(err, jwt.ErrTokenSignatureInvalid) ||
		errors.Is(err, jwt.ErrTokenRequiredClaimMissing) ||
		errors.Is(err, jwt.ErrTokenInvalidAudience) ||
		errors.Is(err, jwt.ErrTokenExpired) ||
		errors.Is(err, jwt.ErrTokenUsedBeforeIssued) ||
		errors.Is(err, jwt.ErrTokenInvalidIssuer) ||
		errors.Is(err, jwt.ErrTokenInvalidSubject) ||
		errors.Is(err, jwt.ErrTokenNotValidYet) ||
		errors.Is(err, jwt.ErrTokenInvalidId) ||
		errors.Is(err, jwt.ErrTokenInvalidClaims) ||
		errors.Is(err, jwt.ErrInvalidType)
}
