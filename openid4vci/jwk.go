// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
)

// publicJWKFields returns only the public members of jwk, dropping any
// private key material (d, p, q, dp, dq, qi, k, oth, ...) a client may have
// included — a WIA's cnf.jwk and a WUA's attested keys are embedded in a
// signed, issued token and must never carry private key bytes.
func publicJWKFields(jwk map[string]any) map[string]any {
	allowed := map[string]struct{}{
		"kty": {}, "crv": {}, "x": {}, "y": {}, "n": {}, "e": {},
		"kid": {}, "use": {}, "key_ops": {}, "alg": {},
	}

	out := make(map[string]any, len(jwk))

	for k, v := range jwk {
		if _, ok := allowed[k]; ok {
			out[k] = v
		}
	}

	return out
}

func (s *Service) publicKeyFromJWK(cnf map[string]any) (any, error) {
	jwk, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return nil, errors.New("unsupported CNF")
	}

	kt, ok := jwk["kty"].(string)
	if !ok {
		return nil, errors.New("missing key type")
	}

	switch kt {
	case "EC":
		crv, ok := jwk["crv"].(string)
		if !ok {
			return nil, errors.New("missing curve")
		}

		var curve elliptic.Curve

		switch crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errors.New("unsupported curve")
		}

		xb, ok := jwk["x"].(string)
		if !ok {
			return nil, errors.New("missing x")
		}

		xbuf, err := base64.RawURLEncoding.DecodeString(xb)
		if err != nil {
			return nil, err
		}

		yb, ok := jwk["y"].(string)
		if !ok {
			return nil, errors.New("missing y")
		}

		ybuf, err := base64.RawURLEncoding.DecodeString(yb)
		if err != nil {
			return nil, err
		}

		size := (curve.Params().BitSize + 7) / 8

		point := make([]byte, 1+2*size)
		point[0] = 4
		copy(point[1+size-len(xbuf):1+size], xbuf)
		copy(point[1+2*size-len(ybuf):], ybuf)

		return ecdsa.ParseUncompressedPublicKey(curve, point)
	case "RSA":
		var (
			e int
			n *big.Int
		)

		var eb string

		if eb, ok = jwk["e"].(string); !ok {
			return nil, errors.New("missing exponent")
		}

		ebuf, err := base64.RawURLEncoding.DecodeString(eb)
		if err != nil {
			return nil, err
		}

		e = int(new(big.Int).SetBytes(ebuf).Uint64()) //nolint:gosec

		var nb string

		if nb, ok = jwk["n"].(string); !ok {
			return nil, errors.New("missing modulus")
		}

		nbuf, err := base64.RawURLEncoding.DecodeString(nb)
		if err != nil {
			return nil, err
		}

		n = new(big.Int).SetBytes(nbuf)

		return rsa.PublicKey{
			E: e,
			N: n,
		}, nil
	default:
		return nil, errors.New("unsupported key type")
	}
}
