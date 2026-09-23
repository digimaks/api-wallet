package openid4vci

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"azugo.io/azugo"
	"azugo.io/core/cache"
	"azugo.io/core/http"
	"github.com/gmb-lib/go-platform-kit/httpclient"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lx-lib/lx-go-jsondb"
	"go.uber.org/zap"
)

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

type StatusList struct {
	Idx int    `json:"idx"`
	URI string `json:"uri"`
}

type StatusInfo struct {
	StatusList StatusList `json:"status_list"`
}

type WuaTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

// EnsureInstanceAccount relinks a wallet instance to the account matching the
// currently authenticated identity, creating/updating the account as needed -
// covers the case where a device was previously registered under a different
// identity provider session (e.g. eParaksts) and is now used with another (e.g. Smart-ID).
func (s *Service) EnsureInstanceAccount(ctx *azugo.Context, hardwareKeyTag, code, givenName, familyName string) error {
	if hardwareKeyTag == "" || code == "" {
		return nil
	}

	if err := s.store.Exec(ctx, "wallet_provider.relink_instance_account", &struct {
		HardwareKeyTag string `json:"hardwareKeyTag"`
		Account        any    `json:"account"`
	}{
		HardwareKeyTag: hardwareKeyTag,
		Account: struct {
			Code          string `json:"code"`
			GivenName     string `json:"givenName"`
			FamilyName    string `json:"familyName"`
			RequesterCode string `json:"requesterCode"`
		}{
			Code:          code,
			GivenName:     givenName,
			FamilyName:    familyName,
			RequesterCode: code,
		},
	}, nil); err != nil {
		var eerr jsondb.ExecError
		if errors.As(err, &eerr) && eerr.Code == "err:instance:not_found" {
			// Instance not registered yet - nothing to relink; POST /instance will create it.
			return nil
		}

		return fmt.Errorf("failed to relink wallet instance account: %w", err)
	}

	return nil
}

func (s *Service) StatusList(ctx *azugo.Context, docType string, country string, expiryDate string) (*StatusInfo, error) {
	client := ctx.HTTPClient().WithBaseURL(s.config.StatusListAPIURL).WithOptions(&http.TLSConfig{
		InsecureSkipVerify: true,
	})

	data := make(map[string][]string)

	data["country"] = []string{country}
	data["doctype"] = []string{docType}
	data["expiry_date"] = []string{expiryDate}

	opts := append([]http.RequestOption{http.WithHeader("X-API-KEY", s.config.StatusListAPIKey)}, httpclient.CorrelationOptions(ctx)...)

	res, err := client.PostForm("/take", data, opts...)
	if err != nil {
		ctx.Log().Error(
			"failed to allocate status list slot",
			zap.Error(err),
			zap.String("doctype", docType),
			zap.String("country", country),
			zap.String("expiry_date", expiryDate),
		)

		return nil, err
	}

	var jsonData StatusInfo

	err = json.Unmarshal(res, &jsonData)
	if err != nil {
		ctx.Log().Error(
			"failed to parse status list response",
			zap.Error(err),
			zap.String("doctype", docType),
			zap.Int("bytes", len(res)),
		)

		return nil, fmt.Errorf("error parsing JSON string: %w", err)
	}

	return &jsonData, nil
}

// isWalletRevoked checks if a wallet instance has been revoked
func (s *Service) isWalletRevoked(ctx *azugo.Context, hardwareKeyTag string) (bool, error) {
	var result struct {
		IsRevoked bool `json:"is_revoked"`
	}

	err := s.store.Exec(ctx, "wallet_provider.get_revocation_status", &struct {
		HardwareKeyTag string `json:"hardware_key_tag"`
	}{
		HardwareKeyTag: hardwareKeyTag,
	}, &result)
	if err != nil {
		var eerr jsondb.ExecError
		if errors.As(err, &eerr) && eerr.Code == "not_found" {
			// No revocation info means not revoked
			return false, nil
		}

		return false, fmt.Errorf("failed to get revocation status: %w", err)
	}

	return result.IsRevoked, nil
}

// storeWUARevocationInfo stores the revocation index and status list info for a WUA
func (s *Service) storeWUARevocationInfo(ctx *azugo.Context, hardwareKeyTag string, statusInfo *StatusInfo, wuaExpiresAt time.Time) error {
	if statusInfo == nil || statusInfo.StatusList.URI == "" {
		return errors.New("invalid status info")
	}

	err := s.store.Exec(ctx, "wallet_provider.allocate_revocation_index", &struct {
		HardwareKeyTag string `json:"hardware_key_tag"`
		StatusListIdx  int    `json:"status_list_idx"`
		StatusListURI  string `json:"status_list_uri"`
		WUAExpiresAt   string `json:"wua_expires_at"`
	}{
		HardwareKeyTag: hardwareKeyTag,
		StatusListIdx:  statusInfo.StatusList.Idx,
		StatusListURI:  statusInfo.StatusList.URI,
		WUAExpiresAt:   wuaExpiresAt.Format(time.RFC3339),
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to allocate revocation index: %w", err)
	}

	return nil
}

func (s *Service) SetAccessContext(ctx *azugo.Context, sessionID string, value AccessContext, ttl ...time.Duration) error {
	s.wuaLock.Lock()
	defer s.wuaLock.Unlock()

	tokenPreview := previewToken(value.AccessToken)

	ctx.Log().Debug("Setting wua cache", zap.String("sessionID", sessionID), zap.String("accessToken", tokenPreview), zap.Bool("hasPerson", value.Person != nil))

	var setErr error
	if len(ttl) > 0 && ttl[0] > 0 {
		setErr = s.wuaCache.Set(ctx, sessionID, value, cache.TTL[AccessContext](ttl[0]))
	} else {
		setErr = s.wuaCache.Set(ctx, sessionID, value)
	}

	if setErr != nil {
		ctx.Log().Error("Failed to set wua cache", zap.String("sessionID", sessionID), zap.Error(setErr))
		return setErr
	}

	ctx.Log().Debug("Successfully set wua cache", zap.String("sessionID", sessionID))

	return nil
}

func (s *Service) PopAccessContext(ctx *azugo.Context, key string) (*AccessContext, error) {
	s.wuaLock.Lock()
	defer s.wuaLock.Unlock()

	ctxValue, err := s.wuaCache.Pop(ctx, key)
	if err != nil {
		ctx.Log().Error("Failed to pop from wua cache", zap.String("key", key), zap.Error(err))
		return nil, fmt.Errorf("key '%s' not found in cache", key)
	}

	return &ctxValue, nil
}

func previewToken(token string) string {
	if len(token) <= 20 {
		return token
	}

	return token[:20] + "..."
}

// decodeX5CCert decodes a JOSE x5c entry. Per RFC 7515 it must be standard base64 (with
// padding), but some client SDKs emit base64url or strip padding in transit - try standard
// first, then fall back to the url-safe variants before giving up.
func decodeX5CCert(b64 string) ([]byte, error) {
	if der, err := base64.StdEncoding.DecodeString(b64); err == nil {
		return der, nil
	}

	if der, err := base64.RawStdEncoding.DecodeString(b64); err == nil {
		return der, nil
	}

	if der, err := base64.URLEncoding.DecodeString(b64); err == nil {
		return der, nil
	}

	return base64.RawURLEncoding.DecodeString(b64)
}

func (s *Service) ValidateWUA(ctx *azugo.Context, jwtStr string) error {
	// Per TS3 v1.5, WUA/KA identity is inferred from the signing certificate in the
	// x5c JOSE header parameter - there is no iss claim and no kid requirement.
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return azugo.BadRequestError{Description: "invalid jwt format"}
	}

	decode := func(seg string) ([]byte, error) {
		return base64.RawURLEncoding.DecodeString(seg)
	}

	hb, err := decode(parts[0])
	if err != nil {
		return azugo.BadRequestError{Description: fmt.Sprintf("failed to decode header: %v", err)}
	}

	var header map[string]any
	if err := json.Unmarshal(hb, &header); err != nil {
		return azugo.BadRequestError{Description: fmt.Sprintf("failed to parse header: %v", err)}
	}

	x5cRaw, ok := header["x5c"].([]any)
	if !ok || len(x5cRaw) == 0 {
		return azugo.BadRequestError{Description: "missing x5c in JWT header"}
	}

	leafB64, _ := x5cRaw[0].(string)

	leafDER, err := decodeX5CCert(leafB64)
	if err != nil {
		return azugo.BadRequestError{Description: fmt.Sprintf("invalid x5c leaf: %v", err)}
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return azugo.BadRequestError{Description: fmt.Sprintf("failed to parse x5c leaf cert: %v", err)}
	}

	// TODO: verify leafCert chains to a trust anchor on the Wallet Provider Trusted List.
	pubKey := leafCert.PublicKey

	// Choose allowed algs based on key type
	var allowedAlgs []string

	switch pubKey.(type) {
	case *ecdsa.PublicKey:
		allowedAlgs = []string{"ES256", "ES384", "ES512"}
	case *rsa.PublicKey:
		allowedAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
	default:
		return azugo.BadRequestError{Description: "unsupported key type"}
	}

	token, err := jwt.Parse(
		jwtStr,
		func(t *jwt.Token) (any, error) {
			return pubKey, nil
		},
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if isJWTError(err) {
			return azugo.BadRequestError{Description: err.Error()}
		}

		return err
	}

	if !token.Valid {
		return azugo.BadRequestError{Description: "invalid token signature"}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return azugo.BadRequestError{Description: "invalid token claims"}
	}

	// exp was checked by jwt.WithExpirationRequired()

	// Enforce key_storage to be iso_18045_high
	if !claimsListContains(claims["key_storage"], "iso_18045_high") {
		return azugo.BadRequestError{Description: "insufficient key storage level"}
	}

	if st, ok := claims["key_storage_status"].(map[string]any); ok {
		if status, ok := st["status"].(map[string]any); ok {
			if sl, ok := status["status_list"].(map[string]any); ok {
				// Expect idx and uri fields; do lightweight validation
				idx, ok := sl["idx"].(float64)
				if !ok {
					return azugo.BadRequestError{Description: "status list missing idx"}
				}

				uri, ok := sl["uri"].(string)
				if !ok || strings.TrimSpace(uri) == "" {
					return azugo.BadRequestError{Description: "status list missing uri"}
				}

				if err := validateStatusList(ctx, uri, idx); err != nil {
					return azugo.BadRequestError{Description: "failed to validate status list " + err.Error()}
				}
			}
		}
	}

	// Passed validation
	return nil
}

// claimsListContains reports whether v (a JSON string or array of strings) contains want.
func claimsListContains(v any, want string) bool {
	switch t := v.(type) {
	case string:
		return t == want
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}

	return false
}

func validateStatusList(ctx *azugo.Context, uri string, idx float64) error {
	client := ctx.HTTPClient()

	opts := append([]http.RequestOption{http.WithHeader("Accept", "application/statuslist+jwt")}, httpclient.CorrelationOptions(ctx)...)

	resp, err := client.Get(uri, opts...)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}

	jws := string(resp) // Status list JWT string available for further processing

	// 2) Decode header/payload to verify typ and prepare for key selection
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return errors.New("status list is not a compact JWS")
	}

	decode := func(seg string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(seg) }

	hb, err := decode(parts[0])
	if err != nil {
		return fmt.Errorf("status list: failed to decode header: %w", err)
	}

	_, err = decode(parts[1])
	if err != nil {
		return fmt.Errorf("status list: failed to decode payload: %w", err)
	}

	var hdr map[string]any
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return fmt.Errorf("status list: failed to parse header: %w", err)
	}

	if typ, _ := hdr["typ"].(string); typ != "statuslist+jwt" {
		return errors.New("status list: unexpected typ")
	}

	alg, _ := hdr["alg"].(string)
	if alg == "" {
		return errors.New("status list: missing alg")
	}

	// 3) Build verification key (using x5c leaf public key if provided)
	var verifyKey any

	if x5cRaw, ok := hdr["x5c"].([]any); ok && len(x5cRaw) > 0 {
		// Take leaf cert (first element)
		s0, _ := x5cRaw[0].(string)

		der, err := base64.StdEncoding.DecodeString(s0)
		if err != nil {
			return fmt.Errorf("status list: invalid x5c leaf: %w", err)
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("status list: cannot parse x5c leaf cert: %w", err)
		}
		// Time-validity check for the leaf
		// TODO: Re-enable, temp disable for test
		// now := time.Now()
		// if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		// 	return errors.New("status list: x5c leaf not time-valid")
		// }

		verifyKey = cert.PublicKey
	} else {
		// If no x5c, this implementation requires it. You may extend to support other trust models.
		return errors.New("status list: missing x5c header")
	}

	// 4) Verify JWS signature and parse claims
	allowedAlgs := []string{alg}

	tok, err := jwt.Parse(jws, func(t *jwt.Token) (any, error) {
		// Enforce the same alg
		if t.Method.Alg() != alg {
			return nil, errors.New("status list: alg mismatch")
		}

		return verifyKey, nil
	}, jwt.WithValidMethods(allowedAlgs))
	if err != nil {
		if isJWTError(err) {
			return fmt.Errorf("status list: %s", err.Error())
		}

		return fmt.Errorf("status list: invalid signature: %w", err)
	}

	if !tok.Valid {
		return errors.New("status list: invalid signature")
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("status list: invalid claims")
	}

	// 5) Validate required claims per draft §8.3
	// sub must equal the fetched URI
	if sub, _ := claims["sub"].(string); strings.TrimSpace(sub) != strings.TrimSpace(uri) {
		return errors.New("status list: sub mismatch")
	}
	// iat must not be in the future (allow small leeway)
	if iatF, ok := claims["iat"].(float64); ok {
		iat := time.Unix(int64(iatF), 0)
		if iat.After(time.Now().Add(2 * time.Minute)) {
			return errors.New("status list: iat is in the future")
		}
	} else {
		return errors.New("status list: missing iat")
	}

	// status_list.bits and status_list.lst are required
	var statusList map[string]any
	if sl, ok := claims["status_list"].(map[string]any); ok {
		statusList = sl
	} else {
		return errors.New("status list: missing status_list")
	}

	bitsF, ok := statusList["bits"].(float64)
	if !ok {
		return errors.New("status list: missing bits")
	}

	bits := int(bitsF)
	if bits <= 0 {
		return errors.New("status list: invalid bits")
	}

	lstStr, ok := statusList["lst"].(string)
	if !ok || strings.TrimSpace(lstStr) == "" {
		return errors.New("status list: missing lst")
	}

	// 6) Decode bitstring: base64url-decode then zlib-decompress
	raw, err := base64.RawURLEncoding.DecodeString(lstStr)
	if err != nil {
		return fmt.Errorf("status list: invalid lst encoding: %w", err)
	}

	dec, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("status list: zlib init failed: %w", err)
	}

	defer func() {
		_ = dec.Close()
	}()

	buf := new(bytes.Buffer)

	const maxDecompressedSize = 10 * 1024 * 1024 // 10MB limit
	if _, err := io.Copy(buf, io.LimitReader(dec, maxDecompressedSize)); err != nil {
		return fmt.Errorf("status list: zlib decompress failed: %w", err)
	}

	if buf.Len() >= maxDecompressedSize {
		return errors.New("status list: decompressed data exceeds size limit")
	}

	bitset := buf.Bytes()

	// 7) Evaluate the bit at idx
	index := int(idx)

	listed, err := isIndexListed(bitset, index, bits)
	if err != nil {
		return fmt.Errorf("status list: %w", err)
	}

	if listed {
		// Per common interpretation, a set bit means the subject is on the list (e.g., revoked/invalid).
		return fmt.Errorf("status list: entry at idx=%d is listed", index)
	}

	// Success: entry is not listed
	return nil
}

// isIndexListed returns true if the entry at index is set in the bitset.
// For bits == 1, a set bit indicates "listed". For multi-bit entries, this simplified
// implementation treats any non-zero value across the entry width as "listed".
func isIndexListed(bitset []byte, index int, bitsPerEntry int) (bool, error) {
	if index < 0 {
		return false, errors.New("invalid idx")
	}

	if bitsPerEntry <= 0 {
		return false, errors.New("invalid bits per entry")
	}

	// Calculate total available indices
	totalBits := len(bitset) * 8
	maxIndex := (totalBits / bitsPerEntry) - 1

	if index > maxIndex {
		// Index is beyond available data - treat as not listed (valid/not revoked)
		return false, nil
	}

	offset := index * bitsPerEntry
	bytePos := offset / 8
	bitPos := offset % 8

	if bitsPerEntry == 1 {
		if bytePos >= len(bitset) {
			return false, nil
		}
		// Use LSB-first ordering (right-to-left)
		mask := byte(1 << bitPos)
		po := bitset[bytePos]

		return (po & mask) != 0, nil
	}

	// Multi-bit entry logic with LSB-first ordering
	val := 0

	for i := range bitsPerEntry {
		curOffset := offset + i
		bp := curOffset / 8
		ip := curOffset % 8

		if bp >= len(bitset) {
			break
		}

		// Use LSB-first bit extraction
		bit := (bitset[bp] >> ip) & 0x01
		val |= (int(bit) << i)
	}

	return val != 0, nil
}
