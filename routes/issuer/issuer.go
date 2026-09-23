// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"azugo.io/azugo"
	"github.com/digimaks/api-wallet/openid4vci"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/gmb-lib/go-platform-kit/httpclient"
	"github.com/gmb-lib/go-platform-kit/propagation"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// @operationId GetOpenIDCredentialIssuer
// @title Gets OpenID Credential Issuer
// @description Gets openid-credential-issuer.json
// @success 200 object string "OK"
// @failure 400 string string "Bad request"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @failure 422 string string "Invalid request"
// @failure 500 string string "Internal server error"
// @resource WellKnown
// @route /.well-known/openid-credential-issuer [get].
func (r *router) openIDCredentialIssuer(ctx *azugo.Context) {
	client := ctx.HTTPClient().WithBaseURL(r.Config().Issuer.APIURL)

	var res map[string]any

	err := client.GetJSON("/.well-known/openid-credential-issuer", &res, httpclient.CorrelationOptions(ctx)...)
	if err != nil {
		ctx.Log().Error("failed to fetch openid-credential-issuer from backend", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:wellknown:issuerMetadataFetchFailed"))

		return
	}

	publicURL := strings.TrimSuffix(r.Config().WalletPublicURL, "/")

	res["nonce_endpoint"] = publicURL + "/nonce"
	res["credential_issuer"] = publicURL
	res["credential_endpoint"] = publicURL + "/credential"
	res["authorization_servers"] = []string{publicURL}

	// Override credential_request_encryption so Android encrypts to
	// the Go server's key (the one it can actually decrypt)
	kid, kidErr := r.OpenID4VCI().SigningCertificateKID()

	pubKey, pubErr := r.OpenID4VCI().SigningPublicKey()
	if kidErr == nil && pubErr == nil {
		kidURLSafe := strings.NewReplacer("+", "-", "/", "_", "=", "").Replace(kid)
		if goKey, jwkErr := publicKeyToJWK(pubKey); jwkErr == nil {
			goKey["kid"] = kidURLSafe
			goKey["use"] = "enc"
			goKey["alg"] = "ECDH-ES"
			res["credential_request_encryption"] = map[string]any{
				"alg_values_supported": []string{"ECDH-ES"},
				"enc_values_supported": []string{"A128GCM", "A192GCM", "A256GCM"},
				"encryption_required":  false,
				"jwks": map[string]any{
					"keys": []any{goKey},
				},
			}
		}
	}

	ctx.JSON(res)
}

// @operationId GetOpenIDConfiguration
// @title Gets OpenID Configuration
// @description Gets openid-configuration.json
// @success 200 object string "OK"
// @failure 400 string string "Bad request"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @failure 422 string string "Invalid request"
// @failure 500 string string "Internal server error"
// @resource WellKnown
// @route /.well-known/openid-configuration [get].
func (r *router) openIDConfiguration(ctx *azugo.Context) {
	client := ctx.HTTPClient().WithBaseURL(r.Config().Issuer.APIURL)

	var res map[string]any

	err := client.GetJSON("/.well-known/openid-configuration", &res, httpclient.CorrelationOptions(ctx)...)
	if err != nil {
		ctx.Log().Error("failed to fetch openid-configuration from backend", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:wellknown:configurationFetchFailed"))

		return
	}

	publicURL := strings.TrimSuffix(r.Config().WalletPublicURL, "/")

	res["token_endpoint"] = publicURL + "/token"
	res["issuer"] = publicURL
	res["jwks_uri"] = publicURL + "/.well-known/jwks"

	ctx.JSON(res)
}

// @operationId GetOauthAuthorizationServer
// @title Gets OAuth 2.0 Configuration
// @description Gets oauth-authorization-server.json
// @success 200 object string "OK"
// @failure 400 string string "Bad request"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @failure 422 string string "Invalid request"
// @failure 500 string string "Internal server error"
// @resource WellKnown
// @route /.well-known/oauth-authorization-server [get].
func (r *router) oauthAuthorizationServer(ctx *azugo.Context) {
	publicURL := strings.TrimSuffix(r.Config().WalletPublicURL, "/")

	authorizationEndpoint := publicURL + "/authorizationV3"

	var pushedAuthorizationRequestEndpoint string

	if u := strings.TrimSuffix(r.Config().IDAuthPublicURL, "/"); u != "" {
		authorizationEndpoint = u + "/authorizationV3"
		pushedAuthorizationRequestEndpoint = u + "/par"
	}

	res := map[string]any{
		"issuer":                 publicURL,
		"authorization_endpoint": authorizationEndpoint,
		"token_endpoint":         publicURL + "/token",
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		},
		"pre-authorized_grant_anonymous_access_supported":     true,
		"token_endpoint_auth_methods_supported":               []string{"attest_jwt_client_auth"},
		"jwks_uri":                                            publicURL + "/.well-known/jwks",
		"client_attestation_signing_alg_values_supported":     []string{"ES256", "ES384", "ES512"},
		"client_attestation_pop_signing_alg_values_supported": []string{"ES256", "ES384", "ES512"},
		"dpop_signing_alg_values_supported":                   []string{"ES256"},
	}

	if pushedAuthorizationRequestEndpoint != "" {
		res["pushed_authorization_request_endpoint"] = pushedAuthorizationRequestEndpoint
	}

	ctx.JSON(res)
}

// @operationId GetOpenIDJWKS
// @title Gets OpenID JWKS
// @description Gets OpenID configuration JSON Web Key Set
// @success 200 object string "OK"
// @failure 400 string string "Bad request"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @failure 422 string string "Invalid request"
// @failure 500 string string "Internal server error"
// @resource WellKnown
// @route /.well-known/jwks [get].
func (r *router) openIDJWKS(ctx *azugo.Context) {
	// Serves wallet-api's OWN keys only. This document is the WUA trust
	// anchor: issuer-go resolves the WUA iss (WalletPublicURL) to this JWKS
	// to verify WUA signatures. issuer-go's keys live in its own
	// /.well-known/jwks.json — no backend proxying here.
	res := struct {
		Keys []map[string]any `json:"keys"`
	}{}

	kid, err := r.OpenID4VCI().SigningCertificateKID()
	if err != nil {
		ctx.Log().Error("failed to get signing certificate KID for JWKS", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:wellknown:signingKidUnavailable"))

		return
	}

	kidURLSafe := strings.NewReplacer("+", "-", "/", "_", "=", "").Replace(kid)

	pubKey, err := r.OpenID4VCI().SigningPublicKey()
	if err != nil {
		ctx.Log().Error("failed to get signing public key for JWKS", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:wellknown:signingKeyUnavailable"))

		return
	}

	goKey, err := publicKeyToJWK(pubKey)
	if err != nil {
		ctx.Log().Error("failed to convert signing public key to JWK", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:wellknown:jwkConversionFailed"))

		return
	}

	goKey["kid"] = kidURLSafe
	goKey["use"] = "enc"
	goKey["alg"] = "ECDH-ES"

	// Remove any existing enc key (Python's) and inject Go's own key
	filtered := make([]map[string]any, 0, len(res.Keys)+1)
	for _, key := range res.Keys {
		u, _ := key["use"].(string)
		if u == "enc" {
			continue // drop Python's enc key - replace with ours below
		}

		filtered = append(filtered, key)
	}

	filtered = append(filtered, goKey)
	res.Keys = filtered

	ctx.Response().Header.Set("Cache-Control", "no-store")
	ctx.JSON(res)
}

func (r *router) credential(ctx *azugo.Context) {
	// Parse the incoming JSON payload
	var payload map[string]interface{}

	contentType := ctx.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/jwt") {
		jweBytes := ctx.Body.Bytes()

		// ── Get ECDH private key from the issuer signing certificate ──
		signingCert, err := r.OpenID4VCI().SigningCertificate()
		if err != nil {
			ctx.Log().Error("Failed to load signing certificate", zap.Error(err))
			ctx.StatusCode(500)
			ctx.JSON(map[string]interface{}{"error": "server_error", "error_description": "key unavailable"})

			return
		}

		ecPriv, ok := signingCert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			ctx.StatusCode(500)
			ctx.JSON(map[string]interface{}{"error": "server_error", "error_description": "invalid key type"})

			return
		}

		ecdhPrivKey, err := ecPriv.ECDH()
		if err != nil {
			ctx.StatusCode(500)
			ctx.JSON(map[string]interface{}{"error": "server_error", "error_description": "key conversion failed"})

			return
		}

		if pub, pErr := r.OpenID4VCI().SigningPublicKey(); pErr == nil {
			if ecdhPub, pErr := pub.ECDH(); pErr == nil {
				raw := ecdhPub.Bytes() // 0x04 || X (32 bytes) || Y (32 bytes)
				ctx.Log().Info(
					"Server ECDH public key",
					zap.String("x", base64.RawURLEncoding.EncodeToString(raw[1:33])),
					zap.String("y", base64.RawURLEncoding.EncodeToString(raw[33:65])),
				)
			}
		}

		decrypted, err := decryptJWE(string(jweBytes), ecdhPrivKey)
		if err != nil {
			ctx.Log().Error("Failed to decrypt JWE", zap.Error(err))
			ctx.StatusCode(400)
			ctx.JSON(map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "failed to decrypt credential request",
			})

			return
		}

		if err := json.Unmarshal(decrypted, &payload); err != nil {
			ctx.Log().Error("Failed to parse decrypted payload", zap.Error(err))
			ctx.StatusCode(400)
			ctx.JSON(map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "invalid content",
			})

			return
		}
	} else {
		// Plain JSON body
		if err := ctx.Body.JSON(&payload); err != nil {
			ctx.Log().Error("Failed to parse JSON payload", zap.Error(err))
			ctx.StatusCode(400)
			ctx.JSON(map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "invalid content",
			})

			return
		}
	}

	// credential_configuration_id is present on every real OID4VCI request
	// (WUA or DPoP-bound), so it can't be what distinguishes them. A
	// WUA-bound proof carrying key_attestation is no longer a sufficient
	// signal on its own — flow-b's DPoP-authenticated path now also requires
	// a key attestation on the proof (see issuer-go's
	// credentialConfigRequiresKeyAttestation), so both paths' proofs can
	// carry it. A DPoP-bound access token always carries a DPoP proof header
	// on every request per RFC 9449; the WUA-as-bearer scheme never does —
	// so DPoP header presence overrides key_attestation as the deciding
	// signal whenever both are present.
	if proofHasKeyAttestation(payload) && ctx.Header.Get("DPoP") == "" {
		r.credentialJWT(ctx, payload)

		return
	}

	// Get authorization header
	authHeader := ctx.Header.Get("Authorization")
	if authHeader == "" {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(map[string]string{"error": "Authorization header required"})

		return
	}

	// Log the forwarded request for debugging
	ctx.Log().Info("Forwarding credential request to issuer")

	// Forward the request to the issuer service
	reqBody, err := json.Marshal(payload)
	if err != nil {
		ctx.Log().Error("failed to marshal credential request", zap.Error(err))
		ctx.StatusCode(fasthttp.StatusInternalServerError)
		ctx.JSON(map[string]string{"error": "server_error", "error_description": "failed to build issuer request"})

		return
	}

	client := ctx.HTTPClient().WithBaseURL(r.Config().Issuer.APIURL)

	req := client.NewRequest()
	defer client.ReleaseRequest(req)

	if err := req.SetRequestURL("/credential"); err != nil {
		ctx.Log().Error("failed to build issuer request URL", zap.Error(err))
		ctx.StatusCode(fasthttp.StatusInternalServerError)
		ctx.JSON(map[string]string{"error": "server_error", "error_description": "failed to build issuer request"})

		return
	}

	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.Set("Content-Type", "application/json")

	if authHeader := ctx.Header.Get("Authorization"); authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	if proof := ctx.Header.Get("DPoP"); proof != "" {
		req.Header.Set("DPoP", proof)
	}

	httpclient.SetCorrelationHeaders(ctx, &req.Header)

	if iid := ctx.Header.Get(propagation.HeaderAppInstanceID); iid != "" {
		req.Header.Set(propagation.HeaderAppInstanceID, iid)
	}

	req.SetBody(reqBody)

	resp := client.NewResponse()
	defer client.ReleaseResponse(resp)

	doErr := client.Do(req, resp)
	if doErr != nil || !resp.Success() {
		relayDownstreamProblem(ctx, "issuer-go", doErr, resp, "issuer service unreachable")

		return
	}

	body, err := resp.BodyUncompressed()
	if err != nil {
		ctx.Log().Error("failed to read issuer response body", zap.Error(err))
		ctx.StatusCode(fasthttp.StatusBadGateway)
		ctx.JSON(map[string]string{"error": "server_error", "error_description": "unexpected response from issuer"})

		return
	}

	if nonce := resp.Header.Peek("DPoP-Nonce"); len(nonce) > 0 {
		ctx.Header.Set("DPoP-Nonce", string(nonce))
	}

	ctx.ContentType("application/json")
	ctx.Raw(body)
}

func (r *router) token(ctx *azugo.Context) {
	grantType, err := ctx.Form.String("grant_type")
	if err != nil {
		ctx.Error(err)

		return
	}

	data := make(map[string][]string)

	for k, v := range ctx.Request().PostArgs().All() {
		data[string(k)] = append(data[string(k)], string(v))
	}

	// Pre-authorized code grant - inject tx_code from cache, forward to idauth
	if grantType == "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
		if err := r.validateClientAttestation(ctx); err != nil {
			var oerr *oauthError
			if errors.As(err, &oerr) {
				ctx.StatusCode(fasthttp.StatusUnauthorized)
				ctx.JSON(oerr)
			} else {
				ctx.Log().Error("failed to validate client attestation", zap.Error(err))
				ctx.Error(pkerrors.NewProblem("err:token:clientAttestationValidationFailed"))
			}

			return
		}

		var preAuthCode string
		if v := ctx.Form.StringOptional("pre-authorized_code"); v != nil {
			preAuthCode = *v
		} else {
			preAuthCode = ""
		}

		var txCode string
		if v := ctx.Form.StringOptional("tx_code"); v != nil {
			txCode = *v
		} else {
			txCode = ""
		}

		if txCode == "" && preAuthCode != "" {
			// Inject tx_code cached during QR generation (internal flow only)
			if cached, err := r.Issuer().GetTXCode(ctx, preAuthCode); err == nil {
				data["tx_code"] = []string{cached}
			}
		}

		client := ctx.HTTPClient().WithBaseURL(r.Config().IDAuth.URL)

		req := client.NewRequest()
		defer client.ReleaseRequest(req)

		if err := req.SetRequestURL("/api/1.0/token"); err != nil {
			ctx.Log().Error("failed to build idauth request URL", zap.Error(err))
			ctx.StatusCode(fasthttp.StatusInternalServerError)
			ctx.JSON(map[string]string{"error": "server_error", "error_description": "failed to build idauth request"})

			return
		}

		req.Header.SetMethod(fasthttp.MethodPost)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		if proof := ctx.Header.Get("DPoP"); proof != "" {
			req.Header.Set("DPoP", proof)
		}

		httpclient.SetCorrelationHeaders(ctx, &req.Header)

		req.PostArgs().Reset()

		for k, vs := range data {
			for _, v := range vs {
				req.PostArgs().Add(k, v)
			}
		}

		resp := client.NewResponse()
		defer client.ReleaseResponse(resp)

		doErr := client.Do(req, resp)
		if doErr != nil || !resp.Success() {
			relayDownstreamProblem(ctx, "idauth", doErr, resp, "idauth service unreachable")

			return
		}

		body, err := resp.BodyUncompressed()
		if err != nil {
			ctx.Log().Error("failed to read idauth response body", zap.Error(err))
			ctx.StatusCode(fasthttp.StatusBadGateway)
			ctx.JSON(map[string]string{"error": "server_error", "error_description": "unexpected response from idauth"})

			return
		}

		if nonce := resp.Header.Peek("DPoP-Nonce"); len(nonce) > 0 {
			ctx.Header.Set("DPoP-Nonce", string(nonce))
		}

		ctx.ContentType("application/json")
		ctx.Raw(body)

		return
	}

	// Authorization code grant - forward to idauth
	if grantType == "authorization_code" {
		if err := r.validateClientAttestation(ctx); err != nil {
			var oerr *oauthError
			if errors.As(err, &oerr) {
				ctx.StatusCode(fasthttp.StatusUnauthorized)
				ctx.JSON(oerr)
			} else {
				ctx.Log().Error("failed to validate client attestation", zap.Error(err))
				ctx.Error(pkerrors.NewProblem("err:token:clientAttestationValidationFailed"))
			}

			return
		}

		client := ctx.HTTPClient().WithBaseURL(r.Config().IDAuth.URL)

		req := client.NewRequest()
		defer client.ReleaseRequest(req)

		if err := req.SetRequestURL("/api/1.0/token"); err != nil {
			ctx.Log().Error("failed to build idauth request URL", zap.Error(err))
			ctx.StatusCode(fasthttp.StatusInternalServerError)
			ctx.JSON(map[string]string{"error": "server_error", "error_description": "failed to build idauth request"})

			return
		}

		req.Header.SetMethod(fasthttp.MethodPost)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		if proof := ctx.Header.Get("DPoP"); proof != "" {
			req.Header.Set("DPoP", proof)
		}

		if wia := string(ctx.Request().Header.Peek("OAuth-Client-Attestation")); wia != "" {
			req.Header.Set("OAuth-Client-Attestation", wia)
		}

		if pop := string(ctx.Request().Header.Peek("OAuth-Client-Attestation-PoP")); pop != "" {
			req.Header.Set("OAuth-Client-Attestation-PoP", pop)
		}

		httpclient.SetCorrelationHeaders(ctx, &req.Header)

		req.PostArgs().Reset()

		for k, vs := range data {
			for _, v := range vs {
				req.PostArgs().Add(k, v)
			}
		}

		resp := client.NewResponse()
		defer client.ReleaseResponse(resp)

		doErr := client.Do(req, resp)
		if doErr != nil || !resp.Success() {
			relayDownstreamProblem(ctx, "idauth", doErr, resp, "idauth service unreachable")

			return
		}

		body, err := resp.BodyUncompressed()
		if err != nil {
			ctx.Log().Error("failed to read idauth response body", zap.Error(err))
			ctx.StatusCode(fasthttp.StatusBadGateway)
			ctx.JSON(map[string]string{"error": "server_error", "error_description": "unexpected response from idauth"})

			return
		}

		if nonce := resp.Header.Peek("DPoP-Nonce"); len(nonce) > 0 {
			ctx.Header.Set("DPoP-Nonce", string(nonce))
		}

		ctx.ContentType("application/json")
		ctx.Raw(body)

		return
	}

	// Refresh token grant — forward to idauth. Unlike the other two
	// grants, this one does NOT call validateClientAttestation: idauth's
	// refresh_token handler authenticates via DPoP-key binding alone, not
	// a fresh WIA. Requiring attestation here would reject every
	// legitimate refresh call.
	if grantType == "refresh_token" {
		client := ctx.HTTPClient().WithBaseURL(r.Config().IDAuth.URL)

		req := client.NewRequest()
		defer client.ReleaseRequest(req)

		if err := req.SetRequestURL("/api/1.0/token"); err != nil {
			ctx.Log().Error("failed to build idauth request URL", zap.Error(err))
			ctx.StatusCode(fasthttp.StatusInternalServerError)
			ctx.JSON(map[string]string{"error": "server_error", "error_description": "failed to build idauth request"})

			return
		}

		req.Header.SetMethod(fasthttp.MethodPost)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		if proof := ctx.Header.Get("DPoP"); proof != "" {
			req.Header.Set("DPoP", proof)
		}

		if wia := string(ctx.Request().Header.Peek("OAuth-Client-Attestation")); wia != "" {
			req.Header.Set("OAuth-Client-Attestation", wia)
		}

		if pop := string(ctx.Request().Header.Peek("OAuth-Client-Attestation-PoP")); pop != "" {
			req.Header.Set("OAuth-Client-Attestation-PoP", pop)
		}

		httpclient.SetCorrelationHeaders(ctx, &req.Header)

		req.PostArgs().Reset()

		for k, vs := range data {
			for _, v := range vs {
				req.PostArgs().Add(k, v)
			}
		}

		resp := client.NewResponse()
		defer client.ReleaseResponse(resp)

		doErr := client.Do(req, resp)
		if doErr != nil || !resp.Success() {
			relayDownstreamProblem(ctx, "idauth", doErr, resp, "idauth service unreachable")

			return
		}

		body, err := resp.BodyUncompressed()
		if err != nil {
			ctx.Log().Error("failed to read idauth response body", zap.Error(err))
			ctx.StatusCode(fasthttp.StatusBadGateway)
			ctx.JSON(map[string]string{"error": "server_error", "error_description": "unexpected response from idauth"})

			return
		}

		if nonce := resp.Header.Peek("DPoP-Nonce"); len(nonce) > 0 {
			ctx.Header.Set("DPoP-Nonce", string(nonce))
		}

		ctx.ContentType("application/json")
		ctx.Raw(body)

		return
	}

	// Unknown grant type
	ctx.StatusCode(fasthttp.StatusBadRequest)
	ctx.JSON(map[string]string{
		"error":             "unsupported_grant_type",
		"error_description": "The authorization grant type is not supported",
	})
}

// validateClientAttestation enforces RFC-draft attest_jwt_client_auth at the token endpoint.
// It reads OAuth-Client-Attestation (WIA) and OAuth-Client-Attestation-PoP headers,
// verifies the WIA was issued by this server, and verifies the PoP proves key possession.
func (r *router) validateClientAttestation(ctx *azugo.Context) error {
	wia := string(ctx.Request().Header.Peek("OAuth-Client-Attestation"))
	if wia == "" {
		return &oauthError{Code: "invalid_client", Description: "OAuth-Client-Attestation header required"}
	}

	if _, _, err := r.OpenID4VCI().VerifyAttestation(ctx, wia); err != nil {
		ctx.Log().Warn("WIA verification failed", zap.Error(err))
		return &oauthError{Code: "invalid_client", Description: "invalid client attestation"}
	}

	pop := string(ctx.Request().Header.Peek("OAuth-Client-Attestation-PoP"))
	if pop == "" {
		return &oauthError{Code: "invalid_client", Description: "OAuth-Client-Attestation-PoP header required"}
	}

	if err := r.OpenID4VCI().VerifyAttestationPoP(wia, pop); err != nil {
		ctx.Log().Warn("attestation PoP verification failed", zap.Error(err))
		return &oauthError{Code: "invalid_client", Description: "invalid client attestation PoP"}
	}

	return nil
}

type oauthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *oauthError) Error() string { return e.Code + ": " + e.Description }

func (r *router) credentialJWT(ctx *azugo.Context, payload map[string]interface{}) {
	// Get authorization header
	authHeader := ctx.Header.Get("Authorization")
	if authHeader == "" {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(map[string]string{"error": "Authorization header required"})

		return
	}

	// Log the authorization header being used for debugging
	ctx.Log().Info("Attempting to retrieve access token from cache", zap.Int("authHeader_length", len(authHeader)))

	ka, proofMode, err := extractAccessContextKey(payload)
	if err != nil {
		ctx.Log().Error(
			"failed to extract access context key from proof", zap.Error(err),
			zap.String("credential_configuration_id", func() string {
				if v, ok := payload["credential_configuration_id"].(string); ok {
					return v
				}

				return ""
			}()),
		)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(map[string]string{"error": err.Error()})

		return
	}

	accessCtx, err := r.OpenID4VCI().PopAccessContext(ctx, ka)
	if err != nil || accessCtx == nil {
		ctx.Log().Error(
			"access context not found for key_attestation",
			zap.String("proof_mode", proofMode),
			zap.String("ka_preview", func() string {
				if len(ka) > 20 {
					return ka[:20] + "..."
				}

				return ka
			}()),
			zap.NamedError("pop_err", err),
		)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(map[string]string{"error": "access context not found for key_attestation"})

		return
	}

	if proof, ok := payload["proof"].(map[string]any); ok {
		switch jwtVal := proof["jwt"].(type) {
		case string:
			proof["jwt"] = []string{jwtVal}
		case []any:
			strs := make([]string, 0, len(jwtVal))
			for _, v := range jwtVal {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					strs = append(strs, s)
				}
			}

			if len(strs) > 0 {
				proof["jwt"] = strs
			}
		}

		payload["proof"] = proof
	}

	ctx.Log().Info("Resolved WUA access context for credential request", zap.Bool("hasPerson", accessCtx.Person != nil))

	// Always forward the client's credential-issuance bearer token (OIDC access token)
	// to the backend. The WUA access token is included in the payload as access_token
	// for the backend to use as additional wallet attestation context.
	// Using the WUA access token as the Authorization header caused 401 because the
	// Python issuer validates Authorization against idauth, not wallet-issued tokens.
	if accessCtx.AccessToken != "" {
		payload["access_token"] = accessCtx.AccessToken
	}

	credentialData, err := r.generateCredentialData(ctx, accessCtx.Person)
	if err != nil {
		ctx.Log().Error("Failed to generate credential data", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:credential:dataGenerationFailed"))

		return
	}

	if proofMode == "jwt" {
		err = r.validateJWT(ctx, payload)
	} else {
		err = r.OpenID4VCI().ValidateWUA(ctx, ka)
	}

	if err != nil {
		ctx.Log().Error("Failed to validate proof", zap.Error(err))

		var bre azugo.BadRequestError
		if errors.As(err, &bre) {
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON(map[string]string{"error": bre.Description})
		} else {
			ctx.Error(pkerrors.NewProblem("err:credential:proofValidationFailed"))
		}

		return
	}

	payload["credential_data"] = credentialData

	namespace, ok := payload["credential_configuration_id"].(string)
	if !ok || strings.TrimSpace(namespace) == "" {
		ctx.Log().Error("credential_configuration_id missing or empty in payload after proof validation")
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(map[string]string{"error": "credential_configuration_id required"})

		return
	}

	// Log the forwarded request for debugging
	ctx.Log().Info(
		"Forwarding credential request to issuer",
		zap.Any("proofs_value", payload["proofs"]),
	)

	// Forward the request to the Python issuer service
	client := ctx.HTTPClient().WithBaseURL(r.Config().Issuer.APIURL)

	reqBody, err := json.Marshal(payload)
	if err != nil {
		ctx.Log().Error("Failed to marshal credential request", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:credential:requestMarshalFailed"))

		return
	}

	req := client.NewRequest()
	defer client.ReleaseRequest(req)

	if err := req.SetRequestURL("/credential"); err != nil {
		ctx.Log().Error("failed to build issuer request URL", zap.Error(err))
		ctx.StatusCode(fasthttp.StatusInternalServerError)
		ctx.JSON(map[string]string{"error": "server_error", "error_description": "failed to build issuer request"})

		return
	}

	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.Set("Content-Type", "application/json")

	if authHeader := ctx.Header.Get("Authorization"); authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	if proof := ctx.Header.Get("DPoP"); proof != "" {
		req.Header.Set("DPoP", proof)
	}

	httpclient.SetCorrelationHeaders(ctx, &req.Header)

	if iid := ctx.Header.Get(propagation.HeaderAppInstanceID); iid != "" {
		req.Header.Set(propagation.HeaderAppInstanceID, iid)
	}

	req.SetBody(reqBody)

	resp := client.NewResponse()
	defer client.ReleaseResponse(resp)

	doErr := client.Do(req, resp)
	if doErr != nil || !resp.Success() {
		relayDownstreamProblem(ctx, "issuer-go", doErr, resp, "issuer service unreachable")

		return
	}

	rawBytes, err := resp.BodyUncompressed()
	if err != nil {
		ctx.Log().Error("failed to read issuer response body", zap.Error(err))
		ctx.StatusCode(fasthttp.StatusBadGateway)
		ctx.JSON(map[string]string{"error": "server_error", "error_description": "unexpected response from issuer"})

		return
	}

	ctx.Log().Debug("Raw credential response from backend", zap.Int("bytes", len(rawBytes)))

	// If the response is a JWE compact token (starts with 'eyJ'), forward it as-is.
	// This happens when the wallet requested credential_response_encryption.
	if len(rawBytes) > 3 && rawBytes[0] == 'e' && rawBytes[1] == 'y' && rawBytes[2] == 'J' {
		ctx.ContentType("application/jwt")
		ctx.Raw(rawBytes)

		return
	}

	var response map[string]interface{}
	if jsonErr := json.Unmarshal(rawBytes, &response); jsonErr != nil {
		ctx.Log().Error("Backend response is not a JSON object",
			zap.Error(jsonErr),
			zap.String("raw", string(rawBytes)))
		ctx.StatusCode(fasthttp.StatusBadGateway)
		ctx.JSON(map[string]string{"error": "unexpected response from issuer"})

		return
	}

	ctx.JSON(response)
}

/*
todo: validation and get expiration date
1. validate wua jwt issuer signature
2. exp
3. key_storage, user_authentication needs to be set to iso_18045_high
4. wallet issuer status list, signature, status check.
*/
func (r *router) validateJWT(ctx *azugo.Context, payload map[string]interface{}) error {
	jwtStr, err := extractProofJWT(payload)
	if err != nil {
		return err
	}

	// Parse JWT header
	header, _, err := peekJWT(jwtStr)
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Extract key_attestation from header
	keyAttestation, ok := header["key_attestation"].(string)
	if !ok {
		return errors.New("missing key_attestation in JWT header")
	}

	err = r.OpenID4VCI().ValidateWUA(ctx, keyAttestation)
	if err != nil {
		return err
	}

	return nil
}

// peekJWT decodes header and payload without verification.
// Returns the header map and claims map.
func peekJWT(token string) (map[string]interface{}, map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("invalid jwt format")
	}

	decode := func(seg string) ([]byte, error) {
		return base64.RawURLEncoding.DecodeString(seg)
	}

	hb, err := decode(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("decode header: %w", err)
	}

	pb, err := decode(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("decode payload: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, nil, fmt.Errorf("parse header: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, nil, fmt.Errorf("parse payload: %w", err)
	}

	return header, claims, nil
}

// proofHasKeyAttestation reports whether the request's proof JWT header
// carries a non-empty key_attestation. On its own this no longer
// distinguishes flow-a (WUA/pre-auth) from flow-b (DPoP/authorization_code) —
// see the routing comment in credential() — but combined with the absence
// of a DPoP header it still correctly identifies the WUA-as-bearer scheme.
func proofHasKeyAttestation(payload map[string]interface{}) bool {
	proofJWT, err := extractProofJWT(payload)
	if err != nil {
		return false
	}

	header, _, err := peekJWT(proofJWT)
	if err != nil {
		return false
	}

	ka, _ := header["key_attestation"].(string)

	return strings.TrimSpace(ka) != ""
}

// extractProofJWT returns payload.proofs[0].jwt as string.
func extractProofJWT(payload map[string]interface{}) (string, error) {
	if po, ok := payload["proof"].(map[string]interface{}); ok {
		return extractJWTFromProofObj(po)
	}

	rawProofs, ok := payload["proofs"]
	if !ok {
		return "", errors.New("missing 'proofs' or 'proof'")
	}

	switch pv := rawProofs.(type) {
	case []interface{}:
		if len(pv) == 0 {
			return "", errors.New("'proofs' is empty")
		}

		proofObj, ok := pv[0].(map[string]interface{})
		if !ok {
			return "", errors.New("'proofs[0]' must be an object")
		}

		return extractJWTFromProofObj(proofObj)

	case map[string]interface{}:
		// Some clients may send a single object instead of an array
		return extractJWTFromProofObj(pv)

	default:
		return "", fmt.Errorf("'proofs' must be an array or object, got %T", rawProofs)
	}
}

func extractAccessContextKey(payload map[string]interface{}) (string, string, error) {
	if att, found, err := extractProofAttestation(payload); err != nil {
		return "", "", err
	} else if found {
		return att, "attestation", nil
	}

	proofJWT, err := extractProofJWT(payload)
	if err != nil {
		return "", "", err
	}

	hdr, _, err := peekJWT(proofJWT)
	if err != nil {
		return "", "", errors.New("invalid proof jwt")
	}

	ka, _ := hdr["key_attestation"].(string)
	if strings.TrimSpace(ka) == "" {
		return "", "", errors.New("missing key_attestation in proof header")
	}

	return ka, "jwt", nil
}

func extractProofAttestation(payload map[string]interface{}) (string, bool, error) {
	if po, ok := payload["proof"].(map[string]interface{}); ok {
		raw, ok := po["attestation"]
		if !ok {
			return "", false, nil
		}

		att, err := extractFirstString(raw, "attestation")
		if err != nil {
			return "", false, err
		}

		return att, true, nil
	}

	rawProofs, ok := payload["proofs"]
	if !ok {
		return "", false, nil
	}

	switch pv := rawProofs.(type) {
	case map[string]interface{}:
		if raw, ok := pv["attestation"]; ok {
			att, err := extractFirstString(raw, "attestation")
			if err != nil {
				return "", false, err
			}

			return att, true, nil
		}

		return "", false, nil

	case []interface{}:
		for _, item := range pv {
			proofObj, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			raw, ok := proofObj["attestation"]
			if !ok {
				continue
			}

			att, err := extractFirstString(raw, "attestation")
			if err != nil {
				return "", false, err
			}

			return att, true, nil
		}

		return "", false, nil

	default:
		return "", false, nil
	}
}

func extractFirstString(raw interface{}, field string) (string, error) {
	switch v := raw.(type) {
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return "", fmt.Errorf("empty '%s' string", field)
		}

		return s, nil
	case []string:
		if len(v) == 0 || strings.TrimSpace(v[0]) == "" {
			return "", fmt.Errorf("empty '%s' array", field)
		}

		return strings.TrimSpace(v[0]), nil
	case []interface{}:
		if len(v) == 0 {
			return "", fmt.Errorf("empty '%s' array", field)
		}

		if s, ok := v[0].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s), nil
		}

		return "", fmt.Errorf("invalid '%s' element type", field)
	default:
		return "", fmt.Errorf("invalid '%s' type", field)
	}
}

func extractJWTFromProofObj(proofObj map[string]interface{}) (string, error) {
	raw, ok := proofObj["jwt"]
	if !ok {
		return "", errors.New("missing 'jwt' in proof object")
	}

	switch v := raw.(type) {
	case string:
		j := strings.TrimSpace(v)
		if j == "" {
			return "", errors.New("empty 'jwt' string")
		}

		return j, nil

	case []string:
		if len(v) == 0 || strings.TrimSpace(v[0]) == "" {
			return "", errors.New("empty 'jwt' array")
		}

		return strings.TrimSpace(v[0]), nil

	case []interface{}:
		if len(v) == 0 {
			return "", errors.New("empty 'jwt' array")
		}

		if s, ok := v[0].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s), nil
		}

		return "", errors.New("invalid 'jwt' element type")

	default:
		return "", fmt.Errorf("unsupported 'jwt' type: %T", raw)
	}
}

func (r *router) generateCredentialData(ctx *azugo.Context, person *openid4vci.AttestationPerson) (map[string]any, error) {
	if person == nil {
		// Android flow: no person context available - return empty data,
		// let the issuer backend resolve identity from the access token
		ctx.Log().Warn("No attestation person in access context, forwarding empty credential data")
		return map[string]any{}, nil
	}

	payload := map[string]any{
		"family_name":                    person.FamilyName,
		"given_name":                     person.GivenName,
		"personal_administrative_number": person.Code,
	}

	return payload, nil
}

// extractFormatAndExpiry reads the real credential format and expiry from the
// first entry of an issuer-go /credential response, falling back per-field
// when either is absent or unparseable (older issuer-go, or the JWE-encrypted
// response path where response is nil). All entries in a single /credential
// call share the same format and expiry (see issuer-go's issueAndRespond),
// so reading the first entry is sufficient.
func extractFormatAndExpiry(response map[string]interface{}, fallbackFormat string, fallbackExpiresAt time.Time) (string, time.Time) {
	format := fallbackFormat
	expiresAt := fallbackExpiresAt

	creds, ok := response["credentials"].([]interface{})
	if !ok || len(creds) == 0 {
		return format, expiresAt
	}

	first, ok := creds[0].(map[string]interface{})
	if !ok {
		return format, expiresAt
	}

	if f, ok := first["format"].(string); ok && f != "" {
		format = f
	}

	if e, ok := first["expires_at"].(string); ok && e != "" {
		if parsed, err := time.Parse(time.RFC3339, e); err == nil {
			expiresAt = parsed
		}
	}

	return format, expiresAt
}

// extractHardwareKeyTag reads the hardware_key_tag claim from the Key
// Attestation JWT embedded in a credential request's proof, reusing the same
// extraction extractAccessContextKey already does for both flow-a
// (credentialJWT) and flow-b (the DPoP forward path). Returns "" on any
// failure (no attestation present, malformed JWT, claim absent) rather than an
// error, since issuance tracking must never fail because device-linking failed.
func extractHardwareKeyTag(payload map[string]interface{}) string {
	ka, _, err := extractAccessContextKey(payload)
	if err != nil || ka == "" {
		return ""
	}

	_, claims, err := peekJWT(ka)
	if err != nil {
		return ""
	}

	tag, _ := claims["hardware_key_tag"].(string)

	return tag
}

// stripAuthScheme returns the bare token from an Authorization header value,
// regardless of scheme label ("DPoP <token>", "Bearer <token>", or a bare
// token). The underlying token is an opaque idauth session identifier, not a
// JWT, so the scheme label doesn't affect the lookup — see
// routes/attestation.go's identical pattern for anonymous vs authenticated
// wallet instance creation.
func stripAuthScheme(authHeader string) string {
	if idx := strings.IndexByte(authHeader, ' '); idx >= 0 {
		return authHeader[idx+1:]
	}

	return authHeader
}

// resolveIdentityFromAuthHeader resolves the caller's identity by calling
// idauth's POST /introspection (RFC 7662) with the bearer/DPoP access token.
// This replaces the previous UserInfo (GET /api/1.0/session) call, which
// silently 404s for DPoP-bound, pid_mdoc-scope access tokens used on this path.
//
// TODO: currently has no production caller (only referenced from
// credential_track_test.go) — check whether it's meant to be wired into the
// credential-issuance path or is dead code.
func (r *router) resolveIdentityFromAuthHeader(ctx *azugo.Context, authHeader string) (*openid4vci.AttestationPerson, error) {
	token := stripAuthScheme(authHeader)

	introspection, err := r.introspectToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to introspect token with idauth: %w", err)
	}

	sub, _ := introspection["sub"].(string)
	givenName, _ := introspection["given_name"].(string)
	familyName, _ := introspection["family_name"].(string)

	return &openid4vci.AttestationPerson{
		Code:       sub,
		GivenName:  givenName,
		FamilyName: familyName,
	}, nil
}

// introspectToken calls idauth's POST /introspection (RFC 7662) directly —
// the endpoint that actually recognizes DPoP-bound, credential-scoped
// access tokens (unlike GET /api/1.0/session, which is for interactive
// browser sessions and silently 404s for this token type). Mirrors
// issuer-go's own idauth.Client.Introspect(), inlined here because the shared
// go-idauth module api-wallet-digimaks depends on doesn't expose an
// Introspect() method.
func (r *router) introspectToken(ctx *azugo.Context, token string) (map[string]interface{}, error) {
	client := ctx.HTTPClient().WithBaseURL(r.Config().IDAuth.URL)

	req := client.NewRequest()
	defer client.ReleaseRequest(req)

	if err := req.SetRequestURL("/introspection"); err != nil {
		return nil, fmt.Errorf("failed to build introspection request URL: %w", err)
	}

	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(r.Config().IDAuth.ClientID+":"+r.Config().IDAuth.ClientSecret),
	))
	httpclient.SetCorrelationHeaders(ctx, &req.Header)

	req.PostArgs().Reset()
	req.PostArgs().Add("token", token)
	req.PostArgs().Add("client_id", r.Config().IDAuth.ClientID)

	resp := client.NewResponse()
	defer client.ReleaseResponse(resp)

	doErr := client.Do(req, resp)
	if doErr != nil {
		return nil, fmt.Errorf("introspection request failed: %w", doErr)
	}

	if !resp.Success() {
		return nil, fmt.Errorf("introspection request returned status %d", resp.StatusCode())
	}

	body, err := resp.BodyUncompressed()
	if err != nil {
		return nil, fmt.Errorf("failed to read introspection response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	return result, nil
}

// @operationId AcknowledgeCredential
// @title Acknowledge credential installation
// @description Allows wallet to acknowledge successful credential installation
// @param id path string true "Credential ID"
// @success 200 object string "OK"
// @failure 400 string string "Bad request"
// @failure 404 string string "Not found"
// @failure 500 string string "Internal server error"
// @resource Credential
// @route /credential/{id}/acknowledge [post].
func (r *router) credentialAcknowledge(ctx *azugo.Context) {
	credentialID := ctx.Params.String("id")
	if credentialID == "" {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(map[string]string{"error": "credential ID required"})

		return
	}

	var req struct {
		Status  string `json:"status"`  // "installed" or "failed"
		Message string `json:"message"` // optional error message
	}

	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	// Validate status
	if req.Status != "installed" && req.Status != "failed" {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(map[string]string{"error": "invalid status, must be 'installed' or 'failed'"})

		return
	}

	err := r.Store().Exec(ctx, "attestation_provider.update_install_status", &struct {
		CredentialID   string `json:"credential_id"`
		InstallStatus  string `json:"install_status"`
		InstallMessage string `json:"install_message,omitempty"`
	}{
		CredentialID:   credentialID,
		InstallStatus:  req.Status,
		InstallMessage: req.Message,
	}, nil)
	if err != nil {
		ctx.Log().Error("Failed to update credential install status",
			zap.Error(err),
			zap.String("credential_id", credentialID))
		ctx.Error(pkerrors.NewProblem("err:credential:installStatusUpdateFailed"))

		return
	}

	ctx.Log().Info("Credential install status updated",
		zap.String("credential_id", credentialID),
		zap.String("status", req.Status))

	ctx.JSON(map[string]any{
		"success": true,
		"message": "credential status updated",
	})
}
