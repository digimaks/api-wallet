// SPDX-License-Identifier: EUPL-1.2

// Package issuer's relay.go replaces svcerrors.Translate() + raw
// header/body forwarding: it decodes a downstream Problem (issuer-go or
// idauth) and reconstructs a fresh, curated {error, error_description} body
// for the external OID4VCI/OAuth2 caller - see
// docs/superpowers/specs/2026-07-02-rfc9457-error-migration-design.md.
package issuer

import (
	"encoding/json"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"github.com/gmb-lib/go-platform-kit/correlation"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// oid4vciError is the OAuth2/OID4VCI-legal external error api-wallet-digimaks
// returns for a given internal go-platform-kit code relayed from issuer-go or
// idauth.
type oid4vciError struct {
	Error       string
	Description string
}

// oauthErrorBody is a downstream OAuth2-legal error pair (RFC 6749 section
// 5.2, RFC 9449) that must reach the wallet unchanged — e.g. idauth's
// invalid_dpop_proof, which is deliberately NOT an RFC 9457 problem because
// the OAuth token endpoint wire format forbids it.
type oauthErrorBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// oid4vciErrors maps every in-scope internal code to its external pair,
// preserving exactly the external body issuer-go/idauth produce today.
var oid4vciErrors = map[string]oid4vciError{
	"err:credential:missingBearerToken":       {"invalid_token", "bearer token missing"},
	"err:credential:invalidRequestBody":       {"invalid_request", "malformed request body"},
	"err:credential:proofTypeUnsupported":     {"invalid_proof", "only proof_type=jwt is supported"},
	"err:credential:nonceMintFailed":          {"server_error", "failed to mint nonce"},
	"err:credential:tokenExpiredOrNotFound":   {"invalid_token", "token expired or not found"},
	"err:credential:configurationUnsupported": {"unsupported_credential_type", "unknown credential_configuration_id"},
	"err:credential:proofInvalid":             {"invalid_proof", "proof verification failed"},
	"err:credential:keyAttestationRequired":   {"invalid_proof", "this credential type requires a hardware key attestation on the proof"},
	"err:credential:signingCertUnavailable":   {"server_error", "signing certificate unavailable"},
	"err:credential:slotAllocationFailed":     {"server_error", "could not allocate revocation slot"},
	"err:credential:issuanceMintFailed":       {"issuance_error", "credential issuance failed"},
	"err:mint:signingKeyLoadFailed":           {"issuance_error", "credential issuance failed"},
	"err:mint:signingKeyInvalidType":          {"issuance_error", "credential issuance failed"},
	"err:mint:sdjwtPartMarshalFailed":         {"issuance_error", "credential issuance failed"},
	"err:mint:mdocNonceGenerationFailed":      {"issuance_error", "credential issuance failed"},
	"err:mint:mdocClaimEncodingFailed":        {"issuance_error", "credential issuance failed"},
	"err:mint:mdocMSOBuildFailed":             {"issuance_error", "credential issuance failed"},
	"err:mint:mdocCertDecodeFailed":           {"issuance_error", "credential issuance failed"},
	"err:mint:mdocCOSEStructureFailed":        {"issuance_error", "credential issuance failed"},
	"err:mint:mdocDocumentEncodingFailed":     {"issuance_error", "credential issuance failed"},
	"err:mint:signatureComputationFailed":     {"issuance_error", "credential issuance failed"},
	"err:session:preAuthCodeMissing":          {"invalid_request", "pre-authorized_code is required"},
	"err:session:preAuthCodeInvalidOrExpired": {"invalid_grant", "invalid or expired pre-authorized code"},
	"err:session:preAuthTXCodeInvalid":        {"invalid_grant", "invalid transaction code"},
	"err:session:preAuthSessionCreateFailed":  {"server_error", "failed to create session"},
}

// oid4vciTranslate maps an internal go-platform-kit error code to the
// OAuth2/OID4VCI-legal external error api-wallet-digimaks returns to a
// wallet. Falls back to "server_error" for a code with no explicit mapping
// (e.g. a not-yet-classified future issuer-go/idauth code), so a relay never
// forwards a raw internal code onto the external wire by omission.
func oid4vciTranslate(code string) (extError, extDescription string) {
	if e, ok := oid4vciErrors[code]; ok {
		return e.Error, e.Description
	}

	return "server_error", "unexpected error"
}

// relayDownstreamProblem logs and relays the outcome of a failed downstream
// call (issuer-go or idauth) to ctx. A DPoP-Nonce response header, if
// present, is always forwarded to the wallet first. If resp carries a
// parseable RFC 9457 problem body, its code is translated via
// oid4vciTranslate and a fresh {error, error_description} body is written
// with the downstream's status. A plain OAuth error pair ({"error":…}) is
// relayed as-is with the downstream's status. Otherwise (transport failure,
// or a non-conforming downstream body) a fixed "service unreachable" 502 is
// written.
func relayDownstreamProblem(ctx *azugo.Context, service string, doErr error, resp *http.Response, unreachableMsg string) {
	if doErr != nil {
		ctx.Log().Error(
			service+" call failed",
			zap.String("correlation_id", correlation.ID(ctx)),
			zap.Error(doErr),
		)
		ctx.StatusCode(fasthttp.StatusBadGateway)
		ctx.JSON(map[string]string{"error": "server_error", "error_description": unreachableMsg})

		return
	}

	// RFC 9449 §8: idauth may challenge a DPoP proof with a fresh nonce on
	// use_dpop_nonce; the wallet needs it to retry, or the DPoP flow deadlocks.
	if nonce := resp.Header.Peek("DPoP-Nonce"); len(nonce) > 0 {
		ctx.Header.Set("DPoP-Nonce", string(nonce))
	}

	body, _ := resp.BodyUncompressed()

	down, ok := pkerrors.ParseProblem(body)
	if !ok {
		var oauthErr oauthErrorBody
		if err := json.Unmarshal(body, &oauthErr); err == nil && oauthErr.Error != "" {
			ctx.Log().Warn(
				service+" returned an OAuth error",
				zap.String("error", oauthErr.Error),
				zap.Int("status", resp.StatusCode()),
				zap.String("correlation_id", correlation.ID(ctx)),
			)
			ctx.StatusCode(resp.StatusCode())
			ctx.JSON(map[string]string{"error": oauthErr.Error, "error_description": oauthErr.Description})

			return
		}

		ctx.Log().Error(
			service+" returned a non-conforming error body",
			zap.Int("status", resp.StatusCode()),
			zap.String("correlation_id", correlation.ID(ctx)),
		)
		ctx.StatusCode(fasthttp.StatusBadGateway)
		ctx.JSON(map[string]string{"error": "server_error", "error_description": unreachableMsg})

		return
	}

	ctx.Log().Error(
		service+" call failed",
		zap.String("code", down.Code),
		zap.String("trace_id", down.TraceID),
		zap.String("correlation_id", correlation.ID(ctx)),
	)

	extErr, extDesc := oid4vciTranslate(down.Code)
	ctx.StatusCode(down.Status)
	ctx.JSON(map[string]string{"error": extErr, "error_description": extDesc})
}
