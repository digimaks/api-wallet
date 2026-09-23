// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"encoding/json"
	"errors"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

var errTestTransport = errors.New("connection refused")

func TestOID4VCITranslate_KnownCodes(t *testing.T) {
	cases := []struct {
		code      string
		wantError string
		wantDesc  string
	}{
		{"err:credential:missingBearerToken", "invalid_token", "bearer token missing"},
		{"err:credential:invalidRequestBody", "invalid_request", "malformed request body"},
		{"err:credential:proofTypeUnsupported", "invalid_proof", "only proof_type=jwt is supported"},
		{"err:credential:nonceMintFailed", "server_error", "failed to mint nonce"},
		{"err:credential:tokenExpiredOrNotFound", "invalid_token", "token expired or not found"},
		{"err:credential:configurationUnsupported", "unsupported_credential_type", "unknown credential_configuration_id"},
		{"err:credential:proofInvalid", "invalid_proof", "proof verification failed"},
		{"err:credential:signingCertUnavailable", "server_error", "signing certificate unavailable"},
		{"err:credential:slotAllocationFailed", "server_error", "could not allocate revocation slot"},
		{"err:credential:issuanceMintFailed", "issuance_error", "credential issuance failed"},
		{"err:mint:signingKeyLoadFailed", "issuance_error", "credential issuance failed"},
		{"err:mint:signatureComputationFailed", "issuance_error", "credential issuance failed"},
		{"err:session:preAuthCodeMissing", "invalid_request", "pre-authorized_code is required"},
		{"err:session:preAuthCodeInvalidOrExpired", "invalid_grant", "invalid or expired pre-authorized code"},
		{"err:session:preAuthTXCodeInvalid", "invalid_grant", "invalid transaction code"},
		{"err:session:preAuthSessionCreateFailed", "server_error", "failed to create session"},
	}

	for _, c := range cases {
		gotError, gotDesc := oid4vciTranslate(c.code)
		qt.Check(t, qt.Equals(gotError, c.wantError), qt.Commentf("error for %s", c.code))
		qt.Check(t, qt.Equals(gotDesc, c.wantDesc), qt.Commentf("description for %s", c.code))
	}
}

func TestOID4VCITranslate_UnknownCodeFallsBackToServerError(t *testing.T) {
	gotError, _ := oid4vciTranslate("err:credential:someFutureCodeNotYetMapped")
	qt.Check(t, qt.Equals(gotError, "server_error"))
}

func TestOID4VCITranslate_NeverReturnsInternalCode(t *testing.T) {
	// Regression guard for the leak this whole layer exists to prevent: no
	// external error value may ever equal the internal err:domain:reason code.
	cases := []string{
		"err:credential:proofInvalid",
		"err:mint:mdocCOSEStructureFailed",
		"err:session:preAuthCodeMissing",
		"err:credential:totallyUnmapped",
	}

	for _, code := range cases {
		gotError, _ := oid4vciTranslate(code)
		qt.Check(t, qt.Not(qt.Equals(gotError, code)), qt.Commentf("code %s must not leak as-is", code))
	}
}

func TestRelayDownstreamProblem_TransportFailure(t *testing.T) {
	// routes/issuer's testApp(t) (router_test.go) returns an already-wrapped
	// *azugo.TestApp plus the underlying *wallet.App - register the extra
	// test-only route on the latter before calling Start.
	ta, app := testApp(t)

	app.Post("/__test_relay_transport_failure", func(ctx *azugo.Context) {
		relayDownstreamProblem(ctx, "issuer-go", errTestTransport, nil, "issuer service unreachable")
	})

	ta.Start(t)
	defer ta.Stop()

	resp, err := ta.TestClient().Post("/__test_relay_transport_failure", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadGateway))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	got := map[string]string{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &got)))
	qt.Check(t, qt.Equals(got["error"], "server_error"))
	qt.Check(t, qt.Equals(got["error_description"], "issuer service unreachable"))
}
