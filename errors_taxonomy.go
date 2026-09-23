// SPDX-License-Identifier: EUPL-1.2

// Package wallet registers api-wallet-digimaks's own error taxonomy reasons -
// the well-known, token, credential, pid, and eparaksts domains' fine-grained
// failure codes - with go-platform-kit so pkerrors.NewProblem derives status
// and title without WithStatus at every call site (see routes/issuer/issuer.go,
// routes/pid.go, routes/eparaksts.go). This is separate from
// routes/issuer/relay.go, which translates *downstream* (issuer-go/idauth)
// problems for the OID4VCI/OAuth2 proxy paths; these reasons cover this
// service's own errors on its non-protocol endpoints.
package wallet

import (
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/valyala/fasthttp"
)

func init() {
	// well-known proxy domain (routes/issuer/issuer.go).
	pkerrors.RegisterReason("issuerMetadataFetchFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("configurationFetchFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("jwksFetchFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("signingKidUnavailable", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("signingKeyUnavailable", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("jwkConversionFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})

	// /token domain (routes/issuer/issuer.go).
	pkerrors.RegisterReason("clientAttestationValidationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})

	// credential domain (routes/issuer/issuer.go - WUA-based issuance path).
	pkerrors.RegisterReason("dataGenerationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("proofValidationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("slotAllocationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("requestMarshalFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("installStatusUpdateFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})

	// pid domain (routes/pid.go).
	pkerrors.RegisterReason("pidServiceCallFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("rtuServiceCallFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("mdlServiceCallFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("credentialOfferGenerationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("credentialOfferParseFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})

	// eparaksts domain (routes/eparaksts.go).
	pkerrors.RegisterReason("invalidRequestBody", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Invalid request body"})
	pkerrors.RegisterReason("sessionLookupFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("prepareFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("sessionCacheStoreFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("fileDownloadFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("sessionCloseFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("sessionCacheDeleteFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("validateFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("identitiesRedirectFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("identitiesLookupFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})

	// auth domain (middleware.go, routes/attestation.go - idauth lookups).
	pkerrors.RegisterReason("userInfoLookupFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})

	// attestation domain (routes/attestation.go, routes/wallet_attestation.go).
	pkerrors.RegisterReason("verificationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("challengeMismatch", pkerrors.ReasonSpec{Status: fasthttp.StatusUnprocessableEntity, Title: "Attestation challenge does not match the requested nonce"})
	pkerrors.RegisterReason("keyTagMismatch", pkerrors.ReasonSpec{Status: fasthttp.StatusUnprocessableEntity, Title: "Hardware key tag does not match the attested public key"})
	pkerrors.RegisterReason("extensionMissing", pkerrors.ReasonSpec{Status: fasthttp.StatusUnprocessableEntity, Title: "Attestation certificate extension not found"})
	pkerrors.RegisterReason("nonceInvalid", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Invalid or expired nonce"})
	pkerrors.RegisterReason("instanceCreateFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("walletInstanceAttestationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("walletUnitAttestationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("instanceNotRegistered", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Wallet instance not registered - call POST /instance first"})

	// nonce domain (routes/issuer/nonce.go).
	pkerrors.RegisterReason("mintFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
}
