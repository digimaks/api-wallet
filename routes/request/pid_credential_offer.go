// SPDX-License-Identifier: EUPL-1.2

//nolint:tagliatelle
package request

import "github.com/digimaks/api-wallet/routes/object"

type PIDCredentialOfferRequest struct {
	object.GenericCredentialOffer
	Form *PIDCredentialOfferForm `json:"form"`
}

type PIDCredentialOfferForm struct {
	object.PidData
	EstimatedIssuanceDate string `json:"estimated_issuance_date"`
	EstimatedExpiryDate   string `json:"estimated_expiry_date"`
}

