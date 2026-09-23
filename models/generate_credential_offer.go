// SPDX-License-Identifier: EUPL-1.2

//nolint:tagliatelle
package models

type GenerateCredentialOffer struct {
	TXCode  *int   `json:"tx_code,omitempty"`
	URLData string `json:"urlData"`
}

type CredentialOffer struct {
	CredentialIssuer           string `json:"credential_issuer"`
	CredentialConfigurationIDs any    `json:"credential_configuration_ids"`
	Grants                     Grants `json:"grants"`
}

type Grants struct {
	PreAuthorizedCode PreAuthorizedCode `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code"`
}

type PreAuthorizedCode struct {
	PreAuthorizedCode string  `json:"pre-authorized_code"`
	TXCode            *TXCode `json:"tx_code,omitempty"`
}

type TXCode struct {
	Length      int    `json:"length,omitempty"`
	InputMode   string `json:"input_mode,omitempty"`
	Description string `json:"description,omitempty"`
}
