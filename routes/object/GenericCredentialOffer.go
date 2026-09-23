// SPDX-License-Identifier: EUPL-1.2

//nolint:tagliatelle,revive
package object

type GenericCredentialOffer struct {
	CredentialIDS      []string `json:"credentialIds"`
	CodeGrant          string   `json:"codeGrant"`
	CredentialOfferURI string   `json:"credentialOfferURI"`
	ReturnInHTML       bool     `json:"returnInHtml"`
}
