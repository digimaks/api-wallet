// SPDX-License-Identifier: EUPL-1.2

package response

type EparakstsSignResponse struct {
	RedirectURL string              `json:"redirectUrl"`
	Sessions    []SimpleSignSession `json:"sessions"`
}

// SimpleSignSession defines simple sign session.
type SimpleSignSession struct {
	// Request ID
	RequestID string `json:"requestId"`
	// Session ID
	SessionID string `json:"sessionId"`
	// Documents represents the documents of the session
	Documents []SimpleSignDocument `json:"documents"`
}

// SimpleSignDocument defines simple sign document.
type SimpleSignDocument struct {
	// ID represents the ID of the document
	ID string `json:"id"`
	// FileName represents the file name of the document
	FileName string `json:"fileName"`
	// Unpack represents the unpack of the document
	Unpack bool `json:"unpack"`
}

type EparakstsSignRedirectResponse struct {
	RedirectURL string `json:"redirectUrl"`
}

// TODO: define validate response fields.
type EparakstsValidateResponse struct{}

// TODO: define identities response fields.
type EparakstsIdentitiesResponse struct{}
