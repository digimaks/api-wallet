// SPDX-License-Identifier: EUPL-1.2

package request

// EparakstsSignRequest is a request model for eparaksts simple sign request.
type EparakstsSignRequest struct {
	RequestID     string  `json:"requestId"`
	Asice         bool    `json:"asice"`
	FileName      string  `json:"fileName"`
	RedirectURL   string  `json:"redirectUrl"`
	RedirectError string  `json:"redirectError"`
	ESealSID      *string `json:"esealSid"`
	UserID        *string `json:"userId"`
	CrossDevice   bool    `json:"crossDevice"`
}

type SimpleSignPrepareRequest struct {
	Requests      []SimpleSignRequest `json:"requests"`
	RedirectURL   string              `json:"redirectUrl"`
	RedirectError string              `json:"redirectError"`
	ESealSID      *string             `json:"esealSid"`
	UserID        *string             `json:"userId"`
	CreateNewDoc  bool                `json:"createNewDoc"`
	CrossDevice   bool                `json:"crossDevice"`
}

type SimpleSignRequest struct {
	RequestID string           `json:"requestId"`
	Type      string           `json:"type"`
	Files     []SimpleSignFile `json:"files"`
}

type SimpleSignFile struct {
	FileName string `json:"fileName"`
}

type ValidateRequest struct {
	Files []SimpleSignFile `json:"files"`
}
