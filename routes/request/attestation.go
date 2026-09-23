// SPDX-License-Identifier: EUPL-1.2

//nolint:tagliatelle
package request

// DeviceIdentifier represents device manufacturer and model information.
type DeviceIdentifier struct {
	// Manufacturer is the device manufacturer name.
	Manufacturer string `json:"manufacturer"`
	// Model is the device model name.
	Model string `json:"model"`
}

// AttestationRequest is a request model wallet initialization.
type AttestationRequest struct {
	// Challenge is a nonce that is used to verify the attestation.
	Challenge string `json:"challenge"`
	// KeyAttestation is a Base64 encoded CBOR attestation statement.
	KeyAttestation string `json:"key_attestation"`
	// HardwareKeyTag is a hardware key tag that is used to verify the attestation.
	HardwareKeyTag string `json:"hardware_key_tag"`
	// DeviceLabel is a user-provided device name (can be null).
	DeviceLabel *string `json:"deviceLabel"`
	// DeviceIdentifiers is an array of device identifiers containing manufacturer and/or model.
	DeviceIdentifiers []DeviceIdentifier `json:"deviceIdentifiers"`
}
