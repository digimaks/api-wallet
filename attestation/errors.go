// SPDX-License-Identifier: EUPL-1.2

package attestation

import (
	"crypto/x509"
	"errors"
	"strings"
)

// CertError is a certificate-related attestation failure with a machine-readable code.
type CertError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e CertError) Error() string { return e.Message }

func certVerifyError(err error) CertError {
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certInvalid) && certInvalid.Reason == x509.Expired {
		return CertError{
			Code:    "certificate_expired",
			Message: "Device attestation certificate has expired and cannot be used",
		}
	}

	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return CertError{
			Code:    "certificate_untrusted",
			Message: "Root certificate is not in the trusted list",
		}
	}

	if isMalformedCertError(err) {
		return CertError{
			Code:    "certificate_malformed",
			Message: "Device attestation certificate is malformed at the hardware/firmware level; this device cannot be verified securely",
		}
	}

	return CertError{
		Code:    "certificate_invalid",
		Message: "Device attestation certificate is invalid",
	}
}

// isMalformedCertError reports whether err comes from the DER parser rejecting
// a certificate outright (bad ASN.1 on the device's side), as opposed to a
// structurally valid certificate failing signature/chain/expiry checks.
// crypto/x509 doesn't expose a typed error for this, so match on message -
// same approach as isIgnorableCertParseError in certificate.go.
func isMalformedCertError(err error) bool {
	msg := strings.ToLower(err.Error())

	return strings.Contains(msg, "malformed extension") ||
		strings.Contains(msg, "malformed certificate") ||
		strings.Contains(msg, "malformed authority") ||
		strings.Contains(msg, "malformed subject") ||
		strings.Contains(msg, "malformed spki") ||
		strings.Contains(msg, "malformed validity") ||
		strings.Contains(msg, "trailing data")
}
