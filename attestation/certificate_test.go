// SPDX-License-Identifier: EUPL-1.2

package attestation

import (
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/go-quicktest/qt"
)

// Real leaf certificate captured from a production HONOR PTP-N49 attestation
// (StrongBox/KeyMint). Its X509v3 Key Usage extension encodes critical=true
// as the byte 0x01 instead of the DER-mandated 0xFF, which Go's crypto/x509
// rejects with "x509: malformed extension critical field".
const malformedCriticalExtensionLeafDER = "MIICsDCCAlagAwIBAgIBATAKBggqhkjOPQQDAjA/MRIwEAYDVQQKEwlTdHJvbmdCb3gxKTAnBgNVBAMTIDA3NmY2MGI1MjM2NTYyMzA0YWI4NGY0NGIwYmU3NWVmMB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASyF28j6i6K2ay6OQrZY+j/ZMi9VkQcxMAnOFtGkdm8wWMSe+wf9yYJOqp958pM1tBgNbYY5KyhS8IR5+tUZokJo4IBYTCCAV0wggFJBgorBgEEAdZ5AgERBIIBOTCCATUCAgEsCgECAgIBLAoBAgQgtdPkquSo32YKUKIKvUcleNOuy0yg362nX9HcCfoP+UsEADBVv4U9CAIGAZ+saF0Ev4VFRQRDMEExGzAZBBJsdi5kYXRpdmEuZGlnaW1ha3MCAwIjRDEiBCCEWmpjh5JD2OblYkpf4fXjGb3/Z6VW7hEjQlAkLTKB1TCBqaEFMQMCAQKiAwIBA6MEAgIBAKUFMQMCAQSqAwIBAb+DeAMCAQO/g3kDAgEev4U+AwIBAL+FQEwwSgQgU0HmsmRpeacOV2UwB6HzEBaUIeyb3Z8aVkj3Wt4AWvEBAf8KAQAEILD1qAWqOkJs/x5zLnXEXMIzAKXg8o3mRZtEVMTraBkFv4VBBQIDAnEAv4VCBQIDAxdtv4VOBgIEATUmlb+FTwYCBAE1JjEwDgYDVR0PAQEBBAQDAgeAMAoGCCqGSM49BAMCA0gAMEUCIQD7yTvP5pspEt6sI4iGkb7LcNlUjENe/TUXMysO2FNRvAIgTvwS2RtXNer679wDdHrrwRTQxvBuSEXiLk1rwrGQ8ec="

// Real intermediate certificate from the same production chain - its
// extensions are already DER-canonical, used to check the repair leaves a
// valid certificate untouched.
const wellFormedExtensionCertDER = "MIIB5DCCAYqgAwIBAgIQB29gtSNlYjBKuE9EsL517zAKBggqhkjOPQQDAjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTMwHhcNMjYwNzE2MDcxNDUzWhcNMjYwNzMxMTc1ODUyWjA/MRIwEAYDVQQKEwlTdHJvbmdCb3gxKTAnBgNVBAMTIDA3NmY2MGI1MjM2NTYyMzA0YWI4NGY0NGIwYmU3NWVmMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk+9m7VmN28t6PokDzM45Vm1lU6s0Ygw4ubHRrmMSlWki+4M5P9Jxk8IZ9ZZsy1GIgVvBLEK7shiKeB40BPwFiaN+MHwwHQYDVR0OBBYEFJeEAvV4L4O24nb17XYot+b0Ou6aMB8GA1UdIwQYMBaAFJzGKQmTYV75CH4dcaCgCRAfti1BMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMBkGCisGAQQB1nkCAR4EC6IBGCADZUhPTk9SMAoGCCqGSM49BAMCA0gAMEUCICK3PaG9Lo/Rw1N6IhK4ztTJVOzWUdj2shX+RyIYLFDsAiEAz8GjavHLjnvfX8F1wW3MixyU5UPvhBEKEUCkMxTdHYM="

func TestRepairNonCanonicalExtensionCriticalBooleans(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(malformedCriticalExtensionLeafDER)
	qt.Assert(t, qt.IsNil(err))

	_, err = x509.ParseCertificate(der)
	qt.Assert(t, qt.ErrorMatches(err, "x509: malformed extension critical field"))

	patched, originalTBS, ok := repairNonCanonicalExtensionCriticalBooleans(der)
	qt.Assert(t, qt.IsTrue(ok))

	cert, err := x509.ParseCertificate(patched)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(cert.Subject.String(), "CN=Android Keystore Key"))
	qt.Check(t, qt.Equals(cert.KeyUsage, x509.KeyUsageDigitalSignature))

	// The whole point of restoring RawTBSCertificate: the issuer signed the
	// ORIGINAL bytes (boolean defect included). Patching-and-reparsing alone
	// changes what gets hashed, which breaks the real signature check - this
	// caused a production regression (Xiaomi 2511FPC34G: "certificate signed
	// by unknown authority ... ECDSA verification failure") that a
	// parse-only test failed to catch.
	cert.RawTBSCertificate = originalTBS

	issuer, err := x509.ParseCertificate(mustDecodeB64(t, wellFormedExtensionCertDER))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(cert.CheckSignatureFrom(issuer)))
}

func TestRepairNonCanonicalExtensionCriticalBooleansWithoutTBSRestoreFailsSignatureCheck(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(malformedCriticalExtensionLeafDER)
	qt.Assert(t, qt.IsNil(err))

	patched, _, ok := repairNonCanonicalExtensionCriticalBooleans(der)
	qt.Assert(t, qt.IsTrue(ok))

	cert, err := x509.ParseCertificate(patched)
	qt.Assert(t, qt.IsNil(err))

	issuer, err := x509.ParseCertificate(mustDecodeB64(t, wellFormedExtensionCertDER))
	qt.Assert(t, qt.IsNil(err))

	// Without restoring RawTBSCertificate, the signature check must fail -
	// this documents exactly the bug that shipped and was caught in prod.
	qt.Check(t, qt.IsNotNil(cert.CheckSignatureFrom(issuer)))
}

func TestRepairNonCanonicalExtensionCriticalBooleansLeavesValidCertUnchanged(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(wellFormedExtensionCertDER)
	qt.Assert(t, qt.IsNil(err))

	_, err = x509.ParseCertificate(der)
	qt.Assert(t, qt.IsNil(err))

	_, _, ok := repairNonCanonicalExtensionCriticalBooleans(der)
	qt.Check(t, qt.IsFalse(ok))
}

func mustDecodeB64(t *testing.T, s string) []byte {
	t.Helper()

	b, err := base64.StdEncoding.DecodeString(s)
	qt.Assert(t, qt.IsNil(err))

	return b
}
