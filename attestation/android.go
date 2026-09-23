// SPDX-License-Identifier: EUPL-1.2

package attestation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"azugo.io/azugo"
	"github.com/fxamacker/cbor/v2"
	"go.uber.org/zap"
)

// https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
// https://android.googleapis.com/attestation/root
// Google rotated Android Key Attestation roots on 2026-02-01.
const androidAppAttestRootCA2022 = `-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----`

const androidAppAttestRootCA2026 = `-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----`

// Older EC root ("Android Keystore Software Attestation Root", valid 2016-01-11 to 2036-01-06)
// still used by many pre-StrongBox / older-Keymaster devices. Missing from the bundle caused
// otherwise-valid chains to fail with "unknown authority" once the expired-intermediate
// workaround in certificate.go cleared the (unrelated) expiry error.
// Published at the same Google endpoint as the roots above: https://android.googleapis.com/attestation/root
const androidAppAttestRootCA2016 = `-----BEGIN CERTIFICATE-----
MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll
dzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYD
VQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3Qw
HhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT
BgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwq
QW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59
dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0O
BBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0W
EOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqG
SM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBN
C/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==
-----END CERTIFICATE-----`

var androidAppAttestRootCAs = []string{
	androidAppAttestRootCA2022,
	androidAppAttestRootCA2026,
	androidAppAttestRootCA2016,
}

func (a *Service) verifyAndroid(att string, challenge []byte, tag string, now time.Time) (*Result, error) {
	buf, err := base64.RawURLEncoding.DecodeString(att)
	if err != nil {
		return nil, azugo.ParamInvalidError{
			Name: "key_attestation",
			Tag:  "invalid",
			Err:  err,
		}
	}

	s := androidAttestation{}

	decoder := cbor.NewDecoder(bytes.NewReader(buf))
	if err := decoder.Decode(&s); err != nil {
		return nil, azugo.ParamInvalidError{
			Name: "key_attestation",
			Tag:  "invalid",
			Err:  err,
		}
	}

	chainLen := 0
	if s.AttStmt != nil {
		chainLen = len(s.AttStmt.X5c)
	}

	if chainLen < 2 {
		return nil, azugo.ParamInvalidError{
			Name: "key_attestation",
			Tag:  "invalid",
			Err:  fmt.Errorf("attestation statement missing certificate chain (chain_len=%d)", chainLen),
		}
	}

	roots := androidAppAttestRootCAs
	if a.androidTestRootCA != "" {
		roots = append(append([]string{}, androidAppAttestRootCAs...), a.androidTestRootCA)
	}

	cert, interms, err := a.verifyCert(s.AttStmt.X5c, roots, now)
	if err != nil {
		a.logAndroidCertVerificationFailure(s.AttStmt.X5c, err)

		return nil, certVerifyError(err)
	}

	// Android Key Attestation provision information extansion data is identified by OID "1.3.6.1.4.1.11129.2.1.30"
	provExtBytes := extensionByOID(cert.Extensions, []int{1, 3, 6, 1, 4, 1, 11129, 2, 1, 30})

	// Android Key Attestation attestation certificate's extension data is identified by the OID "1.3.6.1.4.1.11129.2.1.17"
	attExtBytes := extensionByOID(cert.Extensions, []int{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17})
	attestationPublicKey := cert.PublicKey

	if len(attExtBytes) == 0 && len(s.AttStmt.X5c) > 0 {
		fallback, fallbackErr := extractRawLeafFallback(s.AttStmt.X5c[0], cert)
		if fallbackErr != nil {
			a.app.Log().Error(
				"android attestation raw leaf resolution failed",
				zap.Error(fallbackErr),
				zap.Int("chain_len", len(s.AttStmt.X5c)),
				zap.Int("intermediate_count", len(interms)),
			)
		} else {
			attExtBytes = fallback.AttestationExtension
			if len(provExtBytes) == 0 {
				provExtBytes = fallback.ProvisioningExtension
			}

			attestationPublicKey = fallback.PublicKey

			a.app.Log().Warn("android attestation using raw leaf certificate path", zap.Int("chain_len", len(s.AttStmt.X5c)))
		}
	}

	if len(attExtBytes) == 0 {
		return nil, azugo.ParamInvalidError{
			Name: "certificate:extension",
			Tag:  "not_found",
		}
	}

	var certsIssued int

	if len(provExtBytes) > 0 {
		decoder := cbor.NewDecoder(bytes.NewReader(provExtBytes))

		prov := provisioningInfo{}
		if err := decoder.Decode(&prov); err != nil {
			return nil, azugo.ParamInvalidError{
				Name: "certificate:extension",
				Tag:  "invalid",
				Err:  err,
			}
		}

		certsIssued = prov.CertsIssued
	}

	decoded := keyDescription{}

	_, err = asn1.Unmarshal(attExtBytes, &decoded)
	if err != nil {
		return nil, azugo.ParamInvalidError{
			Name: "certificate:extension",
			Tag:  "invalid",
			Err:  err,
		}
	}

	if decoded.AttestationSecurityLevel == attestationSecurityLevelSoftware ||
		decoded.KeymasterSecurityLevel == attestationSecurityLevelSoftware {
		return nil, CertError{
			Code:    "attestation_insecure",
			Message: "Software attestation level rejected",
		}
	}

	teeAuth, err := parseAuthorizationList(decoded.TeeEnforced.FullBytes)
	if err != nil {
		return nil, azugo.ParamInvalidError{
			Name: "certificate:extension",
			Tag:  "invalid",
			Err:  fmt.Errorf("tee authorization list: %w", err),
		}
	}

	softAuth, err := parseAuthorizationList(decoded.SoftwareEnforced.FullBytes)
	if err != nil {
		return nil, azugo.ParamInvalidError{
			Name: "certificate:extension",
			Tag:  "invalid",
			Err:  fmt.Errorf("software authorization list: %w", err),
		}
	}

	origin := teeAuth.Origin
	if origin == 0 && softAuth.Origin != 0 {
		origin = softAuth.Origin
	}

	if origin != keyOriginGenerated {
		return nil, CertError{
			Code:    "attestation_key_not_generated",
			Message: "Attested key was not generated on-device",
		}
	}

	purpose := teeAuth.Purpose
	if len(purpose) == 0 {
		purpose = softAuth.Purpose
	}

	if !containsInt(purpose, keyPurposeSign) {
		return nil, CertError{
			Code:    "attestation_key_purpose_invalid",
			Message: "Attested key does not permit signing",
		}
	}

	if a.config.RequireVerifiedBoot {
		if teeAuth.RootOfTrust.VerifiedBootState != Verified || !teeAuth.RootOfTrust.DeviceLocked {
			return nil, CertError{
				Code:    "attestation_boot_not_verified",
				Message: "Device boot state is not verified/locked",
			}
		}
	}

	if a.config.AndroidPackageName != "" || len(a.config.AndroidSigningCertSHA256) > 0 {
		appID := teeAuth.AttestationApplicationID
		if len(appID) == 0 {
			appID = softAuth.AttestationApplicationID
		}

		if err := a.verifyAttestationApplicationID(appID); err != nil {
			return nil, err
		}
	}

	// todo: skip for now
	//if serial, err := a.revocation.revokedSerial(context.Background(), append([]*x509.Certificate{cert}, interms...)); err != nil {
	//	a.app.Log().Warn("android attestation revocation list unavailable, skipping check", zap.Error(err))
	//} else if serial != "" {
	//	return nil, CertError{
	//		Code:    "certificate_revoked",
	//		Message: "Device attestation certificate has been revoked",
	//	}
	//}

	if challenge != nil && !bytes.Equal(decoded.AttestationChallenge, challenge) {
		return nil, azugo.ParamInvalidError{
			Name: "challenge",
			Tag:  "invalid",
			Err: fmt.Errorf("attestation challenge mismatch: cert=%s (len=%d) expected=%s (attestation_version=%d)",
				base64.RawURLEncoding.EncodeToString(decoded.AttestationChallenge),
				len(decoded.AttestationChallenge),
				base64.RawURLEncoding.EncodeToString(challenge),
				decoded.AttestationVersion),
		}
	}

	// Convert public key to X9.62 format
	pk, ok := attestationPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key type: %T", attestationPublicKey)
	}

	pubkey, err := pk.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key: %w", err)
	}

	calulatedTagBytes := sha256.Sum256(pubkey.Bytes())

	tagBytes, err := base64.StdEncoding.DecodeString(tag)
	if err != nil {
		return nil, azugo.ParamInvalidError{
			Name: "hardware_key_tag",
			Tag:  "invalid",
			Err:  err,
		}
	}

	// Verify the tag
	if !bytes.Equal(tagBytes, calulatedTagBytes[:]) {
		return nil, azugo.ParamInvalidError{
			Name: "hardware_key_tag",
			Tag:  "invalid",
			Err: fmt.Errorf("hardware key tag mismatch: presented=%s calculated=%s",
				tag, base64.StdEncoding.EncodeToString(calulatedTagBytes[:])),
		}
	}

	// Export the public key in PEM format
	buf, err = x509.MarshalPKIXPublicKey(attestationPublicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal public key: %w", err)
	}

	publicKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: buf,
	})

	// Extract WSCD information
	wscdType := "TrustedEnvironment"

	switch decoded.AttestationSecurityLevel {
	case attestationSecurityLevelStrongBox:
		wscdType = "StrongBox"
	case attestationSecurityLevelTEE:
		wscdType = "TrustedEnvironment"
	}

	// Extract anchor hash from rootOfTrust.verifiedBootKey
	wscdAnchorHash := ""

	if len(teeAuth.RootOfTrust.VerifiedBootKey) > 0 {
		anchorHashBytes := sha256.Sum256(teeAuth.RootOfTrust.VerifiedBootKey)
		wscdAnchorHash = base64.StdEncoding.EncodeToString(anchorHashBytes[:])
	}

	return &Result{
		DeviceType:     "android",
		CertsIssued:    certsIssued,
		HardwareKeyTag: tag,
		PublicKey:      string(publicKey),
		WSCDAnchorHash: wscdAnchorHash,
		WSCDType:       wscdType,
	}, nil
}

func containsInt(haystack []int, needle int) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}

	return false
}

// verifyAttestationApplicationID enforces the configured expected Android
// package name / release signing certificate digest against the
// attestationApplicationId extension (tag 709), when either is configured
// (see Configuration).
func (a *Service) verifyAttestationApplicationID(der []byte) error {
	if len(der) == 0 {
		return azugo.ParamInvalidError{
			Name: "certificate:extension",
			Tag:  "not_found",
			Err:  errors.New("attestationApplicationId extension missing"),
		}
	}

	appID, err := parseAttestationApplicationID(der)
	if err != nil {
		return azugo.ParamInvalidError{
			Name: "certificate:extension",
			Tag:  "invalid",
			Err:  fmt.Errorf("attestationApplicationId: %w", err),
		}
	}

	if a.config.AndroidPackageName != "" {
		found := false

		for _, pkg := range appID.PackageInfos {
			if string(pkg.PackageName) == a.config.AndroidPackageName {
				found = true

				break
			}
		}

		if !found {
			return CertError{
				Code:    "attestation_package_mismatch",
				Message: "Attested app package name is not recognized",
			}
		}
	}

	if len(a.config.AndroidSigningCertSHA256) > 0 {
		found := false

		for _, digest := range appID.SignatureDigests {
			// signatureDigests already holds the SHA-256 digest of each signing
			// certificate (see AttestationApplicationId in the Android
			// key-attestation schema) - it is not re-hashed here.
			hexDigest := fmt.Sprintf("%x", digest)

			for _, allowed := range a.config.AndroidSigningCertSHA256 {
				if strings.EqualFold(allowed, hexDigest) {
					found = true

					break
				}
			}
		}

		if !found {
			return CertError{
				Code:    "attestation_signing_cert_mismatch",
				Message: "Attested app signing certificate is not recognized",
			}
		}
	}

	return nil
}

func (a *Service) logAndroidCertVerificationFailure(chain [][]byte, verifyErr error) {
	summaries := make([]string, 0, len(chain))

	for i, der := range chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			summaries = append(summaries, fmt.Sprintf("index=%d parse_error=%v der_len=%d der=%s", i, err, len(der), base64.StdEncoding.EncodeToString(der)))

			continue
		}

		summaries = append(summaries, fmt.Sprintf(
			"index=%d serial=%s is_ca=%t subject=%q issuer=%q not_before=%s not_after=%s ski=%s aki=%s unknown_eku=%d unhandled_critical_ext=%d cert=%s",
			i,
			cert.SerialNumber.String(),
			cert.IsCA,
			cert.Subject.String(),
			cert.Issuer.String(),
			cert.NotBefore.UTC().Format(time.RFC3339),
			cert.NotAfter.UTC().Format(time.RFC3339),
			base64.StdEncoding.EncodeToString(cert.SubjectKeyId),
			base64.StdEncoding.EncodeToString(cert.AuthorityKeyId),
			len(cert.UnknownExtKeyUsage),
			len(cert.UnhandledCriticalExtensions),
			base64.StdEncoding.EncodeToString(der), // <-- raw DER
		))
	}

	fields := []zap.Field{
		zap.Error(verifyErr),
		zap.String("verify_error_type", fmt.Sprintf("%T", verifyErr)),
		zap.Int("chain_len", len(chain)),
		zap.Strings("chain", summaries),
	}

	var unknownAuthorityErr x509.UnknownAuthorityError

	if errors.As(verifyErr, &unknownAuthorityErr) && unknownAuthorityErr.Cert != nil {
		fields = append(
			fields,
			zap.String("unknown_authority_cert_subject", unknownAuthorityErr.Cert.Subject.String()),
			zap.String("unknown_authority_cert_issuer", unknownAuthorityErr.Cert.Issuer.String()),
		)
	}

	a.app.Log().Error("android attestation certificate verification failed", fields...)

	if len(summaries) > 0 {
		a.app.Log().Info("android attestation certificate chain overview", zap.String("summary", strings.Join(summaries, " | ")))
	}
}
