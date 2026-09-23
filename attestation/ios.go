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
	"time"

	"github.com/fxamacker/cbor/v2"
	"go.uber.org/zap"
)

// https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
const appleAppAttestRootCA = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`

func (a *Service) verifyIOS(att string, challenge []byte, tag string, now time.Time) (*Result, error) {
	buf, err := base64.RawURLEncoding.DecodeString(att)
	if err != nil {
		return nil, err
	}

	s := appleAttestation{}

	decoder := cbor.NewDecoder(bytes.NewReader(buf))
	if err := decoder.Decode(&s); err != nil {
		return nil, err
	}

	cert, _, err := a.verifyCert(s.AttStmt.X5c, []string{appleAppAttestRootCA}, now)
	if err != nil {
		return nil, certVerifyError(err)
	}

	var attExtBytes []byte

	for _, extension := range cert.Extensions {
		// Client credential data is stored in certificate extension identified by OID "1.2.840.113635.100.8.2"
		if extension.Id.Equal([]int{1, 2, 840, 113635, 100, 8, 2}) {
			attExtBytes = extension.Value
		}
	}

	if len(attExtBytes) == 0 {
		return nil, errors.New("attestation certificate extensions missing 1.2.840.113635.100.8.2")
	}

	decoded := appleAnonymousAttestation{}

	if _, err = asn1.Unmarshal(attExtBytes, &decoded); err != nil {
		return nil, fmt.Errorf("unable to parse apple attestation certificate extension: %w", err)
	}

	challengeHash := sha256.Sum256(challenge)

	nonce := sha256.Sum256(append(s.AuthData, challengeHash[:]...))

	// TODO - remove this log when we fix ios problem
	logLen := len(challenge)
	if logLen > 32 {
		logLen = 32
	}

	a.app.Log().Debug("iOS attestation nonce verification",
		zap.Int("challenge_len", len(challenge)),
		zap.String("challenge_hex", fmt.Sprintf("%x", challenge[:logLen])),
		zap.String("challenge_hash", fmt.Sprintf("%x", challengeHash)),
		zap.String("computed_nonce", fmt.Sprintf("%x", nonce)),
		zap.String("cert_nonce", fmt.Sprintf("%x", decoded.Nonce)))

	if !bytes.Equal(decoded.Nonce, nonce[:]) {
		return nil, errors.New("attestation challenge mismatch")
	}

	// Convert public key to X9.62 format
	pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key type")
	}

	pubkey, err := pk.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key: %w", err)
	}

	calulatedTagBytes := sha256.Sum256(pubkey.Bytes())

	tagBytes, err := base64.StdEncoding.DecodeString(tag)
	if err != nil {
		return nil, fmt.Errorf("unable to decode hardware key tag bytes: %w", err)
	}

	// Verify the tag
	if !bytes.Equal(tagBytes, calulatedTagBytes[:]) {
		return nil, errors.New("hardware key tag mismatch")
	}

	// Export the public key in PEM format
	buf, err = x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal public key: %w", err)
	}

	publicKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: buf,
	})

	// For iOS, WSCD type is always SECURE_ENCLAVE
	// Extract anchor hash from the certificate's public key
	wscdAnchorHash := ""

	if pk, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		if pubkeyECDH, err := pk.ECDH(); err == nil {
			anchorHashBytes := sha256.Sum256(pubkeyECDH.Bytes())
			wscdAnchorHash = base64.StdEncoding.EncodeToString(anchorHashBytes[:])
		}
	}

	return &Result{
		DeviceType:     "ios",
		HardwareKeyTag: tag,
		PublicKey:      string(publicKey),
		WSCDAnchorHash: wscdAnchorHash,
		WSCDType:       "SECURE_ENCLAVE",
	}, nil
}
