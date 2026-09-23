// SPDX-License-Identifier: EUPL-1.2

package attestation

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

func (a *Service) verifyCert(chain [][]byte, rootCAs []string, now time.Time) (*x509.Certificate, []*x509.Certificate, error) {
	roots := x509.NewCertPool()

	rootPublicKeys := make([]any, 0, len(rootCAs))

	for _, rootCA := range rootCAs {
		rootCA = strings.TrimSpace(rootCA)
		if rootCA == "" {
			continue
		}

		if strings.HasPrefix(rootCA, "-----BEGIN PUBLIC KEY-----") {
			block, _ := pem.Decode([]byte(rootCA))
			if block == nil {
				return nil, nil, errors.New("unable to parse root public key PEM")
			}

			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, nil, err
			}

			rootPublicKeys = append(rootPublicKeys, pub)

			continue
		}

		rootCerts, err := parseCertificatesFromPEM([]byte(rootCA))
		if err != nil {
			return nil, nil, errors.New("unable to parse root certificate PEM")
		}

		for _, rootCert := range rootCerts {
			roots.AddCert(rootCert)
			rootPublicKeys = append(rootPublicKeys, rootCert.PublicKey)
		}
	}

	intermCap := len(chain) - 2
	if intermCap < 0 {
		intermCap = 0
	}

	interms := make([]*x509.Certificate, 0, intermCap)
	parseErrors := make([]string, 0)

	var cert *x509.Certificate

	for i, buf := range chain {
		c, err := x509.ParseCertificate(buf)
		if err != nil && strings.Contains(err.Error(), "malformed extension critical field") {
			if patched, originalTBS, ok := repairNonCanonicalExtensionCriticalBooleans(buf); ok {
				if c2, err2 := x509.ParseCertificate(patched); err2 == nil {
					// The signature was computed over the original bytes (boolean
					// defect included) - restore them so signature/chain
					// verification hashes what was actually signed, not the
					// cosmetically patched copy used only to get a valid parse.
					c2.RawTBSCertificate = originalTBS
					c, err = c2, nil
				}
			}
		}

		if err != nil {
			if isIgnorableCertParseError(err) {
				parseErrors = append(parseErrors, fmt.Sprintf("index=%d: %v", i, err))

				continue
			}

			return nil, nil, err
		}

		// TODO check CRLs

		if c.Subject.String() == c.Issuer.String() {
			for _, rootPub := range rootPublicKeys {
				if equalKeys(c.PublicKey, rootPub) {
					roots.AddCert(c)

					break
				}
			}

			continue
		}

		// Attestation leaf is expected to be an end-entity cert.
		// Some vendor/intermediate CA certs also contain KeyUsageDigitalSignature,
		// so selecting leaf by KU bit alone is not reliable.
		if !c.IsCA {
			/*
				1.2.840.113635.100.4.24 is an Apple-defined Object Identifier (OID) used by iOS App Attest.
				go parser doesn't recognize it and puts it in the UnknownExtKeyUsage field, but it causes the Verify function to fail with "unsupported extended key usage".
			*/
			toDelete := -1

			for i, ext := range c.UnknownExtKeyUsage {
				if ext.String() == "1.2.840.113635.100.4.24" || ext.String() == "1.2.840.113635.100.4.25" {
					toDelete = i
				}
			}

			if toDelete != -1 {
				// Remove the element at index toDelete from c.UnknownExtKeyUsage
				c.UnknownExtKeyUsage = append(c.UnknownExtKeyUsage[:toDelete], c.UnknownExtKeyUsage[toDelete+1:]...)
			}

			// If multiple end-entity certs are present, prefer one suitable for signatures.
			if cert == nil || (cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 && c.KeyUsage&x509.KeyUsageDigitalSignature != 0) {
				cert = c
			}

			continue
		}

		interms = append(interms, c)
	}

	intermediates := x509.NewCertPool()

	for _, c := range interms {
		intermediates.AddCert(c)
	}

	if cert == nil {
		if len(parseErrors) > 0 {
			return nil, nil, fmt.Errorf("valid certificate not found in attestation (ignored parse errors: %s)", strings.Join(parseErrors, "; "))
		}

		return nil, nil, errors.New("valid certificate not found in attestation")
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(verifyOpts); err != nil {
		// ponytail: CAs (e.g. Google's Android Key Attestation intermediate) rotate
		// their intermediate certs periodically, leaving them expired relative to
		// wall-clock time even though attestations signed under them remain valid.
		// Go's x509.Verify checks every cert in the chain against a single
		// CurrentTime, so an expired intermediate fails the whole chain. Retry once,
		// pinned to the expired intermediate's own validity window, but only after
		// confirming the leaf itself is valid at the real time - the leaf/root
		// expiry check is never relaxed. Upgrade path: none needed unless Google
		// starts rotating faster than this reasoning holds.
		var certErr x509.CertificateInvalidError
		if !errors.As(err, &certErr) || certErr.Reason != x509.Expired || certErr.Cert == nil || !isIntermediateCert(certErr.Cert, interms) {
			if len(parseErrors) > 0 {
				return nil, nil, fmt.Errorf("%w (ignored parse errors: %s)", err, strings.Join(parseErrors, "; "))
			}

			return nil, nil, err
		}

		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return nil, nil, err
		}

		pinnedOpts := verifyOpts
		pinnedOpts.CurrentTime = certErr.Cert.NotAfter.Add(-time.Second)

		if _, retryErr := cert.Verify(pinnedOpts); retryErr != nil {
			if len(parseErrors) > 0 {
				return nil, nil, fmt.Errorf("%w (ignored parse errors: %s)", err, strings.Join(parseErrors, "; "))
			}

			return nil, nil, err
		}

		a.app.Log().Warn(
			"attestation chain accepted despite expired intermediate certificate",
			zap.Time("now", now),
			zap.String("intermediate_subject", certErr.Cert.Subject.String()),
			zap.Time("intermediate_not_after", certErr.Cert.NotAfter),
		)
	}

	return cert, interms, nil
}

func isIntermediateCert(c *x509.Certificate, interms []*x509.Certificate) bool {
	for _, i := range interms {
		if i == c || bytesEqual(i.Raw, c.Raw) {
			return true
		}
	}

	return false
}

func bytesEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

// derTLV is one decoded DER TLV plus its absolute byte offsets within the
// buffer it was read from - tracked explicitly rather than derived from
// slice lengths, since a content slice generally does NOT extend to the end
// of the original buffer (it has siblings after it), which makes
// len(original)-len(subslice) an invalid way to recover an offset.
type derTLV struct {
	tag       byte
	content   []byte
	contentAt int // absolute offset where content begins
	nextAt    int // absolute offset of the byte right after this TLV
}

func readTLVAt(der []byte, offset int) (derTLV, bool) {
	b := der[offset:]
	if len(b) < 2 {
		return derTLV{}, false
	}

	tag := b[0]
	lenByte := b[1]

	var length, headerLen int

	if lenByte&0x80 == 0 {
		length = int(lenByte)
		headerLen = 2
	} else {
		numBytes := int(lenByte & 0x7F)
		if numBytes == 0 || numBytes > 4 || len(b) < 2+numBytes {
			return derTLV{}, false
		}

		for i := 0; i < numBytes; i++ {
			length = length<<8 | int(b[2+i])
		}

		headerLen = 2 + numBytes
	}

	if length < 0 || len(b) < headerLen+length {
		return derTLV{}, false
	}

	contentAt := offset + headerLen

	return derTLV{
		tag:       tag,
		content:   der[contentAt : contentAt+length],
		contentAt: contentAt,
		nextAt:    contentAt + length,
	}, true
}

// repairNonCanonicalExtensionCriticalBooleans returns a copy of der with any
// X.509 extension's "critical" BOOLEAN normalized to the DER-canonical 0xFF,
// for extensions where it was encoded as some other non-zero byte, plus the
// byte range of the ORIGINAL (unpatched) TBSCertificate within der.
//
// ponytail: some StrongBox/KeyMint firmware (seen on Xiaomi and HONOR
// devices so far) encodes a critical=true extension flag as the BER-legal
// but DER-illegal byte 0x01 instead of the mandatory 0xFF. Go's crypto/x509
// enforces strict DER and rejects the whole certificate with "malformed
// extension critical field" for this. Only the Extension-sequence-level
// BOOLEAN is touched here; extnValue payloads (including the attestation
// extension's own ASN.1 content) are never inspected or modified, so this
// can't corrupt attestation data.
//
// Patching any byte inside TBSCertificate changes what a signature check
// would hash, which breaks verification against the issuer's signature -
// computed over the ORIGINAL bytes, boolean defect included. The caller must
// re-parse the patched bytes to get valid Go structures (extensions, public
// key, ...), then overwrite the resulting cert's RawTBSCertificate with the
// originalTBS range returned here before using it for chain/signature
// verification, so CheckSignatureFrom hashes what was actually signed.
//
// Returns ok=false if the expected Certificate/TBSCertificate/Extensions
// structure isn't found, so the caller falls back to the original parse
// error. Upgrade path: none needed unless a device is found encoding
// critical=false as a non-zero byte too (currently only true-as-0x01 has
// been observed).
func repairNonCanonicalExtensionCriticalBooleans(der []byte) (patched, originalTBS []byte, ok bool) {
	cert, ok := readTLVAt(der, 0)
	if !ok {
		return nil, nil, false
	}

	tbs, ok := readTLVAt(der, cert.contentAt)
	if !ok || tbs.tag != 0x30 {
		return nil, nil, false
	}

	originalTBS = der[cert.contentAt:tbs.nextAt]

	var extWrapper derTLV

	found := false

	for offset := tbs.contentAt; offset < tbs.nextAt; {
		child, ok := readTLVAt(der, offset)
		if !ok {
			return nil, nil, false
		}

		if child.tag == 0xA3 { // [3] EXPLICIT extensions
			extWrapper = child
			found = true

			break
		}

		offset = child.nextAt
	}

	if !found {
		return nil, nil, false
	}

	extsSeq, ok := readTLVAt(der, extWrapper.contentAt)
	if !ok {
		return nil, nil, false
	}

	patched = append([]byte(nil), der...)
	changed := false

	for offset := extsSeq.contentAt; offset < extsSeq.nextAt; {
		ext, ok := readTLVAt(der, offset)
		if !ok || ext.tag != 0x30 {
			return nil, nil, false
		}

		oid, ok := readTLVAt(der, ext.contentAt)
		if !ok || oid.tag != 0x06 {
			return nil, nil, false
		}

		if oid.nextAt < ext.nextAt {
			if boolTLV, ok := readTLVAt(der, oid.nextAt); ok && boolTLV.tag == 0x01 && len(boolTLV.content) == 1 {
				if valByte := der[boolTLV.contentAt]; valByte != 0x00 && valByte != 0xFF {
					patched[boolTLV.contentAt] = 0xFF
					changed = true
				}
			}
		}

		offset = ext.nextAt
	}

	if !changed {
		return nil, nil, false
	}

	return patched, originalTBS, true
}

func isIgnorableCertParseError(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(strings.ToLower(err.Error()), "invalid crl distribution points")
}

func parseCertificatesFromPEM(buf []byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, 1)
	rest := buf

	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}

		rest = next

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates found in PEM")
	}

	return certs, nil
}

func equalKeys(a, b interface{}) bool {
	aBytes, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}

	bBytes, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}
