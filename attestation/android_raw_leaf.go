// SPDX-License-Identifier: EUPL-1.2

package attestation

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

type rawCertificateParts struct {
	TBSCertificate       []byte
	SignatureAlgorithm   pkix.AlgorithmIdentifier
	Signature            []byte
	SubjectPublicKeyInfo []byte
	Extensions           []pkix.Extension
}

type rawLeafFallback struct {
	PublicKey             any
	AttestationExtension  []byte
	ProvisioningExtension []byte
}

func extractRawLeafFallback(leafDER []byte, signer *x509.Certificate) (*rawLeafFallback, error) {
	parts, err := parseRawCertificateParts(leafDER)
	if err != nil {
		return nil, fmt.Errorf("unable to parse raw leaf certificate: %w", err)
	}

	sigAlg := signatureAlgorithmFromOID(parts.SignatureAlgorithm.Algorithm)
	if sigAlg == x509.UnknownSignatureAlgorithm {
		return nil, fmt.Errorf("unsupported signature algorithm OID: %s", parts.SignatureAlgorithm.Algorithm.String())
	}

	if signer == nil {
		return nil, fmt.Errorf("missing signer certificate")
	}

	if err := signer.CheckSignature(sigAlg, parts.TBSCertificate, parts.Signature); err != nil {
		return nil, fmt.Errorf("unable to verify raw leaf signature: %w", err)
	}

	pubKey, err := x509.ParsePKIXPublicKey(parts.SubjectPublicKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("unable to parse raw leaf public key: %w", err)
	}

	attExt := extensionByOID(parts.Extensions, []int{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17})
	if len(attExt) == 0 {
		return nil, fmt.Errorf("android attestation extension not found in raw leaf")
	}

	provExt := extensionByOID(parts.Extensions, []int{1, 3, 6, 1, 4, 1, 11129, 2, 1, 30})

	return &rawLeafFallback{
		PublicKey:             pubKey,
		AttestationExtension:  attExt,
		ProvisioningExtension: provExt,
	}, nil
}

func parseRawCertificateParts(der []byte) (*rawCertificateParts, error) {
	var certSeq asn1.RawValue

	rest, err := asn1.Unmarshal(der, &certSeq)
	if err != nil {
		return nil, err
	}

	if len(rest) != 0 || certSeq.Tag != asn1.TagSequence || !certSeq.IsCompound {
		return nil, fmt.Errorf("invalid certificate structure")
	}

	rest = certSeq.Bytes

	var tbs asn1.RawValue

	rest, err = asn1.Unmarshal(rest, &tbs)
	if err != nil {
		return nil, fmt.Errorf("unable to parse TBSCertificate: %w", err)
	}

	var sigAlgo pkix.AlgorithmIdentifier

	rest, err = asn1.Unmarshal(rest, &sigAlgo)
	if err != nil {
		return nil, fmt.Errorf("unable to parse signature algorithm: %w", err)
	}

	var sigValue asn1.BitString

	rest, err = asn1.Unmarshal(rest, &sigValue)
	if err != nil {
		return nil, fmt.Errorf("unable to parse signature value: %w", err)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("unexpected trailing data in certificate")
	}

	spki, extensions, err := parseTBSCertificateParts(tbs.Bytes)
	if err != nil {
		return nil, err
	}

	return &rawCertificateParts{
		TBSCertificate:       tbs.FullBytes,
		SignatureAlgorithm:   sigAlgo,
		Signature:            sigValue.RightAlign(),
		SubjectPublicKeyInfo: spki,
		Extensions:           extensions,
	}, nil
}

func parseTBSCertificateParts(tbsDER []byte) ([]byte, []pkix.Extension, error) {
	fields := make([]asn1.RawValue, 0, 8)
	rest := tbsDER

	for len(rest) > 0 {
		var rv asn1.RawValue

		next, err := asn1.Unmarshal(rest, &rv)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse TBSCertificate fields: %w", err)
		}

		rest = next

		fields = append(fields, rv)
	}

	if len(fields) < 6 {
		return nil, nil, fmt.Errorf("unexpected TBSCertificate field count: %d", len(fields))
	}

	idx := 0
	if fields[0].Class == asn1.ClassContextSpecific && fields[0].Tag == 0 {
		idx = 1
	}

	if len(fields) < idx+6 {
		return nil, nil, fmt.Errorf("unexpected TBSCertificate layout")
	}

	spki := fields[idx+5].FullBytes
	extensions := make([]pkix.Extension, 0, 8)

	for _, field := range fields[idx+6:] {
		if field.Class != asn1.ClassContextSpecific || field.Tag != 3 {
			continue
		}

		var extSeq asn1.RawValue

		if _, err := asn1.Unmarshal(field.Bytes, &extSeq); err != nil {
			return nil, nil, fmt.Errorf("unable to parse extensions sequence: %w", err)
		}

		extRest := extSeq.Bytes
		for len(extRest) > 0 {
			var ext pkix.Extension

			next, err := asn1.Unmarshal(extRest, &ext)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to parse extension: %w", err)
			}

			extRest = next

			extensions = append(extensions, ext)
		}
	}

	return spki, extensions, nil
}

func extensionByOID(extensions []pkix.Extension, oid asn1.ObjectIdentifier) []byte {
	for _, ext := range extensions {
		if ext.Id.Equal(oid) {
			return ext.Value
		}
	}

	return nil
}

func signatureAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	switch {
	case oid.Equal([]int{1, 2, 840, 10045, 4, 3, 2}):
		return x509.ECDSAWithSHA256
	case oid.Equal([]int{1, 2, 840, 10045, 4, 3, 3}):
		return x509.ECDSAWithSHA384
	case oid.Equal([]int{1, 2, 840, 10045, 4, 3, 4}):
		return x509.ECDSAWithSHA512
	case oid.Equal([]int{1, 2, 840, 113549, 1, 1, 5}):
		return x509.SHA1WithRSA
	case oid.Equal([]int{1, 2, 840, 113549, 1, 1, 11}):
		return x509.SHA256WithRSA
	case oid.Equal([]int{1, 2, 840, 113549, 1, 1, 12}):
		return x509.SHA384WithRSA
	case oid.Equal([]int{1, 2, 840, 113549, 1, 1, 13}):
		return x509.SHA512WithRSA
	default:
		return x509.UnknownSignatureAlgorithm
	}
}
