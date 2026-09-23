// SPDX-License-Identifier: EUPL-1.2

package attestation

import (
	"encoding/asn1"
	"fmt"
)

// parseAuthorizationList walks a KeyMint AuthorizationList SEQUENCE element by
// element, dispatching on each element's context-specific tag number. Unknown
// tags (from a newer KeyMint version) are skipped, keeping this
// forward-compatible without a whitelist of known versions.
func parseAuthorizationList(der []byte) (authorizationList, error) {
	var out authorizationList

	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return out, fmt.Errorf("unmarshal sequence: %w", err)
	}

	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return out, fmt.Errorf("expected SEQUENCE, got class=%d tag=%d", seq.Class, seq.Tag)
	}

	rest := seq.Bytes
	for len(rest) > 0 {
		var el asn1.RawValue

		var err error

		rest, err = asn1.Unmarshal(rest, &el)
		if err != nil {
			return out, fmt.Errorf("unmarshal element: %w", err)
		}

		if el.Class != asn1.ClassContextSpecific {
			continue
		}

		if err := assignAuthorizationField(&out, el); err != nil {
			return out, err
		}
	}

	return out, nil
}

//nolint:cyclop,gocyclo // one dispatch switch over KeyMint's flat tag namespace is clearer than splitting it up.
func assignAuthorizationField(out *authorizationList, el asn1.RawValue) error {
	switch el.Tag {
	case 1:
		return unmarshalSetInto(el, &out.Purpose)
	case 2:
		return unmarshalInto(el, &out.Algorithm)
	case 3:
		return unmarshalInto(el, &out.KeySize)
	case 5:
		return unmarshalSetInto(el, &out.Digest)
	case 6:
		return unmarshalSetInto(el, &out.Padding)
	case 10:
		return unmarshalInto(el, &out.EcCurve)
	case 200:
		return unmarshalInto(el, &out.RsaPublicExponent)
	case 203:
		return unmarshalSetInto(el, &out.MgfDigest)
	case 303:
		out.RollbackResistance = true
	case 305:
		out.EarlyBootOnly = true
	case 400:
		return unmarshalInto(el, &out.ActiveDateTime)
	case 401:
		return unmarshalInto(el, &out.OriginationExpireDateTime)
	case 402:
		return unmarshalInto(el, &out.UsageExpireDateTime)
	case 403:
		return unmarshalInto(el, &out.UsageCountLimit)
	case 503:
		out.NoAuthRequired = true
	case 504:
		return unmarshalInto(el, &out.UserAuthType)
	case 505:
		return unmarshalInto(el, &out.AuthTimeout)
	case 506:
		out.AllowWhileOnBody = true
	case 507:
		out.TrustedUserPresenceRequired = true
	case 508:
		out.TrustedConfirmationRequired = true
	case 509:
		out.UnlockedDeviceRequired = true
	case 600:
		out.AllApplications = true
	case 601:
		return unmarshalInto(el, &out.ApplicationID)
	case 701:
		return unmarshalInto(el, &out.CreationDateTime)
	case 702:
		return unmarshalInto(el, &out.Origin)
	case 704:
		rot, err := parseRootOfTrust(el.Bytes)
		if err != nil {
			return fmt.Errorf("rootOfTrust: %w", err)
		}

		out.RootOfTrust = rot
	case 705:
		return unmarshalInto(el, &out.OsVersion)
	case 706:
		return unmarshalInto(el, &out.OsPatchLevel)
	case 709:
		return unmarshalInto(el, &out.AttestationApplicationID)
	case 710:
		return unmarshalInto(el, &out.AttestationIDBrand)
	case 711:
		return unmarshalInto(el, &out.AttestationIDDevice)
	case 712:
		return unmarshalInto(el, &out.AttestationIDProduct)
	case 713:
		return unmarshalInto(el, &out.AttestationIDSerial)
	case 714:
		return unmarshalInto(el, &out.AttestationIDImei)
	case 715:
		return unmarshalInto(el, &out.AttestationIDMeid)
	case 716:
		return unmarshalInto(el, &out.AttestationIDManufacturer)
	case 717:
		return unmarshalInto(el, &out.AttestationIDModel)
	case 718:
		return unmarshalInto(el, &out.VendorPatchLevel)
	case 719:
		return unmarshalInto(el, &out.BootPatchLevel)
	case 720:
		out.DeviceUniqueAttestation = true
	case 723:
		return unmarshalInto(el, &out.AttestationIDSecondIMEI)
	case 724:
		return unmarshalInto(el, &out.ModuleHash)
	default:
		// unknown/newer KeyMint tag: forward-compatible, ignore.
	}

	return nil
}

// unmarshalInto decodes the EXPLICIT tag's inner DER value (el.Bytes) into v.
func unmarshalInto(el asn1.RawValue, v any) error {
	if _, err := asn1.Unmarshal(el.Bytes, v); err != nil {
		return fmt.Errorf("tag %d: %w", el.Tag, err)
	}

	return nil
}

// unmarshalSetInto decodes a KeyMint SET OF field (e.g. purpose, digest,
// padding), which is DER tag 17 rather than the SEQUENCE OF (tag 16)
// asn1.Unmarshal assumes by default.
func unmarshalSetInto(el asn1.RawValue, v any) error {
	if _, err := asn1.UnmarshalWithParams(el.Bytes, v, "set"); err != nil {
		return fmt.Errorf("tag %d: %w", el.Tag, err)
	}

	return nil
}

// parseRootOfTrust decodes the KeyMint RootOfTrust SEQUENCE field by field
// rather than via a struct tag (asn1.Unmarshal into the whole struct at
// once), for two reasons:
//
//  1. VerifiedBootState is DER ENUMERATED, which Go's asn1 package only maps
//     to asn1.Enumerated - not a custom int type - so it must be decoded
//     into that type first and converted.
//  2. deviceLocked (BOOLEAN) is decoded leniently: some KeyMint/StrongBox
//     firmware - the same defect class as the extension-critical-flag bug
//     handled in certificate.go - encodes true as a non-canonical nonzero
//     byte instead of DER's mandatory 0xFF (seen on a Xiaomi Redmi Note 8
//     Pro: "asn1: syntax error: invalid boolean"). asn1.Unmarshal into a Go
//     bool enforces strict DER and rejects any byte other than 0x00/0xFF;
//     reading the raw TLV and treating any nonzero byte as true (standard
//     BER/CER semantics) works around it without needing a byte-patch.
func parseRootOfTrust(der []byte) (rootOfTrust, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return rootOfTrust{}, fmt.Errorf("unmarshal sequence: %w", err)
	}

	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return rootOfTrust{}, fmt.Errorf("expected SEQUENCE, got class=%d tag=%d", seq.Class, seq.Tag)
	}

	var out rootOfTrust

	var verifiedBootKey asn1.RawValue

	rest, err := asn1.Unmarshal(seq.Bytes, &verifiedBootKey)
	if err != nil {
		return rootOfTrust{}, fmt.Errorf("verifiedBootKey: %w", err)
	}

	out.VerifiedBootKey = verifiedBootKey.Bytes

	var deviceLocked asn1.RawValue

	rest, err = asn1.Unmarshal(rest, &deviceLocked)
	if err != nil {
		return rootOfTrust{}, fmt.Errorf("deviceLocked: %w", err)
	}

	if len(deviceLocked.Bytes) != 1 {
		return rootOfTrust{}, fmt.Errorf("deviceLocked: expected 1-byte BOOLEAN, got %d bytes", len(deviceLocked.Bytes))
	}

	out.DeviceLocked = deviceLocked.Bytes[0] != 0x00

	var bootState asn1.Enumerated

	rest, err = asn1.Unmarshal(rest, &bootState)
	if err != nil {
		return rootOfTrust{}, fmt.Errorf("verifiedBootState: %w", err)
	}

	out.VerifiedBootState = verifiedBootState(bootState)

	if len(rest) > 0 {
		var verifiedBootHash asn1.RawValue

		if _, err := asn1.Unmarshal(rest, &verifiedBootHash); err != nil {
			return rootOfTrust{}, fmt.Errorf("verifiedBootHash: %w", err)
		}

		out.VerifiedBootHash = verifiedBootHash.Bytes
	}

	return out, nil
}

// attestationApplicationID is the KeyMint AttestationApplicationId structure
// (tag 709): the calling app's package name(s)/version and signing
// certificate digest(s), used to bind an attested key to a specific app.
type attestationApplicationID struct {
	PackageInfos     []attestationPackageInfo
	SignatureDigests [][]byte
}

type attestationPackageInfo struct {
	PackageName []byte
	Version     int
}

func parseAttestationApplicationID(der []byte) (attestationApplicationID, error) {
	var raw struct {
		PackageInfos     []attestationPackageInfo `asn1:"set"`
		SignatureDigests [][]byte                 `asn1:"set"`
	}

	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return attestationApplicationID{}, err
	}

	return attestationApplicationID{
		PackageInfos:     raw.PackageInfos,
		SignatureDigests: raw.SignatureDigests,
	}, nil
}
