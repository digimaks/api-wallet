// SPDX-License-Identifier: EUPL-1.2

package attestation

import (
	"encoding/asn1"
)

type keyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TeeEnforced              asn1.RawValue
}

// authorizationList mirrors KeyMint's AuthorizationList SEQUENCE. Every field
// is an OPTIONAL, EXPLICIT context-tagged element; only the tags a given
// device emits are present. It is populated by parseAuthorizationList, which
// walks the SEQUENCE manually by tag number instead of relying on
// encoding/asn1 struct-tag positional matching (that approach silently
// desynchronizes on the `any`-typed presence-only fields - see
// docs/plans/analysis.md §4.1).
type authorizationList struct {
	Purpose                     []int
	Algorithm                   int
	KeySize                     int
	Digest                      []int
	Padding                     []int
	EcCurve                     int
	RsaPublicExponent           int
	MgfDigest                   []int
	RollbackResistance          bool
	EarlyBootOnly               bool
	ActiveDateTime              int64
	OriginationExpireDateTime   int64
	UsageExpireDateTime         int64
	UsageCountLimit             int
	NoAuthRequired              bool
	UserAuthType                int64
	AuthTimeout                 int
	AllowWhileOnBody            bool
	TrustedUserPresenceRequired bool
	TrustedConfirmationRequired bool
	UnlockedDeviceRequired      bool
	AllApplications             bool
	ApplicationID               []byte
	CreationDateTime            int64
	Origin                      int
	RootOfTrust                 rootOfTrust
	OsVersion                   int
	OsPatchLevel                int
	AttestationApplicationID    []byte
	AttestationIDBrand          []byte
	AttestationIDDevice         []byte
	AttestationIDProduct        []byte
	AttestationIDSerial         []byte
	AttestationIDImei           []byte
	AttestationIDMeid           []byte
	AttestationIDManufacturer   []byte
	AttestationIDModel          []byte
	VendorPatchLevel            int
	BootPatchLevel              int
	DeviceUniqueAttestation     bool
	AttestationIDSecondIMEI     []byte
	ModuleHash                  []byte
}

type rootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState verifiedBootState
	VerifiedBootHash  []byte
}

type verifiedBootState int

const (
	Verified verifiedBootState = iota
	SelfSigned
	Unverified
	Failed
)

const (
	attestationSecurityLevelSoftware  asn1.Enumerated = 0
	attestationSecurityLevelTEE       asn1.Enumerated = 1
	attestationSecurityLevelStrongBox asn1.Enumerated = 2
)

const (
	keyOriginGenerated int = 0
	keyPurposeSign     int = 2
)

type provisioningInfo struct {
	CertsIssued int `cbor:"1,keyasint"`
}

type androidAttestation struct {
	AttStmt *androidStmt `cbor:"attStmt"`
}

type androidStmt struct {
	X5c [][]byte `cbor:"x5c"`
}
