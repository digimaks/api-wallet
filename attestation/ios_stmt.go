// SPDX-License-Identifier: EUPL-1.2

package attestation

type appleAttestation struct {
	AttStmt  *appleStmt `cbor:"attStmt"`
	AuthData []byte     `cbor:"authData"`
}

type appleStmt struct {
	X5c     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt"`
}

type appleAnonymousAttestation struct {
	Nonce []byte `asn1:"tag:1,explicit"`
}
