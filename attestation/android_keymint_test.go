// SPDX-License-Identifier: EUPL-1.2

package attestation

import (
	"testing"

	"github.com/go-quicktest/qt"
)

// rootOfTrustDER builds a RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET
// STRING, deviceLocked BOOLEAN, verifiedBootState ENUMERATED, verifiedBootHash
// OCTET STRING } with the given raw byte for the deviceLocked BOOLEAN, so
// non-canonical encodings (anything other than 0x00/0xFF) can be exercised.
func rootOfTrustDER(deviceLockedByte byte) []byte {
	content := []byte{
		0x04, 0x02, 0xAA, 0xBB, // verifiedBootKey: OCTET STRING [0xAA, 0xBB]
		0x01, 0x01, deviceLockedByte, // deviceLocked: BOOLEAN
		0x0A, 0x01, 0x00, // verifiedBootState: ENUMERATED 0 (Verified)
		0x04, 0x01, 0xCC, // verifiedBootHash: OCTET STRING [0xCC]
	}

	return append([]byte{0x30, byte(len(content))}, content...)
}

func TestParseRootOfTrustLenientBoolean(t *testing.T) {
	cases := []struct {
		name         string
		byteValue    byte
		wantDeviceLk bool
	}{
		{"canonical true (0xFF)", 0xFF, true},
		{"canonical false (0x00)", 0x00, false},
		{"non-canonical true (0x01, seen on Xiaomi Redmi Note 8 Pro)", 0x01, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rot, err := parseRootOfTrust(rootOfTrustDER(c.byteValue))
			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.DeepEquals(rot.VerifiedBootKey, []byte{0xAA, 0xBB}))
			qt.Check(t, qt.Equals(rot.DeviceLocked, c.wantDeviceLk))
			qt.Check(t, qt.Equals(rot.VerifiedBootState, Verified))
			qt.Check(t, qt.DeepEquals(rot.VerifiedBootHash, []byte{0xCC}))
		})
	}
}
