// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// decryptJWE decrypts a JWE compact serialization encrypted with ECDH-ES.
// Supported: alg=ECDH-ES, enc=A128GCM | A192GCM | A256GCM
func decryptJWE(token string, privateKey *ecdh.PrivateKey) ([]byte, error) {
	// JWE compact: header.encryptedKey.iv.ciphertext.tag
	parts := strings.SplitN(token, ".", 5)
	if len(parts) != 5 {
		return nil, errors.New("invalid JWE: expected 5 dot-separated parts")
	}

	// 1. Decode and parse the protected header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("JWE header decode: %w", err)
	}

	var header struct {
		Alg string          `json:"alg"`
		Enc string          `json:"enc"`
		EPK json.RawMessage `json:"epk"`
		APU string          `json:"apu,omitempty"`
		APV string          `json:"apv,omitempty"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("JWE header parse: %w", err)
	}

	if header.Alg != "ECDH-ES" {
		return nil, fmt.Errorf("unsupported JWE alg %q (only ECDH-ES supported)", header.Alg)
	}

	// 2. Parse the Ephemeral Public Key (EPK) from the header
	var epkJWK struct {
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(header.EPK, &epkJWK); err != nil {
		return nil, fmt.Errorf("JWE EPK parse: %w", err)
	}

	xb, err := base64.RawURLEncoding.DecodeString(epkJWK.X)
	if err != nil {
		return nil, fmt.Errorf("JWE EPK x: %w", err)
	}

	yb, err := base64.RawURLEncoding.DecodeString(epkJWK.Y)
	if err != nil {
		return nil, fmt.Errorf("JWE EPK y: %w", err)
	}

	// Determine the curve and its fixed coordinate byte-length
	var (
		curve     ecdh.Curve
		coordSize int
	)

	switch epkJWK.Crv {
	case "P-256":
		curve, coordSize = ecdh.P256(), 32
	case "P-384":
		curve, coordSize = ecdh.P384(), 48
	case "P-521":
		curve, coordSize = ecdh.P521(), 66
	default:
		return nil, fmt.Errorf("unsupported EPK curve %q", epkJWK.Crv)
	}

	// Build uncompressed EC point: 0x04 || X (zero-padded) || Y (zero-padded)
	epkRaw := make([]byte, 1+2*coordSize)
	epkRaw[0] = 0x04
	copy(epkRaw[1+coordSize-len(xb):1+coordSize], xb) // left-pad X
	copy(epkRaw[1+2*coordSize-len(yb):], yb)          // left-pad Y

	epk, err := curve.NewPublicKey(epkRaw)
	if err != nil {
		return nil, fmt.Errorf("JWE EPK reconstruct: %w", err)
	}

	// 3. ECDH: derive shared secret Z
	z, err := privateKey.ECDH(epk)
	if err != nil {
		return nil, fmt.Errorf("JWE ECDH: %w", err)
	}

	// 4. Derive the Content Encryption Key (CEK) via Concat KDF (RFC 7518 §4.6.2)
	cek, err := jweConcatKDF(z, header.Enc, header.APU, header.APV)
	if err != nil {
		return nil, fmt.Errorf("JWE KDF: %w", err)
	}

	// 5. Decode IV, ciphertext, and authentication tag
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("JWE IV decode: %w", err)
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("JWE ciphertext decode: %w", err)
	}

	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("JWE tag decode: %w", err)
	}

	// 6. Decrypt with AES-GCM; the encoded header string is the AAD
	aad := []byte(parts[0])

	switch header.Enc {
	case "A128GCM", "A192GCM", "A256GCM":
		block, err := aes.NewCipher(cek)
		if err != nil {
			return nil, fmt.Errorf("JWE AES cipher: %w", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("JWE GCM init: %w", err)
		}
		// cipher.GCM.Open expects ciphertext || tag concatenated
		combined := append(ciphertext, tag...) //nolint:gocritic

		plaintext, err := gcm.Open(nil, iv, combined, aad)
		if err != nil {
			return nil, fmt.Errorf("JWE decrypt: %w", err)
		}

		return plaintext, nil
	default:
		return nil, fmt.Errorf("unsupported JWE enc %q", header.Enc)
	}
}

// jweConcatKDF implements the one-pass Concat KDF defined in NIST SP 800-56A
// and required by RFC 7518 §4.6.2 for ECDH-ES key derivation.
func jweConcatKDF(z []byte, enc, apuB64, apvB64 string) ([]byte, error) {
	// CEK length determined by the content-encryption algorithm
	var keyLen int

	switch enc {
	case "A128GCM":
		keyLen = 16
	case "A192GCM":
		keyLen = 24
	case "A256GCM", "A128CBC-HS256":
		keyLen = 32
	case "A192CBC-HS384":
		keyLen = 48
	case "A256CBC-HS512":
		keyLen = 64
	default:
		return nil, fmt.Errorf("unsupported enc for KDF: %s", enc)
	}

	// apu / apv are base64url-encoded in the header; decode to raw bytes
	apu, _ := base64.RawURLEncoding.DecodeString(apuB64)
	apv, _ := base64.RawURLEncoding.DecodeString(apvB64)
	encBytes := []byte(enc)

	// Build OtherInfo: len32(AlgID)||AlgID || len32(APU)||APU || len32(APV)||APV || len32(keydatalen_bits)
	var otherInfo bytes.Buffer

	writeU32 := func(n int) {
		otherInfo.WriteByte(byte(n >> 24))
		otherInfo.WriteByte(byte(n >> 16))
		otherInfo.WriteByte(byte(n >> 8))
		otherInfo.WriteByte(byte(n))
	}
	writeU32(len(encBytes))
	otherInfo.Write(encBytes)
	writeU32(len(apu))
	otherInfo.Write(apu)
	writeU32(len(apv))
	otherInfo.Write(apv)
	writeU32(keyLen * 8) // keydatalen in bits

	// Single SHA-256 round (round counter = 1 as big-endian uint32)
	h := sha256.New()
	h.Write([]byte{0, 0, 0, 1}) // round number
	h.Write(z)
	h.Write(otherInfo.Bytes())
	digest := h.Sum(nil)

	return digest[:keyLen], nil
}

func publicKeyToJWK(publicKey any) (map[string]any, error) {
	switch pk := publicKey.(type) {
	case *ecdsa.PublicKey:
		point, err := pk.Bytes()
		if err != nil {
			return nil, err
		}

		size := (pk.Curve.Params().BitSize + 7) / 8
		x := point[1 : 1+size]
		y := point[1+size:]

		return map[string]any{
			"kty": "EC",
			"crv": pk.Curve.Params().Name,
			"x":   base64.RawURLEncoding.EncodeToString(x),
			"y":   base64.RawURLEncoding.EncodeToString(y),
		}, nil
	case *rsa.PublicKey:
		n := pk.N.Bytes()
		e := big.NewInt(int64(pk.E)).Bytes()

		if len(n) > 256 {
			n = n[len(n)-256:]
		}

		if len(e) > 3 {
			e = e[len(e)-3:]
		}

		return map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(n),
			"e":   base64.RawURLEncoding.EncodeToString(e),
		}, nil
	default:
		return nil, errors.New("unsupported key type")
	}
}
