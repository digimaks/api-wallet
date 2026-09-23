// SPDX-License-Identifier: EUPL-1.2

package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"azugo.io/azugo"
	corecfg "azugo.io/core/config"
	"github.com/fxamacker/cbor/v2"
)

type Service struct {
	app        *azugo.App
	config     *Configuration
	revocation *revocationChecker
	// androidTestRootCA is an extra PEM root CA trusted for Android key
	// attestation, on top of the real Google roots. Dev/E2E only — set via
	// ANDROID_ATTESTATION_TEST_ROOT_CA (or _FILE), never in production.
	// (Was dropped in the d59f64e attestation refactor; restored for the
	// scripts/flow-*-e2e fake-attestation harnesses.)
	androidTestRootCA string
}

func New(app *azugo.App, config *Configuration) (*Service, error) {
	if config == nil {
		config = &Configuration{}
	}

	androidTestRootCA, _ := corecfg.LoadRemoteSecret("ANDROID_ATTESTATION_TEST_ROOT_CA")

	return &Service{
		app:               app,
		config:            config,
		androidTestRootCA: androidTestRootCA,
		revocation:        newRevocationChecker(),
	}, nil
}

type DeviceIdentifier struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
}

type Result struct {
	HardwareKeyTag    string             `json:"hardwareKeyTag"`
	CertsIssued       int                `json:"certsIssued,omitempty"`
	DeviceType        string             `json:"deviceType"`
	PublicKey         string             `json:"publicKey"`
	DeviceLabel       *string            `json:"deviceLabel,omitempty"`
	DeviceIdentifiers []DeviceIdentifier `json:"deviceIdentifiers,omitempty"`
	WSCDAnchorHash    string             `json:"wscdAnchorHash"`
	WSCDType          string             `json:"wscdType"`
}

// VerifyChain verifies the attestation certificate chain and hardware security
// level without checking the nonce/challenge. Used for WUA key attestations
// that were generated at wallet registration time and are reused per WUA request.
func (a *Service) VerifyChain(att string, tag string) (*Result, error) {
	buf, err := base64.RawURLEncoding.DecodeString(att)
	if err != nil {
		return nil, err
	}

	af := struct {
		Format string `cbor:"fmt"`
	}{}

	decoder := cbor.NewDecoder(bytes.NewReader(buf))
	if err := decoder.Decode(&af); err != nil {
		return nil, err
	}

	switch af.Format {
	case "android-key", "android":
		// Pass nil challenge to skip nonce check; the attestation cert challenge
		// is from key registration time, not the current WUA nonce.
		return a.verifyAndroid(att, nil, tag, time.Now())
	default:
		return nil, fmt.Errorf("unsupported attestation format for chain verification: %s", af.Format)
	}
}

func (a *Service) Verify(att string, challenge []byte, tag string, challengeStr ...string) (*Result, error) {
	buf, err := base64.RawURLEncoding.DecodeString(att)
	if err != nil {
		return nil, err
	}

	af := struct {
		Format string `cbor:"fmt"`
	}{}

	decoder := cbor.NewDecoder(bytes.NewReader(buf))
	if err := decoder.Decode(&af); err != nil {
		return nil, err
	}

	switch af.Format {
	case "android-key", "android":
		attch := sha256.Sum256(challenge)
		return a.verifyAndroid(att, attch[:], tag, time.Now())
	case "apple-appattest", "apple":
		// iOS hashes the base64url string, not the decoded bytes
		iOSChallenge := challenge
		if len(challengeStr) > 0 {
			iOSChallenge = []byte(challengeStr[0])
		}

		return a.verifyIOS(att, iOSChallenge, tag, time.Now())
	default:
		return nil, fmt.Errorf("unknown attestation format: %s", af.Format)
	}
}
