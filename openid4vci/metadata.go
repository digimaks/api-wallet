// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"azugo.io/azugo"
)

type Metadata struct {
	CredentialIssuer                  string                              `json:"credential_issuer"`
	NonceEndpoint                     string                              `json:"nonce_endpoint,omitempty"`
	CredentialConfigurationsSupported map[string]*CredentialConfiguration `json:"credential_configurations_supported"`
}

type CredentialConfigurationFormat string

const (
	CredentialConfigurationFormatJWTVC CredentialConfigurationFormat = "dc+sd-jwt" //nolint: gosec
	CredentialConfigurationFormatMDOC  CredentialConfigurationFormat = "mso_mdoc"
)

type CredentialConfiguration struct {
	Format CredentialConfigurationFormat `json:"format"`
}

func (s *Service) Metadata(_ *azugo.Context) (*Metadata, error) {
	return &Metadata{
		CredentialIssuer:                  s.walletPublicURL,
		NonceEndpoint:                     s.walletPublicURL + "/nonce",
		CredentialConfigurationsSupported: map[string]*CredentialConfiguration{},
	}, nil
}

func (s *Service) SigningCertificate() (*tls.Certificate, error) {
	return s.config.SigningCertificate()
}

func (s *Service) SigningPublicKey() (*ecdsa.PublicKey, error) {
	cert, err := s.config.SigningCertificate()
	if err != nil {
		return nil, err
	}

	if len(cert.Certificate) == 0 {
		return nil, errors.New("no certificate found")
	}

	c, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	publicKey, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key type")
	}

	return publicKey, nil
}

func (s *Service) SigningCertificateKID() (string, error) {
	publicKey, err := s.SigningPublicKey()
	if err != nil {
		return "", err
	}

	pubkey, err := publicKey.ECDH()
	if err != nil {
		return "", fmt.Errorf("failed to convert public key: %w", err)
	}

	kidBytes := sha256.Sum256(pubkey.Bytes())

	return base64.RawURLEncoding.EncodeToString(kidBytes[:]), nil
}

func (s *Service) SigningCertificateX5C() ([]string, error) {
	cert, err := s.SigningCertificate()
	if err != nil {
		return nil, err
	}

	if len(cert.Certificate) == 0 {
		return nil, errors.New("no certificate found")
	}

	x5c := make([]string, 0, len(cert.Certificate))
	for _, der := range cert.Certificate {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(der))
	}

	return x5c, nil
}
