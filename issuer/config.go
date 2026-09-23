// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"time"

	"azugo.io/core/cert"
	"azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration of the Issuer.
type Configuration struct {
	NonceTTL          time.Duration `mapstructure:"nonce_ttl" validate:"required,gt=0"`
	NonceSharedSecret string        `mapstructure:"nonce_shared_secret" validate:"required,base64"`
	// AttestationCertificate signs WIA/WUA/OAuth client-attestation JWTs (not issued PID credentials — see issuer-go's ISSUER_CERTIFICATE for that).
	AttestationCertificate                 string        `mapstructure:"attestation_certificate" validate:"required"`
	AttestationCertificatePassword         string        `mapstructure:"attestation_certificate_password"`
	APIURL                                 string        `mapstructure:"issuer_url" validate:"required"`
	TxCodeCacheTTL                         time.Duration `mapstructure:"issuer_tx_cache_ttl" validate:"required,gt=0"`
	StatusListAPIURL                       string        `mapstructure:"status_list_api_url" validate:"required"`
	StatusListAPIKey                       string        `mapstructure:"status_list_api_key" validate:"required"`
	WalletSolutionProviderName             string        `mapstructure:"wallet_solution_provider_name" validate:"required"`
	WalletSolutionID                       string        `mapstructure:"wallet_solution_id" validate:"required"`
	WalletSolutionVersion                  string        `mapstructure:"wallet_solution_version" validate:"required"`
	WalletSolutionCertificationInformation string        `mapstructure:"wallet_solution_certificate_information"`
	WalletLink                             string        `mapstructure:"wallet_link"`
	WSCDCertificationInformation           string        `mapstructure:"wscd_certification_information"`
	signingCertificate                     *tls.Certificate
}

func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	nonceSharedSecret, _ := config.LoadRemoteSecret("ISSUER_NONCE_SHARED_SECRET")
	v.SetDefault(prefix+".nonce_shared_secret", nonceSharedSecret)
	v.SetDefault(prefix+".nonce_ttl", 10*time.Minute)
	v.SetDefault(prefix+".wallet_solution_certificate_information", "https://digimaks.local/certification")
	v.SetDefault(prefix+".wallet_solution_version", "0.1")
	v.SetDefault(prefix+".wallet_link", "https://digimaks.local/info")
	v.SetDefault(prefix+".wscd_certification_information", "https://digimaks.local/certification")

	certificate, _ := config.LoadRemoteSecret("ATTESTATION_CERTIFICATE")
	v.SetDefault(prefix+".attestation_certificate", certificate)

	password, _ := config.LoadRemoteSecret("ATTESTATION_CERTIFICATE_PASSWORD")
	v.SetDefault(prefix+".attestation_certificate_password", password)

	apiKey, _ := config.LoadRemoteSecret("STATUS_LIST_API_KEY")
	v.SetDefault(prefix+".status_list_api_key", apiKey)

	v.SetDefault(prefix+".issuer_tx_cache_ttl", 10*time.Minute)

	_ = v.BindEnv(prefix+".nonce_shared_secret", "ISSUER_NONCE_SHARED_SECRET")
	_ = v.BindEnv(prefix+".nonce_ttl", "ISSUER_NONCE_TTL")
	_ = v.BindEnv(prefix+".attestation_certificate", "ATTESTATION_CERTIFICATE")
	_ = v.BindEnv(prefix+".attestation_certificate_password", "ATTESTATION_CERTIFICATE_PASSWORD")
	_ = v.BindEnv(prefix+".issuer_url", "ISSUER_API_URL")
	_ = v.BindEnv(prefix+".issuer_tx_cache_ttl", "ISSUER_TX_CACHE_TTL")
	_ = v.BindEnv(prefix+".status_list_api_url", "STATUS_LIST_API_URL")
	_ = v.BindEnv(prefix+".status_list_api_key", "STATUS_LIST_API_KEY")
	_ = v.BindEnv(prefix+".wallet_solution_provider_name", "WALLET_SOLUTION_PROVIDER_NAME")
	_ = v.BindEnv(prefix+".wallet_solution_id", "WALLET_SOLUTION_ID")
	_ = v.BindEnv(prefix+".wallet_solution_version", "WALLET_SOLUTION_VERSION")
	_ = v.BindEnv(prefix+".wallet_solution_certificate_information", "WALLET_SOLUTION_CERTIFICATE_INFORMATION")
}

func (c *Configuration) SigningCertificate() (*tls.Certificate, error) {
	// Skip if the certificate is already loaded
	if c.signingCertificate != nil {
		return c.signingCertificate, nil
	}

	certbuf, keybuf, err := cert.LoadPEMFromReader(bytes.NewReader([]byte(c.AttestationCertificate)), cert.Password(c.AttestationCertificatePassword))
	if err != nil {
		return nil, err
	}

	signCert, err := cert.LoadTLSCertificate(certbuf, keybuf)
	if err != nil {
		return nil, err
	}

	c.signingCertificate = signCert

	return c.signingCertificate, nil
}

// Validate Issuer configuration section.
func (c *Configuration) Validate(valid *validation.Validate) error {
	if err := valid.Struct(c); err != nil {
		return err
	}

	b, err := base64.StdEncoding.DecodeString(c.NonceSharedSecret)
	if err != nil {
		return errors.New("nonce_shared_secret must be a valid base64 encoded string")
	}

	if len(b) != 32 {
		return errors.New("nonce_shared_secret must be exactly 32 bytes long")
	}

	_, err = c.SigningCertificate()

	return err
}
