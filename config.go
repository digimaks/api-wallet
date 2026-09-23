// SPDX-License-Identifier: EUPL-1.2

package wallet

import (
	"time"

	"azugo.io/opentelemetry"
	"github.com/digimaks/api-wallet/attestation"
	"github.com/digimaks/api-wallet/issuer"

	"azugo.io/azugo/config"
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/digimaks/go-idauth"
	"github.com/lx-lib/lx-go-jsondb"
	"github.com/spf13/viper"
)

// Configuration represents the configuration for the application.
type Configuration struct {
	*config.Configuration `mapstructure:",squash"`

	Postgres    *jsondb.Configuration      `mapstructure:"postgres"`
	IDAuth      *idauth.Configuration      `mapstruct:"idauth"`
	Issuer      *issuer.Configuration      `mapstruct:"issuer"`
	Attestation *attestation.Configuration `mapstruct:"attestation"`

	QRAPIDeepLink       string        `mapstructure:"qr_api_deep_link" validate:"required"`
	PidServiceType      string        `mapstructure:"pid_service_type" validate:"required,oneof=local"`
	SimpleSignService   string        `mapstructure:"simple_sign_service" validate:"required,url"`
	SimpleSignPublicURL string        `mapstructure:"simple_sign_public_url" validate:"required,url"`
	SimpleSignAPIKey    string        `mapstructure:"simple_sign_api_key" validate:"required"`
	SimpleSignCacheTTL  time.Duration `mapstructure:"simple_sign_cache_ttl" validate:"required,gt=0"`
	WalletCheckInterval time.Duration `mapstructure:"wallet_check_interval" validate:"required"`
	WalletOlderThan     time.Duration `mapstructure:"wallet_older_than" validate:"required"`
	WalletPublicURL     string        `mapstructure:"wallet_api_public_url" validate:"required,url"`
	// IDAuthPublicURL is idauth's wallet-reachable base URL. When set, the
	// AS metadata advertises idauth's authorization endpoint instead of the
	// proxy's own (which is not implemented here).
	IDAuthPublicURL string                       `mapstructure:"idauth_public_url" validate:"omitempty,url"`
	Telemetry       *opentelemetry.Configuration `mapstructure:"telemetry"`
}

// NewConfiguration returns a new configuration.
func NewConfiguration() *Configuration {
	return &Configuration{
		Configuration: config.New(),
	}
}

// Core returns the core configuration.
func (c *Configuration) ServerCore() *config.Configuration {
	return c.Configuration
}

// Bind configuration to viper.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.Configuration.Bind("", v)

	c.Postgres = config.Bind(c.Postgres, "postgres", v)
	c.Issuer = config.Bind(c.Issuer, "issuer", v)
	c.IDAuth = config.Bind(c.IDAuth, "idauth", v)
	c.Telemetry = config.Bind(c.Telemetry, "telemetry", v)
	c.Attestation = config.Bind(c.Attestation, "attestation", v)

	v.SetDefault("pid_service_type", "local")
	v.SetDefault("wallet_check_interval", 30*time.Minute)
	v.SetDefault("wallet_older_than", 1*time.Hour)
	v.SetDefault("simple_sign_cache_ttl", 10*time.Minute)

	_ = v.BindEnv("pid_service_type", "PID_SERVICE_TYPE")
	_ = v.BindEnv("qr_api_deep_link", "QR_API_DEEP_LINK")
	_ = v.BindEnv("wallet_api_public_url", "WALLET_API_PUBLIC_URL")
	_ = v.BindEnv("idauth_public_url", "IDAUTH_PUBLIC_URL")
	_ = v.BindEnv("simple_sign_service", "SIMPLE_SIGN_SERVICE")
	_ = v.BindEnv("simple_sign_public_url", "SIMPLE_SIGN_PUBLIC_URL")
	_ = v.BindEnv("simple_sign_cache_ttl", "SIMPLE_SIGN_CACHE_TTL")

	key, _ := corecfg.LoadRemoteSecret("SIMPLE_SIGN_API_KEY")
	v.SetDefault("simple_sign_api_key", key)
	_ = v.BindEnv("simple_sign_api_key", "SIMPLE_SIGN_API_KEY")
	_ = v.BindEnv("wallet_check_interval", "WALLET_CHECK_INTERVAL")
	_ = v.BindEnv("wallet_older_than", "WALLET_OLDER_THAN")
}

// Validate application configuration.
func (c *Configuration) Validate(validate *validation.Validate) error {
	if err := validate.Struct(c); err != nil {
		return err
	}

	if err := c.Postgres.Validate(validate); err != nil {
		return err
	}

	if err := c.Issuer.Validate(validate); err != nil {
		return err
	}

	if err := c.IDAuth.Validate(validate); err != nil {
		return err
	}

	if err := c.Telemetry.Validate(validate); err != nil {
		return err
	}

	if err := c.Attestation.Validate(validate); err != nil {
		return err
	}

	return nil
}
