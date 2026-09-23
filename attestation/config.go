// SPDX-License-Identifier: EUPL-1.2

package attestation

import (
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration controls the optional, deployment-specific Android
// attestation checks. Every field defaults to disabled (empty/false) so a
// deployment that hasn't set these values keeps today's behavior; set them to
// turn on the stricter checks once the expected app identity is known.
type Configuration struct {
	// AndroidPackageName is the expected Android package name in the
	// attestation's attestationApplicationId extension (tag 709). Empty
	// disables the check.
	AndroidPackageName string `mapstructure:"android_package_name"`
	// AndroidSigningCertSHA256 lists the accepted SHA-256 digests (hex) of the
	// app's release signing certificate(s), as reported by
	// attestationApplicationId. Empty disables the check.
	AndroidSigningCertSHA256 []string `mapstructure:"android_signing_cert_sha256"`
	// RequireVerifiedBoot rejects attestations whose RootOfTrust reports a
	// non-Verified boot state or an unlocked bootloader.
	RequireVerifiedBoot bool `mapstructure:"require_verified_boot"`
}

func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	_ = v.BindEnv(prefix+".android_package_name", "ATTESTATION_ANDROID_PACKAGE_NAME")
	_ = v.BindEnv(prefix+".android_signing_cert_sha256", "ATTESTATION_ANDROID_SIGNING_CERT_SHA256")
	_ = v.BindEnv(prefix+".require_verified_boot", "ATTESTATION_REQUIRE_VERIFIED_BOOT")
}

// Validate application configuration.
func (c *Configuration) Validate(validate *validation.Validate) error {
	return validate.Struct(c)
}
