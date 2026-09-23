# Api-Wallet

digimaks Mobile Wallet and Issuer API

## Built with Azugo Go Web Framework

This project is built using the [Azugo Go Web Framework](https://azugo.io), a powerful and flexible framework for building modern web applications in Go. Check out the [Azugo GitHub page](https://github.com/azugo) for more information and documentation.

<!-- TOC -->

- [Api-Wallet](#api-wallet)
  - [Built with Azugo Go Web Framework](#built-with-azugo-go-web-framework)
  - [Development](#development)
    - [Prepare dependencies](#prepare-dependencies)
    - [Local development](#local-development)
    - [Before commit](#before-commit)
  - [Environment variables](#environment-variables)
    - [Local example](#local-example)
  - [Endpoints](#endpoints)
    - [Digimaks application version information](#digimaks-application-version-information)
    - [Generate local certs](#generate-local-certs)
      - [Attestation](#attestation)
      - [PID-DS (issuer-go signing cert)](#pid-ds-issuer-go-signing-cert)
      - [Dev LoTE (self-hosted trust list)](#dev-lote-self-hosted-trust-list)
      - [Status list signing cert](#status-list-signing-cert)
  - [License](#license)

<!-- /TOC -->

## Development

### Prepare dependencies

```sh
go mod download
go generate ./...
```

### Local development

To build in VS Code use `Ctrl`+`Shift`+`B`.

To debug project in VS Code use `F5`.

### Before commit

> CI requires linted, formatted code

You should run:

```sh
gofmt -s -w ./..
```

or

```sh
gofumpt -w ./..
```

and fix any errors reported by

```sh
golangci-lint run
```

## Environment variables

In order to run the service you need configure environment variables. List of environment variables:

| Variable | Description | Default value | Required |
| --- | --- | --- | --- |
| `SERVER_URLS` | An server URL or multiple URLS separated by semicolon to listen on. | 0.0.0.0:8080 | Yes |
| `ENVIRONMENT` | Environment name. Possible values: `Development`, `Staging`, `Production` | `Development` | Yes |
| `BASE_PATH` | Base path for all routes | `/` (or take value from `SERVER_URLS` path if exists) | No |
| `ACCESS_LOG_ENABLED` | Enable access log | `true` | Yes |
| `REVERSE_PROXY_LIMIT` | Limit for reverse proxy. | `1` | No |
| `REVERSE_PROXY_TRUSTED_IPS` | List of trusted IP addresses for reverse proxy. Separated by `;` | `"127.0.0.1"` | No |
| `REVERSE_PROXY_TRUSTED_HEADERS` | List of trusted headers for reverse proxy. Separated by `;` | `X-Real-IP; X-Forwarded-For` | No |
| `LOG_LEVEL` | Minimal log level. Allowed values are `debug`, `info`, `warn`, `error`, `fatal`, `panic` | `info` | Yes |
| `CACHE_TYPE` | Cache type to use in service. Allowed values are `memory`, `redis`, `redis-cluster`. | `memory` | No |
| `CACHE_TTL` | Duration on how long to keep items in cache. Defaults to 0 meaning to never expire. | `0` | No |
| `CACHE_KEY_PREFIX` | Prefix all cache keys with specified value. | `""` | No |
| `CACHE_CONNECTION` | If other than memory cache is used specifies connection string on how to connect to cache storage. | `""` | No |
| `CACHE_PASSWORD` / `CACHE_PASSWORD_FILE` | Password to use in connection string. | `""` | No |
| `POSTGRES_HOST` | PostgreSQL HOST FQDN | `"db.example.lv"` | Yes |
| `POSTGRES_PORT` | PostgreSQL port | `"5432"` | Yes |
| `POSTGRES_USER` | PostgreSQL  | `"digimaks_public"` | Yes |
| `POSTGRES_DB` | PostgreSQL  | `"digimaks"` | Yes |
| `POSTGRES_PASSWORD` | PostgreSQL  | `/secret/digimaks-public-db-pw` | Yes |
| `IDAUTH_URL` | "" | URL for IDAuth service (empty/not configured) | Yes |
| `IDAUTH_PUBLIC_URL` | idauth's wallet-reachable base URL. When set, the wallet-facing `/.well-known/oauth-authorization-server` advertises idauth's real `authorization_endpoint` and `pushed_authorization_request_endpoint` (RFC 9126 PAR) instead of a proxy-local fallback that isn't implemented. | `""` | No |
| `IDAUTH_CLIENT_ID` | "" | `api-wallet` id registrated in idAuth service | Yes |
| `IDAUTH_CLIENT_SECRET_FILE` | "/secret/digimaks-idauth-client-secret-api-mdl-data" | Path to the file containing the client secret for authentication | Yes |
| `IDAUTH_SYSTEM_CLIENT_ID` | System-token client id used for service-to-service calls via the go-idauth library | `""` | No |
| `IDAUTH_SYSTEM_EXPIRATION_TIME` | System-token lifetime in seconds | `"600"` | No |
| `IDAUTH_SKIP_VERIFY` | Skip TLS verification on idauth calls (dev only) | `"false"` | No |
| `ISSUER_NONCE_SHARED_SECRET` / `ISSUER_NONCE_SHARED_SECRET_FILE` | Base64 encoded 256-bit secret that is used to encrypt and decrypt nonce | `""` | Yes |
| `ISSUER_API_URL` | Internal URL for the `demo-issuer` service | `"http://demo-issuer.digimaks-test.svc.cluster.local:5000"` | Yes |
| `ATTESTATION_CERTIFICATE_FILE` | Path to certificate PEM signing WIA/WUA/OAuth client-attestation JWTs (not issued PID credentials) | `/secret/digimaks-issuer-certificate` | Yes |
| `ATTESTATION_CERTIFICATE_PASSWORD` / `ATTESTATION_CERTIFICATE_PASSWORD_FILE` | Attestation signing certificate PEM password | `""` | No |
| `ISSUER_API_URL` | Internal URL for the `demo-issuer` service | `"http://demo-issuer.digimaks-test.svc.cluster.local:5000"` | Yes |
| `PID_SERVICE_TYPE` | PID service type: <br/> `local` - PID data will be taken from iDAuth | `local` | Yes |
| `WALLET_API_PUBLIC_URL` | Public URL for the `api-wallet` service, that will be put in deeplink|`"https://digimaks-api-dev.local/wallet"` | Yes |
| `AUDIT_ENDPOINT` | Internal URL for the `api-audit` service|`"http://api-audit.digimaks-test.svc.cluster.local:8080/audit/1.0"` | Yes |
| `QR_API_DEEP_LINK` | Schema to add to response|`"openid-credential-offer"` | Yes |
| `SIMPLE_SIGN_SERVICE` | URL for simple sign service|`"https://eparaksts-dev.example.com/simple-sign/"` | Yes |
| `SIMPLE_SIGN_PUBLIC_URL` | Public URL for simple sign service|`"https://eparaksts-dev.example.com/simple-sign/"` | Yes |
| `SIMPLE_SIGN_API_KEY` | API key simple sign service|`"examplekey"` | No |
| `SIMPLE_SIGN_CACHE_TTL` | Duration on how long to keep items in cache for simple sign service. Defaults to 10min. | `10m` | No |
| `WALLET_CHECK_INTERVAL` | How frequently check expired wallet instances (e.g., `1m` for 1 min, `1h` for 1 hour, `1d` for 1 day) |`"30m"` | No |
| `WALLET_OLDER_THAN` | Duration specifying how long wallet instances remain valid (e.g., `1m` for 1 min, `1h` for 1 hour, `1d` for 1 day)  |`"1h"` | No |
| `STATUS_LIST_API_URL` | Internal URL of the IETF Token Status List service — used to allocate WUA revocation slots at WUA issuance | `"http://statuslist:8080/token_status_list"` | Yes |
| `STATUS_LIST_API_KEY` | Secret passed as `X-API-Key` to the status list service | `""` | Yes |
| `WALLET_SOLUTION_PROVIDER_NAME` | Wallet provider name embedded in issued WIA/WUA (`eudi_wallet_info`) | `""` | Yes |
| `WALLET_SOLUTION_ID` | Wallet solution identifier embedded in issued WIA/WUA | `""` | Yes |
| `WALLET_SOLUTION_VERSION` | Wallet solution version embedded in issued WIA/WUA | `""` | Yes |
| `ATTESTATION_ANDROID_PACKAGE_NAME` | Expected Android package name in the key attestation's `attestationApplicationId` (tag 709). Empty disables the check. | `""` | No |
| `ATTESTATION_ANDROID_SIGNING_CERT_SHA256` | Accepted SHA-256 digests (hex, comma-separated) of the app's release signing certificate(s). Empty disables the check. | `""` | No |
| `ATTESTATION_REQUIRE_VERIFIED_BOOT` | Reject attestations whose RootOfTrust reports non-Verified boot or an unlocked bootloader | `"false"` | No |
| `ANDROID_ATTESTATION_URL` | Google attestation revocation status list URL (checked at `/instance`; fails open on fetch errors) | `"https://android.googleapis.com/attestation/status"` | No |
| `ANDROID_ATTESTATION_TEST_ROOT_CA` / `ANDROID_ATTESTATION_TEST_ROOT_CA_FILE` | **Test/dev only.** Extra PEM root CA trusted for Android key attestation on top of the real Google roots — lets the `scripts/flow-*-e2e` harnesses register fake attested devices. Never set in production. | `""` | No |
| `OTEL_SERVICE_NAME` | APM service name| `"digimaks-api-wallet"`| No |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | APM endpoint server| `"https://apm.server:8200"`| No |
| `OTEL_EXPORTER_OTLP_INSECURE_SKIP_VERIFY` | APM skip insecure https| `"true"`| No |
| `ELASTIC_APM_SECRET_TOKEN` | APM credentials| `"generated_credentials"`| No |

### Local example

Generate nonce encryptoion secret using command line:

```sh
openssl rand -base64 32
```

In local development you must create `.env` file in the root of the project. Example:

```sh
IDAUTH_URL=https://digimaks-dev.local/idauth/
IDAUTH_CLIENT_ID=digimaks-demo
IDAUTH_CLIENT_SECRET=digimaks-demo

POSTGRES_HOST=digimaks-db-dev.local
POSTGRES_PORT=5432
POSTGRES_USER=wallet_public
POSTGRES_DB=digimaks
POSTGRES_PASSWORD=xxx

ISSUER_API_URL=https://digimaks-demo-issuer-dev.local/
ISSUER_NONCE_SHARED_SECRET=xxx

QR_API_DEEP_LINK=test
WALLET_API_PUBLIC_URL=https://digimaks-api-dev.local/wallet

WALLET_CHECK_INTERVAL=30m
WALLET_OLDER_THAN=1h
```


## Endpoints

### Digimaks application version information

```
/.well-known/appspecific/version.json
```


### Generate local certs

#### Attestation

Bundle format (cert + encrypted PKCS8 key), loaded by wallet's `ATTESTATION_CERTIFICATE_FILE`. Signs WIA/WUA/OAuth client-attestation JWTs — not issued PID credentials (see [PID-DS](#pid-ds-issuer-go-signing-cert) for that). EC required (idauth's trust-anchor loader rejects RSA outright); self-signed single leaf is accepted, no CA/chain requirement.

```
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 3650 -subj "/CN=digimaks-wallet-attestation-dev"

# encrypt
openssl pkcs8 -topk8 -in key.pem -out key_enc.pem -v2 aes256 -passout pass:changeit
cat cert.pem key_enc.pem > attestation_signing_cert.pem
```

Wire into compose (wallet service):
```
ATTESTATION_CERTIFICATE_FILE: "app/attestation_signing_cert.pem"
ATTESTATION_CERTIFICATE_PASSWORD: changeit
```
(adjust path/mount to match your `./certs/wallet:/app` volume mapping)

Distribute cert.pem (public only) to:
- idauth's CLIENT_ATTESTATION_TRUST_ANCHORS_FILE
- issuer-go's ISSUER_TRUSTED_WALLET_PROVIDER_ROOTS_FILE

#### PID-DS (issuer-go signing cert)

Same bundle format as attestation (cert + encrypted PKCS8 key), loaded by issuer-go's `ISSUER_CERTIFICATE_FILE`. Signs issued PID credentials (SD-JWT-VC/mso_mdoc) and the signed issuer metadata JWT — keep it EC **P-256** (issuer-go's `.well-known/jwks` endpoint hardcodes curve `"P-256"`, and the signing alg is hardcoded `ES256` regardless of actual curve). Self-signed single leaf is accepted — no chain-length or CA requirement enforced.

```
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 3650 -subj "/CN=digimaks-pid-ds-dev"

# encrypt
openssl pkcs8 -topk8 -in key.pem -out key_enc.pem -v2 aes256 -passout pass:changeit
cat cert.pem key_enc.pem > pid_ds_signing_cert.pem
```

Wire into compose (goissuer service):
```
ISSUER_CERTIFICATE_FILE: "app/pid_ds_signing_cert.pem"
ISSUER_CERTIFICATE_PASSWORD: changeit
```

Note: issuer-go never validates this cert at startup — an expired/invalid cert only fails on the first `/credential`, `/wellknown`, or metadata-signing request.

#### Dev LoTE (self-hosted trust list)

Our dev PID-DS cert's CA isn't on the real `trustedlist.serviceproviders.eudiw.dev` — so the wallet's issuer-trust check needs a self-hosted substitute. issuer-go can serve one at `/dev-lote/{PIDProviders,WRPACProviders,PubEAAProviders}.jwt` (`ISSUER_DEV_LOTE_DIR`, `issuer-go/routes/devlote.go`); point the wallet's dev-build LoTE URIs there instead of the real eudiw.dev list.

Each `.jwt` is an ETSI-119602-shaped LoTE JWT that lists **your PID-DS cert itself** as the trusted entity and is self-signed by that same cert's key (`x5c` header = the same cert). Generate/regenerate with `issuer-go/scripts/dev-pki/gen-dev-lote` whenever the PID-DS cert changes — the LoTE trust list and `ISSUER_CERTIFICATE_FILE` must reference the same keypair or wallet-side trust checks fail:

```sh
cd issuer-go/scripts/dev-pki/gen-dev-lote

go run . -ca <path>/cert.pem -ca-key <path>/key.pem -out PIDProviders.jwt \
  -service-type "http://uri.etsi.org/19602/SvcType/PID/Issuance" \
  -lote-type "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList"

go run . -ca <path>/cert.pem -ca-key <path>/key.pem -out WRPACProviders.jwt \
  -service-type "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance" \
  -lote-type "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList"

go run . -ca <path>/cert.pem -ca-key <path>/key.pem -out PubEAAProviders.jwt \
  -service-type "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance" \
  -lote-type "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList"
```

`-ca-key` must be the **unencrypted** EC key (not the PKCS8-encrypted one bundled into `ISSUER_CERTIFICATE_FILE`) — it signs the LoTE JWT itself. Drop the three generated files into the directory mounted at `ISSUER_DEV_LOTE_DIR`.

Also update `issuer-go/scripts/dev-pki/gen-dev-pki.sh` if you're generating a fresh CA+leaf pair rather than reusing an existing cert — it produces matching `ca.cert.pem`/`ca.key.pem`/`dev-pid-ds.pem` in one shot.

#### Status list signing cert

status-list-go's `PRIVATE_KEY_PATH`/`CERTIFICATE_PATH` are **separate files, not a bundle**, and the private key must be **unencrypted** — its loader explicitly rejects `ENCRYPTED PRIVATE KEY` PEM blocks. EC only (RSA is rejected); signing alg is hardcoded ES256. The certificate's raw bytes are embedded as `x5c` in every issued status-list token, so it's not just informational.

```
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl req -new -x509 -key private-key.pem -out certificate.pem -days 3650 -subj "/CN=digimaks-statuslist-dev"
```

Wire into compose (statuslist service):
```
PRIVATE_KEY_PATH: "/app/certs/private-key.pem"
CERTIFICATE_PATH: "/app/certs/certificate.pem"
```

No startup validation here either — an expired cert isn't caught until the first status-list generation call.

## License

EUPL-1.2 — see [LICENSE](./LICENSE).