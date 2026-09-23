// SPDX-License-Identifier: EUPL-1.2

package wallet

import (
	"time"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"azugo.io/opentelemetry"
	"github.com/lx-lib/lx-go-jsondb"
	"github.com/digimaks/api-wallet/attestation"
	"github.com/digimaks/api-wallet/issuer"
	"github.com/digimaks/api-wallet/openid4vci"
	"github.com/digimaks/api-wallet/tasks"
	"github.com/digimaks/go-idauth"
	kitconfig "github.com/gmb-lib/go-platform-kit/config"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/gmb-lib/go-platform-kit/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// App is the application instance.
type App struct {
	*azugo.App

	config *Configuration

	store jsondb.Store

	vci         *openid4vci.Service
	issuer      *issuer.Issuer
	attestation *attestation.Service
	idauth      *idauth.Client

	simpleSignClient *SimpleSignClient
}

// New returns a new application instance.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := NewConfiguration()

	a, err := server.New(cmd, server.Options{
		AppName:       "Digimaks Mobile Wallet API",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	store, _, err := jsondb.New(a.App, config.Postgres)
	if err != nil {
		return nil, err
	}

	if err := platform.Setup(a, platform.Options{
		Config: &kitconfig.BaseConfiguration{Telemetry: config.Telemetry},
		TracingOptions: []opentelemetry.Option{
			opentelemetry.InstrumentationRecorder("db", jsondb.Tracing, jsondb.InstrumentationExec),
		},
		PublicErrors: true,
		OnFailure:    auditFailureHook(store),
	}); err != nil {
		return nil, err
	}

	idauth, err := idauth.NewClient(config.IDAuth)
	if err != nil {
		return nil, err
	}

	att, err := attestation.New(a, config.Attestation)
	if err != nil {
		return nil, err
	}

	vci, err := openid4vci.New(a, store, config.Issuer, att, config.WalletPublicURL)
	if err != nil {
		return nil, err
	}

	instance := &App{
		App:         a,
		config:      config,
		store:       store,
		idauth:      idauth,
		vci:         vci,
		attestation: att,
	}

	instance.issuer, err = issuer.NewIssuer(instance, instance.Config().Issuer.TxCodeCacheTTL, instance.Config().WalletPublicURL)
	if err != nil {
		return nil, err
	}

	instance.simpleSignClient, err = NewSimpleSignClient(instance, instance.Config().SimpleSignService, instance.Config().SimpleSignPublicURL, instance.Config().SimpleSignAPIKey, instance.Config().SimpleSignCacheTTL)
	if err != nil {
		return nil, err
	}

	store.AddTask(tasks.NewWalletInstanceCleanupTask(a, store, instance.Config().WalletCheckInterval, instance.Config().WalletOlderThan))

	return instance, nil
}

// auditFailureHook persists an audit.failure_events row for every error
// response this service itself originates (see pkerrors.Handler — a relayed
// downstream error does not reach here). Best-effort: a write failure is
// logged and swallowed, never allowed to affect the already-sent response.
func auditFailureHook(store jsondb.Store) pkerrors.FailureHook {
	return func(ctx *azugo.Context, evt pkerrors.FailureEvent) {
		var result struct {
			Success bool `json:"success"`
		}

		err := store.Exec(ctx, "audit.insert_failure_event", &struct {
			Service       string `json:"service"`
			Endpoint      string `json:"endpoint"`
			ErrorMessage  string `json:"error_message"`
			StatusCode    int    `json:"status_code"`
			AppInstanceID string `json:"app_instance_id"`
			OccurredAt    string `json:"occurred_at"`
		}{
			Service:       evt.Service,
			Endpoint:      evt.Endpoint,
			ErrorMessage:  evt.ErrorMessage,
			StatusCode:    evt.StatusCode,
			AppInstanceID: evt.AppInstanceID,
			OccurredAt:    evt.OccurredAt.Format(time.RFC3339),
		}, &result)
		if err != nil {
			ctx.Log().Error("failed to record failure audit event", zap.Error(err))
		}
	}
}

// Start the application.
func (a *App) Start() error {
	if err := a.Store().Start(a.BackgroundContext()); err != nil {
		return err
	}

	return a.App.Start()
}

// Config returns application configuration.
//
// Panics if configuration is not loaded.
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}

	return a.config
}

func (a *App) Store() jsondb.Store {
	return a.store
}

func (a *App) IDAuth() *idauth.Client {
	return a.idauth
}

func (a *App) Issuer() *issuer.Issuer {
	return a.issuer
}

func (a *App) Attestation() *attestation.Service {
	return a.attestation
}

func (a *App) OpenID4VCI() *openid4vci.Service {
	return a.vci
}

func (a *App) SimpleSignClient() *SimpleSignClient {
	return a.simpleSignClient
}
