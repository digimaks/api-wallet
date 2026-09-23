// SPDX-License-Identifier: EUPL-1.2

package tasks

import (
	"context"
	"time"

	"azugo.io/azugo"
	"azugo.io/core"
	"github.com/lx-lib/lx-go-jsondb"
	"go.uber.org/zap"
)

type walletInstanceCleanupTask struct {
	*azugo.App
	db            jsondb.Store
	checkInterval time.Duration
	olderThan     time.Duration
	ticker        *time.Ticker
	stop          chan bool
}

// NewWalletInstanceCleanupTask creates new task that will clean up wallet instances with person_id=0.
func NewWalletInstanceCleanupTask(app *azugo.App, db jsondb.Store, checkInterval time.Duration, olderThan time.Duration) core.Tasker {
	return &walletInstanceCleanupTask{
		App:           app,
		db:            db,
		checkInterval: checkInterval,
		olderThan:     olderThan,
	}
}

func (s *walletInstanceCleanupTask) Name() string {
	return "wallet-instance-cleanup"
}

func (s *walletInstanceCleanupTask) Start(ctx context.Context) error {
	if s.ticker != nil {
		s.ticker.Reset(s.checkInterval)

		return nil
	}

	s.stop = make(chan bool)
	s.ticker = time.NewTicker(s.checkInterval)

	go func() {
		for {
			select {
			case <-s.stop:
				return
			case <-s.ticker.C:
				if err := s.instanceCleanup(ctx); err != nil {
					s.Log().Error("failed to clean up", zap.Error(err))
				}
			}
		}
	}()

	return nil
}

func (s *walletInstanceCleanupTask) Stop() {
	if s.ticker == nil {
		return
	}

	s.ticker.Stop()

	s.stop <- true

	s.ticker = nil
}

func (s *walletInstanceCleanupTask) instanceCleanup(ctx context.Context) error {
	if err := s.db.Exec(ctx, "wallet_provider.delete_inactive_instances", &struct {
		//nolint:tagliatelle
		OlderThanInMin int `json:"OlderThanInMin"`
	}{
		OlderThanInMin: int(s.olderThan.Minutes()),
	}, nil); err != nil {
		s.Log().Error("Error delete_inactive_instances", zap.Error(err))

		return err
	}

	return nil
}
