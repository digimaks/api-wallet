// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"testing"

	wallet "github.com/digimaks/api-wallet"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
)

func testApp(t testing.TB) (*azugo.TestApp, *wallet.App) {
	app := wallet.TestApp(t)

	err := Bind(app, app)
	qt.Assert(t, qt.IsNil(err))

	return azugo.NewTestApp(app.App), app
}
