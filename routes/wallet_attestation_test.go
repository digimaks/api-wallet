// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/valyala/fasthttp"
)

func TestWalletInstanceAttestation_NoClientID_FallsBackToWalletPublicURL(t *testing.T) {
	app := testApp(t)

	app.Start(t)
	defer app.Stop()

	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "9q6DgLiriNFoqcBkARdl1G9enkG_BkQWy_V3c3MoI18",
		"y":   "CnZqFFOA7e-Lywj5zOSMaaBE5250-i_IoOYg89O9oxo",
	}

	resp, err := app.TestClient().PostJSON("/wallet-instance-attestation/jwk", map[string]any{"jwk": jwk})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)

	body := struct {
		WalletInstanceAttestation string `json:"walletInstanceAttestation"`
	}{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))

	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(body.WalletInstanceAttestation, claims)
	qt.Assert(t, qt.IsNil(err))

	sub, _ := claims["sub"].(string)
	iss, _ := claims["iss"].(string)
	qt.Check(t, qt.Equals(sub, iss)) // fallback: sub == iss == walletPublicURL
}

func TestWalletInstanceAttestation_WithClientID_SetsSubToClientID(t *testing.T) {
	app := testApp(t)

	app.Start(t)
	defer app.Stop()

	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "9q6DgLiriNFoqcBkARdl1G9enkG_BkQWy_V3c3MoI18",
		"y":   "CnZqFFOA7e-Lywj5zOSMaaBE5250-i_IoOYg89O9oxo",
	}

	resp, err := app.TestClient().PostJSON("/wallet-instance-attestation/jwk", map[string]any{
		"jwk":      jwk,
		"clientId": "digimaks.wallet.instance",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)

	body := struct {
		WalletInstanceAttestation string `json:"walletInstanceAttestation"`
	}{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))

	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(body.WalletInstanceAttestation, claims)
	qt.Assert(t, qt.IsNil(err))

	sub, _ := claims["sub"].(string)
	iss, _ := claims["iss"].(string)
	qt.Check(t, qt.Equals(sub, "digimaks.wallet.instance"))
	qt.Check(t, qt.Not(qt.Equals(sub, iss))) // sub and iss are now genuinely different
}

func TestWalletUnitAttestationJWKSet_Unauthenticated_Rejected(t *testing.T) {
	app := testApp(t)

	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/wallet-unit-attestation/jwk-set", map[string]any{
		"jwkSet":         map[string]any{"keys": []map[string]any{}},
		"hardwareKeyTag": "some-tag",
	})
	qt.Assert(t, qt.IsNil(err))
	// idauth is unreachable in the test environment, so the middleware errors
	// out before reaching UserHasScope; what matters here is that the request
	// never succeeds, i.e. the route is no longer reachable unauthenticated.
	qt.Assert(t, qt.Not(qt.Equals(resp.StatusCode(), fasthttp.StatusOK)))
	fasthttp.ReleaseResponse(resp)
}
