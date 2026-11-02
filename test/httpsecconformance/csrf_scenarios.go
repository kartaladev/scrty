package httpsecconformance

import (
	"maps"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// WebhookPath is the application route the CSRF scenarios exempt, as a
// payment provider's webhook would be.
const WebhookPath = "/webhooks/payments"

// csrfScenarios is every behaviour of CSRF protection that must be identical
// on every adapter: a cross-site login, password re-proof and sign-in end
// refused before anything is checked or changed, and an exempt route reached
// while another method on its path is still judged.
func csrfScenarios() []Scenario {
	return []Scenario{
		crossSiteLoginIsRefused(),
		crossSiteReproofIsRefused(),
		crossSiteSessionEndIsRefused(),
		exemptRouteIsNotJudged(),
	}
}

// crossSite returns header with the Fetch Metadata a browser sends on a
// request another site's page made, leaving header unchanged.
func crossSite(header map[string]string) map[string]string {
	out := maps.Clone(header)
	if out == nil {
		out = map[string]string{}
	}

	out["Sec-Fetch-Site"] = "cross-site"

	return out
}

// requireCrossSiteRefusal asserts the request was refused as cross-site, with
// the mapped status, before anything behind the chain ran.
func requireCrossSiteRefusal(t *testing.T, res Result) {
	t.Helper()

	require.ErrorIs(t, res.Refusal, httpsec.ErrCrossSiteRequest)
	assert.Equal(t, http.StatusForbidden, res.Status)
	assert.False(t, res.RouteRan)
}

// crossSiteLoginIsRefused pins spec csrf-protection "Login CSRF".
func crossSiteLoginIsRefused() Scenario {
	return Scenario{
		Name: "a cross-site login is refused before any credential is checked",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			effects := newEffects(t)

			return ChainSpec{
				Options: append(formLoginOptions(effects), httpsec.EnableCSRFProtection()),
				Effects: effects,
			}
		},
		Request: func(ChainSpec) RequestSpec {
			req := formBody("username=" + Username + "&password=" + Password)
			req.Header = crossSite(req.Header)

			return req
		},
		Assert: func(t *testing.T, res Result) {
			requireCrossSiteRefusal(t, res)
			assert.Equal(t, 0, res.Effects.AuthenticatorCalls(), "no credential was checked")
			assert.Equal(t, 0, res.Effects.ActiveSessions(t), "no session was created")
		},
	}
}

// crossSiteReproofIsRefused pins spec csrf-protection "Re-proof endpoint".
func crossSiteReproofIsRefused() Scenario {
	return Scenario{
		Name: "a cross-site password re-proof is refused",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			spec := newReauthSpec(t, reauthWiring{login: true})
			spec.Options = append(spec.Options, httpsec.EnableCSRFProtection())

			return spec
		},
		Request: func(spec ChainSpec) RequestSpec {
			req := formPost(httpsec.DefaultReauthenticationPrefix+"/password",
				issuedTokenFor(Username, spec.Effects.SessionID),
				url.Values{httpsec.DefaultLoginPasswordParam: {Password}})
			req.Header = crossSite(req.Header)

			return req
		},
		Assert: func(t *testing.T, res Result) {
			requireCrossSiteRefusal(t, res)
			assert.Equal(t, 0, res.Effects.AuthenticatorCalls(), "no password was checked")
		},
	}
}

// crossSiteSessionEndIsRefused pins spec csrf-protection "Session management".
func crossSiteSessionEndIsRefused() Scenario {
	return Scenario{
		Name: "a cross-site DELETE of the other sign-ins is refused and ends none",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			// Fresh enough to end sign-ins, so only CSRF protection stops it.
			spec := newSessionManagementSpec(t, 2*time.Minute)
			spec.Options = append(spec.Options, httpsec.EnableCSRFProtection())

			return spec
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			req := managedRequest(spec, http.MethodDelete, httpsec.DefaultSessionManagementPrefix)
			req.Header = crossSite(req.Header)

			res := send(req)
			requireCrossSiteRefusal(t, res)
			assert.Len(t, signInsOf(t, spec, UserID), 2, "no sign-in was ended")
		},
	}
}

// exemptRouteIsNotJudged pins spec csrf-protection "Webhook route" and "Other
// method stays protected".
func exemptRouteIsNotJudged() Scenario {
	return Scenario{
		Name: "an exempt route is reached cross-site, and another method on its path is refused",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			effects := newEffects(t)

			return ChainSpec{
				Options: []httpsec.Option{httpsec.EnableCSRFProtection(
					httpsec.WithCSRFExemption(http.MethodPost, WebhookPath))},
				Effects: effects,
				Routes: []Route{
					{Method: http.MethodPost, Path: WebhookPath, Body: RouteBody},
					{Method: http.MethodDelete, Path: WebhookPath, Body: RouteBody},
				},
			}
		},
		Steps: func(t *testing.T, _ ChainSpec, send func(RequestSpec) Result) {
			delivered := send(RequestSpec{
				Method: http.MethodPost, Path: WebhookPath,
				Header: crossSite(nil), ClientAddress: ClientAddress,
			})
			require.NoError(t, delivered.Refusal)
			assert.Equal(t, http.StatusOK, delivered.Status)
			assert.True(t, delivered.RouteRan)
			assert.Equal(t, RouteBody, delivered.Body)

			requireCrossSiteRefusal(t, send(RequestSpec{
				Method: http.MethodDelete, Path: WebhookPath,
				Header: crossSite(nil), ClientAddress: ClientAddress,
			}))
		},
	}
}
