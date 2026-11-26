package httpsecconformance

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// SessionCookieScenarioNames is the name of every row sessionCookieScenarios
// returns, so a suite can pin that they are all part of Scenarios.
func SessionCookieScenarioNames() []string {
	var names []string
	for _, sc := range sessionCookieScenarios() {
		names = append(names, sc.Name)
	}

	return names
}

// sessionCookieScenarios is every behaviour of a cookie chain that must be
// identical on every adapter: the cookie a sign-in sets and its attributes,
// the expiry of a cookie no session answers to, and the expiry a logout writes.
func sessionCookieScenarios() []Scenario {
	return []Scenario{
		sessionCookieSignInSetsTheCookie(),
		sessionCookieRefusedValueIsExpired(),
		sessionCookieLogoutExpiresIt(),
	}
}

// sessionCookieOptions is the wiring of a cookie chain: the session cookie,
// the form login that opens a session (it takes no token generator on this
// chain) and the logout. CSRF protection is switched off, since the rows are
// about the cookie and not about the token an unsafe request must carry.
func sessionCookieOptions(e *Effects) []httpsec.Option {
	return []httpsec.Option{
		httpsec.WithoutCSRFProtection(),
		httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: e.Sessions, Users: fixtureUsers{}}),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: &fixtureAuthenticator{calls: &e.authCalls},
			Sessions:      e.Sessions,
			Attempts:      e.Attempts,
		}),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: e.Sessions}),
	}
}

// assertCookieAttributes pins the default attributes of the session cookie.
func assertCookieAttributes(t *testing.T, c *http.Cookie) {
	t.Helper()

	assert.Equal(t, "__Host-scrty-session", c.Name)
	assert.Equal(t, "/", c.Path)
	assert.Empty(t, c.Domain, "a __Host- cookie names no domain")
	assert.True(t, c.Secure)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
}

// assertExpiredCookie pins a cookie written to remove the session cookie:
// Max-Age=0, which a parsed cookie reports as a negative MaxAge, under the
// attributes the cookie was set with.
func assertExpiredCookie(t *testing.T, c *http.Cookie) {
	t.Helper()

	assertCookieAttributes(t, c)
	assert.Empty(t, c.Value)
	assert.Equal(t, -1, c.MaxAge, "Max-Age=0")
}

func sessionCookieSignInSetsTheCookie() Scenario {
	return Scenario{
		Name: "session cookie: a sign-in sets the cookie with its attributes and no token",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			return ChainSpec{Options: sessionCookieOptions(effects), Effects: effects}
		},
		Request: sending(formBody("username=" + Username + "&password=" + Password)),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusSeeOther, res.Status)
			assert.Equal(t, "/", res.Header.Get("Location"))
			assert.NotContains(t, res.Body, "access_token", "no credential in the body")

			cookies := assertOneSetCookiePerCookie(t, res, httpsec.DefaultSessionCookieName)
			assertCookieAttributes(t, cookies[0])
			assertSessionCookie(t, cookies[0])
			assert.True(t, session.ValidIdentifier(cookies[0].Value), "the value is the session's identifier")

			assert.Equal(t, 1, res.Effects.ActiveSessions(t), "one session was opened")
		},
	}
}

func sessionCookieRefusedValueIsExpired() Scenario {
	return Scenario{
		Name: "session cookie: a value no session answers to is refused 401 and the cookie expired",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			return ChainSpec{
				Options: sessionCookieOptions(effects),
				Effects: effects,
				Routes:  plainRoute(),
			}
		},
		Request: sending(RequestSpec{
			Method:        http.MethodGet,
			Path:          RoutePath,
			Header:        map[string]string{"Cookie": httpsec.DefaultSessionCookieName + "=stale"},
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			require.ErrorIs(t, res.Refusal, httpsec.ErrAuthenticationRequired)
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			assert.False(t, res.RouteRan, "the route behind the chain did not run")

			cookies := assertOneSetCookiePerCookie(t, res, httpsec.DefaultSessionCookieName)
			assertExpiredCookie(t, cookies[0])
		},
	}
}

func sessionCookieLogoutExpiresIt() Scenario {
	return Scenario{
		Name: "session cookie: a logout ends the session and expires the cookie",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			liveSession(t, effects)

			return ChainSpec{Options: sessionCookieOptions(effects), Effects: effects}
		},
		Request: func(spec ChainSpec) RequestSpec {
			return RequestSpec{
				Method:        http.MethodPost,
				Path:          LogoutPath,
				Header:        map[string]string{"Cookie": httpsec.DefaultSessionCookieName + "=" + spec.Effects.SessionID},
				ClientAddress: ClientAddress,
			}
		},
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusOK, res.Status)

			cookies := assertOneSetCookiePerCookie(t, res, httpsec.DefaultSessionCookieName)
			assertExpiredCookie(t, cookies[0])

			assert.Equal(t, 0, res.Effects.ActiveSessions(t), "the session was ended")
		},
	}
}
