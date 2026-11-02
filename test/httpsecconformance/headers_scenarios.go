package httpsecconformance

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
)

// headerScenarios is every behaviour of the security-headers layer that must be
// identical on every adapter: the layer sets its headers on the response before
// the chain's own refusals, so each framework's default error handling must
// carry them out.
func headerScenarios() []Scenario {
	return []Scenario{
		securityHeadersAreOffUntilEnabled(),
		securityHeadersDefaultDocumentSet(),
		securityHeadersOnARefusal(),
		securityHeadersOnAHostRefusal(),
		securityHeadersAPIProfile(),
		securityHeadersHSTSOnlyWhenSecure(),
		securityHeadersReportOnly(),
		securityHeadersEnforcedAndCandidateShareANonce(),
		securityHeadersHashPreset(),
		securityHeadersEditedAPIProfile(),
		securityHeadersClearSiteDataOnSecureLogout(),
	}
}

var nonceSource = regexp.MustCompile(`'nonce-[A-Za-z0-9+/]{22}=='`)

// assertDocumentHeaders checks h carries the strict document set, with a nonce
// in the policy when withNonce, and none of the headers the layer never sends.
func assertDocumentHeaders(t *testing.T, h http.Header, withNonce bool) {
	t.Helper()

	csp := h.Get("Content-Security-Policy")
	if withNonce {
		require.Regexp(t, nonceSource, csp)
		assert.Regexp(t, `^script-src 'nonce-[^']+' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'$`, csp)
	} else {
		assert.Equal(t, "script-src 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", csp,
			"a response no handler reads carries the policy without a nonce source")
	}

	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", h.Get("Referrer-Policy"))
	assert.Equal(t, "same-origin-allow-popups", h.Get("Cross-Origin-Opener-Policy"))

	for _, name := range []string{"X-Xss-Protection", "X-Frame-Options", "Cross-Origin-Embedder-Policy", "Origin-Agent-Cluster"} {
		assert.Empty(t, h.Values(name), "%s is never sent by default", name)
	}
}

func headerRoute() []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/page", Status: http.StatusOK, Body: RouteBody},
		{Method: http.MethodGet, Path: "/api/orders", Status: http.StatusOK, Body: RouteBody},
	}
}

func securityHeadersAreOffUntilEnabled() Scenario {
	return Scenario{
		Name: "security headers: none are sent until the layer is enabled",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{Routes: headerRoute()}
		},
		Request: sending(RequestSpec{Method: http.MethodGet, Path: "/page", ClientAddress: ClientAddress}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)

			for _, name := range []string{
				"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
				"Referrer-Policy", "Cross-Origin-Opener-Policy",
			} {
				assert.Empty(t, res.Header.Values(name), name)
			}
		},
	}
}

func securityHeadersDefaultDocumentSet() Scenario {
	return Scenario{
		Name: "security headers: a page carries the strict document set",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{Options: []httpsec.Option{httpsec.EnableSecurityHeaders()}, Routes: headerRoute()}
		},
		Request: sending(RequestSpec{Method: http.MethodGet, Path: "/page", ClientAddress: ClientAddress}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			assert.Equal(t, http.StatusOK, res.Status)
			assertDocumentHeaders(t, res.Header, true)
			assert.Empty(t, res.Header.Values("Strict-Transport-Security"), "plain HTTP never gets HSTS")
		},
	}
}

func securityHeadersOnARefusal() Scenario {
	return Scenario{
		Name: "security headers: a refusal through the framework's default error handling carries them",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			liveSession(t, effects)

			return ChainSpec{
				Options: append([]httpsec.Option{httpsec.EnableSecurityHeaders()}, bearerOptions(effects)...),
				Effects: effects,
				Routes:  plainRoute(),
			}
		},
		Request: sending(RequestSpec{
			Method:        http.MethodGet,
			Path:          RoutePath,
			Header:        map[string]string{"Authorization": "Bearer not-a-token"},
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			require.ErrorIs(t, res.Refusal, authenticate.ErrAuthenticationFailed)
			assert.False(t, res.RouteRan)
			assertDocumentHeaders(t, res.Header, true)
		},
	}
}

func securityHeadersOnAHostRefusal() Scenario {
	return Scenario{
		Name: "security headers: a host refusal, which no interceptor sees, carries them",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{
				Options: []httpsec.Option{trustingTheProxy(), httpsec.EnableSecurityHeaders()},
				Routes:  headerRoute(),
			}
		},
		Request: sending(RequestSpec{
			Method:        http.MethodGet,
			Path:          "/page",
			Header:        map[string]string{"X-Forwarded-For": clientAddress, "X-Forwarded-Host": "evil.example"},
			ClientAddress: proxyAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusBadRequest, res.Status)
			require.ErrorIs(t, res.Refusal, httpsec.ErrHostNotAllowed)
			assert.False(t, res.RouteRan)
			assertDocumentHeaders(t, res.Header, false)
			assert.Empty(t, res.Header.Values("Strict-Transport-Security"),
				"the forwarded scheme was refused with the host, so the transport's plain HTTP decides")
		},
	}
}

func securityHeadersAPIProfile() Scenario {
	return Scenario{
		Name: "security headers: a route the API profile selects gets the minimal set and no nonce",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{
				Options: []httpsec.Option{httpsec.EnableSecurityHeaders(
					httpsec.WithHeaderProfile(httpsec.APIHeaders(), httpsec.PathPrefix("/api/")))},
				Routes: headerRoute(),
			}
		},
		Request: sending(RequestSpec{Method: http.MethodGet, Path: "/api/orders", ClientAddress: ClientAddress}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", res.Header.Get("Content-Security-Policy"))
			assert.NotContains(t, res.Header.Get("Content-Security-Policy"), "nonce", "the API profile sends no nonce")
			assert.Equal(t, "nosniff", res.Header.Get("X-Content-Type-Options"))
			assert.Equal(t, "no-referrer", res.Header.Get("Referrer-Policy"))
		},
	}
}

func securityHeadersHSTSOnlyWhenSecure() Scenario {
	return Scenario{
		Name: "security headers: HSTS follows the chain's reading of the scheme, not the framework's",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{
				Options:                []httpsec.Option{trustingTheProxy(), httpsec.EnableSecurityHeaders()},
				Routes:                 headerRoute(),
				FrameworkTrustsProxies: true,
			}
		},
		Request: sending(RequestSpec{
			Method:        http.MethodGet,
			Path:          "/page",
			Header:        map[string]string{"X-Forwarded-For": clientAddress, "X-Forwarded-Proto": "https"},
			ClientAddress: proxyAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			assert.Equal(t, "max-age=31536000; includeSubDomains", res.Header.Get("Strict-Transport-Security"))
		},
	}
}

func securityHeadersReportOnly() Scenario {
	return Scenario{
		Name: "security headers: report-only mode sends the report-only policy and the reporting endpoint",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{
				Options: []httpsec.Option{httpsec.EnableSecurityHeaders(
					httpsec.WithCSPReportOnly(),
					httpsec.WithReportingEndpoint("csp", "https://reports.example.com/csp"))},
				Routes: headerRoute(),
			}
		},
		Request: sending(RequestSpec{Method: http.MethodGet, Path: "/page", ClientAddress: ClientAddress}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			assert.Empty(t, res.Header.Values("Content-Security-Policy"))
			assert.Regexp(t, nonceSource, res.Header.Get("Content-Security-Policy-Report-Only"))
			assert.Contains(t, res.Header.Get("Content-Security-Policy-Report-Only"), "report-to csp")
			assert.Contains(t, res.Header.Get("Content-Security-Policy-Report-Only"),
				"report-uri https://reports.example.com/csp")
			assert.Equal(t, `csp="https://reports.example.com/csp"`, res.Header.Get("Reporting-Endpoints"))
		},
	}
}

func securityHeadersEnforcedAndCandidateShareANonce() Scenario {
	return Scenario{
		Name: "security headers: an enforced and a report-only policy carry one nonce",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{
				Options: []httpsec.Option{httpsec.EnableSecurityHeaders(
					httpsec.WithCSPReportOnlyPolicy(httpsec.StrictCSP(httpsec.CSPDirective("img-src", "'self'"))))},
				Routes: headerRoute(),
			}
		},
		Request: sending(RequestSpec{Method: http.MethodGet, Path: "/page", ClientAddress: ClientAddress}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)

			enforced := nonceSource.FindString(res.Header.Get("Content-Security-Policy"))
			candidate := nonceSource.FindString(res.Header.Get("Content-Security-Policy-Report-Only"))

			require.NotEmpty(t, enforced)
			assert.Equal(t, enforced, candidate, "one handler nonce serves both policies")
		},
	}
}

func securityHeadersHashPreset() Scenario {
	const hash = "sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI="

	return Scenario{
		Name: "security headers: the hash preset lists the hash and sends no nonce",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{
				Options: []httpsec.Option{httpsec.EnableSecurityHeaders(httpsec.WithCSP(httpsec.HashCSP(hash)))},
				Routes:  headerRoute(),
			}
		},
		Request: sending(RequestSpec{Method: http.MethodGet, Path: "/page", ClientAddress: ClientAddress}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			assert.Equal(t, "script-src '"+hash+"'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
				res.Header.Get("Content-Security-Policy"))
			assert.NotContains(t, res.Header.Get("Content-Security-Policy"), "nonce")
		},
	}
}

func securityHeadersEditedAPIProfile() Scenario {
	return Scenario{
		Name: "security headers: an edited API profile serves its edit",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{
				Options: []httpsec.Option{httpsec.EnableSecurityHeaders(
					httpsec.WithHeaderProfile(
						httpsec.APIHeaders(httpsec.WithHeader("Referrer-Policy", "same-origin")),
						httpsec.PathPrefix("/api/")))},
				Routes: headerRoute(),
			}
		},
		Request: sending(RequestSpec{Method: http.MethodGet, Path: "/api/orders", ClientAddress: ClientAddress}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			assert.Equal(t, "same-origin", res.Header.Get("Referrer-Policy"))
			assert.Equal(t, "nosniff", res.Header.Get("X-Content-Type-Options"), "the rest of the profile stays")
		},
	}
}

func securityHeadersClearSiteDataOnSecureLogout() Scenario {
	return Scenario{
		Name: "logout: a secure, successful logout sends Clear-Site-Data",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			liveSession(t, effects)

			return ChainSpec{
				Options: append(bearerOptions(effects),
					trustingTheProxy(),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: effects.Sessions},
						httpsec.WithLogoutClearSiteData("cache", "cookies", "storage"))),
				Effects:                effects,
				Routes:                 plainRoute(),
				FrameworkTrustsProxies: true,
			}
		},
		Request: func(spec ChainSpec) RequestSpec {
			return RequestSpec{
				Method: http.MethodPost,
				Path:   LogoutPath,
				Header: map[string]string{
					"Authorization":     "Bearer " + issuedTokenFor(Username, spec.Effects.SessionID),
					"X-Forwarded-For":   clientAddress,
					"X-Forwarded-Proto": "https",
				},
				ClientAddress: proxyAddress,
			}
		},
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, []string{`"cache", "cookies", "storage"`}, res.Header.Values("Clear-Site-Data"))
		},
	}
}
