package httpsecconformance

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
)

// CORSOrigin is the one origin the CORS scenarios allow.
const CORSOrigin = "https://app.example.com"

// corsPath is the application route the CORS scenarios call.
const corsPath = "/api/orders"

// preflightVary is the Vary value every preflight answer carries.
const preflightVary = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"

// corsScenarios is every behaviour of the CORS layer that must be identical on
// every adapter: it answers a preflight inside the chain, before any route or
// authentication, and sets its headers before the chain's own refusals, so
// each framework must neither route the preflight away nor drop the headers
// from its default error handling.
func corsScenarios() []Scenario {
	return []Scenario{
		corsAllowedOrigin(),
		corsOtherOrigin(),
		corsRefusalReadable(),
		corsPreflightAllowed(),
		corsPreflightMethodNotAllowed(),
		corsPlainOptionsContinues(),
		corsVaryKeepsEarlierValue(),
		corsPreflightVaryKeepsEarlierValue(),
		corsAnyOriginAllowsNull(),
	}
}

// corsPolicy allows CORSOrigin to send the Authorization header and read
// WWW-Authenticate.
func corsPolicy() httpsec.Option {
	return httpsec.EnableCORS(httpsec.CORSPolicy{
		AllowedOrigins: []string{CORSOrigin},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
		ExposedHeaders: []string{"WWW-Authenticate"},
	})
}

// corsGetRoutes mounts no OPTIONS route, so a preflight answered 204 can only
// have been answered by the chain, not by the framework's router.
func corsGetRoutes() []Route {
	return []Route{{Method: http.MethodGet, Path: corsPath, Status: http.StatusOK, Body: RouteBody}}
}

func corsRoutes() []Route {
	return []Route{
		{Method: http.MethodGet, Path: corsPath, Status: http.StatusOK, Body: RouteBody},
		{Method: http.MethodOptions, Path: corsPath, Status: http.StatusOK, Body: RouteBody},
	}
}

// assertNoCORS checks h carries no CORS header.
func assertNoCORS(t *testing.T, h http.Header) {
	t.Helper()

	for _, n := range []string{
		"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Expose-Headers",
		"Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Max-Age",
	} {
		assert.Empty(t, h.Values(n), n)
	}
}

func corsAllowedOrigin() Scenario {
	return Scenario{
		Name: "cors: an allowed origin's actual request gets its origin, the exposed headers and Vary",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{Options: []httpsec.Option{corsPolicy()}, Routes: corsRoutes()}
		},
		Request: sending(RequestSpec{
			Method: http.MethodGet, Path: corsPath, ClientAddress: ClientAddress,
			Header: map[string]string{"Origin": CORSOrigin},
		}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			assert.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, CORSOrigin, res.Header.Get("Access-Control-Allow-Origin"))
			assert.Equal(t, "WWW-Authenticate", res.Header.Get("Access-Control-Expose-Headers"))
			assert.Equal(t, []string{"Origin"}, res.Header.Values("Vary"))
		},
	}
}

func corsOtherOrigin() Scenario {
	return Scenario{
		Name: "cors: another origin gets no CORS header but Vary, and is otherwise unaffected",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{Options: []httpsec.Option{corsPolicy()}, Routes: corsRoutes()}
		},
		Request: sending(RequestSpec{
			Method: http.MethodGet, Path: corsPath, ClientAddress: ClientAddress,
			Header: map[string]string{"Origin": "https://app.example.com.evil.example"},
		}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			assert.Equal(t, http.StatusOK, res.Status)
			assertNoCORS(t, res.Header)
			assert.Equal(t, []string{"Origin"}, res.Header.Values("Vary"))
		},
	}
}

func corsRefusalReadable() Scenario {
	return Scenario{
		Name: "cors: a bearer refusal through the framework's default error handling is readable by an allowed origin",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			liveSession(t, effects)

			return ChainSpec{
				Options: append([]httpsec.Option{corsPolicy()}, bearerOptions(effects)...),
				Effects: effects,
				Routes:  corsRoutes(),
			}
		},
		Request: sending(RequestSpec{
			Method: http.MethodGet, Path: corsPath, ClientAddress: ClientAddress,
			Header: map[string]string{"Origin": CORSOrigin, "Authorization": "Bearer not-a-token"},
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			require.ErrorIs(t, res.Refusal, authenticate.ErrAuthenticationFailed)
			assert.False(t, res.RouteRan)
			assert.Equal(t, CORSOrigin, res.Header.Get("Access-Control-Allow-Origin"))
			assert.Equal(t, "WWW-Authenticate", res.Header.Get("Access-Control-Expose-Headers"))
			assert.Equal(t, []string{"Origin"}, res.Header.Values("Vary"))
		},
	}
}

func corsPreflightAllowed() Scenario {
	return Scenario{
		Name: "cors: an allowed preflight is answered 204 by the chain, before authentication, on a path with no OPTIONS route",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			return ChainSpec{
				Options: append([]httpsec.Option{httpsec.EnableSecurityHeaders(), corsPolicy()}, bearerOptions(effects)...),
				Effects: effects,
				Routes:  corsGetRoutes(),
			}
		},
		Request: sending(RequestSpec{
			Method: http.MethodOptions, Path: corsPath, ClientAddress: ClientAddress,
			Header: map[string]string{
				"Origin":                         CORSOrigin,
				"Access-Control-Request-Method":  http.MethodGet,
				"Access-Control-Request-Headers": "authorization",
			},
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusNoContent, res.Status)
			require.NoError(t, res.Refusal)
			assert.False(t, res.RouteRan)
			assert.Equal(t, CORSOrigin, res.Header.Get("Access-Control-Allow-Origin"))
			assert.Equal(t, "GET, HEAD, POST", res.Header.Get("Access-Control-Allow-Methods"))
			assert.Equal(t, "Authorization", res.Header.Get("Access-Control-Allow-Headers"))
			assert.Equal(t, "600", res.Header.Get("Access-Control-Max-Age"))
			assert.Equal(t, preflightVary, res.Header.Get("Vary"))
			assert.Equal(t, "nosniff", res.Header.Get("X-Content-Type-Options"), "the preflight passes through the security-headers slot")
		},
	}
}

func corsPreflightMethodNotAllowed() Scenario {
	return Scenario{
		Name: "cors: a preflight for a method not allowed gets a bare 204, on a path with no OPTIONS route",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{Options: []httpsec.Option{corsPolicy()}, Routes: corsGetRoutes()}
		},
		Request: sending(RequestSpec{
			Method: http.MethodOptions, Path: corsPath, ClientAddress: ClientAddress,
			Header: map[string]string{"Origin": CORSOrigin, "Access-Control-Request-Method": http.MethodDelete},
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusNoContent, res.Status)
			require.NoError(t, res.Refusal)
			assert.False(t, res.RouteRan)
			assertNoCORS(t, res.Header)
			assert.Equal(t, preflightVary, res.Header.Get("Vary"))
		},
	}
}

func corsPlainOptionsContinues() Scenario {
	return Scenario{
		Name: "cors: an OPTIONS request without a requested method is not a preflight and reaches the route",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{Options: []httpsec.Option{corsPolicy()}, Routes: corsRoutes()}
		},
		Request: sending(RequestSpec{
			Method: http.MethodOptions, Path: corsPath, ClientAddress: ClientAddress,
			Header: map[string]string{"Origin": CORSOrigin},
		}),
		Assert: func(t *testing.T, res Result) {
			assert.True(t, res.RouteRan)
			assert.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, CORSOrigin, res.Header.Get("Access-Control-Allow-Origin"))
			assert.Equal(t, []string{"Origin"}, res.Header.Values("Vary"))
		},
	}
}

func corsVaryKeepsEarlierValue() Scenario {
	return Scenario{
		Name: "cors: Origin is added to a Vary an earlier interceptor set, not in place of it",
		Build: func(*testing.T) ChainSpec {
			earlier := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				ex.Writer.SetHeader("Vary", "Accept-Encoding")

				return next(ex)
			}), httpsec.Before(httpsec.OrderCORS))

			return ChainSpec{Options: []httpsec.Option{earlier, corsPolicy()}, Routes: corsRoutes()}
		},
		Request: sending(RequestSpec{
			Method: http.MethodGet, Path: corsPath, ClientAddress: ClientAddress,
			Header: map[string]string{"Origin": CORSOrigin},
		}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			assert.Equal(t, CORSOrigin, res.Header.Get("Access-Control-Allow-Origin"))
			assert.Equal(t, []string{"Accept-Encoding", "Origin"}, res.Header.Values("Vary"))
		},
	}
}

func corsPreflightVaryKeepsEarlierValue() Scenario {
	return Scenario{
		Name: "cors: an allowed preflight adds its Vary values to one an earlier interceptor set, not in place of it",
		Build: func(*testing.T) ChainSpec {
			earlier := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				ex.Writer.SetHeader("Vary", "Accept-Encoding")

				return next(ex)
			}), httpsec.Before(httpsec.OrderCORS))

			return ChainSpec{Options: []httpsec.Option{earlier, corsPolicy()}, Routes: corsGetRoutes()}
		},
		Request: sending(RequestSpec{
			Method: http.MethodOptions, Path: corsPath, ClientAddress: ClientAddress,
			Header: map[string]string{"Origin": CORSOrigin, "Access-Control-Request-Method": http.MethodGet},
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusNoContent, res.Status)
			require.NoError(t, res.Refusal)
			assert.False(t, res.RouteRan)
			assert.Equal(t, CORSOrigin, res.Header.Get("Access-Control-Allow-Origin"))
			assert.Equal(t, []string{"Accept-Encoding", preflightVary}, res.Header.Values("Vary"))
		},
	}
}

func corsAnyOriginAllowsNull() Scenario {
	return Scenario{
		Name: `cors: "*" without credentials answers the null origin with "*"`,
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{
				Options: []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{"*"}})},
				Routes:  corsRoutes(),
			}
		},
		Request: sending(RequestSpec{
			Method: http.MethodGet, Path: corsPath, ClientAddress: ClientAddress,
			Header: map[string]string{"Origin": "null"},
		}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			assert.Equal(t, "*", res.Header.Get("Access-Control-Allow-Origin"))
			assert.Empty(t, res.Header.Values("Access-Control-Allow-Credentials"))
			assert.Equal(t, []string{"Origin"}, res.Header.Values("Vary"))
		},
	}
}
