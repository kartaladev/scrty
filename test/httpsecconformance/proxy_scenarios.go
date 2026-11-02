package httpsecconformance

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// The addresses the trusted-proxy scenarios use: the proxy in front of the
// app, a client it forwards, and a peer that reaches the app directly.
const (
	proxyAddress  = "10.0.0.2"
	clientAddress = "198.51.100.7"
	directPeer    = "198.51.100.9"
	forgedAddress = "203.0.113.9"
)

// proxyScenarios is every behaviour of client resolution that must be
// identical on every adapter: each adapter hands the chain the raw transport
// peer and headers, and the chain's own trusted proxies decide, whatever the
// framework's own proxy settings say.
func proxyScenarios() []Scenario {
	return []Scenario{
		frameworkProxyTrustDoesNotChangeTheChain(),
		untrustedPeerCannotPoseAsTheTrustedProxy(),
		trustedProxyNamesTheClientOnEveryAdapter(),
		consumedForwardedHeadersAreRemovedBeforeTheRoute(),
		forwardedHostOutsideTheAllowlistIsRefused(),
	}
}

// trustingTheProxy is the chain's trusted-proxy configuration the scenarios
// share: proxyAddress alone, trusted for the client address, the scheme and
// app.example.com as the host.
func trustingTheProxy() httpsec.Option {
	return httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix(proxyAddress + "/32")},
		Headers: httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto,
			httpsec.ForwardedHost("app.example.com")),
	})
}

// proxyRoute is the one route the scenarios mount behind the chain.
func proxyRoute() []Route {
	return []Route{{Method: http.MethodGet, Path: "/orders", Status: http.StatusOK, Body: RouteBody}}
}

func frameworkProxyTrustDoesNotChangeTheChain() Scenario {
	return Scenario{
		Name: "the framework's own proxy trust does not change the chain",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{Routes: proxyRoute(), FrameworkTrustsProxies: true}
		},
		Request: sending(RequestSpec{
			Method: http.MethodGet,
			Path:   "/orders",
			Header: map[string]string{
				"X-Forwarded-For":   forgedAddress,
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "evil.example",
			},
			ClientAddress: clientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			require.True(t, res.ClientKnown, "the chain publishes the client on every request")
			assert.Equal(t, httpsec.Client{IP: clientAddress, Host: "example.com"}, res.Client,
				"the transport peer, plain HTTP and the Host header, never the framework's forwarded values")
			assert.Equal(t, forgedAddress, res.RouteHeader.Get("X-Forwarded-For"),
				"without trusted proxies the chain leaves the headers alone")
		},
	}
}

func untrustedPeerCannotPoseAsTheTrustedProxy() Scenario {
	return Scenario{
		Name: "an untrusted peer cannot pose as the trusted proxy",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{
				Options:                []httpsec.Option{trustingTheProxy()},
				Routes:                 proxyRoute(),
				FrameworkTrustsProxies: true,
			}
		},
		Request: sending(RequestSpec{
			Method: http.MethodGet,
			Path:   "/orders",
			Header: map[string]string{
				// The framework, trusting every peer, would read the proxy's
				// address from here and hand the chain a trusted peer.
				"X-Forwarded-For":   proxyAddress,
				"X-Forwarded-Proto": "https",
			},
			ClientAddress: directPeer,
		}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			assert.Equal(t, httpsec.Client{IP: directPeer, Host: "example.com"}, res.Client,
				"the peer's forwarded headers are ignored: it is not a trusted proxy")
		},
	}
}

func trustedProxyNamesTheClientOnEveryAdapter() Scenario {
	return Scenario{
		Name: "a trusted proxy names the client the same way on every adapter",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{Options: []httpsec.Option{trustingTheProxy()}, Routes: proxyRoute()}
		},
		Request: sending(RequestSpec{
			Method: http.MethodGet,
			Path:   "/orders",
			Header: map[string]string{
				"X-Forwarded-For":   forgedAddress + ", " + clientAddress,
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "App.Example.COM",
			},
			ClientAddress: proxyAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			assert.Equal(t,
				httpsec.Client{IP: clientAddress, Secure: true, Host: "app.example.com", ViaProxy: true}, res.Client)
		},
	}
}

func consumedForwardedHeadersAreRemovedBeforeTheRoute() Scenario {
	return Scenario{
		Name: "consumed forwarded headers are removed before the route",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{Options: []httpsec.Option{trustingTheProxy()}, Routes: proxyRoute()}
		},
		Request: sending(RequestSpec{
			Method: http.MethodGet,
			Path:   "/orders",
			Header: map[string]string{
				"Forwarded":          "for=" + clientAddress,
				"X-Forwarded-For":    clientAddress,
				"X-Forwarded-Host":   "app.example.com",
				"X-Forwarded-Port":   "443",
				"X-Forwarded-Prefix": "/app",
				"X-Request-Id":       "r-1",
			},
			ClientAddress: proxyAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)

			for _, name := range []string{
				"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Prefix",
			} {
				assert.Empty(t, res.RouteHeader.Get(name), "%s is removed", name)
			}

			assert.Equal(t, "r-1", res.RouteHeader.Get("X-Request-Id"), "an unrelated header is left alone")
		},
	}
}

func forwardedHostOutsideTheAllowlistIsRefused() Scenario {
	return Scenario{
		Name: "a forwarded host outside the allowlist is refused 400",
		Build: func(*testing.T) ChainSpec {
			return ChainSpec{Options: []httpsec.Option{trustingTheProxy()}, Routes: proxyRoute()}
		},
		Request: sending(RequestSpec{
			Method:        http.MethodGet,
			Path:          "/orders",
			Header:        map[string]string{"X-Forwarded-For": clientAddress, "X-Forwarded-Host": "evil.example"},
			ClientAddress: proxyAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusBadRequest, res.Status)
			assert.Empty(t, res.Body)
			require.ErrorIs(t, res.Refusal, httpsec.ErrHostNotAllowed)
			assert.NotContains(t, res.Refusal.Error(), "evil.example")
			assert.False(t, res.RouteRan)
		},
	}
}
