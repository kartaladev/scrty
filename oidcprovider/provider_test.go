package oidcprovider_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/signingkey"
)

const issuer = "https://id.example.com"

// webClient is a client that passes validation, for rows about something else.
func webClient() oidcprovider.Client {
	return oidcprovider.Client{
		ID:           "billing-web",
		Type:         oidcprovider.Confidential,
		Secret:       []byte("0123456789abcdef0123456789abcdef"),
		RedirectURIs: []string{"https://rp.example.com/cb"},
	}
}

// plainKeys is a key source reporting neither its algorithms nor its lifetimes,
// so only RS256 is accepted and no key cap applies. Nothing calls it at
// construction, as the absent expectations pin.
func plainKeys(t *testing.T) signingkey.KeySource {
	t.Helper()

	return NewMockKeySource(gomock.NewController(t))
}

func users(t *testing.T) identity.UserLoader {
	t.Helper()

	return NewMockUserLoader(gomock.NewController(t))
}

// validDeps is the minimum wiring that builds.
func validDeps(t *testing.T) oidcprovider.Deps {
	t.Helper()

	return oidcprovider.Deps{
		Issuer:       issuer,
		Clients:      []oidcprovider.Client{webClient()},
		Keys:         plainKeys(t),
		Users:        users(t),
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	}
}

func TestNew_Construction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		deps   func(d *oidcprovider.Deps)
		opts   []oidcprovider.Option
		assert func(t *testing.T, p *oidcprovider.Provider, err error)
	}

	refused := func(setting string) func(*testing.T, *oidcprovider.Provider, error) {
		return func(t *testing.T, p *oidcprovider.Provider, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.ErrorContains(t, err, setting)
			assert.Nil(t, p)
		}
	}
	built := func(t *testing.T, p *oidcprovider.Provider, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, p)
	}
	setIssuer := func(v string) func(*oidcprovider.Deps) {
		return func(d *oidcprovider.Deps) { d.Issuer = v }
	}

	const loopback = "http://127.0.0.1:8080"
	loopbackDeps := func(d *oidcprovider.Deps) {
		d.Issuer = loopback
		d.LoginURL = loopback + "/login"
		d.ConsentURL = loopback + "/consent"
		d.LogoutURL = loopback + "/logout"
		d.LoggedOutURL = loopback + "/bye"
	}

	var typedNilKeys *signingkey.Keys
	registry := NewMockClientRegistry(gomock.NewController(t))

	durable, err := session.NewMemoryStore()
	require.NoError(t, err)
	durableStore := oplineage.New(durable)
	sharedKey := bytes.Repeat([]byte("k"), 32)
	refusedWithoutKey := func(t *testing.T, p *oidcprovider.Provider, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrConfig)
		assert.ErrorContains(t, err, "WithRefreshSuccessorKey")
		assert.ErrorContains(t, err, "WithRefreshSuccessorWindow(0)")
		assert.Nil(t, p)
	}

	cases := []testCase{
		{name: "minimum wiring builds", assert: built},

		// A durable refresh-token store needs a successor key all replicas share.
		{
			name:   "a refresh token store with no key is refused",
			opts:   []oidcprovider.Option{oidcprovider.WithRefreshTokenStore(durableStore)},
			assert: refusedWithoutKey,
		},
		{
			name: "a refresh token store with no key is refused, window option after",
			opts: []oidcprovider.Option{
				oidcprovider.WithRefreshTokenStore(durableStore),
				oidcprovider.WithRefreshSuccessorWindow(time.Second),
			},
			assert: refusedWithoutKey,
		},
		{
			name: "a refresh token store with no key is refused, window option before",
			opts: []oidcprovider.Option{
				oidcprovider.WithRefreshSuccessorWindow(time.Second),
				oidcprovider.WithRefreshTokenStore(durableStore),
			},
			assert: refusedWithoutKey,
		},
		{
			name: "a refresh token store with a 32-byte key builds",
			opts: []oidcprovider.Option{
				oidcprovider.WithRefreshTokenStore(durableStore), oidcprovider.WithRefreshSuccessorKey(sharedKey),
			},
			assert: built,
		},
		{
			name: "a refresh token store with the window off and no key builds",
			opts: []oidcprovider.Option{
				oidcprovider.WithRefreshSuccessorWindow(0), oidcprovider.WithRefreshTokenStore(durableStore),
			},
			assert: built,
		},
		{name: "memory stores with no options draw their own key", assert: built},

		// Issuer.
		{name: "issuer with a query", deps: setIssuer("https://id.example.com?x=1"), assert: refused("Issuer")},
		{name: "issuer with a fragment", deps: setIssuer("https://id.example.com#f"), assert: refused("Issuer")},
		{name: "issuer over http", deps: setIssuer("http://id.example.com"), assert: refused("Issuer")},
		{name: "relative issuer", deps: setIssuer("/id"), assert: refused("Issuer")},
		{name: "empty issuer", deps: setIssuer(""), assert: refused("Issuer")},
		{name: "issuer with user information", deps: setIssuer("https://a:b@id.example.com"), assert: refused("Issuer")},
		{name: "loopback http without the option", deps: loopbackDeps, assert: refused("Issuer")},
		{
			name: "loopback http with the option", deps: loopbackDeps,
			opts:   []oidcprovider.Option{oidcprovider.WithLoopbackHTTPIssuer()},
			assert: built,
		},
		{
			name: "the loopback name with the option",
			deps: func(d *oidcprovider.Deps) {
				d.Issuer = "http://localhost:8080"
				d.LoginURL = "http://localhost:8080/login"
				d.ConsentURL = "http://localhost:8080/consent"
				d.LogoutURL = "http://localhost:8080/logout"
				d.LoggedOutURL = "http://localhost:8080/bye"
			},
			opts:   []oidcprovider.Option{oidcprovider.WithLoopbackHTTPIssuer()},
			assert: built,
		},
		{
			name: "non-loopback http with the option", deps: setIssuer("http://id.example.com"),
			opts:   []oidcprovider.Option{oidcprovider.WithLoopbackHTTPIssuer()},
			assert: refused("Issuer"),
		},

		// Required ports, and the one registry source.
		{name: "nil keys", deps: func(d *oidcprovider.Deps) { d.Keys = nil }, assert: refused("Keys")},
		{name: "typed nil keys", deps: func(d *oidcprovider.Deps) { d.Keys = typedNilKeys }, assert: refused("Keys")},
		{name: "nil users", deps: func(d *oidcprovider.Deps) { d.Users = nil }, assert: refused("Users")},
		{name: "neither clients nor registry", deps: func(d *oidcprovider.Deps) { d.Clients = nil }, assert: refused("Clients")},
		{
			name: "both clients and registry",
			deps: func(d *oidcprovider.Deps) {
				d.Registry = registry
			},
			assert: refused("Registry"),
		},
		{
			name: "registry alone builds",
			deps: func(d *oidcprovider.Deps) {
				d.Clients = nil
				d.Registry = registry
			},
			assert: built,
		},

		// The consumer's pages (R9).
		{name: "empty login URL", deps: func(d *oidcprovider.Deps) { d.LoginURL = "" }, assert: refused("LoginURL")},
		{name: "empty consent URL", deps: func(d *oidcprovider.Deps) { d.ConsentURL = "" }, assert: refused("ConsentURL")},
		{name: "relative login URL", deps: func(d *oidcprovider.Deps) { d.LoginURL = "/login" }, assert: refused("LoginURL")},
		{
			name:   "login URL on another origin",
			deps:   func(d *oidcprovider.Deps) { d.LoginURL = "https://login.example.com/" },
			assert: refused("LoginURL"),
		},
		{
			name:   "consent URL on another port",
			deps:   func(d *oidcprovider.Deps) { d.ConsentURL = issuer + ":8443/consent" },
			assert: refused("ConsentURL"),
		},
		{
			name:   "login URL with user information",
			deps:   func(d *oidcprovider.Deps) { d.LoginURL = "https://u@id.example.com/login" },
			assert: refused("LoginURL"),
		},
		{
			name:   "login URL with a fragment",
			deps:   func(d *oidcprovider.Deps) { d.LoginURL = issuer + "/login#x" },
			assert: refused("LoginURL"),
		},

		// Logout: both pages are required (R3).
		{
			name:   "no logout pages",
			deps:   func(d *oidcprovider.Deps) { d.LogoutURL, d.LoggedOutURL = "", "" },
			assert: refused("LogoutURL"),
		},
		{
			name:   "logout page without the logged-out page",
			deps:   func(d *oidcprovider.Deps) { d.LoggedOutURL = "" },
			assert: refused("LoggedOutURL"),
		},
		{
			name:   "logged-out page without the logout page",
			deps:   func(d *oidcprovider.Deps) { d.LogoutURL = "" },
			assert: refused("LogoutURL"),
		},
		{
			name:   "relative logout page",
			deps:   func(d *oidcprovider.Deps) { d.LogoutURL = "/logout" },
			assert: refused("LogoutURL"),
		},
		{
			name:   "logout page on another origin",
			deps:   func(d *oidcprovider.Deps) { d.LogoutURL = "https://login.example.com/logout" },
			assert: refused("LogoutURL"),
		},
		{
			name:   "logged-out page on another origin",
			deps:   func(d *oidcprovider.Deps) { d.LoggedOutURL = "https://login.example.com/bye" },
			assert: refused("LoggedOutURL"),
		},
		{
			name:   "logout confirmation is just an option",
			opts:   []oidcprovider.Option{oidcprovider.WithLogoutConfirmation()},
			assert: built,
		},

		// Lifetimes and bounds.
		{
			name:   "pending lifetime past the bound",
			opts:   []oidcprovider.Option{oidcprovider.WithPendingRequestLifetime(2 * time.Hour)},
			assert: refused("WithPendingRequestLifetime"),
		},
		{
			name:   "pending lifetime of zero",
			opts:   []oidcprovider.Option{oidcprovider.WithPendingRequestLifetime(0)},
			assert: refused("WithPendingRequestLifetime"),
		},
		{
			name:   "pending lifetime at the bound",
			opts:   []oidcprovider.Option{oidcprovider.WithPendingRequestLifetime(30 * time.Minute)},
			assert: built,
		},
		{
			name:   "code lifetime past the bound",
			opts:   []oidcprovider.Option{oidcprovider.WithCodeLifetime(15 * time.Minute)},
			assert: refused("WithCodeLifetime"),
		},
		{
			name:   "code lifetime of zero",
			opts:   []oidcprovider.Option{oidcprovider.WithCodeLifetime(0)},
			assert: refused("WithCodeLifetime"),
		},
		{
			name:   "assertion bound past the limit",
			opts:   []oidcprovider.Option{oidcprovider.WithClientAssertionMaxLifetime(2 * time.Hour)},
			assert: refused("WithClientAssertionMaxLifetime"),
		},
		{
			name:   "assertion bound at the limit",
			opts:   []oidcprovider.Option{oidcprovider.WithClientAssertionMaxLifetime(time.Hour)},
			assert: built,
		},
		{
			name:   "unknown audience rule",
			opts:   []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceRule(9))},
			assert: refused("WithClientAssertionAudience"),
		},
		{
			name: "token endpoint on the issuer's origin, under the compatibility rule",
			opts: []oidcprovider.Option{
				oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
				oidcprovider.WithAssertionTokenEndpoint(issuer + "/api/oauth/token"),
			},
			assert: built,
		},
		{
			name: "token endpoint relative",
			opts: []oidcprovider.Option{
				oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
				oidcprovider.WithAssertionTokenEndpoint("/api/oauth/token"),
			},
			assert: refused("WithAssertionTokenEndpoint"),
		},
		{
			name: "token endpoint empty",
			opts: []oidcprovider.Option{
				oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
				oidcprovider.WithAssertionTokenEndpoint(""),
			},
			assert: refused("WithAssertionTokenEndpoint"),
		},
		{
			name: "token endpoint on another origin",
			opts: []oidcprovider.Option{
				oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
				oidcprovider.WithAssertionTokenEndpoint("https://other.example.com/token"),
			},
			assert: refused("WithAssertionTokenEndpoint"),
		},
		{
			name: "token endpoint on another port",
			opts: []oidcprovider.Option{
				oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
				oidcprovider.WithAssertionTokenEndpoint(issuer + ":8443/token"),
			},
			assert: refused("WithAssertionTokenEndpoint"),
		},
		{
			name: "token endpoint with a fragment",
			opts: []oidcprovider.Option{
				oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
				oidcprovider.WithAssertionTokenEndpoint(issuer + "/token#x"),
			},
			assert: refused("WithAssertionTokenEndpoint"),
		},
		{
			name: "token endpoint with a query",
			opts: []oidcprovider.Option{
				oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
				oidcprovider.WithAssertionTokenEndpoint(issuer + "/token?x=1"),
			},
			assert: refused("WithAssertionTokenEndpoint"),
		},
		{
			name: "token endpoint with user information",
			opts: []oidcprovider.Option{
				oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
				oidcprovider.WithAssertionTokenEndpoint("https://u@id.example.com/token"),
			},
			assert: refused("WithAssertionTokenEndpoint"),
		},
		{
			name:   "token endpoint under the default issuer-only rule means nothing",
			opts:   []oidcprovider.Option{oidcprovider.WithAssertionTokenEndpoint(issuer + "/api/oauth/token")},
			assert: refused("WithAssertionTokenEndpoint"),
		},
		{
			name: "token endpoint under an explicit issuer-only rule means nothing",
			opts: []oidcprovider.Option{
				oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOnly),
				oidcprovider.WithAssertionTokenEndpoint(issuer + "/api/oauth/token"),
			},
			assert: refused("WithAssertionTokenEndpoint"),
		},
		{
			name:   "refetch cooldown of zero",
			opts:   []oidcprovider.Option{oidcprovider.WithClientKeysRefetchCooldown(0)},
			assert: refused("WithClientKeysRefetchCooldown"),
		},
		{
			name:   "negative request bound",
			opts:   []oidcprovider.Option{oidcprovider.WithRequestBounds(oidcprovider.RequestBounds{State: -1})},
			assert: refused("WithRequestBounds"),
		},
		{
			name:   "negative id_token_hint bound",
			opts:   []oidcprovider.Option{oidcprovider.WithRequestBounds(oidcprovider.RequestBounds{IDTokenHint: -1})},
			assert: refused("WithRequestBounds"),
		},

		// Ports replaced with nothing.
		{name: "nil clock", opts: []oidcprovider.Option{oidcprovider.WithClock(nil)}, assert: refused("WithClock")},
		{name: "nil logger", opts: []oidcprovider.Option{oidcprovider.WithLogger(nil)}, assert: refused("WithLogger")},
		{name: "nil random", opts: []oidcprovider.Option{oidcprovider.WithRandom(nil)}, assert: refused("WithRandom")},
		{name: "nil outbound", opts: []oidcprovider.Option{oidcprovider.WithOutbound(nil)}, assert: refused("WithOutbound")},
		{name: "nil assertion store", opts: []oidcprovider.Option{oidcprovider.WithAssertionIDStore(nil)}, assert: refused("WithAssertionIDStore")},
		{name: "typed nil assertion store", opts: []oidcprovider.Option{oidcprovider.WithAssertionIDStore((*MockAssertionIDStore)(nil))}, assert: refused("WithAssertionIDStore")},
		{name: "a zero key-set lifetime", opts: []oidcprovider.Option{oidcprovider.WithClientKeysTTL(0)}, assert: refused("WithClientKeysTTL")},
		{name: "a negative key-set lifetime", opts: []oidcprovider.Option{oidcprovider.WithClientKeysTTL(-time.Second)}, assert: refused("WithClientKeysTTL")},
		{name: "nil option is skipped", opts: []oidcprovider.Option{nil}, assert: built},

		// Defaults and their overrides.
		{
			name: "defaults",
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, 10*time.Minute, p.PendingLifetimeForTest())
				assert.Equal(t, 60*time.Second, p.CodeLifetimeForTest())
				assert.Equal(t, 5*time.Minute, p.AssertionMaxForTest())
				assert.Equal(t, oidcprovider.AudienceIssuerOnly, p.AssertionAudienceForTest())
				assert.Equal(t, 30*time.Second, p.RefetchCooldownForTest())
				assert.Equal(t, oidcprovider.RequestBounds{
					State: 2048, Nonce: 2048, LoginHint: 2048, Resource: 2048, Scope: 4096, IDTokenHint: 8192,
				}, p.BoundsForTest())
				assert.True(t, p.BrowserSessionsForTest())
				assert.False(t, p.LogoutConfirmationForTest())
			},
		},
		{
			name: "the token endpoint in use, by rule",
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Empty(t, p.AssertionTokenEndpoint(), "the default rule names no token endpoint")
			},
		},
		{
			name: "the token endpoint under the compatibility rule is derived from the issuer",
			opts: []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint)},
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, issuer+"/oauth2/token", p.AssertionTokenEndpoint())
			},
		},
		{
			name: "the token endpoint under the compatibility rule is the one given",
			opts: []oidcprovider.Option{
				oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
				oidcprovider.WithAssertionTokenEndpoint(issuer + "/api/oauth/token"),
			},
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, issuer+"/api/oauth/token", p.AssertionTokenEndpoint())
			},
		},
		{
			name: "overrides are recorded",
			opts: []oidcprovider.Option{
				oidcprovider.WithoutBrowserSessions(),
				oidcprovider.WithLogoutConfirmation(),
				oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
				oidcprovider.WithRequestBounds(oidcprovider.RequestBounds{State: 100}),
			},
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, p.BrowserSessionsForTest())
				assert.True(t, p.LogoutConfirmationForTest())
				assert.Equal(t, oidcprovider.AudienceIssuerOrTokenEndpoint, p.AssertionAudienceForTest())
				assert.Equal(t, oidcprovider.RequestBounds{
					State: 100, Nonce: 2048, LoginHint: 2048, Resource: 2048, Scope: 4096, IDTokenHint: 8192,
				}, p.BoundsForTest())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := validDeps(t)
			if tc.deps != nil {
				tc.deps(&d)
			}

			p, err := oidcprovider.New(d, tc.opts...)
			tc.assert(t, p, err)
		})
	}
}

func TestError_Text(t *testing.T) {
	t.Parallel()

	err := &oidcprovider.Error{Code: oidcprovider.CodeInvalidClient}
	assert.Equal(t, "oidcprovider: invalid_client", err.Error())
}
