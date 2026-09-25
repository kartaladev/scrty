package httpsec_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// oidcFixture is what a construction row wires EnableOIDCLogin with.
type oidcFixture struct {
	manager  *oidc.Manager
	handoffs *oidc.HandoffManager
	tokens   *MockGenerator
	sessions *session.Manager
}

// required is the minimal wiring every accepted configuration carries.
func (f oidcFixture) required(opts ...httpsec.OIDCOption) []httpsec.OIDCOption {
	return append([]httpsec.OIDCOption{
		httpsec.WithOIDCTokens(f.tokens),
		httpsec.WithOIDCSessions(f.sessions),
	}, opts...)
}

// TestEnableOIDCLoginConstruction pins what a chain with federated login
// refuses to be built with, one row per refusal, beside the configurations it
// accepts. Every refusal is a wiring mistake that would otherwise surface at
// the first login: an endpoint swallowed by another, a login conveyed by
// nothing, a limit that limits nothing.
func TestEnableOIDCLoginConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// manager builds the OIDC manager; nil means the fixture's.
		manager func(t *testing.T) *oidc.Manager

		// enable builds the option under test from the fixture.
		enable func(f oidcFixture) httpsec.Option

		// chain is any other chain option the row needs beside it.
		chain []httpsec.Option

		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	built := func(t *testing.T, c *httpsec.Chain, err error) {
		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	refused := func(fragments ...string) func(t *testing.T, c *httpsec.Chain, err error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, c, "a chain that cannot be configured is not half-built")
			for _, fragment := range fragments {
				assert.ErrorContains(t, err, fragment)
			}
		}
	}

	// with enables federated login with the required wiring plus opts.
	with := func(opts ...httpsec.OIDCOption) func(f oidcFixture) httpsec.Option {
		return func(f oidcFixture) httpsec.Option {
			return httpsec.EnableOIDCLogin(f.manager, f.handoffs, f.required(opts...)...)
		}
	}

	conveyed := httpsec.WithCallbackSuccess(func(*httpsec.Exchange, oidc.CallbackResult, string) error {
		return nil
	})

	// convey enables federated login with the consumer's own conveyance, a
	// nil handoff manager and no token generator: the handoff endpoint is
	// never reached under WithCallbackSuccess, so neither is required.
	convey := func(opts ...httpsec.OIDCOption) func(f oidcFixture) httpsec.Option {
		return func(f oidcFixture) httpsec.Option {
			return httpsec.EnableOIDCLogin(f.manager, nil, append([]httpsec.OIDCOption{
				httpsec.WithOIDCSessions(f.sessions), conveyed,
			}, opts...)...)
		}
	}

	syncingRoles := func(t *testing.T) *oidc.Manager {
		return newTestOIDCManager(t,
			oidc.WithRoleClaim(testOIDCProvider, "realm_access.roles"),
			oidc.WithRoleSync(testOIDCProvider, true))
	}

	cases := []testCase{
		// Accepted.
		{name: "the minimal wiring", enable: with(), assert: built},
		{
			name: "the session manager comes from another built-in",
			enable: func(f oidcFixture) httpsec.Option {
				return httpsec.EnableOIDCLogin(f.manager, f.handoffs, httpsec.WithOIDCTokens(f.tokens))
			},
			chain: []httpsec.Option{
				httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: mustSessions(t)}),
			},
			assert: built,
		},
		{
			name:   "no handoff manager and no token generator when the consumer conveys the login",
			enable: convey(),
			assert: built,
		},
		{
			name: "every option given a consumer value",
			enable: with(
				httpsec.WithOIDCAuthorizePath("/auth/oidc/start/"),
				httpsec.WithOIDCCallbackPath("/auth/oidc/callback/"),
				httpsec.WithOIDCHandoffPath("/auth/oidc/handoff"),
				httpsec.WithBackchannelLogoutPath("/auth/oidc/backchannel/"),
				httpsec.WithOIDCFlowCookieName("login_flow"),
				httpsec.WithOIDCAllowedRedirects("/welcome", "https://app.example.com/home"),
				httpsec.WithOIDCAllowedOrigins("https://app.example.com"),
				httpsec.WithHandoffLimiter(mustLimiter(t)),
				httpsec.WithHandoffRateLimit(3, time.Minute),
				httpsec.WithHandoffCountRefusals(false),
				httpsec.WithBackchannelLogoutScope(httpsec.AllSessions),
				httpsec.WithOIDCRPInitiatedLogout(false),
				httpsec.WithHandoffRedeemer(newTestHandoffManager(t)),
			),
			assert: built,
		},
		{
			name: "prefixes given without a trailing slash",
			enable: with(
				httpsec.WithOIDCAuthorizePath("/auth/start"),
				httpsec.WithOIDCCallbackPath("/auth/callback"),
				httpsec.WithBackchannelLogoutPath("/auth/backchannel"),
			),
			assert: built,
		},
		{
			name:    "role sync with a consumer conveyance",
			manager: syncingRoles,
			enable:  convey(),
			assert:  built,
		},

		// Required dependencies.
		{
			name: "no OIDC manager",
			enable: func(f oidcFixture) httpsec.Option {
				return httpsec.EnableOIDCLogin(nil, f.handoffs, f.required()...)
			},
			assert: refused("EnableOIDCLogin", "OIDC manager"),
		},
		{
			name: "no handoff manager and no consumer conveyance",
			enable: func(f oidcFixture) httpsec.Option {
				return httpsec.EnableOIDCLogin(f.manager, nil, f.required()...)
			},
			assert: refused("EnableOIDCLogin", "handoff manager", "WithCallbackSuccess"),
		},
		{
			name: "no token generator",
			enable: func(f oidcFixture) httpsec.Option {
				return httpsec.EnableOIDCLogin(f.manager, f.handoffs, httpsec.WithOIDCSessions(f.sessions))
			},
			assert: refused("EnableOIDCLogin", "token generator", "WithOIDCTokens"),
		},
		{
			name:   "a nil token generator",
			enable: with(httpsec.WithOIDCTokens(nil)),
			assert: refused("WithOIDCTokens"),
		},
		{
			name:   "a token generator interface holding a nil pointer",
			enable: with(httpsec.WithOIDCTokens((*MockGenerator)(nil))),
			assert: refused("WithOIDCTokens"),
		},
		{
			name: "no session manager anywhere on the chain",
			enable: func(f oidcFixture) httpsec.Option {
				return httpsec.EnableOIDCLogin(f.manager, f.handoffs, httpsec.WithOIDCTokens(f.tokens))
			},
			assert: refused("EnableOIDCLogin", "session manager", "WithOIDCSessions"),
		},
		{
			name:   "a nil session manager",
			enable: with(httpsec.WithOIDCSessions(nil)),
			assert: refused("WithOIDCSessions"),
		},

		// Paths.
		{
			name:   "an empty authorize path",
			enable: with(httpsec.WithOIDCAuthorizePath("")),
			assert: refused("WithOIDCAuthorizePath"),
		},
		{
			name:   "an empty callback path",
			enable: with(httpsec.WithOIDCCallbackPath("")),
			assert: refused("WithOIDCCallbackPath"),
		},
		{
			name:   "an empty handoff path",
			enable: with(httpsec.WithOIDCHandoffPath("")),
			assert: refused("WithOIDCHandoffPath"),
		},
		{
			name:   "an empty back-channel path",
			enable: with(httpsec.WithBackchannelLogoutPath("")),
			assert: refused("WithBackchannelLogoutPath"),
		},
		{
			name:   "a path that is not absolute",
			enable: with(httpsec.WithOIDCHandoffPath("login/handoff")),
			assert: refused("WithOIDCHandoffPath", `"login/handoff"`),
		},
		{
			name:   "the handoff path equal to the callback prefix",
			enable: with(httpsec.WithOIDCHandoffPath(httpsec.DefaultOIDCCallbackPath)),
			assert: refused("collide", httpsec.DefaultOIDCCallbackPath),
		},
		{
			name:   "the handoff path answered by the authorize prefix",
			enable: with(httpsec.WithOIDCHandoffPath(httpsec.DefaultOIDCAuthorizePath + "handoff")),
			assert: refused("collide", httpsec.DefaultOIDCAuthorizePath+"handoff"),
		},
		{
			// Spec oidc-logout, "Back-channel path shadows the callback".
			name:   "the back-channel prefix equal to the callback prefix",
			enable: with(httpsec.WithBackchannelLogoutPath(httpsec.DefaultOIDCCallbackPath)),
			assert: refused("collide", httpsec.DefaultOIDCCallbackPath),
		},
		{
			name:   "the authorize prefix equal to the callback prefix without its slash",
			enable: with(httpsec.WithOIDCAuthorizePath("/login/oauth2/callback")),
			assert: refused("collide", httpsec.DefaultOIDCCallbackPath),
		},
		{
			name:   "the handoff path equal to a prefix given without its trailing slash",
			enable: with(httpsec.WithOIDCHandoffPath("/login/oauth2/callback")),
			assert: refused("collide", httpsec.DefaultOIDCCallbackPath),
		},
		{
			name:   "the root path as the authorize prefix",
			enable: with(httpsec.WithOIDCAuthorizePath("/")),
			assert: refused("WithOIDCAuthorizePath", "root path", "every one-segment path"),
		},
		{
			name:   "the root path as the callback prefix",
			enable: with(httpsec.WithOIDCCallbackPath("/")),
			assert: refused("WithOIDCCallbackPath", "root path", "every one-segment path"),
		},
		{
			name:   "the root path as the back-channel prefix",
			enable: with(httpsec.WithBackchannelLogoutPath("/")),
			assert: refused("WithBackchannelLogoutPath", "root path", "every one-segment path"),
		},
		{
			name:   "an empty flow cookie name",
			enable: with(httpsec.WithOIDCFlowCookieName("")),
			assert: refused("WithOIDCFlowCookieName"),
		},
		{
			name:   "a flow cookie name that is not a cookie token",
			enable: with(httpsec.WithOIDCFlowCookieName("oidc flow")),
			assert: refused("WithOIDCFlowCookieName", `"oidc flow"`),
		},

		// Redirect allowlist.
		{
			name:   "a protocol-relative allowlist entry",
			enable: with(httpsec.WithOIDCAllowedRedirects("//evil.example/app")),
			assert: refused("WithOIDCAllowedRedirects", "//evil.example/app"),
		},
		{
			name:   "an absolute entry on an undeclared origin",
			enable: with(httpsec.WithOIDCAllowedRedirects("https://evil.example/app")),
			assert: refused("WithOIDCAllowedRedirects", "https://evil.example/app"),
		},
		{
			name:   "a plain-http declared origin that is not loopback",
			enable: with(httpsec.WithOIDCAllowedOrigins("http://app.example.com")),
			assert: refused("WithOIDCAllowedOrigins", "http://app.example.com"),
		},

		// Conveyance and redemption.
		{
			name:   "a nil callback conveyance",
			enable: with(httpsec.WithCallbackSuccess(nil)),
			assert: refused("WithCallbackSuccess"),
		},
		{
			name:   "a nil handoff redeemer",
			enable: with(httpsec.WithHandoffRedeemer(nil)),
			assert: refused("WithHandoffRedeemer"),
		},
		{
			name:   "a handoff redeemer interface holding a nil pointer",
			enable: with(httpsec.WithHandoffRedeemer((*oidc.HandoffManager)(nil))),
			assert: refused("WithHandoffRedeemer"),
		},
		{
			name:   "a nil handoff limiter",
			enable: with(httpsec.WithHandoffLimiter(nil)),
			assert: refused("WithHandoffLimiter"),
		},
		{
			name:   "a handoff limiter interface holding a nil pointer",
			enable: with(httpsec.WithHandoffLimiter((*ratelimit.MemoryLimiter)(nil))),
			assert: refused("WithHandoffLimiter"),
		},
		{
			name:   "a zero handoff rate limit",
			enable: with(httpsec.WithHandoffRateLimit(0, time.Minute)),
			assert: refused("WithHandoffRateLimit"),
		},
		{
			name:   "a negative handoff rate limit",
			enable: with(httpsec.WithHandoffRateLimit(-1, time.Minute)),
			assert: refused("WithHandoffRateLimit"),
		},
		{
			name:   "a zero handoff rate window",
			enable: with(httpsec.WithHandoffRateLimit(10, 0)),
			assert: refused("WithHandoffRateLimit"),
		},
		{
			name:   "a negative handoff rate window",
			enable: with(httpsec.WithHandoffRateLimit(10, -time.Second)),
			assert: refused("WithHandoffRateLimit"),
		},
		{
			name: "a handoff manager given with the consumer conveyance",
			enable: func(f oidcFixture) httpsec.Option {
				return httpsec.EnableOIDCLogin(f.manager, f.handoffs,
					httpsec.WithOIDCSessions(f.sessions), conveyed)
			},
			assert: refused("EnableOIDCLogin", "WithCallbackSuccess", "handoff manager"),
		},
		{
			name:   "a handoff redeemer given with the consumer conveyance",
			enable: convey(httpsec.WithHandoffRedeemer(newTestHandoffManager(t))),
			assert: refused("WithHandoffRedeemer", "WithCallbackSuccess"),
		},
		{
			name:   "a handoff limiter given with the consumer conveyance",
			enable: convey(httpsec.WithHandoffLimiter(mustLimiter(t))),
			assert: refused("WithHandoffLimiter", "WithCallbackSuccess"),
		},
		{
			name:   "a handoff rate limit given with the consumer conveyance",
			enable: convey(httpsec.WithHandoffRateLimit(3, time.Minute)),
			assert: refused("WithHandoffRateLimit", "WithCallbackSuccess"),
		},
		{
			name:   "handoff refusal counting given with the consumer conveyance",
			enable: convey(httpsec.WithHandoffCountRefusals(false)),
			assert: refused("WithHandoffCountRefusals", "WithCallbackSuccess"),
		},
		{
			name:   "a handoff path given with the consumer conveyance",
			enable: convey(httpsec.WithOIDCHandoffPath("/login/oauth2/handoff-custom")),
			assert: refused("WithOIDCHandoffPath", "WithCallbackSuccess"),
		},

		// Logout.
		{
			name:   "an undefined back-channel logout scope",
			enable: with(httpsec.WithBackchannelLogoutScope(httpsec.BackchannelLogoutScope(7))),
			assert: refused("WithBackchannelLogoutScope"),
		},

		// Role sync.
		{
			name:    "role sync with the handoff conveyance",
			manager: syncingRoles,
			enable:  with(),
			assert:  refused("role sync", testOIDCProvider, "WithCallbackSuccess"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := oidcFixture{
				manager:  newTestOIDCManager(t),
				handoffs: newTestHandoffManager(t),
				tokens:   NewMockGenerator(gomock.NewController(t)),
				sessions: mustSessions(t),
			}
			if tc.manager != nil {
				f.manager = tc.manager(t)
			}

			c, err := httpsec.New(append([]httpsec.Option{tc.enable(f)}, tc.chain...)...)
			tc.assert(t, c, err)
		})
	}
}

// mustSessions builds an in-memory session manager.
func mustSessions(t *testing.T) *session.Manager {
	t.Helper()

	m, err := session.NewManager()
	require.NoError(t, err)

	return m
}

// mustLimiter builds an in-memory limiter.
func mustLimiter(t *testing.T) ratelimit.Limiter {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(5, time.Minute)
	require.NoError(t, err)

	return l
}
