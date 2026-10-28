package httpsec_test

import (
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// TestChain_LoginEnabledTwice pins that one chain has one form login and one
// Basic authentication: a second call is a configuration error naming the
// option, even when the second call is shaped differently (another path, its
// own limiter), because a chain that honoured both would run two guards over
// one endpoint set.
//
// Not rows of TestFormLoginConstruction: it builds on the login-guard harness.
func TestChain_LoginEnabledTwice(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T, h *loginGuardHarness) []httpsec.Option
		assert  func(t *testing.T, c *httpsec.Chain, err error)
	}

	formLogin := func(h *loginGuardHarness, opts ...httpsec.LoginOption) httpsec.Option {
		return httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
		}, opts...)
	}
	basicAuth := func(h *loginGuardHarness, opts ...httpsec.BasicAuthOption) httpsec.Option {
		return httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{
			Authenticator: h.authn, Attempts: h.attempts,
		}, opts...)
	}

	refusedTwice := func(option string) func(t *testing.T, c *httpsec.Chain, err error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), option, "the error names the option given twice")
			assert.Contains(t, err.Error(), "given twice")
			assert.Nil(t, c)
		}
	}

	cases := []testCase{
		{
			name: "form login twice",
			options: func(t *testing.T, h *loginGuardHarness) []httpsec.Option {
				return []httpsec.Option{
					formLogin(h, httpsec.WithLoginLimiter(memLimiter(t, 10, time.Minute))),
					formLogin(h,
						httpsec.WithLoginRequestPath("/admin/login"),
						httpsec.WithLoginLimiter(memLimiter(t, 5, time.Hour))),
				}
			},
			assert: refusedTwice("EnableFormLogin"),
		},
		{
			name: "Basic twice",
			options: func(t *testing.T, h *loginGuardHarness) []httpsec.Option {
				return []httpsec.Option{
					basicAuth(h, httpsec.WithBasicAuthLimiter(memLimiter(t, 10, time.Minute))),
					basicAuth(h,
						httpsec.WithBasicAuthRealm("admin"),
						httpsec.WithBasicAuthLimiter(memLimiter(t, 5, time.Hour))),
				}
			},
			assert: refusedTwice("EnableBasicAuth"),
		},
		{
			name: "each once",
			options: func(_ *testing.T, h *loginGuardHarness) []httpsec.Option {
				return []httpsec.Option{formLogin(h), basicAuth(h)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, c)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newLoginGuardHarness(t)

			c, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithLogger(slog.New(slog.DiscardHandler)),
			}, tc.options(t, h)...)...)
			tc.assert(t, c, err)
		})
	}
}

// rememberLifetime asks for 30 days when the login carries remember set to
// true (a JSON boolean) or "true" (a form value), and for nothing otherwise.
func rememberLifetime(_ *httpsec.Exchange, f httpsec.LoginFields) time.Duration {
	if v, _ := f.Value("remember"); v == true || v == "true" {
		return 30 * day
	}

	return 0
}

func TestFormLogin_Lifetime(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

	type testCase struct {
		name    string
		manager []session.Option
		opts    []httpsec.LoginOption
		req     func(t *testing.T) *http.Request
		// mockStore builds the manager over a mock store that expects no
		// Create, so a session created anyway fails the test.
		mockStore bool
		assert    func(t *testing.T, out served, s *session.Session)
	}

	remember := []httpsec.LoginOption{httpsec.WithLoginLifetime(rememberLifetime)}
	long := []session.Option{session.WithMaxAbsoluteLifetime(30 * day)}

	json := func(body string) func(*testing.T) *http.Request {
		return func(t *testing.T) *http.Request { return jsonRequest(t.Context(), "/login", body) }
	}
	form := func(body string) func(*testing.T) *http.Request {
		return func(t *testing.T) *http.Request { return formRequest(t.Context(), "/login", body) }
	}

	lives := func(d time.Duration) func(*testing.T, served, *session.Session) {
		return func(t *testing.T, out served, s *session.Session) {
			t.Helper()

			require.NoError(t, out.err)
			require.NotNil(t, s)
			assert.Equal(t, start.Add(d), s.AbsoluteExpiresAt)
		}
	}

	cases := []testCase{
		{
			name:   "no function gives the absolute timeout",
			req:    json(`{"username":"ada","password":"pw","remember":true}`),
			assert: lives(12 * time.Hour),
		},
		{
			name:    "a JSON boolean the function reads gives its lifetime",
			manager: long,
			opts:    remember,
			req:     json(`{"username":"ada","password":"pw","remember":true}`),
			assert:  lives(30 * day),
		},
		{
			name:    "a form value the function reads gives its lifetime",
			manager: long,
			opts:    remember,
			req:     form("username=ada&password=pw&remember=true"),
			assert:  lives(30 * day),
		},
		{
			name:    "a function returning nothing keeps the absolute timeout",
			manager: long,
			opts:    remember,
			req:     json(`{"username":"ada","password":"pw"}`),
			assert:  lives(12 * time.Hour),
		},
		{
			name:    "a function returning a negative lifetime keeps the absolute timeout",
			manager: long,
			opts: []httpsec.LoginOption{httpsec.WithLoginLifetime(
				func(*httpsec.Exchange, httpsec.LoginFields) time.Duration { return -time.Hour })},
			req:    json(`{"username":"ada","password":"pw"}`),
			assert: lives(12 * time.Hour),
		},
		{
			name:      "a lifetime above the lifetime maximum refuses the login and creates no session",
			opts:      remember,
			req:       json(`{"username":"ada","password":"pw","remember":true}`),
			mockStore: true,
			assert: func(t *testing.T, out served, s *session.Session) {
				require.ErrorIs(t, out.err, session.ErrConfig)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.Nil(t, s)
				assert.False(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			clk := clockwork.NewFakeClockAt(start)
			h := newAuthHarness(t)

			var store session.Store = session.NewMemoryStore(session.WithMemoryStoreClock(clk))
			if tc.mockStore {
				store = NewMockStore(ctrl) // no Create expected
			}

			var err error

			h.sessions, err = session.New(append([]session.Option{
				session.WithClock(clk),
				session.WithStore(store),
				session.WithAbsoluteTimeout(12 * time.Hour),
			}, tc.manager...)...)
			require.NoError(t, err)

			h.expectAuthenticated(testPrincipal())
			h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)

			if !tc.mockStore {
				h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("tok", nil)
			}

			var got *session.Session

			chain, err := httpsec.New(
				httpsec.WithClock(clk),
				httpsec.EnableFormLogin(h.formLoginDeps(), append(tc.opts,
					httpsec.WithLoginResponder(func(ex *httpsec.Exchange, r httpsec.LoginResult) error {
						got = r.Session
						ex.Writer.WriteHeader(http.StatusOK)

						return nil
					}))...),
			)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.req(t)), got)
		})
	}
}

// TestFormLoginConstruction pins that a login that could not work is refused
// before the chain exists, naming the option and the dependency at fault.
func TestFormLoginConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T, h *authHarness) []httpsec.Option
		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refused := func(names ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, chain, "a chain that cannot work must not exist to serve traffic")
			for _, name := range names {
				assert.Contains(t, err.Error(), name)
			}
		}
	}

	cases := []testCase{
		{
			name: "a fully wired login builds",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableFormLogin(h.formLoginDeps())}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, chain)
			},
		},
		{
			name: "no authenticator",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				d := h.formLoginDeps()
				d.Authenticator = nil

				return []httpsec.Option{httpsec.EnableFormLogin(d)}
			},
			assert: refused("EnableFormLogin", "authenticator"),
		},
		{
			name: "an authenticator holding a typed nil",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				d := h.formLoginDeps()
				d.Authenticator = (*MockAuthenticator)(nil)

				return []httpsec.Option{httpsec.EnableFormLogin(d)}
			},
			assert: refused("EnableFormLogin", "authenticator"),
		},
		{
			name: "no session manager",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				d := h.formLoginDeps()
				d.Sessions = nil

				return []httpsec.Option{httpsec.EnableFormLogin(d)}
			},
			assert: refused("EnableFormLogin", "session manager"),
		},
		{
			name: "no token generator",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				d := h.formLoginDeps()
				d.Tokens = nil

				return []httpsec.Option{httpsec.EnableFormLogin(d)}
			},
			assert: refused("EnableFormLogin", "token generator"),
		},
		{
			name: "no attempt store",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				d := h.formLoginDeps()
				d.Attempts = nil

				return []httpsec.Option{httpsec.EnableFormLogin(d)}
			},
			assert: refused("EnableFormLogin", "attempt store"),
		},
		{
			name: "a body limit of zero",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginBodyLimit(0)),
				}
			},
			assert: refused("WithLoginBodyLimit"),
		},
		{
			name: "a negative body limit",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginBodyLimit(-1)),
				}
			},
			assert: refused("WithLoginBodyLimit"),
		},
		{
			name: "an empty login path",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginRequestPath("")),
				}
			},
			assert: refused("WithLoginRequestPath"),
		},
		{
			name: "a missing field name",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginParams("email", "")),
				}
			},
			assert: refused("WithLoginParams"),
		},
		{
			name: "one field name for both credentials",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps(),
						httpsec.WithLoginParams("login", "login")),
				}
			},
			assert: refused("WithLoginParams"),
		},
		{
			name: "a nil responder",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginResponder(nil)),
				}
			},
			assert: refused("WithLoginResponder"),
		},
		{
			name: "with login lifetime nil function is refused",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginLifetime(nil))}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithLoginLifetime")
				assert.Nil(t, chain)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.build(t, newAuthHarness(t))...)
			tc.assert(t, chain, err)
		})
	}
}
