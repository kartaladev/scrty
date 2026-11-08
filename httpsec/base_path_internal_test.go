package httpsec

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// TestBasePath_Settled pins the value a base path settles as, which the public
// API does not expose: one trailing slash dropped, and the last option given
// winning.
func TestBasePath_Settled(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		given  []string
		assert func(t *testing.T, c *config, err error)
	}

	cases := []testCase{
		{
			name:  "none given settles as none",
			given: nil,
			assert: func(t *testing.T, c *config, err error) {
				require.NoError(t, err)
				assert.Empty(t, c.basePath)
			},
		},
		{
			name:  "a trailing slash is dropped",
			given: []string{"/auth/"},
			assert: func(t *testing.T, c *config, err error) {
				require.NoError(t, err)
				assert.Equal(t, "/auth", c.basePath)
			},
		},
		{
			name:  "the last one given wins",
			given: []string{"/a", "/b/"},
			assert: func(t *testing.T, c *config, err error) {
				require.NoError(t, err)
				assert.Equal(t, "/b", c.basePath)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := &config{}
			c.enable(optionOIDCProvider, func() error { return nil })

			for _, p := range tc.given {
				require.NoError(t, WithBasePath(p)(c))
			}

			tc.assert(t, c, c.settleBasePath())
		})
	}
}

// resolvedPaths is where each resolved built-in of a test configuration answers.
type resolvedPaths struct {
	logout, gatesLogout, management, passwordChange, signals string
}

// TestResolvePaths pins the resolution step's own guarantees, which the public
// API shows only indirectly: resolving is computed from the declared paths, so
// a second run cannot prefix twice; the logout path handed to the gates is the
// one logout answers; and the paths the base path's repeat check judges are the
// ones resolution places.
func TestResolvePaths(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []Option

		// runs is how many times resolution runs.
		runs   int
		assert func(t *testing.T, c *config, got resolvedPaths)
	}

	enabled := func(extra ...Option) []Option {
		sessions := must.Must(session.New())

		return append([]Option{
			EnableLogout(LogoutDeps{Sessions: sessions}),
			WithSessions(sessions),
			EnableSessionManagement(WithSessionManagementPrefix("/my-sessions/")),
			EnablePasswordChangeGate(sessions,
				WithPasswordChangeEndpoint("/password", func(*Exchange) error { return nil })),
			EnableSessionSignals(SessionSignals{}),
		}, extra...)
	}

	cases := []testCase{
		{
			name: "with no base path every built-in answers where it was declared",
			opts: enabled(),
			runs: 1,
			assert: func(t *testing.T, _ *config, got resolvedPaths) {
				assert.Equal(t, resolvedPaths{
					logout: DefaultLogoutPath, gatesLogout: DefaultLogoutPath, management: "/my-sessions",
					passwordChange: "/password", signals: DefaultSessionSignalsPath,
				}, got)
			},
		},
		{
			name: "every built-in answers under the base path, and the gates exempt the moved logout",
			opts: enabled(WithBasePath("/auth/")),
			runs: 1,
			assert: func(t *testing.T, _ *config, got resolvedPaths) {
				assert.Equal(t, resolvedPaths{
					logout: "/auth/sign-out", gatesLogout: "/auth/sign-out", management: "/auth/my-sessions",
					passwordChange: "/auth/password", signals: "/auth/session/signals",
				}, got)
			},
		},
		{
			name: "resolving twice does not prefix twice",
			opts: enabled(WithBasePath("/auth")),
			runs: 2,
			assert: func(t *testing.T, _ *config, got resolvedPaths) {
				assert.Equal(t, resolvedPaths{
					logout: "/auth/sign-out", gatesLogout: "/auth/sign-out", management: "/auth/my-sessions",
					passwordChange: "/auth/password", signals: "/auth/session/signals",
				}, got)
			},
		},
		{
			name: "a path the repeat check judges is the path resolution places",
			opts: enabled(WithBasePath("/auth")),
			runs: 1,
			assert: func(t *testing.T, c *config, _ resolvedPaths) {
				judged := 0

				require.NoError(t, eachInterceptor(c, func(d pathDeclarer) error {
					for _, p := range d.declaredPaths() {
						judged++

						assert.True(t, c.answersAt("/auth"+strings.TrimSuffix(p.path, "/")),
							"%s's %q is answered under the base", p.setting, p.path)
					}

					return nil
				}))

				assert.Equal(t, 2, judged, "the management prefix and the password-change path were declared")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := &config{}
			for _, opt := range tc.opts {
				require.NoError(t, opt(c))
			}

			require.NoError(t, c.settleBasePath())

			for range tc.runs {
				c.resolvePaths()
			}

			var got resolvedPaths

			got.logout = c.logout.path
			got.gatesLogout = c.logoutPath

			_ = eachInterceptor(c, func(m *sessionManagement) error { got.management = m.prefix; return nil })
			_ = eachInterceptor(c, func(g *passwordChangeGate) error { got.passwordChange = g.path; return nil })
			_ = eachInterceptor(c, func(e *sessionSignals) error { got.signals = e.path; return nil })

			tc.assert(t, c, got)
		})
	}
}

// answersAt reports whether a resolved built-in of the test configuration
// answers at p.
func (c *config) answersAt(p string) bool {
	found := false

	_ = eachInterceptor(c, func(m *sessionManagement) error { found = found || m.prefix == p; return nil })
	_ = eachInterceptor(c, func(g *passwordChangeGate) error { found = found || g.path == p; return nil })

	return found
}
