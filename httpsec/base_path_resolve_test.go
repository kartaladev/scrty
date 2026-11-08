package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// nextHandlerHeader marks a response written by the handler behind the chain, so a
// request the chain answered is told from one it passed through.
const nextHandlerHeader = "X-Base-Path-Next"

// coreEndpoint is one built-in endpoint the base path moves, with the options
// that enable it on an otherwise complete chain.
type coreEndpoint struct {
	name string

	// method is the method the endpoint answers.
	method string

	// defaultPath is where it answers with no path of the consumer's. The
	// password-change endpoint has no default, so its own is given every time.
	defaultPath string

	// consumerPath is a path the consumer sets for it, without the base.
	consumerPath string

	// served is where consumerPath answers without a base. It differs from
	// consumerPath only where the setting drops a trailing slash.
	served string

	// options enables the endpoint with path, the default when path is "".
	options func(t *testing.T, path string) []httpsec.Option
}

// coreEndpoints lists the endpoints whose paths the resolution step resolves
// first: password sign-in, logout, the key set, session renewal, the
// password-change endpoint, the signal stream and session management.
func coreEndpoints() []coreEndpoint {
	return []coreEndpoint{
		{
			name:         "password sign-in",
			method:       http.MethodPost,
			defaultPath:  httpsec.DefaultLoginPath,
			consumerPath: "/signin",
			served:       "/signin",
			options: func(t *testing.T, path string) []httpsec.Option {
				h := newLoginGuardHarness(t)

				var opts []httpsec.LoginOption
				if path != "" {
					opts = append(opts, httpsec.WithLoginRequestPath(path))
				}

				return []httpsec.Option{httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
				}, opts...)}
			},
		},
		{
			name:         "logout",
			method:       http.MethodPost,
			defaultPath:  httpsec.DefaultLogoutPath,
			consumerPath: "/signout",
			served:       "/signout",
			options: func(_ *testing.T, path string) []httpsec.Option {
				var opts []httpsec.LogoutOption
				if path != "" {
					opts = append(opts, httpsec.WithLogoutRequestPath(path))
				}

				return []httpsec.Option{httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: must.Must(session.New())}, opts...)}
			},
		},
		{
			name:         "key set",
			method:       http.MethodGet,
			defaultPath:  httpsec.DefaultJWKSPath,
			consumerPath: "/keys",
			served:       "/keys",
			options: func(t *testing.T, path string) []httpsec.Option {
				keys := NewMockKeySetProvider(gomock.NewController(t))
				keys.EXPECT().JWKS(gomock.Any()).Return([]byte(`{"keys":[]}`), nil).AnyTimes()

				var opts []httpsec.JWKSOption
				if path != "" {
					opts = append(opts, httpsec.WithJWKSEndpointPath(path))
				}

				return []httpsec.Option{httpsec.EnableJWKSEndpoint(keys, opts...)}
			},
		},
		{
			name:         "session renewal",
			method:       http.MethodPost,
			defaultPath:  httpsec.DefaultSessionRenewalPath,
			consumerPath: "/renew",
			served:       "/renew",
			options: func(t *testing.T, path string) []httpsec.Option {
				h := newAuthHarness(t)

				var opts []httpsec.SessionRenewalOption
				if path != "" {
					opts = append(opts, httpsec.WithRenewalPath(path))
				}

				return []httpsec.Option{
					httpsec.EnableSessionBearer(h.sessionBearerDeps()),
					httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: h.sessions, Users: h.users}, opts...),
				}
			},
		},
		{
			name:         "password change",
			method:       http.MethodPost,
			defaultPath:  "/account/password",
			consumerPath: "/password",
			served:       "/password",
			options: func(_ *testing.T, path string) []httpsec.Option {
				if path == "" {
					path = "/account/password"
				}

				return []httpsec.Option{httpsec.EnablePasswordChangeGate(must.Must(session.New()),
					httpsec.WithPasswordChangeEndpoint(path, func(*httpsec.Exchange) error { return nil }))}
			},
		},
		{
			name:         "signal stream",
			method:       http.MethodGet,
			defaultPath:  httpsec.DefaultSessionSignalsPath,
			consumerPath: "/me/signals/",
			served:       "/me/signals/",
			options: func(t *testing.T, path string) []httpsec.Option {
				f := newConstructionFixture(t)

				return []httpsec.Option{f.bearer, httpsec.EnableSessionSignals(httpsec.SessionSignals{Path: path})}
			},
		},
		{
			name:         "session management",
			method:       http.MethodGet,
			defaultPath:  httpsec.DefaultSessionManagementPrefix,
			consumerPath: "/my-sessions/",
			served:       "/my-sessions",
			options: func(_ *testing.T, path string) []httpsec.Option {
				var opts []httpsec.SessionManagementOption
				if path != "" {
					opts = append(opts, httpsec.WithSessionManagementPrefix(path))
				}

				return []httpsec.Option{
					httpsec.WithSessions(must.Must(session.New())),
					httpsec.EnableSessionManagement(opts...),
				}
			},
		},
	}
}

// answered reports whether the chain answered method and path itself, rather
// than passing the request to the handler behind it.
func answered(t *testing.T, c *httpsec.Chain, method, path string) bool {
	t.Helper()

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(nextHandlerHeader, "1")
		w.WriteHeader(http.StatusTeapot)
	})

	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	rec := httptest.NewRecorder()
	c.Middleware()(next).ServeHTTP(rec, req)

	return rec.Header().Get(nextHandlerHeader) == ""
}

// TestBasePath_ResolvesCoreEndpoints pins where each of the first endpoints
// answers under a base path: at the base followed by its own path, the default
// or the consumer's, wherever the base path option stands among the others, and
// never at the path without the base.
func TestBasePath_ResolvesCoreEndpoints(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		endpoint coreEndpoint

		// path is the consumer's path for the endpoint, "" for its default.
		path string

		// before and after are the chain options given before and after the
		// endpoint's own.
		before, after []httpsec.Option

		assert func(t *testing.T, e coreEndpoint, c *httpsec.Chain, err error)
	}

	answersAt := func(at string, passes ...string) func(t *testing.T, e coreEndpoint, c *httpsec.Chain, err error) {
		return func(t *testing.T, e coreEndpoint, c *httpsec.Chain, err error) {
			require.NoError(t, err)
			require.NotNil(t, c)

			assert.True(t, answered(t, c, e.method, at), "%s %s is answered by the chain", e.method, at)

			for _, p := range passes {
				assert.False(t, answered(t, c, e.method, p), "%s %s passes through to the handler", e.method, p)
			}
		}
	}

	var cases []testCase

	for _, e := range coreEndpoints() {
		cases = append(cases,
			testCase{
				name:     e.name + ": no base path leaves the default where it was",
				endpoint: e,
				assert:   answersAt(e.defaultPath, "/auth"+e.defaultPath),
			},
			testCase{
				name:     e.name + ": no base path leaves the consumer's path where it was",
				endpoint: e,
				path:     e.consumerPath,
				assert:   answersAt(e.served, "/auth"+e.served),
			},
			testCase{
				name:     e.name + ": the base path given first moves the default",
				endpoint: e,
				before:   []httpsec.Option{httpsec.WithBasePath("/auth")},
				assert: answersAt("/auth"+e.defaultPath,
					e.defaultPath, "/authx"+e.defaultPath, "/Auth"+e.defaultPath, "/auth/auth"+e.defaultPath),
			},
			testCase{
				name:     e.name + ": the base path given last moves the default the same",
				endpoint: e,
				after:    []httpsec.Option{httpsec.WithBasePath("/auth")},
				assert: answersAt("/auth"+e.defaultPath,
					e.defaultPath, "/authx"+e.defaultPath, "/Auth"+e.defaultPath, "/auth/auth"+e.defaultPath),
			},
			testCase{
				name:     e.name + ": a base path with a trailing slash moves the default the same",
				endpoint: e,
				after:    []httpsec.Option{httpsec.WithBasePath("/auth/")},
				assert:   answersAt("/auth"+e.defaultPath, e.defaultPath, "/auth/"+e.defaultPath),
			},
			testCase{
				name:     e.name + ": the consumer's path answers within the base",
				endpoint: e,
				path:     e.consumerPath,
				before:   []httpsec.Option{httpsec.WithBasePath("/auth")},
				assert:   answersAt("/auth"+e.served, e.served, "/auth"+e.defaultPath),
			},
			testCase{
				name:     e.name + ": the consumer's path answers within the base given last",
				endpoint: e,
				path:     e.consumerPath,
				after:    []httpsec.Option{httpsec.WithBasePath("/auth")},
				assert:   answersAt("/auth"+e.served, e.served, "/auth"+e.defaultPath),
			},
			testCase{
				name:     e.name + ": given twice, the last base path moves it",
				endpoint: e,
				before:   []httpsec.Option{httpsec.WithBasePath("/a")},
				after:    []httpsec.Option{httpsec.WithBasePath("/b")},
				assert:   answersAt("/b"+e.defaultPath, "/a"+e.defaultPath, "/a/b"+e.defaultPath, e.defaultPath),
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := append([]httpsec.Option{}, tc.before...)
			opts = append(opts, tc.endpoint.options(t, tc.path)...)
			opts = append(opts, tc.after...)

			c, err := httpsec.New(opts...)
			tc.assert(t, tc.endpoint, c, err)
		})
	}
}
