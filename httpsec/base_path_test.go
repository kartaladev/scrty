package httpsec_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// TestWithBasePath pins what building a chain does with a base path: the
// unusable ones are refused naming the option, a path that repeats the base is
// refused naming its own option and the doubled result, and the rest build.
// Where a base path moves each endpoint is the resolution step's business, and
// is pinned beside it.
func TestWithBasePath(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) (*httpsec.Chain, error)
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	keySet := func(t *testing.T, opts ...httpsec.JWKSOption) httpsec.Option {
		t.Helper()

		return httpsec.EnableJWKSEndpoint(NewMockKeySetProvider(gomock.NewController(t)), opts...)
	}

	withKeySet := func(base string) func(t *testing.T) (*httpsec.Chain, error) {
		return func(t *testing.T) (*httpsec.Chain, error) {
			return httpsec.New(keySet(t), httpsec.WithBasePath(base))
		}
	}

	refused := func(parts ...string) func(t *testing.T, c *httpsec.Chain, err error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, c, "a refused build returns no chain")

			for _, part := range parts {
				assert.ErrorContains(t, err, part)
			}
		}
	}

	built := func(t *testing.T, c *httpsec.Chain, err error) {
		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	cases := []testCase{
		{
			name:   "the root is refused",
			build:  withKeySet("/"),
			assert: refused("WithBasePath"),
		},
		{
			name:   "a relative path is refused",
			build:  withKeySet("auth"),
			assert: refused("WithBasePath"),
		},
		{
			name:   "a dot segment is refused",
			build:  withKeySet("/auth/../admin"),
			assert: refused("WithBasePath"),
		},
		{
			name:   "a path needing escaping is refused",
			build:  withKeySet("/auth%20x"),
			assert: refused("WithBasePath"),
		},
		{
			name:   "an empty path is refused",
			build:  withKeySet(""),
			assert: refused("WithBasePath"),
		},
		{
			name:   "one trailing slash is dropped",
			build:  withKeySet("/auth/"),
			assert: built,
		},
		{
			name: "a chain with no built-in endpoint is refused",
			build: func(*testing.T) (*httpsec.Chain, error) {
				return httpsec.New(httpsec.WithBasePath("/auth"))
			},
			assert: refused("WithBasePath"),
		},
		{
			name: "a chain with only non-endpoint built-ins is refused",
			build: func(*testing.T) (*httpsec.Chain, error) {
				return httpsec.New(httpsec.EnableSecurityHeaders(), httpsec.WithBasePath("/auth"))
			},
			assert: refused("WithBasePath"),
		},
		{
			// Bearer authentication and authorization answer no path of their
			// own, so a base path has nothing to move on this chain.
			name: "a chain with only bearer and authorization is refused",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				h := newRecoveryHarness(t)

				return httpsec.New(
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
						Verifier: h.tokens, Sessions: h.sessions, Users: h.users,
					}),
					httpsec.EnableAuthorization(permittingAuthorizer(t), authorize.Rule[httpsec.Request]{
						Match:   func(httpsec.Request) bool { return true },
						Require: authorize.PermitAll(),
					}),
					httpsec.WithBasePath("/auth"))
			},
			assert: refused("WithBasePath", "move nothing"),
		},
		{
			name: "a login path that repeats the base is refused, the base given last",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return newLoginGuardHarness(t).tryChain(t,
					[]httpsec.LoginOption{httpsec.WithLoginRequestPath("/auth/sign-in/password")}, nil,
					httpsec.WithBasePath("/auth"))
			},
			assert: refused("WithLoginRequestPath", "/auth/auth/sign-in/password"),
		},
		{
			name: "a login path given twice is judged and answered at its last value",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return newLoginGuardHarness(t).tryChain(t,
					[]httpsec.LoginOption{
						httpsec.WithLoginRequestPath("/auth/a"),
						httpsec.WithLoginRequestPath("/b"),
					}, nil,
					httpsec.WithBasePath("/auth"))
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err, "the replaced first path is not judged")
				require.NotNil(t, c)
				assert.True(t, answered(t, c, http.MethodPost, "/auth/b"), "the last path answers under the base")
				assert.False(t, answered(t, c, http.MethodPost, "/auth/auth/a"), "the replaced path answers nowhere")
			},
		},
		{
			name: "a login path given twice is refused when its last value repeats the base",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return newLoginGuardHarness(t).tryChain(t,
					[]httpsec.LoginOption{
						httpsec.WithLoginRequestPath("/b"),
						httpsec.WithLoginRequestPath("/auth/a"),
					}, nil,
					httpsec.WithBasePath("/auth"))
			},
			assert: refused("WithLoginRequestPath", "/auth/auth/a"),
		},
		{
			name: "a key set path that repeats the base is refused, the base given first",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(
					httpsec.WithBasePath("/auth"),
					keySet(t, httpsec.WithJWKSEndpointPath("/auth/keys")))
			},
			assert: refused("WithJWKSEndpointPath", "/auth/auth/keys"),
		},
		{
			name: "a path equal to the base is refused",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(
					httpsec.WithBasePath("/auth/"),
					keySet(t, httpsec.WithJWKSEndpointPath("/auth")))
			},
			assert: refused("WithJWKSEndpointPath", "/auth/auth"),
		},
		{
			name: "a path sharing only a string prefix with the base is not a repeat",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(
					keySet(t, httpsec.WithJWKSEndpointPath("/api-keys")),
					httpsec.WithBasePath("/api"))
			},
			assert: built,
		},
		{
			name: "a path outside the base is accepted",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(
					keySet(t, httpsec.WithJWKSEndpointPath("/keys")),
					httpsec.WithBasePath("/auth"))
			},
			assert: built,
		},
		{
			name: "given twice, the last one is judged and wins",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(
					keySet(t, httpsec.WithJWKSEndpointPath("/auth/keys")),
					httpsec.WithBasePath("auth"),
					httpsec.WithBasePath("/other"))
			},
			assert: built,
		},
		{
			name: "given twice, a bad last one is refused",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				return httpsec.New(
					keySet(t),
					httpsec.WithBasePath("/auth"),
					httpsec.WithBasePath("/"))
			},
			assert: refused("WithBasePath"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := tc.build(t)
			tc.assert(t, c, err)
		})
	}
}

// TestWithBasePath_RefusedWhenPasswordChangeGateAnswersNoEndpoint pins that the
// password-change gate counts as answering an endpoint only when the consumer
// gave it one. The gate alone answers no path, so a base path on a chain whose
// only built-in is that gate would move nothing and is refused; given its
// resolve endpoint, the gate answers a path the base path moves.
func TestWithBasePath_RefusedWhenPasswordChangeGateAnswersNoEndpoint(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.PasswordChangeOption
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	cases := []testCase{
		{
			name: "the gate without a resolve endpoint moves nothing",
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.ErrorContains(t, err, "WithBasePath")
			},
		},
		{
			name: "the gate with a resolve endpoint is moved",
			opts: []httpsec.PasswordChangeOption{
				httpsec.WithPasswordChangeEndpoint(testChangePasswordPath, func(*httpsec.Exchange) error { return nil }),
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.True(t, answered(t, c, http.MethodPost, "/auth"+testChangePasswordPath))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(
				httpsec.EnablePasswordChangeGate(must.Must(session.New()), tc.opts...),
				httpsec.WithBasePath("/auth"))
			tc.assert(t, c, err)
		})
	}
}

// TestWithBasePath_SharedPrefixServes pins where a key set whose path only
// shares a string prefix with the base answers: under the base followed by its
// own path, and nowhere else.
func TestWithBasePath_SharedPrefixServes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string
		wire   func(keys *MockKeySetProvider)
		assert func(t *testing.T, s served)
	}

	cases := []testCase{
		{
			name: "the key set answers at the base followed by its path",
			path: "/api/api-keys",
			wire: func(keys *MockKeySetProvider) {
				keys.EXPECT().JWKS(gomock.Any()).Return([]byte(publicKeySet), nil)
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.False(t, s.handlerRan)
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assert.Equal(t, "application/json", s.rec.Header().Get("Content-Type"))
				assert.JSONEq(t, publicKeySet, s.rec.Body.String())
			},
		},
		{
			name: "the path without the base passes through",
			path: "/api-keys",
			wire: func(*MockKeySetProvider) {},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan, "the key set does not answer outside the base")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := NewMockKeySetProvider(gomock.NewController(t))
			tc.wire(keys)

			chain, err := httpsec.New(
				httpsec.EnableJWKSEndpoint(keys, httpsec.WithJWKSEndpointPath("/api-keys")),
				httpsec.WithBasePath("/api"))
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, jwksRequest(t.Context(), http.MethodGet, tc.path)))
		})
	}
}
