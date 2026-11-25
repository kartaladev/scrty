package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// scopeRoute is one request through a chain whose resource server accepts every token as user u-1
// holding the scopes the case names, and what came back.
type scopeRoute struct {
	rec        *httptest.ResponseRecorder
	err        error
	handlerRan bool
}

// TestResourceServer_InsufficientScope pins how a missing scope is answered (design 14): an
// access-token caller refused by a chain rule or a guard gets 403 with exactly one challenge naming
// error="insufficient_scope" and the scopes the first refusing scope requirement names, under the
// scheme its token came under; the refusal is identifiable as the insufficient-scope refusal and
// still as the scope refusal and the access denial. A caller that is no access-token caller is
// answered as before: 403 with no challenge.
func TestResourceServer_InsufficientScope(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name string

		// dpop enables DPoP on the chain; bound makes the token bound to key and presented under
		// DPoP with a proof.
		dpop, bound bool

		// rule is the chain rule's requirement; guard is a guard's requirement instead.
		rule, guard authorize.Requirement

		// scopes are the token's.
		scopes []string

		// notAccessToken publishes a caller of its own ahead of the resource server, as an API key
		// or a session would, and presents no access token.
		notAccessToken bool

		// noChallenge builds the chain WithoutBearerChallenge.
		noChallenge bool

		// preset is a challenge something inside the chain already set on the response.
		preset string

		assert func(t *testing.T, out scopeRoute)
	}

	insufficient := func(want string) func(t *testing.T, out scopeRoute) {
		return func(t *testing.T, out scopeRoute) {
			t.Helper()
			assert.Equal(t, http.StatusForbidden, out.rec.Code)
			assert.Equal(t, []string{want}, out.rec.Header().Values("WWW-Authenticate"), "exactly one challenge")
			assert.False(t, out.handlerRan)

			if out.err != nil {
				assert.ErrorIs(t, out.err, httpsec.ErrInsufficientScope)
				assert.ErrorIs(t, out.err, authorize.ErrAccessDenied)
				assert.Equal(t, httpsec.ErrInsufficientScope.Error(), out.err.Error(),
					"fixed text, never the requirement's")

				var missing *authorize.MissingScopesError
				assert.ErrorAs(t, out.err, &missing)
			}
		}
	}

	cases := []testCase{
		{
			name:   "chain rule under DPoP names the scope and the algorithms",
			dpop:   true,
			bound:  true,
			rule:   authorize.HasAnyScope("orders:write"),
			scopes: []string{"orders:read"},
			assert: insufficient(`DPoP error="insufficient_scope", scope="orders:write", algs="ES256"`),
		},
		{
			name:   "chain rule under Bearer",
			rule:   authorize.HasAnyScope("orders:write"),
			scopes: []string{"orders:read"},
			assert: insufficient(`Bearer error="insufficient_scope", scope="orders:write"`),
		},
		{
			name:   "guard under Bearer names every scope of an all-of requirement",
			guard:  authorize.HasAllScopes("orders:read", "orders:export"),
			scopes: []string{"orders:read"},
			assert: insufficient(`Bearer error="insufficient_scope", scope="orders:read orders:export"`),
		},
		{
			name:   "guard under DPoP with DPoP optional",
			dpop:   true,
			bound:  true,
			guard:  authorize.HasAnyScope("orders:write"),
			scopes: []string{"orders:read"},
			assert: insufficient(`DPoP error="insufficient_scope", scope="orders:write", algs="ES256"`),
		},
		{
			name: "a composite names the first refusing scope requirement",
			rule: authorize.AnyOf(authorize.HasAnyScope("orders:write"),
				authorize.HasAllScopes("orders:admin", "orders:export")),
			scopes: []string{"orders:read"},
			assert: insufficient(`Bearer error="insufficient_scope", scope="orders:write"`),
		},
		{
			name:           "a caller that is no access-token caller gets 403 with no challenge, as before",
			rule:           authorize.HasAnyScope("orders:write"),
			notAccessToken: true,
			assert: func(t *testing.T, out scopeRoute) {
				assert.Equal(t, http.StatusForbidden, out.rec.Code)
				assert.Empty(t, out.rec.Header().Values("WWW-Authenticate"))
				require.Error(t, out.err)
				assert.ErrorIs(t, out.err, authorize.ErrAccessDenied)
				assert.NotErrorIs(t, out.err, httpsec.ErrInsufficientScope)
			},
		},
		{
			name:   "a DPoP caller's refusal adds no second challenge beside one already set",
			dpop:   true,
			bound:  true,
			rule:   authorize.HasAnyScope("orders:write"),
			scopes: []string{"orders:read"},
			preset: `Bearer realm="preset"`,
			assert: insufficient(`Bearer realm="preset"`),
		},
		{
			name:   "a scope that cannot be quoted unchanged leaves the scope parameter out",
			guard:  authorize.HasAnyScope(`orders"write`),
			scopes: []string{"orders:read"},
			assert: insufficient(`Bearer error="insufficient_scope"`),
		},
		{
			name:        "with the challenge turned off the refusal is the plain access denial",
			rule:        authorize.HasAnyScope("orders:write"),
			scopes:      []string{"orders:read"},
			noChallenge: true,
			assert: func(t *testing.T, out scopeRoute) {
				assert.Equal(t, http.StatusForbidden, out.rec.Code)
				assert.Empty(t, out.rec.Header().Values("WWW-Authenticate"))
				require.ErrorIs(t, out.err, authorize.ErrAccessDenied)
				assert.NotErrorIs(t, out.err, httpsec.ErrInsufficientScope)
			},
		},
		{
			name:   "a granted scope passes",
			guard:  authorize.HasAnyScope("orders:read"),
			scopes: []string{"orders:read"},
			assert: func(t *testing.T, out scopeRoute) {
				assert.Equal(t, http.StatusNoContent, out.rec.Code)
				assert.True(t, out.handlerRan)
				assert.Empty(t, out.rec.Header().Values("WWW-Authenticate"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := &httpsec.StubSource{
				Name: "provider", Provider: true, Unbound: !tc.bound, TokenScopes: tc.scopes,
				Verify: func(context.Context, string) (*identity.Principal, map[string]string, error) {
					var cnf map[string]string
					if tc.bound {
						cnf = map[string]string{"jkt": key.jkt}
					}

					return &identity.Principal{ID: "u-1", Kind: identity.KindUser}, cnf, nil
				},
			}

			out := scopeRoute{rec: httptest.NewRecorder()}

			rule := tc.rule
			if rule == nil {
				rule = authorize.PermitAll()
			}

			opts := []httpsec.Option{
				httpsec.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
					out.err = err
					w.WriteHeader(httpsec.StatusForError(err))
				}),
				httpsec.WithClock(clockwork.NewFakeClockAt(dpopNow)),
				httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"),
					httpsec.WithStubSource(src)),
				httpsec.EnableAuthorization(permittingAuthorizer(t), authorize.Rule[httpsec.Request]{
					Match:   func(httpsec.Request) bool { return true },
					Require: rule,
				}),
			}
			if tc.dpop {
				opts = append(opts, httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}))
			}

			if tc.noChallenge {
				opts = append(opts, httpsec.WithoutBearerChallenge())
			}

			if tc.preset != "" {
				opts = append(opts, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						ex.Writer.AddHeader("WWW-Authenticate", tc.preset)

						return next(ex)
					}), httpsec.OrderSecurityHeaders+2))
			}

			if tc.notAccessToken {
				opts = append(opts, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						ex.Authentication = &authenticate.Authentication{
							Principal: &identity.Principal{ID: "svc-1", Kind: identity.KindService},
						}
						ex.SetContext(httpsec.WithCaller(ex.Context(), ex.Authentication))

						return next(ex)
					}), httpsec.OrderAPIKey))
			}

			c, err := httpsec.New(opts...)
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/api/orders", nil)

			switch {
			case tc.notAccessToken:
			case tc.bound:
				req.Header.Set("Authorization", "DPoP "+rsToken)
				req.Header.Set("DPoP", key.validProof("j-scope").with(map[string]any{"ath": tokenHash(rsToken)}).sign(t))
			default:
				req.Header.Set("Authorization", "Bearer "+rsToken)
			}

			var route http.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				out.handlerRan = true
				w.WriteHeader(http.StatusNoContent)
			})

			if tc.guard != nil {
				guards, err := httpsec.NewGuards(permittingAuthorizer(t), httpsec.WithGuardErrorHandler(
					func(w http.ResponseWriter, _ *http.Request, err error) {
						out.err = err
						w.WriteHeader(httpsec.StatusForError(err))
					}))
				require.NoError(t, err)

				guarded, err := guards.Require(tc.guard)
				require.NoError(t, err)

				route = guarded(route)
			}

			c.Middleware()(route).ServeHTTP(out.rec, req)

			tc.assert(t, out)
		})
	}
}
