package httpsec_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/token"
)

// challengeRoute is the consumer's protected route the bearer-challenge tests request.
const challengeRoute = "http://example.com/api"

// refuseUnauthenticated is a consumer interceptor that refuses a request nothing
// authenticated, as a consumer's own access rule would.
func refuseUnauthenticated() httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
		func(ex *httpsec.Exchange, next httpsec.Next) error {
			if ex.Authentication == nil {
				return httpsec.ErrAuthenticationRequired
			}

			return next(ex)
		}), httpsec.OrderAuthorizer)
}

// refuseAlways is a consumer interceptor that refuses every request with err.
func refuseAlways(err error) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
		func(*httpsec.Exchange, httpsec.Next) error { return err }), httpsec.OrderAuthorizer)
}

// TestBearerChallenge pins the challenge a 401 carries on a chain with a built-in bearer,
// at a consumer's route, run as net/http middleware.
func TestBearerChallenge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// opts are the chain's options beside the clock and logger; bearer adds the
		// world's signed bearer.
		opts   func(w *dpopBearerWorld) []httpsec.Option
		bearer bool
		// guard puts RequireAuthenticated behind the chain.
		guard bool
		// credential is the Authorization line the request presents, none when empty.
		credential func(t *testing.T, w *dpopBearerWorld) string
		// request changes the request beside its credential.
		request func(req *http.Request)
		assert  func(t *testing.T, rec *httptest.ResponseRecorder)
	}

	challenged := func(challenges ...string) func(*testing.T, *httptest.ResponseRecorder) {
		return func(t *testing.T, rec *httptest.ResponseRecorder) {
			t.Helper()

			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Equal(t, challenges, rec.Header().Values("WWW-Authenticate"))
		}
	}

	// expired is a Bearer line with a token of u-1's whose lifetime has passed.
	expired := func(t *testing.T, w *dpopBearerWorld) string {
		t.Helper()

		tok := w.token(token.Confirmation{})
		w.clk.Advance(2 * time.Hour)

		return "Bearer " + tok
	}

	valid := func(t *testing.T, w *dpopBearerWorld) string {
		t.Helper()

		return "Bearer " + w.token(token.Confirmation{})
	}

	cases := []testCase{
		{
			name:       "an expired bearer token: one Bearer invalid_token",
			bearer:     true,
			credential: expired,
			assert:     challenged(`Bearer error="invalid_token"`),
		},
		{
			name:   "no credential, refused by the consumer's interceptor: Bearer with no code",
			bearer: true,
			opts:   func(*dpopBearerWorld) []httpsec.Option { return []httpsec.Option{refuseUnauthenticated()} },
			assert: challenged("Bearer"),
		},
		{
			name:   "no credential, refused by a guard behind the chain: Bearer with no code",
			bearer: true,
			guard:  true,
			assert: challenged("Bearer"),
		},
		{
			name:   "a valid token the consumer refuses later: Bearer with no code",
			bearer: true,
			opts: func(*dpopBearerWorld) []httpsec.Option {
				return []httpsec.Option{refuseAlways(httpsec.ErrAuthenticationRequired)}
			},
			credential: valid,
			assert:     challenged("Bearer"),
		},
		{
			name: "an expired token under a consumer's own scheme: Bearer with no code",
			opts: func(w *dpopBearerWorld) []httpsec.Option { return []httpsec.Option{customSchemeBearer(w)} },
			credential: func(t *testing.T, w *dpopBearerWorld) string {
				t.Helper()

				tok := w.token(token.Confirmation{})
				w.clk.Advance(2 * time.Hour)

				return "Token " + tok
			},
			assert: challenged("Bearer"),
		},
		{
			name:   "an expired token with DPoP on: DPoP's challenge, beside Bearer",
			bearer: true,
			opts: func(*dpopBearerWorld) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL})}
			},
			credential: expired,
			assert:     challenged(`DPoP algs="ES256"`, "Bearer"),
		},
		{
			name:   "an expired token with DPoP required: DPoP's challenge alone",
			bearer: true,
			opts: func(*dpopBearerWorld) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL, Require: true})}
			},
			credential: func(t *testing.T, w *dpopBearerWorld) string {
				t.Helper()

				tok := w.token(token.Confirmation{})
				w.clk.Advance(2 * time.Hour)

				return "DPoP " + tok
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusUnauthorized, rec.Code)
				values := rec.Header().Values("WWW-Authenticate")
				require.Len(t, values, 1, "one challenge")
				assert.Contains(t, values[0], "DPoP ")
			},
		},
		{
			name:       "WithoutBearerChallenge: no challenge",
			bearer:     true,
			opts:       func(*dpopBearerWorld) []httpsec.Option { return []httpsec.Option{httpsec.WithoutBearerChallenge()} },
			credential: expired,
			assert:     challenged(),
		},
		{
			name:   "a chain with no built-in bearer: no challenge",
			opts:   func(*dpopBearerWorld) []httpsec.Option { return []httpsec.Option{refuseUnauthenticated()} },
			assert: challenged(),
		},
		{
			// The chain authenticates by session cookie alone: the library registers no
			// challenge, whatever scheme the consumer's own interceptor reads.
			name: "a chain with session cookies and no built-in bearer: 401 with no challenge",
			opts: func(w *dpopBearerWorld) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithSessions(w.sessions),
					httpsec.WithoutCSRFProtection(),
					httpsec.RegisterInterceptor(consumerSessionCookie{sessions: w.sessions}, httpsec.OrderBearerToken),
				}
			},
			request: withSignalsCookie("an-unknown-session"),
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusUnauthorized, rec.Code)
				assert.Empty(t, rec.Header().Values("WWW-Authenticate"), "the library sets none")
			},
		},
		{
			name:   "a refusal that is not a 401: no challenge",
			bearer: true,
			opts: func(*dpopBearerWorld) []httpsec.Option {
				return []httpsec.Option{refuseAlways(authorize.ErrAccessDenied)}
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusForbidden, rec.Code)
				assert.Empty(t, rec.Header().Values("WWW-Authenticate"))
			},
		},
		{
			name:   "the consumer's error handler sets its own Bearer challenge: it is the only one",
			bearer: true,
			opts: func(*dpopBearerWorld) []httpsec.Option {
				return []httpsec.Option{httpsec.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
					w.Header().Set("WWW-Authenticate", `Bearer realm="x"`)
					w.WriteHeader(httpsec.StatusForError(err))
				})}
			},
			credential: expired,
			assert:     challenged(`Bearer realm="x"`),
		},
		{
			name:   "a consumer's interceptor that set its own Bearer challenge: it is the only one",
			bearer: true,
			opts: func(*dpopBearerWorld) []httpsec.Option {
				return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, _ httpsec.Next) error {
						ex.Writer.AddHeader("WWW-Authenticate", `Bearer realm="x"`)

						return httpsec.ErrAuthenticationRequired
					}), httpsec.OrderAuthorizer)}
			},
			assert: challenged(`Bearer realm="x"`),
		},
		{
			name:   "DPoP optional, a consumer's interceptor set its own Bearer challenge: one Bearer, and DPoP's",
			bearer: true,
			opts: func(*dpopBearerWorld) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}),
					httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
						func(ex *httpsec.Exchange, _ httpsec.Next) error {
							ex.Writer.AddHeader("WWW-Authenticate", `Bearer realm="x"`)

							return httpsec.ErrAuthenticationRequired
						}), httpsec.OrderAuthorizer),
				}
			},
			assert: challenged(`Bearer realm="x"`, `DPoP algs="ES256"`),
		},
		{
			name:   "DPoP required, a consumer's interceptor set its own DPoP challenge: one DPoP",
			bearer: true,
			opts: func(*dpopBearerWorld) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL, Require: true}),
					httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
						func(ex *httpsec.Exchange, _ httpsec.Next) error {
							ex.Writer.AddHeader("WWW-Authenticate", `DPoP realm="x"`)

							return httpsec.ErrAuthenticationRequired
						}), httpsec.OrderAuthorizer),
				}
			},
			assert: challenged(`DPoP realm="x"`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newDPoPBearerWorld(t)

			opts := []httpsec.Option{httpsec.WithClock(w.clk), httpsec.WithLogger(slog.New(slog.DiscardHandler))}
			if tc.bearer {
				opts = append(opts, httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Verifier: w.gen, Sessions: w.sessions, Users: w.users,
				}))
			}

			if tc.opts != nil {
				opts = append(opts, tc.opts(w)...)
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			var route http.Handler = http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				rw.WriteHeader(http.StatusNoContent)
			})
			if tc.guard {
				route = mustGuards(t, NewMockAuthorizer(gomock.NewController(t))).RequireAuthenticated()(route)
			}

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, challengeRoute, nil)
			if tc.credential != nil {
				req.Header.Set("Authorization", tc.credential(t, w))
			}

			if tc.request != nil {
				tc.request(req)
			}

			rec := httptest.NewRecorder()
			chain.Middleware()(route).ServeHTTP(rec, req)

			tc.assert(t, rec)
		})
	}
}

// customSchemeBearer is the world's signed bearer reading the Token scheme alone.
func customSchemeBearer(w *dpopBearerWorld) httpsec.Option {
	return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: w.gen, Sessions: w.sessions, Users: w.users},
		httpsec.WithBearerScheme("Token"))
}

// TestWithoutBearerChallenge_RefusedWithoutBearer pins that the opt-out on a chain with no
// built-in bearer, which has no challenge to turn off, fails construction.
func TestWithoutBearerChallenge_RefusedWithoutBearer(t *testing.T) {
	t.Parallel()

	_, err := httpsec.New(httpsec.WithoutBearerChallenge())
	require.ErrorIs(t, err, httpsec.ErrConfig)
	assert.Contains(t, err.Error(), "WithoutBearerChallenge")
}
