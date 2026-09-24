package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// errLookupFailed is the internal fault a refusal must not repeat to a client.
// Its text names a host and a port on purpose: that is what leaks.
var errLookupFailed = errors.New("connection refused to db-primary:5432")

// upstreamKey is what a middleware outside the chain put on the request before
// the chain ever saw it.
type upstreamKey struct{}

// mounted is what serving one request through a chain's middleware produced.
type mounted struct {
	rec *httptest.ResponseRecorder

	handlerRan bool

	// handlerCtx is the context the downstream handler read through
	// r.Context(), and nil when the handler was never reached.
	handlerCtx context.Context //nolint:containedctx // captured for assertions, never used to call anything
}

// publishing is an interceptor that resolves a request the way an
// authenticating one would, so a test can pin what the handler behind the
// middleware reads without standing up a whole first factor.
func publishing(p *identity.Principal, s *session.Session) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		ctx := ex.Context()
		if p != nil {
			ctx = identity.WithPrincipal(ctx, p)
		}
		if s != nil {
			ctx = httpsec.WithSession(ctx, s)
			ex.Session = s
		}
		ex.SetContext(ctx)

		return next(ex)
	})
}

// refusing is an interceptor that refuses every request with err, after running
// act so a test can have it commit headers or a status first.
func refusing(err error, act func(ex *httpsec.Exchange)) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
		if act != nil {
			act(ex)
		}

		return err
	})
}

// mount runs req through chain.Middleware in front of a handler that records
// that it was reached and what context it read.
func mount(t *testing.T, chain *httpsec.Chain, req *http.Request) mounted {
	t.Helper()

	out := mounted{rec: httptest.NewRecorder()}
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		out.handlerRan = true
		out.handlerCtx = r.Context()
	})

	chain.Middleware()(handler).ServeHTTP(out.rec, req)

	return out
}

// TestMiddleware pins what the net/http entrypoint hands the handler: what the
// chain resolved, what was already on the request, and the client's own
// cancellation.
func TestMiddleware(t *testing.T) {
	t.Parallel()

	principal := testPrincipal()
	live := touchableSession()

	type testCase struct {
		name string

		// chain builds what the request is mounted behind, and nil means the
		// stand-in interceptor that publishes principal and live directly.
		chain func(t *testing.T) *httpsec.Chain

		// request is what is sent, and nil means a plain GET of a route.
		request func(ctx context.Context) *http.Request

		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, out mounted)
	}

	cases := []testCase{
		{
			name: "the principal and the session reach the handler",
			assert: func(t *testing.T, out mounted) {
				require.True(t, out.handlerRan)

				p, ok := identity.PrincipalFromContext(out.handlerCtx)
				require.True(t, ok, "the handler reads the caller through r.Context()")
				assert.Same(t, principal, p)

				s, ok := httpsec.SessionFromContext(out.handlerCtx)
				require.True(t, ok)
				assert.Same(t, live, s)
			},
		},
		{
			name: "a first factor's own principal reaches the handler",
			chain: func(t *testing.T) *httpsec.Chain {
				t.Helper()

				h := newAuthHarness(t)
				h.expectAuthenticated(testPrincipal())

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBasicAuth(h.basicAuthDeps()))
				require.NoError(t, err)

				return chain
			},
			request: func(ctx context.Context) *http.Request {
				return basicRequest(ctx, "ada", "s3cret")
			},
			assert: func(t *testing.T, out mounted) {
				require.True(t, out.handlerRan)

				p, ok := identity.PrincipalFromContext(out.handlerCtx)
				require.True(t, ok,
					"a handler behind a first factor reads the caller, not only the event")
				assert.Equal(t, identity.UserID("u-1"), p.ID)

				auth, ok := authenticate.AuthenticationFromContext(out.handlerCtx)
				require.True(t, ok)
				assert.Same(t, p, auth.Principal,
					"the two answer different questions about one caller, so they agree")
			},
		},
		{
			name: "an upstream request identifier survives the chain",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, upstreamKey{}, "r-1")
			},
			assert: func(t *testing.T, out mounted) {
				require.True(t, out.handlerRan)
				assert.Equal(t, "r-1", out.handlerCtx.Value(upstreamKey{}),
					"the chain derives the context it was seeded with, never replaces it")
			},
		},
		{
			name: "the client's cancellation reaches the handler",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, out mounted) {
				require.True(t, out.handlerRan)
				require.ErrorIs(t, out.handlerCtx.Err(), context.Canceled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain := tc.chain
			if chain == nil {
				chain = func(t *testing.T) *httpsec.Chain {
					t.Helper()

					c, err := httpsec.New(httpsec.RegisterInterceptor(
						publishing(principal, live), httpsec.OrderBearerToken))
					require.NoError(t, err)

					return c
				}
			}

			request := tc.request
			if request == nil {
				request = func(ctx context.Context) *http.Request {
					return httptest.NewRequestWithContext(ctx, http.MethodGet, "/records", nil)
				}
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			tc.assert(t, mount(t, chain(t), request(ctx)))
		})
	}
}

// TestDefaultErrorResponse pins the fail-closed default: the mapped status,
// nothing in the body, and whatever the refusing interceptor had already set.
func TestDefaultErrorResponse(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		stage  httpsec.Interceptor
		assert func(t *testing.T, out mounted)
	}

	cases := []testCase{
		{
			name:  "an unauthenticated request",
			stage: refusing(httpsec.ErrAuthenticationRequired, nil),
			assert: func(t *testing.T, out mounted) {
				assert.Equal(t, http.StatusUnauthorized, out.rec.Code)
				assert.Empty(t, out.rec.Body.String())
				assert.False(t, out.handlerRan)
			},
		},
		{
			name:  "internal error text is withheld",
			stage: refusing(errLookupFailed, nil),
			assert: func(t *testing.T, out mounted) {
				assert.Equal(t, http.StatusInternalServerError, out.rec.Code)
				assert.Empty(t, out.rec.Body.String())
				assert.NotContains(t, out.rec.Body.String(), "connection refused")
				assert.NotContains(t, out.rec.Body.String(), "db-primary")
				assert.False(t, out.handlerRan)
			},
		},
		{
			name: "a challenge header set before refusing is kept",
			stage: refusing(httpsec.ErrAuthenticationRequired, func(ex *httpsec.Exchange) {
				ex.Writer.SetHeader("WWW-Authenticate", `Basic realm="Restricted"`)
			}),
			assert: func(t *testing.T, out mounted) {
				assert.Equal(t, http.StatusUnauthorized, out.rec.Code)
				assert.Equal(t, `Basic realm="Restricted"`,
					out.rec.Header().Get("WWW-Authenticate"))
				assert.Empty(t, out.rec.Body.String())
			},
		},
		{
			name: "an interceptor that already answered is not overwritten",
			stage: refusing(errLookupFailed, func(ex *httpsec.Exchange) {
				ex.Writer.WriteHeader(http.StatusTeapot)
			}),
			assert: func(t *testing.T, out mounted) {
				assert.Equal(t, http.StatusTeapot, out.rec.Code,
					"the status an interceptor chose survives the refusal behind it")
				assert.Empty(t, out.rec.Body.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(
				httpsec.RegisterInterceptor(tc.stage, httpsec.OrderBearerToken))
			require.NoError(t, err)

			tc.assert(t, mount(t, chain,
				httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/records", nil)))
		})
	}
}

// TestConsumerErrorHandler pins that a consumer's handler replaces the default
// outright, rather than being written over it.
func TestConsumerErrorHandler(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		refuse error
		render func(w http.ResponseWriter, r *http.Request, err error)
		assert func(t *testing.T, out mounted, seen error)
	}

	cases := []testCase{
		{
			name:   "a consumer renders a JSON body",
			refuse: authorize.ErrAccessDenied,
			render: func(w http.ResponseWriter, _ *http.Request, err error) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(httpsec.StatusForError(err))
				_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			},
			assert: func(t *testing.T, out mounted, seen error) {
				require.ErrorIs(t, seen, authorize.ErrAccessDenied,
					"the propagated refusal reaches the consumer's handler")
				assert.Equal(t, http.StatusForbidden, out.rec.Code)
				assert.JSONEq(t, `{"error":"forbidden"}`, out.rec.Body.String())
			},
		},
		{
			name:   "the default is not also written",
			refuse: authorize.ErrAccessDenied,
			render: func(w http.ResponseWriter, _ *http.Request, _ error) {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte("mine"))
			},
			assert: func(t *testing.T, out mounted, _ error) {
				assert.Equal(t, http.StatusConflict, out.rec.Code,
					"the library's own status was not written over the consumer's")
				assert.Equal(t, "mine", out.rec.Body.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var seen error

			chain, err := httpsec.New(
				httpsec.RegisterInterceptor(refusing(tc.refuse, nil), httpsec.OrderBearerToken),
				httpsec.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
					seen = err
					tc.render(w, r, err)
				}),
			)
			require.NoError(t, err)

			out := mount(t, chain,
				httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/records", nil))

			assert.False(t, out.handlerRan)
			tc.assert(t, out, seen)
		})
	}
}

// TestGuardErrorHandler pins the same contract at a guard: the consumer's
// handler replaces the default, and the default agrees with the public table.
func TestGuardErrorHandler(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(seen *error) []httpsec.GuardOption
		assert func(t *testing.T, run guardRun, seen error)
	}

	cases := []testCase{
		{
			name: "a consumer handler receives the guard's refusal",
			opts: func(seen *error) []httpsec.GuardOption {
				return []httpsec.GuardOption{
					httpsec.WithGuardErrorHandler(
						func(w http.ResponseWriter, _ *http.Request, err error) {
							*seen = err
							w.WriteHeader(http.StatusConflict)
						}),
				}
			},
			assert: func(t *testing.T, run guardRun, seen error) {
				require.ErrorIs(t, seen, authorize.ErrInvalidAttributes)
				assert.Equal(t, http.StatusConflict, run.rec.Code,
					"the guard's own default was not written over the consumer's")
			},
		},
		{
			name: "a guard with no handler agrees with the table",
			opts: func(*error) []httpsec.GuardOption { return nil },
			assert: func(t *testing.T, run guardRun, _ error) {
				// Deliberate: invalid attributes come from a misbuilt guard, not
				// from the client, so the table's 500 stands and the guard does
				// not answer 400 from a switch of its own.
				assert.Equal(t, http.StatusInternalServerError, run.rec.Code)
				assert.Empty(t, run.rec.Body.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var seen error

			misbuilt := refusingAuthorizer(t, authorize.ErrInvalidAttributes)
			g := httpsec.NewGuards(misbuilt, tc.opts(&seen)...)

			run := runGuard(t, g.ResourcePrivileges("admin", "user").RequireOne("read"),
				guardRequest(t, testPrincipal(), nil))

			assert.False(t, run.routeRan)
			tc.assert(t, run, seen)
		})
	}
}

// TestNewRefusesRefusalPathWiring pins that the two ways a chain can be left
// unable to judge or to answer a refusal are faults at construction, not
// surprises at the first request.
func TestNewRefusesRefusalPathWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "authorization with no authorizer",
			opts: []httpsec.Option{httpsec.EnableAuthorization(nil)},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "EnableAuthorization")
				assert.Contains(t, err.Error(), "authorizer")
			},
		},
		{
			name: "an error handler that is not there",
			opts: []httpsec.Option{httpsec.WithErrorHandler(nil)},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithErrorHandler")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.opts...)
			assert.Nil(t, chain, "a chain that cannot answer a refusal must not exist")
			tc.assert(t, err)
		})
	}
}
