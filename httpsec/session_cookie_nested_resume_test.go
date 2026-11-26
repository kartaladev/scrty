package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
)

// blankIDStore answers Load with the session's ID blanked once blank is set,
// a store breaking its contract.
type blankIDStore struct {
	session.Store
	blank atomic.Bool
}

func (s *blankIDStore) Load(ctx context.Context, id string) (*session.Session, error) {
	got, err := s.Store.Load(ctx, id)
	if err != nil || got == nil || !s.blank.Load() {
		return got, err
	}

	c := *got
	c.ID = ""

	return &c, nil
}

// errNestedRun is what a nested run's interceptor answers in a row that has
// the run fail.
var errNestedRun = errors.New("nested run failed")

// nestIn makes w serve through an outer chain built with opts, whose
// interceptor at order runs w's own chain on the same exchange and then
// continues the outer chain. The outer chain's refusals are recorded as w's.
func nestIn(t *testing.T, w *opFlow, order httpsec.Order, opts ...httpsec.Option) {
	t.Helper()

	inner := w.chain

	outer, err := httpsec.New(append([]httpsec.Option{
		httpsec.WithClock(w.clk),
		httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			return inner.Assemble(next)(ex)
		}), order),
		httpsec.WithErrorHandler(func(rw http.ResponseWriter, _ *http.Request, err error) {
			w.lastErr.Store(&err)
			rw.WriteHeader(httpsec.StatusForError(err))
		}),
	}, opts...)...)
	require.NoError(t, err)

	w.chain = outer
}

// outerCookieChain is the options of a plain cookie chain over w's sessions,
// with CSRF protection, as a consumer's application chain would be.
func outerCookieChain(w *opFlow) []httpsec.Option {
	return []httpsec.Option{
		httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users}),
		httpsec.EnableCSRFProtection(),
	}
}

// nestedRunThen is an interceptor, registered just after the cookie session
// publishes and before the provider's resume, that runs inner on the same
// exchange, discards whatever that run answered (a panic included), and
// continues the chain it stands in.
func nestedRunThen(inner func(ex *httpsec.Exchange) error) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		func() {
			defer func() { _ = recover() }()

			_ = inner(ex)
		}()

		return next(ex)
	}), httpsec.OrderSessionTouch+1)
}

// TestSessionCookie_NestedProviderChainResume pins that the cookie session's
// mark belongs to the chain that set it: a header-bearer provider chain run
// inside a cookie chain's request does not take the outer cookie sign-in at
// its resume; a nested chain's own cookie session marks its own sign-in; and
// after a nested run that completes, fails or panics the enclosing chain
// still holds its mark, so its provider still resumes with its cookie.
func TestSessionCookie_NestedProviderChainResume(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	// restored is a cookie chain running the provider whose consumer
	// interceptor runs, on the same exchange, a nested chain whose own
	// interceptor ends as step does; the provider's resume then answers.
	restored := func(t *testing.T, step func(ex *httpsec.Exchange, next httpsec.Next) error) {
		t.Helper()

		w, _, err := newCookieOP(t, func(setup *flowSetup) {
			setup.chain = func(t *testing.T, _ *opFlow) []httpsec.Option {
				t.Helper()

				nested, err := httpsec.New(httpsec.RegisterInterceptor(httpsec.InterceptorFunc(step), httpsec.OrderAuthorizer))
				require.NoError(t, err)

				return []httpsec.Option{nestedRunThen(nested.Assemble(func(*httpsec.Exchange) error { return nil }))}
			}
		})
		require.NoError(t, err)

		s := w.session(t, session.WithCSRFToken())
		handle, flow := w.park(t, flowFirstParty)

		resumedWithCode(t, w.cookieResume(t, handle, flow, s.ID, s.CSRFToken))
	}

	cases := []testCase{
		{
			name: "a header-bearer provider chain inside a cookie chain refuses the outer cookie sign-in",
			assert: func(t *testing.T) {
				t.Helper()

				w := newOPFlow(t, flowSetup{})
				nestIn(t, w, httpsec.OrderAuthorizer, outerCookieChain(w)...)

				s := w.session(t, session.WithCSRFToken())
				handle, flow := w.park(t, flowFirstParty)

				a := w.cookieResume(t, handle, flow, s.ID, s.CSRFToken)
				assert.Equal(t, http.StatusUnauthorized, a.status, a.body)
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				assert.Nil(t, a.cookie(flowSession), "no browser session is set")
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "the header-bearer provider chain's own bearer still resumes inside a cookie chain",
			assert: func(t *testing.T) {
				t.Helper()

				w := newOPFlow(t, flowSetup{})
				nestIn(t, w, httpsec.OrderAuthorizer, outerCookieChain(w)...)

				s := w.session(t)
				handle, flow := w.park(t, flowFirstParty)

				resumedWithCode(t, w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow)))
			},
		},
		{
			name: "a cookie provider chain inside a cookie chain resumes with its own cookie sign-in",
			assert: func(t *testing.T) {
				t.Helper()

				w, _, err := newCookieOP(t, nil)
				require.NoError(t, err)
				nestIn(t, w, httpsec.OrderAuthorizer, outerCookieChain(w)...)

				s := w.session(t, session.WithCSRFToken())
				handle, flow := w.park(t, flowFirstParty)

				resumedWithCode(t, w.cookieResume(t, handle, flow, s.ID, s.CSRFToken))
			},
		},
		{
			name: "a nested run that completes hands the cookie chain its mark back",
			assert: func(t *testing.T) {
				t.Helper()

				restored(t, func(ex *httpsec.Exchange, next httpsec.Next) error { return next(ex) })
			},
		},
		{
			name: "a nested run that fails hands the cookie chain its mark back",
			assert: func(t *testing.T) {
				t.Helper()

				restored(t, func(*httpsec.Exchange, httpsec.Next) error { return errNestedRun })
			},
		},
		{
			name: "a nested run that panics hands the cookie chain its mark back",
			assert: func(t *testing.T) {
				t.Helper()

				restored(t, func(*httpsec.Exchange, httpsec.Next) error { panic(errNestedRun) })
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t)
		})
	}
}

// composeAround is an interceptor at order that runs inner around the rest of
// the chain it stands in: inner's run continues into the next step, so
// everything after order runs inside inner's run.
func composeAround(inner *httpsec.Chain, order httpsec.Order) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		return inner.Assemble(next)(ex)
	}), order)
}

// TestSessionCookie_ComposedChainResume pins that the cookie session's mark
// belongs to the chain that set it, however chains are composed on one
// request: a header-bearer provider chain that runs a cookie chain around the
// rest of its own run does not take that cookie chain's sign-in at its resume,
// and a cookie chain running the provider keeps its own resume whether it runs
// another chain, a cookie chain on its own cookie included, around the rest of
// its run or another chain runs it. Each chain keeps its own mark: a composed
// cookie chain that publishes another session in place of this chain's is
// refused.
func TestSessionCookie_ComposedChainResume(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	// headerAroundCookie is a header-bearer provider chain whose interceptor at
	// order runs a cookie chain around the rest of its run; csrfOff builds both
	// without CSRF protection, the provider without browser sessions. The
	// cookie resume is refused, and the request stays parked.
	headerAroundCookie := func(t *testing.T, order httpsec.Order, csrfOff bool) {
		t.Helper()

		setup := flowSetup{
			noCSRF: csrfOff,
			chain: func(t *testing.T, w *opFlow) []httpsec.Option {
				t.Helper()

				cookieOpts := outerCookieChain(w)
				if csrfOff {
					cookieOpts = []httpsec.Option{cookieOpts[0], httpsec.WithoutCSRFProtection()}
				}

				cookie, err := httpsec.New(cookieOpts...)
				require.NoError(t, err)

				opts := []httpsec.Option{composeAround(cookie, order)}
				if csrfOff {
					opts = append(opts, httpsec.WithoutCSRFProtection())
				}

				return opts
			},
		}
		if csrfOff {
			setup.provider = []oidcprovider.Option{oidcprovider.WithoutBrowserSessions()}
		}

		w, err := newOPFlowErr(t, setup)
		require.NoError(t, err)

		s := w.session(t, session.WithCSRFToken())
		handle, flow := w.park(t, flowFirstParty)

		a := w.cookieResume(t, handle, flow, s.ID, s.CSRFToken)
		assert.Equal(t, http.StatusUnauthorized, a.status, a.body)
		require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
		flowUnspent(t, w, handle, flow)
	}

	// cookieResumes asserts that w, a cookie chain running the provider however
	// it is composed, resumes with its own cookie sign-in.
	cookieResumes := func(t *testing.T, w *opFlow) {
		t.Helper()

		s := w.session(t, session.WithCSRFToken())
		handle, flow := w.park(t, flowFirstParty)

		resumedWithCode(t, w.cookieResume(t, handle, flow, s.ID, s.CSRFToken))
	}

	cases := []testCase{
		{
			name: "a header-bearer provider chain running a cookie chain before its CSRF check refuses the cookie sign-in",
			assert: func(t *testing.T) {
				t.Helper()

				headerAroundCookie(t, httpsec.OrderCSRF-1, false)
			},
		},
		{
			name: "a header-bearer provider chain running a cookie chain after its session touch refuses the cookie sign-in",
			assert: func(t *testing.T) {
				t.Helper()

				headerAroundCookie(t, httpsec.OrderSessionTouch+1, false)
			},
		},
		{
			name: "a header-bearer provider chain without CSRF protection running a cookie chain refuses the cookie sign-in",
			assert: func(t *testing.T) {
				t.Helper()

				headerAroundCookie(t, httpsec.OrderSessionTouch+1, true)
			},
		},
		{
			name: "a header-bearer provider chain running a cookie chain refuses the cookie sign-in when the store returns a blank session identifier",
			assert: func(t *testing.T) {
				t.Helper()

				store := &blankIDStore{Store: must.Must(session.NewMemoryStore())}

				w, err := newOPFlowErr(t, flowSetup{
					sessions: []session.Option{session.WithStore(store)},
					chain: func(t *testing.T, w *opFlow) []httpsec.Option {
						t.Helper()

						cookie, err := httpsec.New(outerCookieChain(w)...)
						require.NoError(t, err)

						return []httpsec.Option{composeAround(cookie, httpsec.OrderSessionTouch+1)}
					},
				})
				require.NoError(t, err)

				s := w.session(t, session.WithCSRFToken())
				_, err = w.sessions.Load(t.Context(), s.ID) // record the first presentation
				require.NoError(t, err)
				store.blank.Store(true)

				handle, flow := w.park(t, flowFirstParty)

				a := w.cookieResume(t, handle, flow, s.ID, s.CSRFToken)
				assert.Equal(t, http.StatusUnauthorized, a.status, a.body)
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "a cookie provider chain running a plain chain around the rest of its run resumes with its cookie",
			assert: func(t *testing.T) {
				t.Helper()

				w, _, err := newCookieOP(t, func(setup *flowSetup) {
					setup.chain = func(t *testing.T, _ *opFlow) []httpsec.Option {
						t.Helper()

						plain, err := httpsec.New()
						require.NoError(t, err)

						return []httpsec.Option{composeAround(plain, httpsec.OrderSessionTouch+1)}
					}
				})
				require.NoError(t, err)

				cookieResumes(t, w)
			},
		},
		{
			name: "a cookie provider chain running a cookie chain on its cookie around the rest of its run resumes with its cookie",
			assert: func(t *testing.T) {
				t.Helper()

				w, _, err := newCookieOP(t, func(setup *flowSetup) {
					setup.chain = func(t *testing.T, w *opFlow) []httpsec.Option {
						t.Helper()

						app, err := httpsec.New(outerCookieChain(w)...)
						require.NoError(t, err)

						return []httpsec.Option{composeAround(app, httpsec.OrderSessionTouch+1)}
					}
				})
				require.NoError(t, err)

				cookieResumes(t, w)
			},
		},
		{
			name: "a cookie provider chain whose composed cookie chain publishes another session refuses that sign-in",
			assert: func(t *testing.T) {
				t.Helper()

				const otherCookie = "other-sid"

				w, _, err := newCookieOP(t, func(setup *flowSetup) {
					setup.chain = func(t *testing.T, w *opFlow) []httpsec.Option {
						t.Helper()

						other, err := httpsec.New(
							httpsec.EnableSessionCookie(
								httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users},
								httpsec.WithSessionCookieName(otherCookie),
							),
							httpsec.WithoutCSRFProtection(),
						)
						require.NoError(t, err)

						// The consumer's interceptor drops the sign-in this
						// chain's cookie published, and the CSRF judgement
						// with it, so the composed chain, which opts out of
						// CSRF protection, publishes the session its own
						// cookie names.
						return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
							func(ex *httpsec.Exchange, next httpsec.Next) error {
								ex.Session, ex.Authentication = nil, nil
								ex.SetContext(t.Context())

								return other.Assemble(next)(ex)
							}), httpsec.OrderSessionTouch+1)}
					}
				})
				require.NoError(t, err)

				own := w.session(t, session.WithCSRFToken())
				foreign := w.session(t)
				handle, flow := w.park(t, flowFirstParty)

				a := w.cookieResume(t, handle, flow, own.ID, own.CSRFToken, flowCookieOf(otherCookie, foreign.ID))
				assert.Equal(t, http.StatusUnauthorized, a.status, a.body)
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "a cookie provider chain run inside a plain chain resumes with its cookie",
			assert: func(t *testing.T) {
				t.Helper()

				w, _, err := newCookieOP(t, nil)
				require.NoError(t, err)
				nestIn(t, w, httpsec.OrderAuthorizer)

				cookieResumes(t, w)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t)
		})
	}
}
