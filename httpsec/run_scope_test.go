package httpsec

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// This file is an internal test: what a run leaves on an exchange includes
// unexported fields, which no exported accessor reads.

// scopeView is what a run may change on an exchange, as one comparable value.
// The late-renewal funcs are not comparable, so only whether each is set is
// kept.
type scopeView struct {
	ctx              context.Context //nolint:containedctx // the view records which context the exchange held
	session          *session.Session
	authentication   *authenticate.Authentication
	bearerCredential string
	renewal          string
	chargeRenewal    bool
	admitRenewal     bool
	perRequest       *perRequestPhase
	csrfOptOut       bool
	raised           policy.ChallengeKind
}

func viewOf(ex *Exchange) scopeView {
	return scopeView{
		ctx:              ex.ctx,
		session:          ex.Session,
		authentication:   ex.Authentication,
		bearerCredential: ex.bearerCredential,
		renewal:          ex.renewal,
		chargeRenewal:    ex.chargeRenewal != nil,
		admitRenewal:     ex.admitRenewal != nil,
		perRequest:       ex.perRequest,
		csrfOptOut:       ex.csrfOptOut,
		raised:           ex.raised,
	}
}

// scopeOutcome is what one case observed. before and after are read by the
// interceptor of the chain one level out, around the step of the chain one
// level in; during is read inside the innermost chain's interceptor, once it
// has changed the exchange. Level 0 is the outermost pair.
type scopeOutcome struct {
	before, after []scopeView
	during        scopeView
	panicked      any
	err           error

	// callerBefore and callerAfter are read by the caller, around the
	// outermost step.
	callerBefore, callerAfter scopeView

	// outerEvents and innerEvents are the names each chain's sink received.
	outerEvents, innerEvents []string
}

// scopeRecorder collects the names of the events a sink receives.
type scopeRecorder struct {
	mu    sync.Mutex
	names []string
}

func (r *scopeRecorder) sink(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.names = append(r.names, e.Name)
}

func (r *scopeRecorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.names...)
}

// scopeConsumerKind is a challenge kind of the consumer's own.
const scopeConsumerKind policy.ChallengeKind = 100

// newScopeExchange is an exchange for GET /x with nothing run on it.
func newScopeExchange(t *testing.T) *Exchange {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)

	return NewExchange(t.Context(), NewHTTPRequest(r), NewHTTPResponseWriter(httptest.NewRecorder()))
}

// scopeChain is a chain with a discard logger and opts.
func scopeChain(t *testing.T, opts ...Option) *Chain {
	t.Helper()

	c, err := New(append([]Option{WithLogger(slog.New(slog.DiscardHandler))}, opts...)...)
	require.NoError(t, err)

	return c
}

// publishing is an interceptor at OrderBearerToken that publishes a session
// of its own, so the run it belongs to carries one.
func publishing(t *testing.T) Option {
	t.Helper()

	return RegisterInterceptor(InterceptorFunc(func(ex *Exchange, next Next) error {
		authn := &authenticate.Authentication{Principal: &identity.Principal{}}
		sess := &session.Session{FamilyID: id.MustParse("01890a5d-ac96-7774-8f5a-4b1c2d3e4f50")}

		if err := ex.PublishSession(authn, sess); err != nil {
			return err
		}

		return next(ex)
	}), OrderBearerToken)
}

// nesting is an interceptor at slot 100 that runs inner's step on its own
// exchange, records the exchange around it into out at level, recovers a
// panic of the inner step into out, and then continues its own run.
func nesting(inner Next, out *scopeOutcome, level int) Option {
	return RegisterInterceptor(InterceptorFunc(func(ex *Exchange, next Next) error {
		out.before[level] = viewOf(ex)

		func() {
			defer func() {
				if p := recover(); p != nil {
					out.panicked = p
				}
			}()

			out.err = inner(ex)
		}()

		out.after[level] = viewOf(ex)

		return next(ex)
	}), Order(100))
}

// nestedRun runs, on one exchange, an outer chain whose interceptor at slot
// 100 runs an inner chain built with innerOpts, the last of which is an
// interceptor at OrderBearerToken that calls change on the exchange. A change
// that panics leaves the inner run by its panic.
func nestedRun(t *testing.T, innerOpts []Option, change func(ex *Exchange)) scopeOutcome {
	t.Helper()

	out := scopeOutcome{before: make([]scopeView, 1), after: make([]scopeView, 1)}

	changing := RegisterInterceptor(InterceptorFunc(func(ex *Exchange, next Next) error {
		defer func() { out.during = viewOf(ex) }()

		change(ex)

		return next(ex)
	}), OrderBearerToken)

	inner := scopeChain(t, append(innerOpts, changing)...).Assemble(func(*Exchange) error { return nil })
	outer := scopeChain(t, nesting(inner, &out, 0)).Assemble(func(*Exchange) error { return nil })

	ex := newScopeExchange(t)
	out.callerBefore = viewOf(ex)
	require.NoError(t, outer(ex))
	out.callerAfter = viewOf(ex)

	return out
}

// putBack asserts that field, as pick reads it, is after the inner step what
// it was before it, and so is the whole exchange, and that the inner run did
// change field, so the case shows a restore and not a field nothing touched.
// pick returns a comparable value, compared with ==.
func putBack(field string, pick func(v scopeView) any, changed func(before, during scopeView) bool) func(t *testing.T, got scopeOutcome) {
	return func(t *testing.T, got scopeOutcome) {
		t.Helper()

		require.Nil(t, got.panicked)
		require.NoError(t, got.err)
		require.True(t, changed(got.before[0], got.during), "the inner run did not change %s", field)
		assert.True(t, pick(got.before[0]) == pick(got.after[0]),
			"%s after the inner step is %+v, the inner run's; want %+v", field, pick(got.after[0]), pick(got.before[0]))
		assertSameScope(t, got.before[0], got.after[0], "the exchange after the inner step is not the one before it ("+field+")")
		assertSameScope(t, got.callerBefore, got.callerAfter, "the exchange after the outer step is not the one before it")
	}
}

// assertSameScope asserts want and got hold the same values, pointers and
// contexts compared by identity: two sessions alike in content are still two
// runs' sessions.
func assertSameScope(t *testing.T, want, got scopeView, msg string) {
	t.Helper()

	if want == got {
		return
	}

	assert.Fail(t, msg, "want %+v\ngot  %+v\ncontext is the same: %t", want, got, want.ctx == got.ctx)
}

// TestChain_RunPutsBackTheExchangeItFound pins that the step a chain assembles
// leaves the exchange carrying what it carried on entry: the context, what the
// run resolved and what its chain configured, however the run ends. What
// coordinates runs on one exchange, the record that a refusal was reported, is
// not put back, and is cleared when an outermost run starts.
func TestChain_RunPutsBackTheExchangeItFound(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T) scopeOutcome
		assert func(t *testing.T, got scopeOutcome)
	}

	cases := []testCase{
		{
			name: "inner chain publishes a session: Session and Authentication",
			run: func(t *testing.T) scopeOutcome {
				t.Helper()

				return nestedRun(t, []Option{publishing(t)}, func(*Exchange) {})
			},
			assert: putBack("Session and Authentication",
				func(v scopeView) any { return [2]any{v.session, v.authentication} },
				func(before, during scopeView) bool {
					return before.session != during.session && before.authentication != during.authentication
				}),
		},
		{
			name: "inner bearer records its credential: bearerCredential",
			run: func(t *testing.T) scopeOutcome {
				t.Helper()

				return nestedRun(t, nil, func(ex *Exchange) { ex.RecordPresentedToken("inner-credential") })
			},
			assert: putBack("bearerCredential",
				func(v scopeView) any { return v.bearerCredential },
				func(before, during scopeView) bool {
					return before.bearerCredential != during.bearerCredential
				}),
		},
		{
			name: "inner late renewal: renewal, chargeRenewal and admitRenewal",
			run: func(t *testing.T) scopeOutcome {
				t.Helper()

				return nestedRun(t, nil, func(ex *Exchange) {
					ex.renewal = "inner-session"
					ex.chargeRenewal = func(context.Context) {}
					ex.admitRenewal = func(*Exchange, *session.Session) (*identity.Details, error) { return nil, nil }
				})
			},
			assert: putBack("the late-renewal fields",
				func(v scopeView) any { return [3]any{v.renewal, v.chargeRenewal, v.admitRenewal} },
				func(before, during scopeView) bool {
					return before.renewal != during.renewal && !before.chargeRenewal && during.chargeRenewal &&
						!before.admitRenewal && during.admitRenewal
				}),
		},
		{
			name: "inner chain built WithoutCSRFProtection: csrfOptOut",
			run: func(t *testing.T) scopeOutcome {
				t.Helper()

				return nestedRun(t, []Option{WithoutCSRFProtection()}, func(*Exchange) {})
			},
			assert: putBack("csrfOptOut",
				func(v scopeView) any { return v.csrfOptOut },
				func(before, during scopeView) bool {
					return !before.csrfOptOut && during.csrfOptOut
				}),
		},
		{
			name: "inner chain's per-request phase: perRequest",
			run: func(t *testing.T) scopeOutcome {
				t.Helper()

				return nestedRun(t, nil, func(*Exchange) {})
			},
			assert: putBack("perRequest",
				func(v scopeView) any { return v.perRequest },
				func(before, during scopeView) bool {
					return before.perRequest != nil && during.perRequest != nil && before.perRequest != during.perRequest
				}),
		},
		{
			name: "inner chain raises a consumer challenge: raised",
			run: func(t *testing.T) scopeOutcome {
				t.Helper()

				return nestedRun(t, nil, func(ex *Exchange) { ex.raised = scopeConsumerKind })
			},
			assert: putBack("raised",
				func(v scopeView) any { return v.raised },
				func(before, during scopeView) bool {
					return before.raised == policy.ChallengeNone && during.raised == scopeConsumerKind
				}),
		},
		{
			name: "inner interceptor panics and the outer recovers it",
			run: func(t *testing.T) scopeOutcome {
				t.Helper()

				return nestedRun(t, []Option{WithoutCSRFProtection(), publishing(t)}, func(ex *Exchange) {
					ex.RecordPresentedToken("inner-credential")
					ex.renewal = "inner-session"
					ex.chargeRenewal = func(context.Context) {}
					ex.admitRenewal = func(*Exchange, *session.Session) (*identity.Details, error) { return nil, nil }
					ex.raised = scopeConsumerKind
					ex.SetContext(context.WithValue(ex.Context(), interceptorScopeKey{}, "inner"))

					panic("inner interceptor panics")
				})
			},
			assert: func(t *testing.T, got scopeOutcome) {
				t.Helper()

				require.Equal(t, "inner interceptor panics", got.panicked)
				require.True(t, got.before[0] != got.during, "the inner run changed nothing")
				assertSameScope(t, got.before[0], got.after[0], "a recovered panic left the inner run's state on the exchange")
				assertSameScope(t, got.callerBefore, got.callerAfter, "the exchange after the outer step is not the one before it")
			},
		},
		{
			name: "three chains on one exchange: each level reads its own run's state",
			run: func(t *testing.T) scopeOutcome {
				t.Helper()

				out := scopeOutcome{before: make([]scopeView, 2), after: make([]scopeView, 2)}

				innermost := scopeChain(t, publishing(t), RegisterInterceptor(InterceptorFunc(func(ex *Exchange, next Next) error {
					ex.RecordPresentedToken("innermost-credential")
					out.during = viewOf(ex)

					return next(ex)
				}), OrderBearerToken)).Assemble(func(*Exchange) error { return nil })

				middle := scopeChain(t, WithoutCSRFProtection(), publishing(t), nesting(innermost, &out, 1)).
					Assemble(func(*Exchange) error { return nil })

				outer := scopeChain(t, nesting(middle, &out, 0)).Assemble(func(*Exchange) error { return nil })

				ex := newScopeExchange(t)
				out.callerBefore = viewOf(ex)
				require.NoError(t, outer(ex))
				out.callerAfter = viewOf(ex)

				return out
			},
			assert: func(t *testing.T, got scopeOutcome) {
				t.Helper()

				require.NoError(t, got.err)
				require.True(t, got.before[1] != got.during, "the innermost run changed nothing")
				require.True(t, got.before[0] != got.before[1], "the middle run changed nothing")
				assertSameScope(t, got.before[1], got.after[1], "the middle level read another run's state")
				assertSameScope(t, got.before[0], got.after[0], "the outer level read another run's state")
				assertSameScope(t, got.callerBefore, got.callerAfter, "the exchange after the outer step is not the one before it")
			},
		},
		{
			name: "the caller's own context, set before the run, is the one after it",
			run: func(t *testing.T) scopeOutcome {
				t.Helper()

				var out scopeOutcome

				step := scopeChain(t, publishing(t)).Assemble(func(ex *Exchange) error {
					out.during = viewOf(ex)

					return nil
				})

				ex := newScopeExchange(t)
				ex.SetContext(context.WithValue(ex.Context(), interceptorScopeKey{}, "the caller's"))
				out.callerBefore = viewOf(ex)
				out.err = step(ex)
				out.callerAfter = viewOf(ex)

				return out
			},
			assert: func(t *testing.T, got scopeOutcome) {
				t.Helper()

				require.NoError(t, got.err)
				require.True(t, got.callerBefore != got.during, "the run changed nothing")
				assert.Equal(t, "the caller's", got.callerAfter.ctx.Value(interceptorScopeKey{}))
				assertSameScope(t, got.callerBefore, got.callerAfter, "the exchange after the run is not the one before it")
			},
		},
		{
			name: "an exchange refused once and run again reports the second refusal",
			run: func(t *testing.T) scopeOutcome {
				t.Helper()

				var (
					out scopeOutcome
					rec scopeRecorder
				)

				step := scopeChain(t, EnableSecurityEvents(rec.sink), RegisterInterceptor(InterceptorFunc(
					func(*Exchange, Next) error { return ErrCrossSiteRequest }), Order(1))).
					Assemble(func(*Exchange) error { return nil })

				ex := newScopeExchange(t)

				for range 2 {
					out.err = step(ex)
					require.ErrorIs(t, out.err, ErrCrossSiteRequest)
				}

				out.outerEvents = rec.got()

				return out
			},
			assert: func(t *testing.T, got scopeOutcome) {
				t.Helper()

				assert.Equal(t, []string{event.MaliciousCSRF, event.MaliciousCSRF}, got.outerEvents,
					"each run's refusal is reported")
			},
		},
		{
			name: "control: an inner refusal is reported once",
			run: func(t *testing.T) scopeOutcome {
				t.Helper()

				var (
					out          scopeOutcome
					outer, inner scopeRecorder
				)

				innerStep := scopeChain(t, EnableSecurityEvents(inner.sink), RegisterInterceptor(InterceptorFunc(
					func(*Exchange, Next) error { return ErrCrossSiteRequest }), Order(1))).
					Assemble(func(*Exchange) error { return nil })

				step := scopeChain(t, EnableSecurityEvents(outer.sink)).Assemble(innerStep)

				out.err = step(newScopeExchange(t))
				out.outerEvents, out.innerEvents = outer.got(), inner.got()

				return out
			},
			assert: func(t *testing.T, got scopeOutcome) {
				t.Helper()

				require.ErrorIs(t, got.err, ErrCrossSiteRequest)
				assert.Equal(t, []string{event.MaliciousCSRF}, got.innerEvents)
				assert.Empty(t, got.outerEvents, "one refusal is reported once")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.run(t))
		})
	}
}

// interceptorScopeKey is a context key a case sets a value under.
type interceptorScopeKey struct{}

// A chain composed around the rest of an outer run (inner.Assemble(next))
// puts back what the outer run's later interceptors set inside it. This pins
// that accepted behaviour: an interceptor of the outer run before the
// composition point reads, after next, the state from before the inner step,
// and the run's own state is read in its terminal.
func TestChain_ComposedInnerStepPutsBackWhatTheOuterRunSetInside(t *testing.T) {
	t.Parallel()

	type outcome struct {
		readerSession  *session.Session
		readerCtx      *session.Session
		terminalSeen   *session.Session
		readerCtxFound bool
	}

	type testCase struct {
		name   string
		assert func(t *testing.T, s1, s2 *session.Session, got outcome)
	}

	cases := []testCase{
		{
			name: "a reader before the composition point sees the pre-composition session",
			assert: func(t *testing.T, s1, s2 *session.Session, got outcome) {
				assert.Same(t, s1, got.readerSession, "ex.Session is put back, not the rotated one")
				assert.NotSame(t, s2, got.readerSession)
				require.True(t, got.readerCtxFound)
				assert.Same(t, got.readerSession, got.readerCtx, "ex.Session and the context's session agree")
			},
		},
		{
			name: "the terminal sees what the later interceptor set",
			assert: func(t *testing.T, _, s2 *session.Session, got outcome) {
				assert.Same(t, s2, got.terminalSeen)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s1 := &session.Session{FamilyID: id.MustParse("01890a5d-ac96-7774-8f5a-4b1c2d3e4f50")}
			s2 := &session.Session{FamilyID: id.MustParse("01890a5d-ac96-7774-8f5a-4b1c2d3e4f50")}

			var got outcome

			reader := InterceptorFunc(func(ex *Exchange, next Next) error {
				err := next(ex)
				got.readerSession = ex.Session
				got.readerCtx, got.readerCtxFound = SessionFromContext(ex.Context())

				return err
			})
			publish := InterceptorFunc(func(ex *Exchange, next Next) error {
				authn := &authenticate.Authentication{Principal: &identity.Principal{}}
				if err := ex.PublishSession(authn, s1); err != nil {
					return err
				}

				return next(ex)
			})

			inner, err := New(WithLogger(slog.New(slog.DiscardHandler)))
			require.NoError(t, err)

			compose := InterceptorFunc(func(ex *Exchange, next Next) error {
				return inner.Assemble(next)(ex)
			})
			rotate := InterceptorFunc(func(ex *Exchange, next Next) error {
				ex.Session = s2
				ex.SetContext(withSession(ex.Context(), s2))

				return next(ex)
			})

			outer, err := New(WithLogger(slog.New(slog.DiscardHandler)),
				RegisterInterceptor(publish, OrderBearerToken),
				RegisterInterceptor(reader, Order(510)),
				RegisterInterceptor(compose, Order(520)),
				RegisterInterceptor(rotate, Order(530)),
			)
			require.NoError(t, err)

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
			ex := NewExchange(t.Context(), NewHTTPRequest(r), NewHTTPResponseWriter(httptest.NewRecorder()))

			require.NoError(t, outer.Assemble(func(ex *Exchange) error {
				got.terminalSeen = ex.Session

				return nil
			})(ex))

			tc.assert(t, s1, s2, got)
		})
	}
}
