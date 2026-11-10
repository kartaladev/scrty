package httpsec_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// msgLatePublication is the record the chain writes when it refuses a session
// published after its gates.
const msgLatePublication = "httpsec: session published after the gates refused"

// publishProbe keeps what the publishing interceptor of one request saw: the
// error PublishSession returned, and whether it was reached at all.
type publishProbe struct {
	reached bool
	err     error
}

// publishingAuthenticator is a consumer's own session authenticator: it loads
// the session named by id from m, publishes it with its user as the caller
// through PublishSession and, when evaluate is set, runs the per-request
// phase, exactly as the package documentation says a first factor of one's own
// does. What PublishSession returned is kept on probe. Only the slot it is
// registered at varies between cases.
func publishingAuthenticator(m *session.Sessions, id string, evaluate bool, probe *publishProbe) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		s, err := m.Load(ex.Context(), id)
		if err != nil {
			return err
		}

		p := &identity.Principal{ID: s.UserID, Username: "ada", Name: "Ada Lovelace"}

		probe.reached = true
		probe.err = ex.PublishSession(&authenticate.Authentication{Principal: p, Time: time.Now()}, s)

		if probe.err != nil {
			return probe.err
		}

		if evaluate {
			if err := ex.EvaluatePerRequest(s, p); err != nil {
				return err
			}
		}

		return next(ex)
	})
}

// signingOut is a consumer interceptor that publishes no session and no
// caller, signing the request's caller out, and keeps what PublishSession
// returned on probe.
func signingOut(probe *publishProbe) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		probe.reached = true
		probe.err = ex.PublishSession(nil, nil)

		if probe.err != nil {
			return probe.err
		}

		return next(ex)
	})
}

// discardingPublisher is a consumer interceptor that publishes the session
// named by id with its user as the caller, discards the error PublishSession
// returns and goes on to next, as a careless consumer would.
func discardingPublisher(m *session.Sessions, id string, probe *publishProbe) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		s, err := m.Load(ex.Context(), id)
		if err != nil {
			return err
		}

		p := &identity.Principal{ID: s.UserID, Username: "ada", Name: "Ada Lovelace"}

		probe.reached = true
		_ = ex.PublishSession(&authenticate.Authentication{Principal: p, Time: time.Now()}, s)

		return next(ex)
	})
}

// authenticatedOnly is the authorization stage requiring an authenticated
// caller on every request, which is what a deployment relying on the gates
// would configure.
func authenticatedOnly(t *testing.T) httpsec.Option {
	t.Helper()

	return httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t)), authorize.Rule[httpsec.Request]{
		Match:   func(httpsec.Request) bool { return true },
		Require: authorize.Authenticated(),
	})
}

// publishOutcome is what one request through a chain came to.
type publishOutcome struct {
	status     int
	handlerRan bool
	probe      *publishProbe

	// session and authenticated are what the handler read from the request
	// context: the published session, and whether a result was there.
	session       *session.Session
	authenticated bool
}

// TestPublishSession_RefusedOnceTheGatesHaveBegun pins that a session a
// consumer interceptor publishes past the first enabled gate is refused with a
// configuration error, publishing nothing, so the handler is never reached
// with a session no gate judged. The "bearer slot" rows are controls: the same
// session, published before the gates, is refused by the gate that confines
// it, as before.
func TestPublishSession_RefusedOnceTheGatesHaveBegun(t *testing.T) {
	t.Parallel()

	late := httpsec.After(httpsec.OrderLogout)
	early := httpsec.OrderBearerToken

	// mfaPending is a chain with the second-factor gate on and a session
	// owing a second factor, published at slot at. withPassword enables the
	// password-change gate too, after it.
	mfaPending := func(at httpsec.Order, withPassword bool) func(t *testing.T, probe *publishProbe) []httpsec.Option {
		return func(t *testing.T, probe *publishProbe) []httpsec.Option {
			t.Helper()

			f := newResolveFixture(t)
			s, err := f.sessions.Load(t.Context(), f.session.ID)
			require.NoError(t, err)
			s.MFA = session.MFAPending
			require.NoError(t, f.sessions.Save(t.Context(), s))

			opts := []httpsec.Option{
				httpsec.WithSessions(f.sessions),
				enableMFAFor(t),
				httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions}),
				authenticatedOnly(t),
				httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, s.ID, false, probe), at),
			}

			if withPassword {
				opts = append(opts, httpsec.EnablePasswordChangeGate(f.sessions))
			}

			return opts
		}
	}

	// passwordOnly is a chain whose only gate is the password-change gate,
	// with a session published at slot at; pending says whether it owes a
	// password change.
	passwordOnly := func(at httpsec.Order, pending bool) func(t *testing.T, probe *publishProbe) []httpsec.Option {
		return func(t *testing.T, probe *publishProbe) []httpsec.Option {
			t.Helper()

			f := newResolveFixture(t)
			s, err := f.sessions.Load(t.Context(), f.session.ID)
			require.NoError(t, err)
			s.PasswordChangePending = pending
			require.NoError(t, f.sessions.Save(t.Context(), s))

			return []httpsec.Option{
				httpsec.WithSessions(f.sessions),
				httpsec.EnablePasswordChangeGate(f.sessions),
				authenticatedOnly(t),
				httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, s.ID, false, probe), at),
			}
		}
	}

	// enrolmentOnly is the enrolment tests' chain (second factor, enrolment
	// gate, logout) with an enrolment-only session published at slot at,
	// registered after the option enabling enrolment.
	enrolmentOnly := func(at httpsec.Order) func(t *testing.T, probe *publishProbe) []httpsec.Option {
		return func(t *testing.T, probe *publishProbe) []httpsec.Option {
			t.Helper()

			h := newEnrolHarness(t)
			s := h.enrolmentOnly(t, factor.Password)
			h.extra = []httpsec.Option{
				authenticatedOnly(t),
				httpsec.RegisterInterceptor(publishingAuthenticator(h.sessions, s.ID, false, probe), at),
			}

			return h.options(t, nil)
		}
	}

	// perRequestMFA is a chain whose per-request policy challenges every full
	// session for a second factor, the consumer running the phase at slot at
	// after publishing.
	perRequestMFA := func(at httpsec.Order) func(t *testing.T, probe *publishProbe) []httpsec.Option {
		return func(t *testing.T, probe *publishProbe) []httpsec.Option {
			t.Helper()

			f := newResolveFixture(t)

			return []httpsec.Option{
				httpsec.WithSessions(f.sessions),
				httpsec.WithPolicyEngine(challengingIn(t, policy.PerRequest, policy.ChallengeMFA)),
				enableMFAFor(t),
				httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions}),
				authenticatedOnly(t),
				httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, true, probe), at),
			}
		}
	}

	// passwordSlotMate is a chain whose password-change gate is enabled, with a
	// session owing a password change published at the gate's own slot by an
	// interceptor registered before the option enabling the gate (before true)
	// or after it.
	passwordSlotMate := func(before bool) func(t *testing.T, probe *publishProbe) []httpsec.Option {
		return func(t *testing.T, probe *publishProbe) []httpsec.Option {
			t.Helper()

			f := newResolveFixture(t)
			s, err := f.sessions.Load(t.Context(), f.session.ID)
			require.NoError(t, err)
			s.PasswordChangePending = true
			require.NoError(t, f.sessions.Save(t.Context(), s))

			publisher := httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, s.ID, false, probe), httpsec.OrderPasswordChange)
			enable := httpsec.EnablePasswordChangeGate(f.sessions)

			opts := []httpsec.Option{httpsec.WithSessions(f.sessions), authenticatedOnly(t)}
			if before {
				return append(opts, publisher, enable)
			}

			return append(opts, enable, publisher)
		}
	}

	// refusedByGate is a control: publishing succeeded, and the gate that
	// confines the session refused the request.
	refusedByGate := func(t *testing.T, o publishOutcome) {
		t.Helper()

		require.True(t, o.probe.reached, "the publishing interceptor never ran")
		require.NoError(t, o.probe.err)
		assert.False(t, o.handlerRan, "the handler was reached with a confined session (status %d)", o.status)
		assert.NotEqual(t, http.StatusOK, o.status)
		assert.NotEqual(t, http.StatusInternalServerError, o.status, "a gate's refusal, not a configuration error")
	}

	// refusedLate is the fix: publishing failed with a configuration error,
	// nothing was published, and the request was answered with a 500.
	refusedLate := func(t *testing.T, o publishOutcome) {
		t.Helper()

		require.True(t, o.probe.reached, "the publishing interceptor never ran")
		assert.Equal(t, http.StatusInternalServerError, o.status)
		assert.False(t, o.handlerRan, "the handler was reached with a session no gate judged")
		require.ErrorIs(t, o.probe.err, httpsec.ErrConfig)
		assert.Contains(t, o.probe.err.Error(), "OrderBearerToken")
		assert.NotContains(t, o.probe.err.Error(), "OrderAccountRecovery", "the advice is OrderBearerToken, no later")
	}

	type testCase struct {
		name   string
		opts   func(t *testing.T, probe *publishProbe) []httpsec.Option
		assert func(t *testing.T, o publishOutcome)
	}

	cases := []testCase{
		{name: "MFA pending, published at the bearer slot (control)", opts: mfaPending(early, false), assert: refusedByGate},
		{name: "MFA pending, published after logout", opts: mfaPending(late, false), assert: refusedLate},
		{name: "MFA pending, published right after the second-factor gate", opts: mfaPending(httpsec.After(httpsec.OrderMFAChallenge), false), assert: refusedLate},
		{
			name:   "MFA pending, published between the second-factor and password-change gates",
			opts:   mfaPending(httpsec.After(httpsec.OrderMFAChallenge), true),
			assert: refusedLate,
		},
		{name: "enrolment-only, published at the enrolment gate's slot after the option enabling it", opts: enrolmentOnly(httpsec.OrderMFAEnrolment), assert: refusedLate},
		{name: "password change pending, published at the bearer slot (control)", opts: passwordOnly(early, true), assert: refusedByGate},
		{name: "password change pending, published after logout", opts: passwordOnly(late, true), assert: refusedLate},
		{name: "full session, published after the only gate (password change)", opts: passwordOnly(httpsec.After(httpsec.OrderPasswordChange), false), assert: refusedLate},
		{name: "password change pending, slot-mate registered before the option enabling the gate (outside it)", opts: passwordSlotMate(true), assert: refusedByGate},
		{name: "password change pending, slot-mate registered after the option enabling the gate (inside it)", opts: passwordSlotMate(false), assert: refusedLate},
		{
			name: "late publication whose error is discarded publishes neither session nor caller",
			opts: func(t *testing.T, probe *publishProbe) []httpsec.Option {
				t.Helper()

				f := newResolveFixture(t)

				return []httpsec.Option{
					httpsec.WithSessions(f.sessions),
					httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.RegisterInterceptor(discardingPublisher(f.sessions, f.session.ID, probe), late),
				}
			},
			assert: func(t *testing.T, o publishOutcome) {
				t.Helper()

				require.True(t, o.probe.reached, "the publishing interceptor never ran")
				assert.True(t, o.handlerRan)
				assert.Nil(t, o.session, "the refused session reached the handler")
				assert.False(t, o.authenticated, "the refused caller reached the handler")
			},
		},
		{name: "enrolment-only, published at the bearer slot (control)", opts: enrolmentOnly(early), assert: refusedByGate},
		{name: "enrolment-only, published after logout", opts: enrolmentOnly(late), assert: refusedLate},
		{name: "per-request MFA challenge, evaluated at the bearer slot (control)", opts: perRequestMFA(early), assert: refusedByGate},
		{name: "per-request MFA challenge, evaluated after logout", opts: perRequestMFA(late), assert: refusedLate},
		{
			name: "full session, published at the bearer slot with every gate enabled",
			opts: func(t *testing.T, probe *publishProbe) []httpsec.Option {
				t.Helper()

				f := newResolveFixture(t)

				return []httpsec.Option{
					httpsec.WithSessions(f.sessions),
					enableMFAFor(t),
					httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions}),
					authenticatedOnly(t),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe), early),
				}
			},
			assert: func(t *testing.T, o publishOutcome) {
				t.Helper()

				require.NoError(t, o.probe.err)
				assert.True(t, o.handlerRan)
				assert.Equal(t, http.StatusOK, o.status)
			},
		},
		{
			name: "no gate enabled, published after logout",
			opts: func(t *testing.T, probe *publishProbe) []httpsec.Option {
				t.Helper()

				f := newResolveFixture(t)

				return []httpsec.Option{
					httpsec.WithSessions(f.sessions),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions}),
					authenticatedOnly(t),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe), late),
				}
			},
			assert: func(t *testing.T, o publishOutcome) {
				t.Helper()

				require.True(t, o.probe.reached)
				require.NoError(t, o.probe.err)
				assert.True(t, o.handlerRan)
				assert.Equal(t, http.StatusOK, o.status)
				require.NotNil(t, o.session, "the handler read no session")
				assert.Equal(t, identity.UserID("u-1"), o.session.UserID)
				assert.True(t, o.authenticated)
			},
		},
		{
			name: "nil session after the gates",
			opts: func(t *testing.T, probe *publishProbe) []httpsec.Option {
				t.Helper()

				f := newResolveFixture(t)

				return []httpsec.Option{
					httpsec.WithSessions(f.sessions),
					httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, &publishProbe{}), early),
					httpsec.RegisterInterceptor(signingOut(probe), late),
				}
			},
			assert: func(t *testing.T, o publishOutcome) {
				t.Helper()

				require.True(t, o.probe.reached)
				require.NoError(t, o.probe.err)
				assert.True(t, o.handlerRan)
				assert.Equal(t, http.StatusOK, o.status)
				assert.Nil(t, o.session, "the handler still read a session")
				assert.False(t, o.authenticated, "the handler still read a result")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			o := publishOutcome{probe: &publishProbe{}}

			chain, err := httpsec.New(tc.opts(t, o.probe)...)
			require.NoError(t, err)

			h := chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				o.handlerRan = true
				o.session, _ = httpsec.SessionFromContext(r.Context())
				_, o.authenticated = authenticate.AuthenticationFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil))
			o.status = rec.Code

			tc.assert(t, o)
		})
	}
}

// runBuiltInInsideGates runs a gateless chain whose session bearer
// authenticates the fixture's session inside a password-change-gated chain's
// gates, on the outer chain's exchange, and sets probe.reached when the
// handler reads a session. With detach, an interceptor past the outer gate
// replaces the context with one not derived from the run's first.
func runBuiltInInsideGates(t *testing.T, f resolveFixture, probe *publishProbe, detach bool) error {
	t.Helper()

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

	outerOpts := []httpsec.Option{httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions)}
	if detach {
		outerOpts = append(outerOpts, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
			func(ex *httpsec.Exchange, next httpsec.Next) error {
				ex.SetContext(context.WithoutCancel(t.Context()))

				return next(ex)
			}), httpsec.After(httpsec.OrderPasswordChange)))
	}

	outer, err := httpsec.New(outerOpts...)
	require.NoError(t, err)

	inner, err := httpsec.New(
		httpsec.WithLogger(slog.New(slog.DiscardHandler)),
		httpsec.WithClock(f.clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: f.sessions, Users: users}),
	)
	require.NoError(t, err)

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)
	r.Header.Set("Authorization", "Bearer "+f.session.ID)
	ex := httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(r), httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))

	return outer.Assemble(inner.Assemble(func(ex *httpsec.Exchange) error {
		probe.reached = ex.Session != nil

		return nil
	}))(ex)
}

// TestPublishSession_GateMarkOnOneExchange pins how the mark the first gate
// sets lives on one exchange run through Assemble: it holds while the gate's
// frame runs, so a different chain nested inside the gated one refuses a
// publication, and it is put back as the frame returns, a panic included, so
// a fresh run of the same exchange starts unmarked.
func TestPublishSession_GateMarkOnOneExchange(t *testing.T) {
	t.Parallel()

	newExchange := func(t *testing.T) *httpsec.Exchange {
		t.Helper()

		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)

		return httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(r), httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))
	}

	type testCase struct {
		name string
		run  func(t *testing.T, f resolveFixture, probe *publishProbe) error
		// assert receives the error of the last run.
		assert func(t *testing.T, probe *publishProbe, err error)
	}

	cases := []testCase{
		{
			name: "different chain nested after the outer chain's gates",
			run: func(t *testing.T, f resolveFixture, probe *publishProbe) error {
				t.Helper()

				outer, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions))
				require.NoError(t, err)

				inner, err := httpsec.New(httpsec.WithSessions(f.sessions),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe), httpsec.OrderBearerToken))
				require.NoError(t, err)

				run := outer.Assemble(inner.Assemble(func(*httpsec.Exchange) error { return nil }))

				return run(newExchange(t))
			},
			assert: func(t *testing.T, probe *publishProbe, err error) {
				t.Helper()

				require.True(t, probe.reached)
				require.ErrorIs(t, probe.err, httpsec.ErrConfig)
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "covering chain nested after the outer chain's gates",
			run: func(t *testing.T, f resolveFixture, probe *publishProbe) error {
				t.Helper()

				// The nested chain enables every gate the outer one does, so
				// its own gates judge what it publishes, on the outer chain's
				// exchange as on a fresh one.
				outer, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions))
				require.NoError(t, err)

				inner, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe), httpsec.OrderBearerToken))
				require.NoError(t, err)

				return outer.Assemble(inner.Assemble(func(*httpsec.Exchange) error { return nil }))(newExchange(t))
			},
			assert: func(t *testing.T, probe *publishProbe, err error) {
				t.Helper()

				require.True(t, probe.reached)
				require.NoError(t, probe.err, "a chain enabling every gate of the enclosing chain was refused")
				require.NoError(t, err)
			},
		},
		{
			name: "nested chain's own late authenticator on the shared exchange",
			run: func(t *testing.T, f resolveFixture, probe *publishProbe) error {
				t.Helper()

				outer, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions))
				require.NoError(t, err)

				inner, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe),
						httpsec.After(httpsec.OrderPasswordChange)))
				require.NoError(t, err)

				return outer.Assemble(inner.Assemble(func(*httpsec.Exchange) error { return nil }))(newExchange(t))
			},
			assert: func(t *testing.T, probe *publishProbe, err error) {
				t.Helper()

				require.True(t, probe.reached)
				require.ErrorIs(t, probe.err, httpsec.ErrConfig)
				require.ErrorContains(t, probe.err, "after the chain's gates had begun")
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "nested chain lacking one of the outer chain's gates",
			run: func(t *testing.T, f resolveFixture, probe *publishProbe) error {
				t.Helper()

				outer, err := httpsec.New(httpsec.WithSessions(f.sessions), enableMFAFor(t),
					httpsec.EnablePasswordChangeGate(f.sessions))
				require.NoError(t, err)

				inner, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe), httpsec.OrderBearerToken))
				require.NoError(t, err)

				return outer.Assemble(inner.Assemble(func(*httpsec.Exchange) error { return nil }))(newExchange(t))
			},
			assert: func(t *testing.T, probe *publishProbe, err error) {
				t.Helper()

				require.True(t, probe.reached)
				require.ErrorIs(t, probe.err, httpsec.ErrConfig)
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "outer chain's late authenticator behind a covering chain it ran its continuation through",
			run: func(t *testing.T, f resolveFixture, probe *publishProbe) error {
				t.Helper()

				// An interceptor past the outer chain's gate runs the rest of
				// the outer chain as the terminal of a chain with the same
				// gate. The publisher after it is still past the outer chain's
				// own gate, and the nested chain's gate has returned to it
				// nothing it judged.
				inner, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions))
				require.NoError(t, err)

				through := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					return inner.Assemble(next)(ex)
				})

				outer, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.RegisterInterceptor(through, httpsec.After(httpsec.OrderPasswordChange)),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe),
						httpsec.After(httpsec.OrderPasswordChange)))
				require.NoError(t, err)

				return outer.Assemble(func(*httpsec.Exchange) error { return nil })(newExchange(t))
			},
			assert: func(t *testing.T, probe *publishProbe, err error) {
				t.Helper()

				require.True(t, probe.reached)
				require.ErrorIs(t, probe.err, httpsec.ErrConfig)
				require.ErrorContains(t, probe.err, "after the chain's gates had begun")
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "nested chain lacking a gate, on a context not derived from the run's",
			run: func(t *testing.T, f resolveFixture, probe *publishProbe) error {
				t.Helper()

				// The outer chain's run is no longer on the context the
				// nested chain sees, so only the exchange's own marks can
				// tell that its gates are running.
				detach := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					ex.SetContext(context.WithoutCancel(t.Context()))

					return next(ex)
				})

				outer, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.RegisterInterceptor(detach, httpsec.After(httpsec.OrderPasswordChange)))
				require.NoError(t, err)

				inner, err := httpsec.New(httpsec.WithSessions(f.sessions),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe), httpsec.OrderBearerToken))
				require.NoError(t, err)

				return outer.Assemble(inner.Assemble(func(*httpsec.Exchange) error { return nil }))(newExchange(t))
			},
			assert: func(t *testing.T, probe *publishProbe, err error) {
				t.Helper()

				require.True(t, probe.reached)
				require.ErrorIs(t, probe.err, httpsec.ErrConfig)
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "gateless nested chain's built-in authenticator, on a context not derived from the run's",
			run: func(t *testing.T, f resolveFixture, probe *publishProbe) error {
				t.Helper()

				// The built-in publishes through the library's own path, which
				// must read the outer run's mark from the exchange as
				// PublishSession does once the context no longer shows it.
				return runBuiltInInsideGates(t, f, probe, true)
			},
			assert: func(t *testing.T, probe *publishProbe, err error) {
				t.Helper()

				require.False(t, probe.reached,
					"a gateless chain's built-in published inside the outer chain's gates on its exchange (err %v)", err)
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "gateless nested chain's built-in authenticator, on the run's context",
			run: func(t *testing.T, f resolveFixture, probe *publishProbe) error {
				t.Helper()

				return runBuiltInInsideGates(t, f, probe, false)
			},
			assert: func(t *testing.T, probe *publishProbe, err error) {
				t.Helper()

				require.False(t, probe.reached,
					"a gateless chain's built-in published inside the outer chain's gates on its exchange (err %v)", err)
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "step kept past its run is refused before the gates",
			run: func(t *testing.T, f resolveFixture, probe *publishProbe) error {
				t.Helper()

				// An interceptor before the gates keeps the step it was given
				// and calls it again once the run has returned: the chain has
				// no run on the exchange to mark, so its gates must not run.
				var kept httpsec.Next

				keeping := httpsec.InterceptorFunc(func(_ *httpsec.Exchange, next httpsec.Next) error {
					kept = next

					return nil
				})

				c, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.RegisterInterceptor(keeping, httpsec.Before(httpsec.OrderBearerToken)),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe),
						httpsec.After(httpsec.OrderPasswordChange)))
				require.NoError(t, err)

				ex := newExchange(t)
				require.NoError(t, c.Assemble(func(*httpsec.Exchange) error { return nil })(ex), "first run")
				require.NotNil(t, kept)

				return kept(ex)
			},
			assert: func(t *testing.T, probe *publishProbe, err error) {
				t.Helper()

				require.False(t, probe.reached, "the gates ran on an exchange their chain was not running (publish err %v)", probe.err)
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "published from the handler inside the gates",
			run: func(t *testing.T, f resolveFixture, probe *publishProbe) error {
				t.Helper()

				// The handler is no chain's interceptor, so no chain's gates
				// judge what it publishes: it is refused like a chain enabling
				// no gate.
				c, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions))
				require.NoError(t, err)

				handler := publishingAuthenticator(f.sessions, f.session.ID, false, probe)

				return c.Assemble(func(ex *httpsec.Exchange) error {
					return handler.Intercept(ex, func(*httpsec.Exchange) error { return nil })
				})(newExchange(t))
			},
			assert: func(t *testing.T, probe *publishProbe, err error) {
				t.Helper()

				require.True(t, probe.reached)
				require.ErrorIs(t, probe.err, httpsec.ErrConfig)
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "same exchange run a second time",
			run: func(t *testing.T, f resolveFixture, probe *publishProbe) error {
				t.Helper()

				c, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe), httpsec.OrderBearerToken))
				require.NoError(t, err)

				run := c.Assemble(func(*httpsec.Exchange) error { return nil })
				ex := newExchange(t)
				require.NoError(t, run(ex), "first run")

				return run(ex)
			},
			assert: func(t *testing.T, probe *publishProbe, err error) {
				t.Helper()

				require.NoError(t, probe.err, "the first run's mark leaked into the second")
				require.NoError(t, err)
			},
		},
		{
			name: "fallback chain served after the gates returned",
			run: func(t *testing.T, f resolveFixture, probe *publishProbe) error {
				t.Helper()

				// A consumer interceptor outside chain a's gates serves a
				// fallback through gateless chain b on the exchange's context
				// once a's gates have returned: a's run is still in progress,
				// but its gate mark must have been put back.
				b, err := httpsec.New(httpsec.WithSessions(f.sessions),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe), httpsec.OrderBearerToken))
				require.NoError(t, err)

				fallback := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					_ = next(ex)

					r := httptest.NewRequestWithContext(ex.Context(), http.MethodGet, "/orders", nil)
					b.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
						ServeHTTP(httptest.NewRecorder(), r)

					return nil
				})

				a, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.RegisterInterceptor(fallback, httpsec.Before(httpsec.OrderBearerToken)))
				require.NoError(t, err)

				return a.Assemble(func(*httpsec.Exchange) error { return nil })(newExchange(t))
			},
			assert: func(t *testing.T, probe *publishProbe, err error) {
				t.Helper()

				require.True(t, probe.reached)
				require.NoError(t, probe.err, "a's run mark outlived its gates")
				require.NoError(t, err)
			},
		},
		{
			name: "gate panics",
			run: func(t *testing.T, f resolveFixture, probe *publishProbe) error {
				t.Helper()

				// The panic is raised inside the first gate's frame, by the step
				// the gate passed the request to, and travels out through the
				// gate as one raised by the gate itself would.
				var panicked bool

				panicking := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					if !panicked {
						panicked = true

						panic("gate panics")
					}

					return next(ex)
				})

				c, err := httpsec.New(httpsec.WithSessions(f.sessions), httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe), httpsec.OrderBearerToken),
					httpsec.RegisterInterceptor(panicking, httpsec.After(httpsec.OrderPasswordChange)))
				require.NoError(t, err)

				run := c.Assemble(func(*httpsec.Exchange) error { return nil })
				ex := newExchange(t)

				require.Panics(t, func() { _ = run(ex) }, "first run")
				require.NoError(t, probe.err, "first run")

				return run(ex)
			},
			assert: func(t *testing.T, probe *publishProbe, err error) {
				t.Helper()

				require.NoError(t, probe.err, "the panicking run's mark leaked into the second")
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			probe := &publishProbe{}
			err := tc.run(t, newResolveFixture(t), probe)
			tc.assert(t, probe, err)
		})
	}
}

// TestPublishSession_LateRefusalIsLoggedSampledWithoutIdentifiers pins the
// record a refused publication leaves, past the chain's own gates or inside
// another chain's: one per sampling window however many requests are refused,
// written by the chain that refused it, carrying neither the session nor the
// user it named.
func TestPublishSession_LateRefusalIsLoggedSampledWithoutIdentifiers(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// build returns the handler-wrapping function, every record of the
		// refusing chain going to logs.
		build func(t *testing.T, f resolveFixture, logs *capturingHandler) func(http.Handler) http.Handler
	}

	cases := []testCase{
		{
			name: "published after the chain's own gates",
			build: func(t *testing.T, f resolveFixture, logs *capturingHandler) func(http.Handler) http.Handler {
				t.Helper()

				chain, err := httpsec.New(
					httpsec.WithLogger(slog.New(logs)),
					httpsec.WithSessions(f.sessions),
					httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, &publishProbe{}),
						httpsec.After(httpsec.OrderPasswordChange)),
				)
				require.NoError(t, err)

				return chain.Middleware()
			},
		},
		{
			name: "published inside another chain's gates",
			build: func(t *testing.T, f resolveFixture, logs *capturingHandler) func(http.Handler) http.Handler {
				t.Helper()

				outer, err := httpsec.New(
					httpsec.WithLogger(slog.New(slog.DiscardHandler)),
					httpsec.WithSessions(f.sessions),
					httpsec.EnablePasswordChangeGate(f.sessions),
				)
				require.NoError(t, err)

				inner, err := httpsec.New(
					httpsec.WithLogger(slog.New(logs)),
					httpsec.WithSessions(f.sessions),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, &publishProbe{}),
						httpsec.OrderBearerToken),
				)
				require.NoError(t, err)

				return func(h http.Handler) http.Handler { return outer.Middleware()(inner.Middleware()(h)) }
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)
			logs := &capturingHandler{}

			h := tc.build(t, f, logs)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			for range 3 {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil))
				require.Equal(t, http.StatusInternalServerError, rec.Code)
			}

			var late []slog.Record

			for _, r := range logs.records() {
				if r.Message == msgLatePublication {
					late = append(late, r)
				}
			}

			require.Len(t, late, 1, "one record per sampling window")
			assert.Equal(t, slog.LevelError, late[0].Level)

			late[0].Attrs(func(a slog.Attr) bool {
				v := a.Value.String()
				assert.NotContains(t, v, f.session.ID, "attribute %q leaks the session", a.Key)
				assert.NotContains(t, v, f.session.FamilyID.String(), "attribute %q leaks the family", a.Key)
				assert.False(t, strings.Contains(v, "u-1"), "attribute %q leaks the user", a.Key)

				return true
			})
		})
	}
}

// retrying is a consumer interceptor that runs the rest of the chain twice and
// returns the second result, a retry the consumer is entitled to write.
func retrying() httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		_ = next(ex)

		return next(ex)
	})
}

// TestChain_RetriedPassPublishesBeforeGates pins that a consumer interceptor
// outside the gates may call next twice, and that the authenticator, which
// publishes before every gate, succeeds on both passes.
func TestChain_RetriedPassPublishesBeforeGates(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		retry  bool
		assert func(t *testing.T, o publishOutcome)
	}

	cases := []testCase{
		{
			name:  "no retry (control)",
			retry: false,
			assert: func(t *testing.T, o publishOutcome) {
				t.Helper()

				require.True(t, o.probe.reached)
				require.NoError(t, o.probe.err)
				assert.True(t, o.handlerRan)
				assert.Equal(t, http.StatusOK, o.status)
			},
		},
		{
			name:  "next called twice by an interceptor outside the gates",
			retry: true,
			assert: func(t *testing.T, o publishOutcome) {
				t.Helper()

				require.True(t, o.probe.reached)
				require.NoError(t, o.probe.err, "the second pass's publication before the gates was refused")
				assert.True(t, o.handlerRan)
				assert.Equal(t, http.StatusOK, o.status)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)
			o := publishOutcome{probe: &publishProbe{}}

			opts := []httpsec.Option{
				httpsec.WithSessions(f.sessions),
				enableMFAFor(t),
				httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions}),
				authenticatedOnly(t),
				httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, o.probe), httpsec.OrderBearerToken),
			}
			if tc.retry {
				opts = append(opts, httpsec.RegisterInterceptor(retrying(), httpsec.Before(httpsec.OrderBearerToken)))
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			h := chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				o.handlerRan = true
				o.session, _ = httpsec.SessionFromContext(r.Context())
				_, o.authenticated = authenticate.AuthenticationFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil))
			o.status = rec.Code

			tc.assert(t, o)
		})
	}
}

// TestChain_SecondChainCannotPublishPastFirstChainsGates pins that a session
// owing a second factor, published by a chain mounted inside a gated chain's
// gates, never reaches the handler as an authenticated caller no gate judged,
// whichever authenticator publishes it and however deep the chain is mounted.
// The controls pin what stays allowed: publishing inside the gated chain
// before its gates, and publishing on a context whose gated run has finished.
func TestChain_SecondChainCannotPublishPastFirstChainsGates(t *testing.T) {
	t.Parallel()

	permitAll := func(t *testing.T) httpsec.Option {
		t.Helper()

		return httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t)), authorize.Rule[httpsec.Request]{
			Match:   func(httpsec.Request) bool { return true },
			Require: authorize.PermitAll(),
		})
	}

	// gated is the outer chain: the second-factor gate on, nothing
	// authenticating, every request permitted, so whatever it mounts runs
	// inside its gates.
	gated := func(t *testing.T, f resolveFixture) *httpsec.Chain {
		t.Helper()

		a, err := httpsec.New(
			httpsec.WithSessions(f.sessions),
			enableMFAFor(t),
			httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions}),
			permitAll(t),
		)
		require.NoError(t, err)

		return a
	}

	// publishing is a gateless chain whose consumer authenticator publishes
	// the fixture's session at the bearer slot.
	publishing := func(t *testing.T, f resolveFixture, probe *publishProbe) *httpsec.Chain {
		t.Helper()

		b, err := httpsec.New(
			httpsec.WithSessions(f.sessions),
			authenticatedOnly(t),
			httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe), httpsec.OrderBearerToken),
		)
		require.NoError(t, err)

		return b
	}

	// refusedInside is the fix: the request is answered with a 500 and the
	// handler never runs.
	refusedInside := func(t *testing.T, o publishOutcome) {
		t.Helper()

		assert.False(t, o.handlerRan, "the handler ran with a session no gate judged (status %d)", o.status)
		assert.Equal(t, http.StatusInternalServerError, o.status)
	}

	// refusedInsideByPublisher is refusedInside for a consumer publisher,
	// whose PublishSession returned a configuration error naming the fix.
	refusedInsideByPublisher := func(t *testing.T, o publishOutcome) {
		t.Helper()

		require.True(t, o.probe.reached, "the inner chain's publisher never ran (status %d)", o.status)
		refusedInside(t, o)
		require.ErrorIs(t, o.probe.err, httpsec.ErrConfig)
		assert.Contains(t, o.probe.err.Error(), "outside the other chain's gates")
	}

	type testCase struct {
		name string
		// authorization is the request's Authorization header, empty for none.
		authorization string
		// build returns the handler-wrapping function and the probe of the
		// owing publisher.
		build  func(t *testing.T, f resolveFixture, probe *publishProbe) func(http.Handler) http.Handler
		assert func(t *testing.T, o publishOutcome)
	}

	cases := []testCase{
		{
			name: "owing session published inside the gated chain, before its gates (control)",
			build: func(t *testing.T, f resolveFixture, probe *publishProbe) func(http.Handler) http.Handler {
				t.Helper()

				a, err := httpsec.New(
					httpsec.WithSessions(f.sessions),
					enableMFAFor(t),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions}),
					permitAll(t),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe), httpsec.OrderBearerToken),
				)
				require.NoError(t, err)

				return a.Middleware()
			},
			assert: func(t *testing.T, o publishOutcome) {
				t.Helper()

				require.True(t, o.probe.reached)
				require.NoError(t, o.probe.err)
				assert.False(t, o.handlerRan, "the handler was reached with a session owing a second factor (status %d)", o.status)
				assert.NotEqual(t, http.StatusOK, o.status)
			},
		},
		{
			name: "owing session published by a second ungated chain mounted behind the gated chain",
			build: func(t *testing.T, f resolveFixture, probe *publishProbe) func(http.Handler) http.Handler {
				t.Helper()

				a, b := gated(t, f), publishing(t, f, probe)

				return func(h http.Handler) http.Handler { return a.Middleware()(b.Middleware()(h)) }
			},
			assert: func(t *testing.T, o publishOutcome) {
				t.Helper()

				require.True(t, o.probe.reached, "the second chain's publisher never ran (status %d)", o.status)
				assert.False(t, o.handlerRan && o.authenticated,
					"the handler ran with session owing a second factor as an authenticated caller no gate judged (status %d, publish err %v)", o.status, o.probe.err)
				refusedInsideByPublisher(t, o)
			},
		},
		{
			name:          "built-in authenticator inside the gates",
			authorization: "Bearer ",
			build: func(t *testing.T, f resolveFixture, _ *publishProbe) func(http.Handler) http.Handler {
				t.Helper()

				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

				a := gated(t, f)
				b, err := httpsec.New(
					httpsec.WithLogger(slog.New(slog.DiscardHandler)),
					httpsec.WithClock(f.clk),
					httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: f.sessions, Users: users}),
					authenticatedOnly(t),
				)
				require.NoError(t, err)

				return func(h http.Handler) http.Handler { return a.Middleware()(b.Middleware()(h)) }
			},
			assert: refusedInside,
		},
		{
			name: "third chain inside the gates",
			build: func(t *testing.T, f resolveFixture, probe *publishProbe) func(http.Handler) http.Handler {
				t.Helper()

				a := gated(t, f)
				b, err := httpsec.New(httpsec.WithSessions(f.sessions), permitAll(t))
				require.NoError(t, err)

				c := publishing(t, f, probe)

				return func(h http.Handler) http.Handler { return a.Middleware()(b.Middleware()(c.Middleware()(h))) }
			},
			assert: refusedInsideByPublisher,
		},
		{
			name: "gated chain inside the gates",
			build: func(t *testing.T, f resolveFixture, probe *publishProbe) func(http.Handler) http.Handler {
				t.Helper()

				// The inner chain's own gate does not confine a session owing a
				// second factor, so only the outer chain's gates could judge it.
				a := gated(t, f)
				b, err := httpsec.New(
					httpsec.WithSessions(f.sessions),
					httpsec.EnablePasswordChangeGate(f.sessions),
					authenticatedOnly(t),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe), httpsec.OrderBearerToken),
				)
				require.NoError(t, err)

				return func(h http.Handler) http.Handler { return a.Middleware()(b.Middleware()(h)) }
			},
			assert: refusedInsideByPublisher,
		},
		{
			name: "chain with fewer gates inside the gates",
			build: func(t *testing.T, f resolveFixture, probe *publishProbe) func(http.Handler) http.Handler {
				t.Helper()

				// The inner chain enables one of the outer chain's two gates,
				// and not the second-factor gate the session owes.
				a, err := httpsec.New(
					httpsec.WithSessions(f.sessions),
					enableMFAFor(t),
					httpsec.EnablePasswordChangeGate(f.sessions),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions}),
					permitAll(t),
				)
				require.NoError(t, err)

				b, err := httpsec.New(
					httpsec.WithSessions(f.sessions),
					httpsec.EnablePasswordChangeGate(f.sessions),
					authenticatedOnly(t),
					httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, probe), httpsec.OrderBearerToken),
				)
				require.NoError(t, err)

				return func(h http.Handler) http.Handler { return a.Middleware()(b.Middleware()(h)) }
			},
			assert: refusedInsideByPublisher,
		},
		{
			name: "finished outer run (control)",
			build: func(t *testing.T, f resolveFixture, probe *publishProbe) func(http.Handler) http.Handler {
				t.Helper()

				a, b := gated(t, f), publishing(t, f, probe)

				// The context the gated chain handed its handler, from inside its
				// gates, is kept past the run and sent through the second chain.
				return func(h http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { //nolint:contextcheck // deliberately serves a context kept from a finished run
						var kept context.Context

						a.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
							kept = r.Context()
						})).ServeHTTP(httptest.NewRecorder(), r)
						require.NotNil(t, kept, "the gated chain's handler never ran")

						b.Middleware()(h).ServeHTTP(w, r.WithContext(kept)) //nolint:contextcheck // the kept context is the point of this case
					})
				}
			},
			assert: func(t *testing.T, o publishOutcome) {
				t.Helper()

				require.True(t, o.probe.reached)
				require.NoError(t, o.probe.err, "a finished run's gates refused a publication")
				assert.True(t, o.handlerRan)
				assert.Equal(t, http.StatusOK, o.status)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)
			s, err := f.sessions.Load(t.Context(), f.session.ID)
			require.NoError(t, err)
			s.MFA = session.MFAPending
			require.NoError(t, f.sessions.Save(t.Context(), s))

			o := publishOutcome{probe: &publishProbe{}}

			h := tc.build(t, f, o.probe)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				o.handlerRan = true
				o.session, _ = httpsec.SessionFromContext(r.Context())
				_, o.authenticated = authenticate.AuthenticationFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization+f.session.ID)
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			o.status = rec.Code

			tc.assert(t, o)
		})
	}
}

// keepingNextErr is a consumer interceptor that keeps what the rest of the chain
// returned on got and returns it unchanged.
func keepingNextErr(got *error) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		*got = next(ex)

		return *got
	})
}

// TestChain_ForwardFromHandlerThroughGatedChain pins that a handler, which runs
// inside its chain's gates, may forward the request in-process through a chain
// enabling every gate its own chain enables, the same chain included: the
// forward's authenticator publishes, and the forward's own gates judge what it
// published.
func TestChain_ForwardFromHandlerThroughGatedChain(t *testing.T) {
	t.Parallel()

	const forwardedPath = "/forwarded"

	// forwardOutcome is what one forwarded request came to.
	type forwardOutcome struct {
		status       int
		forwardedRan bool
		// outer and inner are the probes of the outer request's and the
		// forward's publishers.
		outer, inner *publishProbe
		// innerErr is what the forward's chain returned past its bearer slot.
		innerErr error
	}

	// chainWith is a chain enabling the second-factor gate whose consumer
	// authenticator publishes the session named by id, and keeps what the
	// rest of its chain returned on got.
	chainWith := func(t *testing.T, f resolveFixture, id string, probe *publishProbe, got *error) *httpsec.Chain {
		t.Helper()

		c, err := httpsec.New(
			httpsec.WithSessions(f.sessions),
			enableMFAFor(t),
			authenticatedOnly(t),
			httpsec.RegisterInterceptor(keepingNextErr(got), httpsec.Before(httpsec.OrderBearerToken)),
			httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, id, false, probe), httpsec.OrderBearerToken),
		)
		require.NoError(t, err)

		return c
	}

	// owingSession stores a second session of the fixture's user still owing
	// a second factor, and returns its ID.
	owingSession := func(t *testing.T, f resolveFixture) string {
		t.Helper()

		s, err := f.sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
		require.NoError(t, err)
		s.MFA = session.MFAPending
		require.NoError(t, f.sessions.Save(t.Context(), s))

		return s.ID
	}

	type testCase struct {
		name string
		// build returns the outer chain and the chain the handler forwards
		// through.
		build  func(t *testing.T, f resolveFixture, o *forwardOutcome) (outer, inner *httpsec.Chain)
		assert func(t *testing.T, o forwardOutcome)
	}

	cases := []testCase{
		{
			name: "forward through the same chain (control)",
			build: func(t *testing.T, f resolveFixture, o *forwardOutcome) (*httpsec.Chain, *httpsec.Chain) {
				t.Helper()

				// One probe serves both passes: each publishes the full
				// session, and both must succeed.
				o.inner = o.outer
				c := chainWith(t, f, f.session.ID, o.outer, &o.innerErr)

				return c, c
			},
			assert: func(t *testing.T, o forwardOutcome) {
				t.Helper()

				require.True(t, o.inner.reached)
				require.NoError(t, o.inner.err, "the forward's publication was refused")
				assert.NotErrorIs(t, o.innerErr, httpsec.ErrConfig)
				assert.True(t, o.forwardedRan)
				assert.Equal(t, http.StatusNoContent, o.status)
			},
		},
		{
			name: "forward through a chain with the same gates",
			build: func(t *testing.T, f resolveFixture, o *forwardOutcome) (*httpsec.Chain, *httpsec.Chain) {
				t.Helper()

				var outerErr error

				return chainWith(t, f, f.session.ID, o.outer, &outerErr),
					chainWith(t, f, owingSession(t, f), o.inner, &o.innerErr)
			},
			assert: func(t *testing.T, o forwardOutcome) {
				t.Helper()

				require.True(t, o.outer.reached)
				require.NoError(t, o.outer.err)
				require.True(t, o.inner.reached, "the forward's publisher never ran (status %d)", o.status)
				require.NoError(t, o.inner.err, "the forward's publication was refused")

				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, o.innerErr, &challenge, "the forward's own gate did not judge its session")
				assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
				assert.False(t, o.forwardedRan, "the forwarded handler ran with a session owing a second factor")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)
			o := forwardOutcome{outer: &publishProbe{}, inner: &publishProbe{}}
			outer, inner := tc.build(t, f, &o)

			forwarded := inner.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				o.forwardedRan = true
				w.WriteHeader(http.StatusNoContent)
			}))

			h := outer.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fwd := r.Clone(r.Context())
				fwd.URL.Path = forwardedPath
				fwd.RequestURI = forwardedPath
				forwarded.ServeHTTP(w, fwd)
			}))

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil))
			o.status = rec.Code

			tc.assert(t, o)
		})
	}
}
