package httpsec_test

import (
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

// TestPublishSession_GateMarkOnOneExchange pins how the mark the first gate
// sets lives on one exchange run through Assemble: it is the exchange's alone,
// so a different chain nested inside the gated one refuses a publication (it
// fails closed, as design decision 2 accepts), and a fresh run of the same
// exchange starts unmarked.
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
// record a late publication leaves: one per sampling window however many
// requests are refused, carrying neither the session nor the user it named.
func TestPublishSession_LateRefusalIsLoggedSampledWithoutIdentifiers(t *testing.T) {
	t.Parallel()

	f := newResolveFixture(t)
	logs := &capturingHandler{}

	chain, err := httpsec.New(
		httpsec.WithLogger(slog.New(logs)),
		httpsec.WithSessions(f.sessions),
		httpsec.EnablePasswordChangeGate(f.sessions),
		httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, &publishProbe{}),
			httpsec.After(httpsec.OrderPasswordChange)),
	)
	require.NoError(t, err)

	h := chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
}
