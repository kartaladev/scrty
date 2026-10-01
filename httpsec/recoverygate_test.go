package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// recoveryLifetime is how long a recovery-pending session lives in these
// tests, the recovery default.
const recoveryLifetime = 15 * time.Minute

// recoveryCodesPath is where the saved-code endpoints answer by default. A
// recovery-pending session must not reach it: a set generated there would be a
// new way back in, minted by a session that has bound nothing.
const recoveryCodesPath = "/recovery/codes"

// recoveryPending is a live session for the enrolling user, created by a
// completed account recovery and marked recovery-pending as the recovery
// marks it.
func (h *enrolHarness) recoveryPending(t *testing.T) *session.Session {
	t.Helper()

	s, err := h.sessions.Create(t.Context(), testMFAUser, session.WithFirstFactor(factor.Recovery))
	require.NoError(t, err)

	h.sessions.MarkRecoveryPending(s, recoveryLifetime, s.CreatedAt)
	require.NoError(t, h.sessions.Save(t.Context(), s))

	return s
}

// TestRecoveryGate pins what a recovery-pending session may reach: a POST
// under an enrolment prefix while the enrolment path is on, a POST to the
// password-change resolve endpoint, and a POST to logout. Everything else is
// refused with an account-recovery challenge carrying the session, before the
// enrolment gate, the second-factor gate, the password-change gate or anything
// behind them runs.
func TestRecoveryGate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// full serves a fully authenticated session instead of a
		// recovery-pending one.
		full bool

		// withoutEnrolment builds the chain with no enrolment path, so its
		// prefixes are routes like any other.
		withoutEnrolment bool

		logoutOpts []httpsec.LogoutOption
		enrolOpts  []httpsec.EnrolmentOption

		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, h *enrolHarness, s *session.Session, w *gateWitnesses, out served)
	}

	get := func(path string) func(ctx context.Context) *http.Request {
		return func(ctx context.Context) *http.Request {
			return httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		}
	}

	postTo := func(path, body string) func(ctx context.Context) *http.Request {
		return func(ctx context.Context) *http.Request { return post(ctx, path, body) }
	}

	head := func(path string) func(ctx context.Context) *http.Request {
		return func(ctx context.Context) *http.Request {
			return httptest.NewRequestWithContext(ctx, http.MethodHead, path, nil)
		}
	}

	challenged := func(t *testing.T, h *enrolHarness, s *session.Session, w *gateWitnesses, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch)
		assert.Equal(t, policy.ChallengeAccountRecovery, ch.Kind)
		require.NotNil(t, ch.Session, "the refusal carries the session, for the consumer to prompt on")
		assert.Equal(t, s.ID, ch.Session.ID)
		assert.Empty(t, ch.Token, "a gate challenges a session that exists, so it issues nothing")
		assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))

		assert.False(t, out.handlerRan, "the handler does not run")
		assert.False(t, w.consumer.Load(), "no consumer interceptor behind the gates runs")
		assert.False(t, w.authorizer.Load(), "the authorizer does not run")
		assert.False(t, w.change.Load(), "no password is changed")

		_, ok := h.enrolment(t)
		assert.False(t, ok, "nothing is enrolled")
		assert.Equal(t, session.MFARecoveryPending, h.stored(t, s.ID).MFA, "the session stays recovery-pending")
	}

	cases := []testCase{
		{
			name:    "a protected route",
			request: get("/invoices"),
			assert:  challenged,
		},
		{
			name:    "a protected route written by POST",
			request: postTo("/invoices", "amount=10"),
			assert:  challenged,
		},
		{
			name:    "the enrolment begin endpoint is reachable",
			request: postTo(enrolBeginPath, ""),
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, w *gateWitnesses, out served) {
				t.Helper()

				begun(t, out)
				assert.False(t, w.consumer.Load(), "the endpoint answers before anything behind the gates")

				e, ok := h.enrolment(t)
				require.True(t, ok, "a pending enrolment is begun")
				assert.True(t, e.ConfirmedAt.IsZero(), "a begun enrolment is pending until it is confirmed")
			},
		},
		{
			name:    "the verify endpoint is refused and no code is verified",
			request: postTo(testMFAVerifyPath, "code="+testMFACode),
			assert:  challenged,
		},
		{
			name:    "a GET on the begin path",
			request: get(enrolBeginPath),
			assert:  challenged,
		},
		{
			name:             "a POST under an enrolment prefix without the enrolment path",
			withoutEnrolment: true,
			request:          postTo(enrolBeginPath, ""),
			assert:           challenged,
		},
		{
			name:    "the password-change resolve endpoint is reachable",
			request: postTo(passwordResolvePath, "password=new"),
			assert: func(t *testing.T, _ *enrolHarness, _ *session.Session, w *gateWitnesses, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.True(t, w.change.Load(), "the consumer's function runs")
			},
		},
		{
			name:    "a GET on the password-change resolve path",
			request: get(passwordResolvePath),
			assert:  challenged,
		},
		{
			name:    "logout ends the session",
			request: postTo(httpsec.DefaultLogoutPath, ""),
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, _ *gateWitnesses, out served) {
				t.Helper()

				require.NoError(t, out.err, "a recovery-pending session can always log out")

				_, err := h.sessions.Load(t.Context(), s.ID)
				require.Error(t, err, "the session is ended, and its handle no longer loads")
			},
		},
		{
			// The gate reads the chain's final logout path at assembly, not
			// whatever was set when it was enabled.
			name:       "a consumer logout path",
			logoutOpts: []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/session/end")},
			request:    postTo("/session/end", ""),
			assert: func(t *testing.T, h *enrolHarness, s *session.Session, _ *gateWitnesses, out served) {
				t.Helper()

				require.NoError(t, out.err)

				_, err := h.sessions.Load(t.Context(), s.ID)
				require.Error(t, err, "the session is ended")
			},
		},
		{
			name:    "a GET on the logout path",
			request: get(httpsec.DefaultLogoutPath),
			assert:  challenged,
		},
		{
			// A path that merely starts with an enrolment prefix is not under
			// it.
			name:    "a lookalike of the begin prefix",
			request: postTo(httpsec.DefaultEnrolmentBeginPrefix+"-evil", ""),
			assert:  challenged,
		},
		{
			name:    "the logout path with a trailing slash",
			request: postTo(httpsec.DefaultLogoutPath+"/", ""),
			assert:  challenged,
		},
		{
			name:    "the password-change resolve path with a trailing slash",
			request: postTo(passwordResolvePath+"/", "password=new"),
			assert:  challenged,
		},
		{
			// With email confirmation off the path serves no confirm-email
			// endpoint, so its prefix is a route like any other.
			name:      "the email-confirm prefix without email confirmation",
			enrolOpts: []httpsec.EnrolmentOption{httpsec.WithoutEmailConfirmation()},
			request:   postTo(httpsec.DefaultEnrolmentEmailConfirmPrefix+"/totp", "code=000000"),
			assert:    challenged,
		},
		{
			name:    "a HEAD on the logout path",
			request: head(httpsec.DefaultLogoutPath),
			assert:  challenged,
		},
		{
			// A set generated here would be a new way back in, minted by a
			// session that has bound nothing.
			name:    "the saved-code endpoint",
			request: postTo(recoveryCodesPath, ""),
			assert:  challenged,
		},
		{
			name:    "a fully authenticated session passes untouched",
			full:    true,
			request: get("/invoices"),
			assert: func(t *testing.T, _ *enrolHarness, _ *session.Session, w *gateWitnesses, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.True(t, out.handlerRan, "the gate guards the recovery-pending state alone")
				assert.True(t, w.consumer.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			h.logoutOpts = tc.logoutOpts
			h.enrolOpts = tc.enrolOpts
			h.withoutGate = tc.withoutEnrolment

			var s *session.Session
			if tc.full {
				s = h.sessionIn(t, factor.Password, session.MFASatisfied)
			} else {
				s = h.recoveryPending(t)
			}

			w := &gateWitnesses{}
			h.extra = append(w.options(h), httpsec.EnableRecoveryGateForTest())

			tc.assert(t, h, s, w, serve(t, h.chain(t, s), tc.request(t.Context())))
		})
	}
}

// TestRecoveryGateAnonymous pins that the gate guards sessions and nothing
// else: a request carrying none is the business of the authentication
// interceptors outside it.
func TestRecoveryGateAnonymous(t *testing.T) {
	t.Parallel()

	h := newEnrolHarness(t)
	h.extra = []httpsec.Option{httpsec.EnableRecoveryGateForTest()}

	out := serve(t, h.chain(t, nil), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil))

	require.NoError(t, out.err)
	assert.True(t, out.handlerRan)
}

// TestRecoveryGatePerRequestPhase pins what bearer authentication's
// per-request phase does for a recovery-pending session: a deny still refuses,
// and a challenge is not marked on the session, because marking one would
// take the session out of the recovery-pending state without a binding. It
// has its own table because it runs the real bearer over a real session
// store, which TestRecoveryGate's harness stands in for.
func TestRecoveryGatePerRequestPhase(t *testing.T) {
	t.Parallel()

	// terms is a consumer's own challenge kind.
	const terms policy.ChallengeKind = 100

	type testCase struct {
		name   string
		engine func(t *testing.T) *policy.Engine

		// enforcers are the consumer kinds declared with
		// WithChallengeEnforcer.
		enforcers []policy.ChallengeKind

		// raised is what Exchange.RaisedChallenge reported to an interceptor
		// between bearer and the recovery gate, zero when none ran.
		assert func(t *testing.T, out served, stored *session.Session, raised policy.ChallengeKind)
	}

	cases := []testCase{
		{
			// A user required to use MFA whose enrolments the recovery
			// removed: the requirement policy raises the enrolment challenge.
			name: "a per-request challenge is not marked",
			engine: func(t *testing.T) *policy.Engine {
				return challengingIn(t, policy.PerRequest, policy.ChallengeMFAEnrolment)
			},
			assert: func(t *testing.T, out served, stored *session.Session, _ policy.ChallengeKind) {
				t.Helper()

				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Equal(t, policy.ChallengeAccountRecovery, ch.Kind)
				assert.False(t, out.handlerRan)

				assert.Equal(t, session.MFARecoveryPending, stored.MFA, "the session is still recovery-pending")
			},
		},
		{
			name: "a per-request deny still refuses",
			engine: func(t *testing.T) *policy.Engine {
				return denyingIn(t, policy.PerRequest, policy.ErrAccountLocked)
			},
			assert: func(t *testing.T, out served, stored *session.Session, _ policy.ChallengeKind) {
				t.Helper()

				require.ErrorIs(t, out.err, policy.ErrAccountLocked)
				assert.False(t, out.handlerRan)
				assert.Equal(t, session.MFARecoveryPending, stored.MFA)
			},
		},
		{
			// Only the mark is skipped for a recovery-pending session: a kind
			// nothing enforces is still a wiring mistake, refused as one.
			name: "a consumer kind nothing enforces is refused as a configuration error",
			engine: func(t *testing.T) *policy.Engine {
				return challengingIn(t, policy.PerRequest, terms)
			},
			assert: func(t *testing.T, out served, stored *session.Session, _ policy.ChallengeKind) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrConfig)
				assert.ErrorContains(t, out.err, "ChallengeKind(100)")

				var ch *httpsec.ChallengeError
				assert.NotErrorAs(t, out.err, &ch, "a wiring fault is not a challenge the caller could answer")
				assert.False(t, out.handlerRan)
				assert.Equal(t, session.MFARecoveryPending, stored.MFA)
			},
		},
		{
			name:      "a declared consumer kind is still recorded on the exchange",
			enforcers: []policy.ChallengeKind{terms},
			engine: func(t *testing.T) *policy.Engine {
				return challengingIn(t, policy.PerRequest, terms)
			},
			assert: func(t *testing.T, out served, stored *session.Session, raised policy.ChallengeKind) {
				t.Helper()

				assert.Equal(t, terms, raised, "the consumer's gate can read the kind it enforces")

				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Equal(t, policy.ChallengeAccountRecovery, ch.Kind, "the recovery gate still refuses")
				assert.False(t, out.handlerRan)
				assert.Equal(t, session.MFARecoveryPending, stored.MFA)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC))

			sessions, err := session.NewManager(session.WithClock(clk),
				session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
			require.NoError(t, err)

			s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Recovery))
			require.NoError(t, err)

			sessions.MarkRecoveryPending(s, recoveryLifetime, clk.Now())
			require.NoError(t, sessions.Save(t.Context(), s))

			ctrl := gomock.NewController(t)
			verifier := NewMockVerifier(ctrl)
			verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).
				Return(token.NewClaims(testSubject, s.ID), nil)

			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)

			var raised policy.ChallengeKind

			observer := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				raised = ex.RaisedChallenge()
				return next(ex)
			})

			opts := []httpsec.Option{
				httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Verifier: verifier, Sessions: sessions, Users: users,
				}),
				httpsec.WithPolicyEngine(tc.engine(t)),
				httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment),
				httpsec.EnableRecoveryGateForTest(),
				httpsec.RegisterInterceptor(observer, httpsec.After(httpsec.OrderBearerToken)),
			}
			for _, kind := range tc.enforcers {
				opts = append(opts, httpsec.WithChallengeEnforcer(kind))
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil)
			req.Header.Set("Authorization", "Bearer abc.def.ghi")

			out := serve(t, chain, req)

			stored, err := sessions.Load(t.Context(), s.ID)
			require.NoError(t, err)

			tc.assert(t, out, stored, raised)
		})
	}
}

// TestRecoveryGateEnforcesItsKind pins that no policy may declare the
// account-recovery challenge. Only the recovery gate raises it, directly; a
// policy raising it would challenge an ordinary session that nothing confines,
// so the declaration fails assembly whether or not the gate is on, and the
// error says why.
func TestRecoveryGateEnforcesItsKind(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.ErrorContains(t, err, "ChallengeAccountRecovery", "the error names the kind")
		assert.ErrorContains(t, err, "only the recovery gate raises", "the error names the reason")
	}

	cases := []testCase{
		{
			name:   "with the gate the chain is refused",
			opts:   []httpsec.Option{httpsec.EnableRecoveryGateForTest()},
			assert: refused,
		},
		{
			name:   "without it the chain is refused for the same reason",
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithPolicyEngine(engineOf(t, declaring{kinds: []policy.ChallengeKind{policy.ChallengeAccountRecovery}})),
			}, tc.opts...)...)

			tc.assert(t, err)
		})
	}
}
