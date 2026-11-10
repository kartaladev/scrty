package httpsec_test

import (
	"errors"
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
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// errEnrolmentStoreDown is the enrolment store failure a second-factor
// method's lookup reports in the rows that pin a failed method lookup.
var errEnrolmentStoreDown = errors.New("enrolment store down")

// assigningSession is a consumer interceptor that puts s on the exchange
// without PublishSession, the way past the gates that PublishSession does not
// police. A real consumer can only assign the exported fields, which changes
// ex.Session and ex.Authentication and nothing a handler reads; the test also
// writes the context (through helpers only tests have) so the rows with rules
// can authenticate the request. A nil s assigns nothing.
func assigningSession(s *session.Session) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if s != nil {
			p := testPrincipal()
			p.ID = s.UserID

			ex.Authentication = &authenticate.Authentication{Principal: p, Time: time.Now()}
			ex.Session = s
			ex.SetContext(httpsec.WithSession(httpsec.WithCaller(ex.Context(), ex.Authentication), s))
		}

		return next(ex)
	})
}

// enrolledEmailMethod is a second-factor method the harness's user is enrolled
// on, so a second-factor challenge offers it; failing makes its enrolment
// lookup fail instead.
func enrolledEmailMethod(t *testing.T, failing bool) mfa.Method {
	t.Helper()

	m := NewMockMethod(gomock.NewController(t))
	m.EXPECT().Name().Return("emailcode").AnyTimes()
	m.EXPECT().Channel().Return(factor.Email).AnyTimes()
	m.EXPECT().Response().Return(mfa.FormField("code", 64)).AnyTimes()

	if failing {
		m.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(false, errEnrolmentStoreDown).AnyTimes()
	} else {
		m.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()
	}

	return m
}

// TestAuthorization_RefusesOwingSession pins that the authorization stage
// refuses a session that still owes a built-in challenge, with the error the
// gate for that challenge returns, before the consumer's rules and the
// handler, whether or not rules are configured.
//
// The session is assigned to the exchange directly by a consumer interceptor
// after logout, past every gate, which is the path PublishSession cannot
// refuse. Each owing row is also run with the same session carried at the
// bearer slot, where the gate refuses it, and the two refusals are compared:
// kind, session, second-factor methods and status.
func TestAuthorization_RefusesOwingSession(t *testing.T) {
	t.Parallel()

	type outcome struct {
		stage served // the session assigned past the gates
		gate  served // the same session carried at the bearer slot
	}

	type testCase struct {
		name string

		// session builds the session the consumer assigns, nil for none.
		session func(t *testing.T, h *enrolHarness) *session.Session

		// rules configures the authorization stage with a rule requiring an
		// authenticated caller on every request; without it the stage
		// enforces no rules.
		rules bool

		// gates names the built-in gates a chain of the row's own registers,
		// in place of the harness's chain with every gate. Nil means the
		// harness's chain.
		gates []string

		// failingLookup makes the second-factor method lookup fail.
		failingLookup bool

		assert func(t *testing.T, s *session.Session, o outcome)
	}

	inState := func(state session.MFAState, passwordChange bool) func(t *testing.T, h *enrolHarness) *session.Session {
		return func(t *testing.T, h *enrolHarness) *session.Session {
			t.Helper()

			var s *session.Session

			switch state {
			case session.MFARecoveryPending:
				s = h.recoveryPending(t)
			default:
				s = h.sessionIn(t, factor.Password, state)
			}

			if passwordChange {
				s.PasswordChangePending = true
				require.NoError(t, h.sessions.Save(t.Context(), s))
			}

			return s
		}
	}

	// refusedAs is the stage refusing with kind, exactly as the gate does.
	refusedAs := func(kind policy.ChallengeKind) func(t *testing.T, s *session.Session, o outcome) {
		return func(t *testing.T, s *session.Session, o outcome) {
			t.Helper()

			assert.False(t, o.stage.handlerRan, "the handler ran for a session owing %v", kind)
			require.Error(t, o.stage.err, "the stage let a session owing %v through", kind)

			var got *httpsec.ChallengeError
			require.ErrorAs(t, o.stage.err, &got)
			assert.Equal(t, kind, got.Kind)
			require.NotNil(t, got.Session)
			assert.Equal(t, s.ID, got.Session.ID)
			assert.Empty(t, got.Token, "a refusal of a session that exists issues nothing")

			var want *httpsec.ChallengeError
			require.ErrorAs(t, o.gate.err, &want, "control: the gate refuses the same session")
			assert.Equal(t, want.Kind, got.Kind, "the gate's kind")
			assert.Equal(t, want.Methods, got.Methods, "the gate's second-factor methods")
			assert.Equal(t, httpsec.StatusForError(o.gate.err), httpsec.StatusForError(o.stage.err), "the gate's status")

			if kind == policy.ChallengeMFA {
				require.Len(t, got.Methods, 1, "a second-factor refusal offers the usable methods")
				assert.Equal(t, "emailcode", got.Methods[0].Name)
			} else {
				assert.Empty(t, got.Methods)
			}
		}
	}

	permitted := func(t *testing.T, _ *session.Session, o outcome) {
		t.Helper()

		require.NoError(t, o.stage.err)
		assert.True(t, o.stage.handlerRan)
		assert.Equal(t, http.StatusOK, o.stage.rec.Code)
	}

	cases := []testCase{}

	owing := []struct {
		name  string
		state session.MFAState
		pw    bool
		kind  policy.ChallengeKind
	}{
		{name: "recovery pending", state: session.MFARecoveryPending, kind: policy.ChallengeAccountRecovery},
		{name: "enrolment pending", state: session.MFAEnrolmentPending, kind: policy.ChallengeMFAEnrolment},
		{name: "second factor pending", state: session.MFAPending, kind: policy.ChallengeMFA},
		{name: "password change pending", state: session.MFASatisfied, pw: true, kind: policy.ChallengePasswordChange},
		// A session owing two challenges is refused with the one the gates
		// would have met first: recovery, enrolment and second factor before
		// password change.
		{name: "second factor and password change pending", state: session.MFAPending, pw: true, kind: policy.ChallengeMFA},
		{name: "recovery and password change pending", state: session.MFARecoveryPending, pw: true, kind: policy.ChallengeAccountRecovery},
		{name: "enrolment and password change pending", state: session.MFAEnrolmentPending, pw: true, kind: policy.ChallengeMFAEnrolment},
	}

	for _, o := range owing {
		for _, rules := range []bool{true, false} {
			name := o.name + ", without rules"
			if rules {
				name = o.name + ", with rules"
			}

			cases = append(cases, testCase{
				name:    name,
				session: inState(o.state, o.pw),
				rules:   rules,
				assert:  refusedAs(o.kind),
			})
		}
	}

	cases = append(cases,
		testCase{
			name:    "full session, with rules",
			session: inState(session.MFASatisfied, false),
			rules:   true,
			assert:  permitted,
		},
		testCase{
			name:    "full session, without rules",
			session: inState(session.MFASatisfied, false),
			assert:  permitted,
		},
		testCase{
			name:    "full session that never needed a second factor, with rules",
			session: inState(session.MFANone, false),
			rules:   true,
			assert:  permitted,
		},
		testCase{
			// Anonymous is the rules' business, as before: the stage judges a
			// session and there is none.
			name:  "anonymous, with rules",
			rules: true,
			assert: func(t *testing.T, _ *session.Session, o outcome) {
				t.Helper()

				require.ErrorIs(t, o.stage.err, httpsec.ErrAuthenticationRequired)

				var ch *httpsec.ChallengeError
				assert.NotErrorAs(t, o.stage.err, &ch)
				assert.False(t, o.stage.handlerRan)
			},
		},
		testCase{
			name:   "anonymous, without rules",
			assert: permitted,
		},
		testCase{
			// The methods a second-factor refusal offers could not be looked
			// up: the stage answers with the lookup's failure, as the gate
			// does, rather than a challenge offering nothing.
			name:          "second factor pending, method lookup fails",
			session:       inState(session.MFAPending, false),
			rules:         true,
			failingLookup: true,
			assert: func(t *testing.T, _ *session.Session, o outcome) {
				t.Helper()

				require.Error(t, o.gate.err, "control: the gate fails on the lookup")
				require.Error(t, o.stage.err)
				assert.False(t, o.stage.handlerRan)

				var ch *httpsec.ChallengeError
				assert.NotErrorAs(t, o.stage.err, &ch, "no challenge offering a partial list")
				assert.NotContains(t, o.stage.err.Error(), errEnrolmentStoreDown.Error(), "the store's text stays out")
				assert.Equal(t, o.gate.err.Error(), o.stage.err.Error(), "the gate's error")
				assert.Equal(t, httpsec.StatusForError(o.gate.err), httpsec.StatusForError(o.stage.err))
			},
		},
		testCase{
			// The stage backs up the gates the chain registers, and stands in
			// for none it leaves out: with no gate, nothing refused this
			// session before, and the stage does not either.
			name:    "second factor pending, no gate registered",
			session: inState(session.MFAPending, false),
			gates:   []string{},
			rules:   true,
			assert:  permitted,
		},
		testCase{
			name:    "password change pending, no gate registered",
			session: inState(session.MFASatisfied, true),
			gates:   []string{},
			assert:  permitted,
		},
		testCase{
			// The second factor owed has no gate on this chain, so the
			// password change, whose gate is registered, is the challenge
			// refused, as that gate refuses it.
			name:    "second factor and password change pending, only the password-change gate",
			session: inState(session.MFAPending, true),
			gates:   []string{"password change"},
			rules:   true,
			assert: func(t *testing.T, s *session.Session, o outcome) {
				t.Helper()

				var want, got *httpsec.ChallengeError
				require.ErrorAs(t, o.gate.err, &want, "control: the gate refuses the same session")
				require.ErrorAs(t, o.stage.err, &got)
				assert.Equal(t, policy.ChallengePasswordChange, got.Kind)
				assert.Equal(t, want.Kind, got.Kind)
				assert.Equal(t, s.ID, got.Session.ID)
				assert.Empty(t, got.Methods)
				assert.False(t, o.stage.handlerRan)
			},
		},
		testCase{
			name:    "second factor pending, only the password-change gate",
			session: inState(session.MFAPending, false),
			gates:   []string{"password change"},
			assert:  permitted,
		},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			h.extraMethods = []mfa.Method{enrolledEmailMethod(t, tc.failingLookup)}

			var s *session.Session
			if tc.session != nil {
				s = tc.session(t, h)
			}

			// stageOpts are the options every chain of the row shares after
			// the harness's own: the remaining gates and the authorization
			// stage.
			stageOpts := func(t *testing.T) []httpsec.Option {
				t.Helper()

				var opts []httpsec.Option
				if tc.gates == nil {
					opts = append(opts, httpsec.EnableRecoveryGateForTest(), httpsec.EnablePasswordChangeGate(h.sessions))
				}

				for _, gate := range tc.gates {
					require.Equal(t, "password change", gate, "a gate this test cannot register alone")
					opts = append(opts, httpsec.EnablePasswordChangeGate(h.sessions))
				}

				if tc.rules {
					opts = append(opts, httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t)),
						authorize.Rule[httpsec.Request]{
							Match:   func(httpsec.Request) bool { return true },
							Require: authorize.Authenticated(),
						}))
				}

				return opts
			}

			build := func(t *testing.T, carried *session.Session, extra ...httpsec.Option) *httpsec.Chain {
				t.Helper()

				var opts []httpsec.Option
				if tc.gates != nil {
					opts = append([]httpsec.Option{httpsec.WithSessions(h.sessions), h.carries(carried)}, extra...)
				} else {
					h.extra = extra
					opts = h.options(t, carried)
				}

				c, err := httpsec.New(append(opts, stageOpts(t)...)...)
				require.NoError(t, err)

				return c
			}

			request := func() *http.Request {
				return httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil)
			}

			var o outcome

			if s != nil && (tc.gates == nil || len(tc.gates) > 0) {
				o.gate = serve(t, build(t, s), request())
			}

			o.stage = serve(t, build(t, nil, httpsec.RegisterInterceptor(assigningSession(s), httpsec.After(httpsec.OrderLogout))), request())

			tc.assert(t, s, o)
		})
	}
}

// msgOwingAtAuthorization is the record the stage writes when it refuses a
// session owing a built-in challenge.
const msgOwingAtAuthorization = "httpsec: session owing a built-in challenge reached the authorization stage"

// TestAuthorization_OwingRefusalIsLoggedSampledWithoutIdentifiers pins the
// record the stage leaves when it refuses an owing session: one per sampling
// window however many requests are refused, naming that the gates were
// bypassed and where an authenticator belongs, carrying neither the session,
// its family nor its user.
func TestAuthorization_OwingRefusalIsLoggedSampledWithoutIdentifiers(t *testing.T) {
	t.Parallel()

	h := newEnrolHarness(t)
	s := h.sessionIn(t, factor.Password, session.MFAPending)
	logs := &capturingHandler{}

	h.extra = []httpsec.Option{
		httpsec.WithLogger(slog.New(logs)),
		httpsec.RegisterInterceptor(assigningSession(s), httpsec.After(httpsec.OrderLogout)),
	}

	opts := append(h.options(t, nil), httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t))))

	chain, err := httpsec.New(opts...)
	require.NoError(t, err)

	for range 3 {
		got := serve(t, chain, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil))
		require.False(t, got.handlerRan)
		require.Error(t, got.err)
	}

	var owing []slog.Record

	for _, r := range logs.records() {
		if r.Message == msgOwingAtAuthorization {
			owing = append(owing, r)
		}
	}

	require.Len(t, owing, 1, "one record per sampling window")
	assert.Equal(t, slog.LevelError, owing[0].Level)

	owing[0].Attrs(func(a slog.Attr) bool {
		v := a.Value.String()
		assert.NotContains(t, v, s.ID, "attribute %q leaks the session", a.Key)
		assert.NotContains(t, v, s.FamilyID.String(), "attribute %q leaks the family", a.Key)
		assert.False(t, strings.Contains(v, string(s.UserID)), "attribute %q leaks the user", a.Key)

		return true
	})
}

// TestAuthorization_BackstopSurfacesMethodLookupFailure pins that the
// authorization backstop answers a failed second-factor method lookup as the
// gate does, and leaves the operator a record of the store failure.
func TestAuthorization_BackstopSurfacesMethodLookupFailure(t *testing.T) {
	t.Parallel()

	type result struct {
		gate, stage served
		logs        []slog.Record
		sessionID   string
		userID      string
	}

	run := func(t *testing.T, stageRequests int) result {
		t.Helper()

		h := newEnrolHarness(t)
		h.extraMethods = []mfa.Method{enrolledEmailMethod(t, true)}
		s := h.sessionIn(t, factor.Password, session.MFAPending)

		req := func() *http.Request {
			return httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil)
		}

		gateChain, err := httpsec.New(h.options(t, s)...)
		require.NoError(t, err)

		logs := &capturingHandler{}
		h.extra = []httpsec.Option{
			httpsec.WithLogger(slog.New(logs)),
			httpsec.RegisterInterceptor(assigningSession(s), httpsec.After(httpsec.OrderLogout)),
		}
		stageOpts := append(h.options(t, nil), httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t))))
		stageChain, err := httpsec.New(stageOpts...)
		require.NoError(t, err)

		gate := serve(t, gateChain, req())

		var stage served
		for range stageRequests {
			stage = serve(t, stageChain, req())
		}

		return result{gate: gate, stage: stage, logs: logs.records(), sessionID: s.ID, userID: string(s.UserID)}
	}

	type testCase struct {
		name string
		// requests is how many times the stage chain is served.
		requests int
		assert   func(t *testing.T, r result)
	}

	cases := []testCase{
		{
			name:     "status and error class match the gate",
			requests: 1,
			assert: func(t *testing.T, r result) {
				t.Helper()
				require.Error(t, r.gate.err, "control: the gate fails on the lookup")
				require.Error(t, r.stage.err)
				assert.False(t, r.stage.handlerRan)
				assert.Equal(t, httpsec.StatusForError(r.gate.err), httpsec.StatusForError(r.stage.err))
				assert.ErrorIs(t, r.stage.err, errEnrolmentStoreDown, "wrapped store error, as the gate's")
				assert.Equal(t, r.gate.err.Error(), r.stage.err.Error())
			},
		},
		{
			name:     "log lets an operator see the lookup failed, sampled, with the hint and without the store's text or identifiers",
			requests: 3,
			assert: func(t *testing.T, r result) {
				t.Helper()
				require.Error(t, r.stage.err)

				var found []slog.Record

				for _, rec := range r.logs {
					assert.NotEqual(t, msgOwingAtAuthorization, rec.Message, "the plain wiring record is not written on the lookup-failure path")

					if strings.Contains(rec.Message, "could not be looked up") {
						found = append(found, rec)
					}
				}

				require.Len(t, found, 1, "one lookup-failure record per sampling window however many requests fail")
				assert.Equal(t, slog.LevelError, found[0].Level)

				var hint string

				found[0].Attrs(func(a slog.Attr) bool {
					if a.Key == "hint" {
						hint = a.Value.String()
					}

					return true
				})
				assert.Equal(t, "the gates were bypassed; register the authenticator at OrderBearerToken", hint)
				assert.NotContains(t, found[0].Message, errEnrolmentStoreDown.Error())

				found[0].Attrs(func(a slog.Attr) bool {
					v := a.Value.String()
					assert.NotContains(t, v, errEnrolmentStoreDown.Error(), "attribute %q leaks the store error", a.Key)
					assert.NotContains(t, v, r.sessionID, "attribute %q leaks the session", a.Key)
					assert.NotContains(t, v, r.userID, "attribute %q leaks the user", a.Key)

					return true
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, run(t, tc.requests))
		})
	}
}

// TestAuthorization_BackstopLooksUpMethodsOnlyForSecondFactor observes through
// a mock expectation that the method store is not consulted for owed kinds
// other than the second factor.
func TestAuthorization_BackstopLooksUpMethodsOnlyForSecondFactor(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		state session.MFAState
		pw    bool
		// assert receives the stage's outcome; the mock's Times(0) on the
		// method lookup is checked when the controller finishes.
		assert func(t *testing.T, got served)
	}

	owedKind := func(want policy.ChallengeKind) func(t *testing.T, got served) {
		return func(t *testing.T, got served) {
			t.Helper()

			require.Error(t, got.err)
			assert.False(t, got.handlerRan)

			var ch *httpsec.ChallengeError
			require.ErrorAs(t, got.err, &ch)
			assert.Equal(t, want, ch.Kind)
		}
	}

	cases := []testCase{
		{name: "enrolment pending", state: session.MFAEnrolmentPending, assert: owedKind(policy.ChallengeMFAEnrolment)},
		{name: "password change pending", state: session.MFASatisfied, pw: true, assert: owedKind(policy.ChallengePasswordChange)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			m := NewMockMethod(gomock.NewController(t))
			m.EXPECT().Name().Return("emailcode").AnyTimes()
			m.EXPECT().Channel().Return(factor.Email).AnyTimes()
			m.EXPECT().Response().Return(mfa.FormField("code", 64)).AnyTimes()
			m.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Times(0)
			h.extraMethods = []mfa.Method{m}

			s := h.sessionIn(t, factor.Password, tc.state)
			if tc.pw {
				s.PasswordChangePending = true
				require.NoError(t, h.sessions.Save(t.Context(), s))
			}

			h.extra = []httpsec.Option{
				httpsec.RegisterInterceptor(assigningSession(s), httpsec.After(httpsec.OrderLogout)),
				httpsec.EnableRecoveryGateForTest(), httpsec.EnablePasswordChangeGate(h.sessions),
				httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t))),
			}
			chain, err := httpsec.New(h.options(t, nil)...)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil)))
		})
	}
}
