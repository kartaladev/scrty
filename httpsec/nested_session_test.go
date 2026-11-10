package httpsec_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// enclosingPublisher is a consumer's own authenticator on the enclosing,
// gateless chain: it reloads s and publishes it with its user as the caller
// through PublishSession, as the package documentation says a first factor of
// one's own does. A nil s publishes a stateless caller and no session.
func enclosingPublisher(sessions *session.Sessions, s *session.Session) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		p := testPrincipal()
		p.ID = testMFAUser

		var loaded *session.Session

		if s != nil {
			var err error

			loaded, err = sessions.Load(ex.Context(), s.ID)
			if err != nil {
				return err
			}
		}

		if err := ex.PublishSession(&authenticate.Authentication{Principal: p, Time: time.Now()}, loaded); err != nil {
			return err
		}

		return next(ex)
	})
}

// contextPastTheGates puts s and its caller on the request context past every gate
// of the chain it is registered on, leaving ex.Session unset: only an
// enclosing chain can leave a session there in production, and this reaches
// the authorization stage's backstop without a gate seeing it first. A nil s
// puts nothing there.
func contextPastTheGates(s *session.Session) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if s != nil {
			p := testPrincipal()
			p.ID = s.UserID

			ex.SetContext(httpsec.WithSession(httpsec.WithCaller(ex.Context(),
				&authenticate.Authentication{Principal: p, Time: time.Now()}), s))
		}

		return next(ex)
	})
}

// cooldownRoute is the route the nested cases mark as sensitive.
var cooldownRoute = httpsec.Route{Method: http.MethodPost, Path: "/account/email"}

// recentRecoveryOf is a record store holding one recovery of the harness's
// user, completed just now, so its cool-down is running.
func recentRecoveryOf(t *testing.T) recovery.RecordStore {
	t.Helper()

	rid, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	at := time.Now().Add(-time.Minute)

	store := recovery.NewMemoryRecordStore()
	require.NoError(t, store.Insert(t.Context(), recovery.Record{
		ID: rid, User: testMFAUser, StartedAt: at, NotBefore: at, CompletedAt: at,
	}))

	return store
}

// nestedOutcome is what the inner chain did with a request.
type nestedOutcome struct {
	code       int
	err        error            // what the inner chain refused with, nil when it served
	handlerRan bool             // the inner chain's handler ran
	served     *session.Session // the session the handler read from the context

	// records are what the inner chain logged.
	records []slog.Record

	// stored is the enclosing session as the store holds it once the request
	// has been answered, nil when the enclosing chain published none.
	stored *session.Session
}

// bypassRecorded reports whether the inner chain's authorization stage logged
// that an owing session reached it past the gates.
func (o nestedOutcome) bypassRecorded() bool {
	return slices.ContainsFunc(o.records, func(r slog.Record) bool { return r.Message == msgOwingAtAuthorization })
}

// TestNestedChain_JudgesEnclosingSession pins that a chain mounted inside a
// gateless chain judges the session that chain published: each built-in that
// judges a session (the recovery, enrolment, second-factor and password-change
// gates, the recovery cool-down and the authorization stage's backstop)
// refuses an owing one with its own error and status, and the inner handler
// does not run. A full session is let through and the handler reads it, and a
// session the inner chain resolves for itself is the one judged.
func TestNestedChain_JudgesEnclosingSession(t *testing.T) {
	t.Parallel()

	type build func(t *testing.T, h *enrolHarness) *session.Session

	type testCase struct {
		name string

		// enclosing is the session the gateless enclosing chain publishes,
		// nil for a stateless caller.
		enclosing build

		// own is the session the inner chain resolves from the request's
		// credential at the bearer slot, nil for none.
		own build

		// late is a session put on the inner chain's context past its gates,
		// nil for none.
		late build

		// rules gives the inner chain an authorization stage requiring an
		// authenticated caller on every request.
		rules bool

		// method and path are the request's; GET /orders when empty.
		method, path string

		assert func(t *testing.T, enclosing, own, late *session.Session, o nestedOutcome)
	}

	inState := func(state session.MFAState, passwordChange bool) build {
		return func(t *testing.T, h *enrolHarness) *session.Session {
			t.Helper()

			var s *session.Session
			if state == session.MFARecoveryPending {
				s = h.recoveryPending(t)
			} else {
				s = h.sessionIn(t, factor.Password, state)
			}

			if passwordChange {
				s.PasswordChangePending = true
				require.NoError(t, h.sessions.Save(t.Context(), s))
			}

			return s
		}
	}

	full := inState(session.MFASatisfied, false)

	// refusedBy is the inner chain refusing with a challenge of kind carrying
	// the session picked from the row's sessions. With atBackstop, the
	// authorization stage refused it and logged the gates' bypass; without,
	// the gate itself refused it and the stage logged nothing, so a gate that
	// stopped judging the enclosing session, leaving the stage to refuse in
	// its place with the same error, is noticed.
	refusedBy := func(atBackstop bool, kind policy.ChallengeKind, status int, pick func(enclosing, own, late *session.Session) *session.Session) func(t *testing.T, enclosing, own, late *session.Session, o nestedOutcome) {
		return func(t *testing.T, enclosing, own, late *session.Session, o nestedOutcome) {
			t.Helper()

			want := pick(enclosing, own, late)

			if atBackstop {
				assert.True(t, o.bypassRecorded(), "the authorization stage did not record the gates' bypass")
			} else {
				assert.False(t, o.bypassRecorded(), "the authorization stage refused in the gate's place")
			}

			assert.False(t, o.handlerRan, "the inner handler ran for a session owing %v", kind)
			assert.Equal(t, status, o.code)

			var got *httpsec.ChallengeError
			require.ErrorAs(t, o.err, &got)
			assert.Equal(t, kind, got.Kind)
			require.NotNil(t, got.Session)
			assert.Equal(t, want.ID, got.Session.ID, "the session judged")
			assert.Empty(t, got.Token, "a gate issues nothing")
		}
	}

	refused := func(kind policy.ChallengeKind, status int, pick func(enclosing, own, late *session.Session) *session.Session) func(t *testing.T, enclosing, own, late *session.Session, o nestedOutcome) {
		return refusedBy(false, kind, status, pick)
	}

	refusedAtBackstop := func(kind policy.ChallengeKind, status int, pick func(enclosing, own, late *session.Session) *session.Session) func(t *testing.T, enclosing, own, late *session.Session, o nestedOutcome) {
		return refusedBy(true, kind, status, pick)
	}

	ofEnclosing := func(enclosing, _, _ *session.Session) *session.Session { return enclosing }
	ofOwn := func(_, own, _ *session.Session) *session.Session { return own }
	ofLate := func(_, _, late *session.Session) *session.Session { return late }

	// served is the inner chain serving its handler the session picked.
	served := func(pick func(enclosing, own, late *session.Session) *session.Session) func(t *testing.T, enclosing, own, late *session.Session, o nestedOutcome) {
		return func(t *testing.T, enclosing, own, late *session.Session, o nestedOutcome) {
			t.Helper()

			require.NoError(t, o.err)
			assert.True(t, o.handlerRan)
			assert.Equal(t, http.StatusOK, o.code)

			want := pick(enclosing, own, late)
			if want == nil {
				assert.Nil(t, o.served, "no session reaches the handler")
				return
			}

			require.NotNil(t, o.served, "the handler reads a session")
			assert.Equal(t, want.ID, o.served.ID, "the session the handler reads")
		}
	}

	cases := []testCase{
		{
			name:      "recovery pending from the enclosing chain",
			enclosing: inState(session.MFARecoveryPending, false),
			assert:    refused(policy.ChallengeAccountRecovery, http.StatusForbidden, ofEnclosing),
		},
		{
			name:      "enrolment pending from the enclosing chain",
			enclosing: inState(session.MFAEnrolmentPending, false),
			assert:    refused(policy.ChallengeMFAEnrolment, http.StatusForbidden, ofEnclosing),
		},
		{
			name:      "second factor pending from the enclosing chain",
			enclosing: inState(session.MFAPending, false),
			assert:    refused(policy.ChallengeMFA, http.StatusUnauthorized, ofEnclosing),
		},
		{
			name:      "password change pending from the enclosing chain",
			enclosing: inState(session.MFASatisfied, true),
			assert:    refused(policy.ChallengePasswordChange, http.StatusForbidden, ofEnclosing),
		},
		{
			// The whole-branch review's reproduction: the inner chain's rule
			// reads the caller from the context and passes, so only the gate
			// stands between the owing session and the handler.
			name:      "second factor pending from the enclosing chain, with rules",
			enclosing: inState(session.MFAPending, false),
			rules:     true,
			assert:    refused(policy.ChallengeMFA, http.StatusUnauthorized, ofEnclosing),
		},
		{
			// The enrolment endpoints serve only the session this chain
			// authenticated: they save the session through this chain's
			// store, which need not be the enclosing chain's. The enclosing
			// session is still judged by the gate, so the request goes no
			// further either.
			name:      "enrolment begin on an enrolment-pending session from the enclosing chain",
			enclosing: inState(session.MFAEnrolmentPending, false),
			method:    http.MethodPost,
			path:      enrolBeginPath,
			assert: func(t *testing.T, enclosing, _, _ *session.Session, o nestedOutcome) {
				t.Helper()

				assert.False(t, o.handlerRan, "the inner handler ran")
				require.ErrorIs(t, o.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, o.code)
				require.NotNil(t, o.stored)
				assert.Equal(t, enclosing.EnrolmentGeneration, o.stored.EnrolmentGeneration,
					"the endpoint saved the enclosing chain's session")
			},
		},
		{
			name:      "recovery cool-down on a full session from the enclosing chain",
			enclosing: full,
			method:    cooldownRoute.Method,
			path:      cooldownRoute.Path,
			assert: func(t *testing.T, _, _, _ *session.Session, o nestedOutcome) {
				t.Helper()

				assert.False(t, o.handlerRan, "the inner handler ran during the cool-down")
				require.ErrorIs(t, o.err, recovery.ErrCooldown)
				assert.Equal(t, http.StatusForbidden, o.code)
			},
		},
		{
			// Past every gate, only the authorization stage's backstop is left
			// to judge the session the context carries.
			name:   "second factor pending on the context past the gates, with rules",
			late:   inState(session.MFAPending, false),
			rules:  true,
			assert: refusedAtBackstop(policy.ChallengeMFA, http.StatusUnauthorized, ofLate),
		},
		{
			name:   "password change pending on the context past the gates, with rules",
			late:   inState(session.MFASatisfied, true),
			rules:  true,
			assert: refusedAtBackstop(policy.ChallengePasswordChange, http.StatusForbidden, ofLate),
		},
		{
			name:      "full session from the enclosing chain, with rules",
			enclosing: full,
			rules:     true,
			assert:    served(ofEnclosing),
		},
		{
			name:      "full session from the enclosing chain, off the cool-down's routes",
			enclosing: full,
			assert:    served(ofEnclosing),
		},
		{
			// The chain's own session wins over the context's, and it is the
			// one its handler reads.
			name:      "own full session over an owing one from the enclosing chain",
			enclosing: inState(session.MFAPending, false),
			own:       full,
			rules:     true,
			assert:    served(ofOwn),
		},
		{
			name:      "own owing session over a full one from the enclosing chain",
			enclosing: full,
			own:       inState(session.MFAPending, false),
			rules:     true,
			assert:    refused(policy.ChallengeMFA, http.StatusUnauthorized, ofOwn),
		},
		{
			// A stateless caller from the enclosing chain leaves no session to
			// judge, as before.
			name:   "stateless caller from the enclosing chain",
			rules:  true,
			assert: served(ofEnclosing),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)

			var enclosing, own, late *session.Session
			if tc.enclosing != nil {
				enclosing = tc.enclosing(t, h)
			}

			if tc.own != nil {
				own = tc.own(t, h)
			}

			if tc.late != nil {
				late = tc.late(t, h)
			}

			outer, err := httpsec.New(httpsec.WithSessions(h.sessions),
				httpsec.RegisterInterceptor(enclosingPublisher(h.sessions, enclosing), httpsec.OrderBearerToken))
			require.NoError(t, err)

			var o nestedOutcome

			logs := &capturingHandler{}

			h.extra = []httpsec.Option{
				httpsec.WithLogger(slog.New(logs)),
				httpsec.WithSessions(h.sessions),
				httpsec.EnableRecoveryGateForTest(),
				httpsec.EnablePasswordChangeGate(h.sessions),
				httpsec.EnableRecoveryCooldown(recentRecoveryOf(t), time.Hour, cooldownRoute),
				httpsec.RegisterInterceptor(contextPastTheGates(late), httpsec.After(httpsec.OrderLogout)),
				httpsec.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
					o.err = err
					w.WriteHeader(httpsec.StatusForError(err))
				}),
			}

			if tc.rules {
				h.extra = append(h.extra, httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t)),
					authorize.Rule[httpsec.Request]{
						Match:   func(httpsec.Request) bool { return true },
						Require: authorize.Authenticated(),
					}))
			}

			inner := h.chain(t, own)

			handler := outer.Middleware()(inner.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				o.handlerRan = true
				o.served, _ = httpsec.SessionFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})))

			method, path := http.MethodGet, "/orders"
			if tc.method != "" {
				method, path = tc.method, tc.path
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, nil))
			o.code = rec.Code
			o.records = logs.records()

			if enclosing != nil {
				o.stored, err = h.sessions.Load(t.Context(), enclosing.ID)
				require.NoError(t, err)
			}

			tc.assert(t, enclosing, own, late, o)
		})
	}
}
