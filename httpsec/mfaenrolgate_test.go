package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// gateWitnesses records which of the steps behind the enrolment gate ran: a
// consumer interceptor after it, the authorizer's rule set, and the
// password-change resolve endpoint.
type gateWitnesses struct {
	consumer   atomic.Bool
	authorizer atomic.Bool
	change     atomic.Bool
}

// passwordResolvePath is where the password-change gate's resolve endpoint
// answers in these tests.
const passwordResolvePath = "/account/password"

// options are the chain options that give each witness something to record.
func (w *gateWitnesses) options(h *enrolHarness) []httpsec.Option {
	consumer := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		w.consumer.Store(true)
		return next(ex)
	})

	everything := authorize.Rule[httpsec.Request]{
		Match: func(httpsec.Request) bool {
			w.authorizer.Store(true)
			return true
		},
		Require: authorize.PermitAll(),
	}

	change := func(*httpsec.Exchange) error {
		w.change.Store(true)
		return nil
	}

	return []httpsec.Option{
		httpsec.EnablePasswordChangeGate(h.sessions,
			httpsec.WithChangePasswordEndpoint(passwordResolvePath, change)),
		httpsec.RegisterInterceptor(consumer, httpsec.After(httpsec.OrderPasswordChange)),
		httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(h.t)), everything),
	}
}

// TestEnrolmentGate pins what an enrolment-only session may reach: the three
// enrolment endpoints, by POST, and logout. Everything else is refused with an
// enrolment challenge carrying the session, before any step behind the gate
// runs — the verify endpoint and the password-change resolve endpoint
// included.
func TestEnrolmentGate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// state is the session's second-factor state; the zero value is
		// session.MFANone, so every case sets it.
		state session.MFAState

		enrolOpts  []httpsec.EnrolmentOption
		logoutOpts []httpsec.LogoutOption

		request func(ctx context.Context) *http.Request

		// refused marks the rows the gate refuses. Each of them is run again
		// on a chain without the gate, where it must reach what it was
		// addressed to — the handler, or the password-change resolve
		// endpoint: that is what shows the gate, and nothing else on the
		// chain, is doing the refusing.
		refused bool

		// reached asserts, on the chain without the gate, that the request
		// reached what it was addressed to. Nil means the handler, with no
		// refusal.
		reached func(t *testing.T, w *gateWitnesses, out served)

		assert func(t *testing.T, h *enrolHarness, s *session.Session, w *gateWitnesses, out served)
	}

	get := func(path string) func(ctx context.Context) *http.Request {
		return func(ctx context.Context) *http.Request {
			return httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		}
	}

	postTo := func(path, body string) func(ctx context.Context) *http.Request {
		return func(ctx context.Context) *http.Request { return post(ctx, path, body) }
	}

	challenged := func(t *testing.T, _ *enrolHarness, s *session.Session, w *gateWitnesses, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch)
		assert.Equal(t, policy.ChallengeMFAEnrolment, ch.Kind)
		require.NotNil(t, ch.Session, "the refusal carries the session, for the consumer to prompt on")
		assert.Equal(t, s.ID, ch.Session.ID)
		assert.Empty(t, ch.Token, "a gate challenges a session that exists, so it issues nothing")
		assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))

		assert.False(t, out.handlerRan, "the handler does not run")
		assert.False(t, w.consumer.Load(), "no consumer interceptor after the gate runs")
		assert.False(t, w.authorizer.Load(), "the authorizer does not run")
		assert.False(t, w.change.Load(), "no password is changed")
	}

	loggedOut := func(t *testing.T, h *enrolHarness, s *session.Session, _ *gateWitnesses, out served) {
		t.Helper()

		require.NoError(t, out.err, "an enrolment-only session can always log out")
		assert.Equal(t, http.StatusOK, out.rec.Code)

		_, err := h.sessions.Load(t.Context(), s.ID)
		require.Error(t, err, "the session is ended, and its handle no longer loads")
	}

	unknownMethod := func(t *testing.T, h *enrolHarness, s *session.Session, w *gateWitnesses, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod)
		assert.Equal(t, http.StatusNotFound, httpsec.StatusForError(out.err))

		var ch *httpsec.ChallengeError
		assert.NotErrorAs(t, out.err, &ch, "the endpoint refuses it, not the gate")
		assert.False(t, out.handlerRan)
		assert.False(t, w.consumer.Load(), "nothing behind the gate runs")

		_, ok := h.enrolment(t)
		assert.False(t, ok, "nothing is stored")
		assert.True(t, h.stored(t, s.ID).EnrolmentGeneration.IsZero())
	}

	cases := []testCase{
		{
			name:    "a protected route",
			state:   session.MFAEnrolmentPending,
			request: postTo("/invoices", "amount=10"),
			refused: true,
			assert:  challenged,
		},
		{
			name:    "a protected route read by GET",
			state:   session.MFAEnrolmentPending,
			request: get("/invoices"),
			refused: true,
			assert:  challenged,
		},
		{
			name:    "the verify endpoint",
			state:   session.MFAEnrolmentPending,
			request: postTo(testMFAVerifyPath, "code="+testMFACode),
			refused: true,
			reached: func(t *testing.T, _ *gateWitnesses, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrMFAMethodNotUsable,
					"the verify endpoint judges the request, and refuses a method the user has not enrolled on")
			},
			assert: challenged,
		},
		{
			// The MFA begin prefix is a different endpoint from the
			// enrolment path's own begin prefix; the gate confines an
			// enrolment-only session away from it too.
			name:    "the MFA begin endpoint",
			state:   session.MFAEnrolmentPending,
			request: postTo(httpsec.DefaultMFABeginPrefix+"/totp", ""),
			refused: true,
			reached: func(t *testing.T, _ *gateWitnesses, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod,
					"the MFA slot judges the request: totp has no begin step")
			},
			assert: challenged,
		},
		{
			name:    "the password-change resolve endpoint",
			state:   session.MFAEnrolmentPending,
			request: postTo(passwordResolvePath, "password=new"),
			refused: true,
			reached: func(t *testing.T, w *gateWitnesses, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.True(t, w.change.Load(), "the resolve endpoint runs")
			},
			assert: challenged,
		},
		{
			name:    "a GET on the begin path",
			state:   session.MFAEnrolmentPending,
			request: get(enrolBeginPath),
			refused: true,
			assert:  challenged,
		},
		{
			name:    "a GET on the confirm path",
			state:   session.MFAEnrolmentPending,
			request: get(enrolConfirmPath),
			refused: true,
			assert:  challenged,
		},
		{
			// Logout is exempt as a POST alone, as every other exemption is:
			// a GET on its path is a link another site could make the
			// caller follow.
			name:    "a GET on the logout path",
			state:   session.MFAEnrolmentPending,
			request: get(httpsec.DefaultLogoutPath),
			refused: true,
			assert:  challenged,
		},
		{
			// With email confirmation off the endpoint does not exist, so
			// its path is a route like any other.
			name:      "the emailed-code path with email confirmation off",
			state:     session.MFAEnrolmentPending,
			enrolOpts: []httpsec.EnrolmentOption{httpsec.WithoutEmailConfirmation()},
			request:   postTo(enrolEmailPath, "code=123456"),
			refused:   true,
			assert:    challenged,
		},
		{
			// A moved endpoint takes its exemption with it: the default path
			// is then a route like any other.
			name:      "the default begin path once the begin prefix is moved",
			state:     session.MFAEnrolmentPending,
			enrolOpts: []httpsec.EnrolmentOption{httpsec.WithEnrolmentBeginPrefix("/account/2fa/start")},
			request:   postTo(enrolBeginPath, ""),
			refused:   true,
			assert:    challenged,
		},
		{
			// Every POST under an enrolment prefix is that endpoint's, so one
			// naming no enrollable method is refused by the endpoint as
			// unknown, rather than challenged by the gate or passed on.
			name:    "a begin path naming no enrollable method",
			state:   session.MFAEnrolmentPending,
			request: postTo(httpsec.DefaultEnrolmentBeginPrefix+"/sms", ""),
			assert:  unknownMethod,
		},
		{
			name:    "the bare begin prefix",
			state:   session.MFAEnrolmentPending,
			request: postTo(httpsec.DefaultEnrolmentBeginPrefix, ""),
			assert:  unknownMethod,
		},
		{
			name:    "a confirm path with an extra segment",
			state:   session.MFAEnrolmentPending,
			request: postTo(enrolConfirmPath+"/x", "code=123456"),
			assert:  unknownMethod,
		},
		{
			name:    "an emailed-code path with an empty segment",
			state:   session.MFAEnrolmentPending,
			request: postTo(httpsec.DefaultEnrolmentEmailConfirmPrefix+"/", "code=123456"),
			assert:  unknownMethod,
		},
		{
			name:    "logout",
			state:   session.MFAEnrolmentPending,
			request: postTo(httpsec.DefaultLogoutPath, ""),
			assert:  loggedOut,
		},
		{
			// EnableMFAEnrolment is applied before EnableLogout, whose path
			// is moved: the gate reads the chain's final logout path at
			// assembly, not whatever was set when it was enabled.
			name:       "a consumer logout path configured after the path",
			state:      session.MFAEnrolmentPending,
			logoutOpts: []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/session/end")},
			request:    postTo("/session/end", ""),
			assert:     loggedOut,
		},
		{
			name:      "a consumer begin prefix",
			state:     session.MFAEnrolmentPending,
			enrolOpts: []httpsec.EnrolmentOption{httpsec.WithEnrolmentBeginPrefix("/account/2fa/start")},
			request:   postTo("/account/2fa/start/totp", ""),
			assert: func(t *testing.T, h *enrolHarness, _ *session.Session, w *gateWitnesses, out served) {
				t.Helper()

				begun(t, out)
				assert.False(t, w.consumer.Load(), "the endpoint answers before anything behind the gate")

				_, ok := h.enrolment(t)
				assert.True(t, ok, "a pending enrolment is begun")
			},
		},
		{
			name:    "a session owing nothing",
			state:   session.MFANone,
			request: get("/invoices"),
			assert: func(t *testing.T, _ *enrolHarness, _ *session.Session, _ *gateWitnesses, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.True(t, out.handlerRan, "the gate guards the enrolment-only state alone")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			h.enrolOpts, h.logoutOpts = tc.enrolOpts, tc.logoutOpts

			s := h.sessionIn(t, factor.Password, tc.state)

			w := &gateWitnesses{}
			h.extra = w.options(h)

			tc.assert(t, h, s, w, serve(t, h.chain(t, s), tc.request(t.Context())))
		})

		if !tc.refused {
			continue
		}

		t.Run(tc.name+", without the gate", func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			h.enrolOpts, h.logoutOpts = tc.enrolOpts, tc.logoutOpts
			h.withoutGate = true

			s := h.sessionIn(t, factor.Password, tc.state)

			w := &gateWitnesses{}
			h.extra = w.options(h)

			out := serve(t, h.chain(t, s), tc.request(t.Context()))

			if tc.reached != nil {
				tc.reached(t, w, out)

				return
			}

			require.NoError(t, out.err, "without the gate nothing on the chain refuses this request")
			assert.True(t, out.handlerRan, "without the gate the handler runs")
		})
	}
}

// TestEnrolmentGateAnonymous pins that the gate guards sessions and nothing
// else: a request carrying none is the business of the authentication
// interceptors outside it.
func TestEnrolmentGateAnonymous(t *testing.T) {
	t.Parallel()

	h := newEnrolHarness(t)

	out := serve(t, h.chain(t, nil),
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil))

	require.NoError(t, out.err)
	assert.True(t, out.handlerRan)
}
