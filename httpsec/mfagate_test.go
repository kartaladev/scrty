package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// TestMFAGate pins what a session owing a second factor may still do. It may
// not reach the application, and the refusal carries the session so a consumer
// can prompt on it.
func TestMFAGate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		state   session.MFAState
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, s *session.Session, out served)
	}

	get := func(path string) func(ctx context.Context) *http.Request {
		return func(ctx context.Context) *http.Request {
			return httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		}
	}

	challenged := func(t *testing.T, s *session.Session, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch)
		assert.Equal(t, policy.ChallengeMFA, ch.Kind)
		require.NotNil(t, ch.Session, "the consumer prompting for the code reads who is challenged")
		assert.Equal(t, s.ID, ch.Session.ID)
		assert.Empty(t, ch.Token,
			"a gate challenges a session that already exists, so it issues nothing")
		assert.False(t, out.handlerRan, "the route's handler is not called")
	}

	passedThrough := func(t *testing.T, _ *session.Session, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.True(t, out.handlerRan, "the request continues to the application untouched")
	}

	cases := []testCase{
		{
			name:    "a pending session requesting a protected route",
			state:   session.MFAPending,
			request: get("/invoices"),
			assert:  challenged,
		},
		{
			name:  "a pending session posting to a protected route",
			state: session.MFAPending,
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/invoices", "amount=10")
			},
			assert: challenged,
		},
		{
			// The exemption is the POST that submits a code, not the path. A
			// consumer serving their own page there serves it to sessions that
			// owe nothing; a session that owes one is held here like anywhere
			// else.
			name:    "a pending session reading the verify path",
			state:   session.MFAPending,
			request: get(testMFAVerifyPath),
			assert:  challenged,
		},
		{
			name:    "a session owing nothing",
			state:   session.MFANone,
			request: get("/invoices"),
			assert:  passedThrough,
		},
		{
			name:    "a session that has already satisfied its second factor",
			state:   session.MFASatisfied,
			request: get("/invoices"),
			assert:  passedThrough,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies().neverChecked().recordsNoFailure()

			s := h.newSession(t, factor.Password, tc.state)

			tc.assert(t, s, serve(t, h.chain(t, s), tc.request(t.Context())))
		})
	}
}

// TestMFAGateAnonymous pins that the gate guards sessions and nothing else: a
// request carrying none is the business of the authentication interceptors
// outside it, and refusing it here would report a challenge nobody owes.
func TestMFAGateAnonymous(t *testing.T) {
	t.Parallel()

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp).neverVerifies().neverChecked().recordsNoFailure()

	out := serve(t, h.chain(t, nil),
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil))

	require.NoError(t, out.err)
	assert.True(t, out.handlerRan)
}

// TestMFAGateLogoutExempt pins the one request a pending session may always
// make besides the code submission.
//
// The gate's slot is outside logout's, so without the exemption a caller
// stranded mid-challenge could not end their own session — on a device that is
// not theirs, the one thing they most need to do. The path comes from the
// chain's own logout configuration, so a consumer who moves the endpoint moves
// the exemption with it and the two cannot drift apart.
func TestMFAGateLogoutExempt(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		logoutOpts []httpsec.LogoutOption
		path       string
	}

	cases := []testCase{
		{name: "the default logout path", path: httpsec.DefaultLogoutPath},
		{
			name:       "a consumer logout path",
			logoutOpts: []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/auth/sign-out")},
			path:       "/auth/sign-out",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies().neverChecked().recordsNoFailure()
			h.logoutOpts = tc.logoutOpts

			s := h.pendingSession(t, factor.Password)

			out := serve(t, h.chain(t, s), formRequest(t.Context(), tc.path, ""))

			require.NoError(t, out.err, "a pending session must always be able to log out")
			assert.Equal(t, http.StatusOK, out.rec.Code)

			_, err := h.sessions.Load(t.Context(), s.ID)
			require.Error(t, err, "the session is ended, pending challenge included")
		})
	}
}

// TestMFAGateVerifyExempt pins that the gate never refuses a code submission
// to any configured method, whatever slot either half is placed at: they are
// one interceptor, so the challenge cannot be made unsatisfiable by ordering.
// A path under the verify prefix naming no method is the endpoint's to refuse
// as unknown, never the gate's to answer with the challenge.
func TestMFAGateVerifyExempt(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string
		wire   func(h *mfaHarness, email *MockMethod)
		assert func(t *testing.T, h *mfaHarness, out served)
	}

	resolved := func(t *testing.T, h *mfaHarness, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.NotErrorAs(t, out.err, &ch, "the gate does not refuse the request that resolves it")
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusOK, out.rec.Code)

		require.NotNil(t, h.resolved)
		assert.Equal(t, session.MFASatisfied, h.stored(t, h.resolved.ID).MFA)
	}

	cases := []testCase{
		{
			name: "TOTP's verify path",
			path: httpsec.DefaultMFAVerifyPrefix + "/totp",
			wire: func(h *mfaHarness, _ *MockMethod) {
				h.allows().accepts().recordsNoFailure()
			},
			assert: resolved,
		},
		{
			name: "the emailed code's verify path",
			path: httpsec.DefaultMFAVerifyPrefix + "/email-code",
			wire: func(h *mfaHarness, email *MockMethod) {
				h.allows().neverVerifies().recordsNoFailure()
				email.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).Return(nil)
			},
			assert: resolved,
		},
		{
			name: "a verify path naming no method",
			path: httpsec.DefaultMFAVerifyPrefix + "/sms",
			wire: func(h *mfaHarness, _ *MockMethod) {
				h.neverVerifies().neverChecked().recordsNoFailure()
			},
			assert: func(t *testing.T, _ *mfaHarness, out served) {
				var ch *httpsec.ChallengeError
				require.NotErrorAs(t, out.err, &ch, "the endpoint refuses it, not the gate")
				require.ErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod)
				assert.False(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)

			email := emailCodeMethod(t)
			email.EXPECT().Enrolled(gomock.Any(), testMFAUser).Return(true, nil).AnyTimes()
			h.extra = []mfa.Method{email}

			tc.wire(h, email)

			s := h.pendingSession(t, factor.Password)

			tc.assert(t, h, serve(t, h.chain(t, s), postCode(t.Context(), tc.path)))
		})
	}
}
