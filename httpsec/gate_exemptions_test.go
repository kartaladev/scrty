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

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// TestGateExemptions_NeverReachTheAuthorizationStage pins that every request a
// built-in gate lets an owing session make is answered by the chain itself,
// never handed on to the authorization stage. The stage refuses a session that
// still owes a challenge, so an exemption that reached it would be refused
// there; this test is what shows the stage's check takes nothing away from
// the gates.
//
// One chain carries every gate and every endpoint a gate exempts: the
// recovery gate, the enrolment path with email confirmation, the second-factor
// gate with its verify, begin and listing endpoints, the password-change gate
// with its resolve endpoint, passkey registration with the passkey method on
// the MFA slot, and logout. Each owing session is sent to the union of the
// exempted requests, so an exemption one gate grants and a later gate fails to
// answer is caught too. A consumer interceptor at Before(OrderAuthorizer)
// records whether anything was handed on that far.
func TestGateExemptions_NeverReachTheAuthorizationStage(t *testing.T) {
	t.Parallel()

	// owing builds a session in one owing state for the harness's user.
	type owing func(t *testing.T, h *passkeyHarness) *session.Session

	recoveryPending := func(t *testing.T, h *passkeyHarness) *session.Session {
		t.Helper()

		return h.recoveryPending(t)
	}

	enrolmentPending := func(t *testing.T, h *passkeyHarness) *session.Session {
		t.Helper()

		return h.enrolmentOnly(t, factor.Password)
	}

	mfaPending := func(t *testing.T, h *passkeyHarness) *session.Session {
		t.Helper()

		return h.sessionIn(t, factor.Password, session.MFAPending)
	}

	passwordChangePending := func(t *testing.T, h *passkeyHarness) *session.Session {
		t.Helper()

		s := h.sessionIn(t, factor.Password, session.MFASatisfied)
		s.PasswordChangePending = true
		require.NoError(t, h.sessions.Save(t.Context(), s))

		return s
	}

	states := []struct {
		name    string
		session owing
	}{
		{name: "recovery pending", session: recoveryPending},
		{name: "enrolment pending", session: enrolmentPending},
		{name: "second factor pending", session: mfaPending},
		{name: "password change pending", session: passwordChangePending},
	}

	postTo := func(path string) func(ctx context.Context) *http.Request {
		return func(ctx context.Context) *http.Request { return post(ctx, path, "") }
	}

	get := func(path string) func(ctx context.Context) *http.Request {
		return func(ctx context.Context) *http.Request {
			return httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		}
	}

	// exempted is every request some gate lets an owing session make, named
	// after the gates that exempt it.
	exempted := []struct {
		name    string
		request func(ctx context.Context) *http.Request
	}{
		// Recovery and enrolment gates: POST under an enrolment prefix.
		{name: "enrolment begin", request: postTo(enrolBeginPath)},
		{name: "enrolment begin, unknown method", request: postTo(httpsec.DefaultEnrolmentBeginPrefix + "/unknown")},
		{name: "enrolment begin, extra segment", request: postTo(enrolBeginPath + "/extra")},
		{name: "enrolment begin, bare prefix", request: postTo(httpsec.DefaultEnrolmentBeginPrefix)},
		{name: "enrolment confirm", request: postTo(httpsec.DefaultEnrolmentConfirmPrefix + "/totp")},
		{name: "enrolment confirm, unknown method", request: postTo(httpsec.DefaultEnrolmentConfirmPrefix + "/unknown")},
		{name: "enrolment email confirm", request: postTo(httpsec.DefaultEnrolmentEmailConfirmPrefix + "/totp")},
		{name: "enrolment email confirm, unknown method", request: postTo(httpsec.DefaultEnrolmentEmailConfirmPrefix + "/unknown")},

		// Recovery and enrolment gates: the passkey registration endpoints.
		{name: "passkey registration begin", request: postTo(passkeyBeginPath)},
		{name: "passkey registration finish", request: postTo(passkeyFinishPath)},
		{name: "passkey registration saved-code confirm", request: postTo(httpsec.DefaultPasskeyRegistrationPrefix + "/confirm")},
		{name: "passkey registration emailed-code confirm", request: postTo(httpsec.DefaultPasskeyRegistrationPrefix + "/confirm-email")},

		// Recovery and password-change gates: the resolve endpoint.
		{name: "password-change resolve", request: postTo(passwordResolvePath)},

		// Second-factor gate: its own endpoints, which never reach the gate.
		{name: "second-factor verify", request: func(ctx context.Context) *http.Request {
			return post(ctx, testMFAVerifyPath, "code="+testMFACode)
		}},
		{name: "second-factor begin", request: postTo(httpsec.DefaultMFABeginPrefix + "/totp")},
		{name: "second-factor method listing", request: get(httpsec.DefaultMFAMethodListingPath)},

		// Every gate: logout.
		{name: "logout", request: postTo(httpsec.DefaultLogoutPath)},
	}

	type testCase struct {
		name    string
		session owing
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, out served, reached bool)
	}

	neverHandedOn := func(t *testing.T, out served, reached bool) {
		t.Helper()

		assert.False(t, reached, "the request was handed on past the gates to slot %d (err %v)",
			httpsec.Before(httpsec.OrderAuthorizer), out.err)
		assert.False(t, out.handlerRan, "the handler ran")
	}

	cases := make([]testCase, 0, len(states)*len(exempted)+1)

	for _, st := range states {
		for _, ex := range exempted {
			cases = append(cases, testCase{
				name:    st.name + ", " + ex.name,
				session: st.session,
				request: ex.request,
				assert:  neverHandedOn,
			})
		}
	}

	// The control shows the probe is where the test says it is: a full
	// session on an ordinary route is handed on to it.
	cases = append(cases, testCase{
		name: "full session, a protected route (control)",
		session: func(t *testing.T, h *passkeyHarness) *session.Session {
			t.Helper()

			return h.sessionIn(t, factor.Password, session.MFASatisfied)
		},
		request: get("/invoices"),
		assert: func(t *testing.T, out served, reached bool) {
			t.Helper()

			require.NoError(t, out.err)
			assert.True(t, reached, "the probe before the authorization stage did not run")
			assert.True(t, out.handlerRan)
		},
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newPasskeyHarness(t)
			h.passkeyMethod = true
			h.withRecoveryGate = true
			h.mfaOpts = []httpsec.MFAOption{httpsec.WithMFAMethodListing()}

			var reached atomic.Bool

			probe := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				reached.Store(true)
				return next(ex)
			})

			permitAll := authorize.Rule[httpsec.Request]{
				Match:   func(httpsec.Request) bool { return true },
				Require: authorize.PermitAll(),
			}

			h.extra = []httpsec.Option{
				httpsec.EnablePasswordChangeGate(h.sessions,
					httpsec.WithPasswordChangeEndpoint(passwordResolvePath, func(*httpsec.Exchange) error { return nil })),
				httpsec.RegisterInterceptor(probe, httpsec.Before(httpsec.OrderAuthorizer)),
				httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t)), permitAll),
			}

			s := tc.session(t, h)
			chain := h.build(t, s)

			tc.assert(t, serve(t, chain, tc.request(t.Context())), reached.Load())
		})
	}
}
