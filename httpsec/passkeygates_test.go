package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// passkeyListPath is the listing endpoint's default path, which a confined
// session must never reach.
const passkeyListPath = httpsec.DefaultPasskeyCredentialsPrefix

// reachedEndpoint asserts out was answered by a passkey endpoint rather than
// a gate: begin issues options, and the others, sent no body, refuse it as
// missing credentials.
func reachedEndpoint(t *testing.T, path string, out served) {
	t.Helper()

	var ch *httpsec.ChallengeError
	require.False(t, errors.As(out.err, &ch), "%s was refused by a gate: %v", path, out.err)
	assert.False(t, out.handlerRan, "%s was answered by the application", path)

	if path == passkeyBeginPath {
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusOK, out.rec.Code)

		return
	}

	require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing, path)
}

// challengedAs asserts out is a gate's challenge of kind.
func challengedAs(kind policy.ChallengeKind) func(t *testing.T, out served) {
	return func(t *testing.T, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch, "got %v", out.err)
		assert.Equal(t, kind, ch.Kind)
		assert.False(t, out.handlerRan)
	}
}

// passkeyLookalike is a consumer's method shaped as the passkey method is: it
// declares it can serve the enrolment path and is not an mfa.Enroller. It is
// not the passkey method, and the chain must not take it for one.
type passkeyLookalike struct{}

func (passkeyLookalike) Name() string                 { return "custom" }
func (passkeyLookalike) Channel() factor.Channel      { return factor.PublicKey }
func (passkeyLookalike) Response() mfa.ResponseFormat { return mfa.JSONBody(1024) }
func (passkeyLookalike) SupportsEnrolmentPath() bool  { return true }

func (passkeyLookalike) Enrolled(context.Context, identity.UserID) (bool, error) {
	return false, nil
}

func (passkeyLookalike) Verify(context.Context, identity.UserID, []byte) error {
	return mfa.ErrInvalidCode
}

// TestPasskeyGates pins which passkey endpoints a confined session reaches:
// the four registration POSTs, through the recovery gate when passkeys are
// enabled with the passkey method on the MFA slot, and through the enrolment gate when passkey registration serves
// the path; never the listing.
func TestPasskeyGates(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		recovered bool
		setup     func(h *passkeyHarness)
		request   *http.Request
		assert    func(t *testing.T, out served)

		// noneIssued asserts no registration challenge was rendered.
		noneIssued bool
	}

	registration := []string{passkeyBeginPath, passkeyFinishPath, passkeyConfirmPath, passkeyConfirmEmailPath}

	var cases []testCase

	for _, path := range registration {
		cases = append(cases,
			testCase{
				name:      "recovery-pending session reaches POST " + path,
				recovered: true,
				setup:     func(h *passkeyHarness) { h.withRecoveryGate, h.passkeyMethod = true, true },
				request:   httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil),
				assert:    func(t *testing.T, out served) { reachedEndpoint(t, path, out) },
			},
			testCase{
				name:      "recovery-pending session is refused POST " + path + " without the passkey method",
				recovered: true,
				setup:     func(h *passkeyHarness) { h.withRecoveryGate = true },
				request:   httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil),
				assert:    challengedAs(policy.ChallengeAccountRecovery),
			},
			testCase{
				name:    "enrolment-only session reaches POST " + path + " when passkeys serve the path",
				setup:   func(h *passkeyHarness) { h.passkeyMethod = true },
				request: httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil),
				assert:  func(t *testing.T, out served) { reachedEndpoint(t, path, out) },
			})
	}

	cases = append(cases,
		testCase{
			name:       "recovery-pending session is refused registration, with no challenge issued, without the passkey method",
			recovered:  true,
			setup:      func(h *passkeyHarness) { h.withRecoveryGate = true },
			request:    httptest.NewRequestWithContext(t.Context(), http.MethodPost, passkeyBeginPath, nil),
			noneIssued: true,
			assert:     challengedAs(policy.ChallengeAccountRecovery),
		},
		testCase{
			name:       "the passkey endpoints refuse a recovery-pending session without the passkey method, behind no gate",
			recovered:  true,
			request:    httptest.NewRequestWithContext(t.Context(), http.MethodPost, passkeyBeginPath, nil),
			noneIssued: true,
			assert:     challengedAs(policy.ChallengeAccountRecovery),
		},
		testCase{
			name:      "recovery-pending session is refused the listing",
			recovered: true,
			setup:     func(h *passkeyHarness) { h.withRecoveryGate, h.passkeyMethod = true, true },
			request:   httptest.NewRequestWithContext(t.Context(), http.MethodGet, passkeyListPath, nil),
			assert:    challengedAs(policy.ChallengeAccountRecovery),
		},
		testCase{
			name:      "recovery-pending session is refused a GET on a registration path",
			recovered: true,
			setup:     func(h *passkeyHarness) { h.withRecoveryGate, h.passkeyMethod = true, true },
			request:   httptest.NewRequestWithContext(t.Context(), http.MethodGet, passkeyBeginPath, nil),
			assert:    challengedAs(policy.ChallengeAccountRecovery),
		},
		testCase{
			name:      "recovery gate exempts the consumer's registration paths, not the defaults",
			recovered: true,
			setup: func(h *passkeyHarness) {
				h.withRecoveryGate, h.passkeyMethod = true, true
				h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyRegistrationPrefix("/account/passkeys"))
			},
			request: httptest.NewRequestWithContext(t.Context(), http.MethodPost, passkeyBeginPath, nil),
			assert:  challengedAs(policy.ChallengeAccountRecovery),
		},
		testCase{
			name:      "recovery gate exempts the consumer's registration begin",
			recovered: true,
			setup: func(h *passkeyHarness) {
				h.withRecoveryGate, h.passkeyMethod = true, true
				h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyRegistrationPrefix("/account/passkeys"))
			},
			request: httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/account/passkeys/begin", nil),
			assert: func(t *testing.T, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
		testCase{
			name:    "enrolment-only session is refused the listing",
			setup:   func(h *passkeyHarness) { h.passkeyMethod = true },
			request: httptest.NewRequestWithContext(t.Context(), http.MethodGet, passkeyListPath, nil),
			assert:  challengedAs(policy.ChallengeMFAEnrolment),
		},
		testCase{
			name:    "enrolment-only session is refused a GET on a registration path",
			setup:   func(h *passkeyHarness) { h.passkeyMethod = true },
			request: httptest.NewRequestWithContext(t.Context(), http.MethodGet, passkeyBeginPath, nil),
			assert:  challengedAs(policy.ChallengeMFAEnrolment),
		},
		testCase{
			name: "enrolment-only session is refused registration when the consumer names TOTP only",
			setup: func(h *passkeyHarness) {
				h.passkeyMethod = true
				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentMethods("totp"))
			},
			request: httptest.NewRequestWithContext(t.Context(), http.MethodPost, passkeyBeginPath, nil),
			assert:  challengedAs(policy.ChallengeMFAEnrolment),
		},
		testCase{
			name:    "enrolment-only session is refused registration when the passkey method is not on the MFA slot",
			request: httptest.NewRequestWithContext(t.Context(), http.MethodPost, passkeyBeginPath, nil),
			assert:  challengedAs(policy.ChallengeMFAEnrolment),
		},
		testCase{
			name: "enrolment-only session reaches registration when the consumer names passkey",
			setup: func(h *passkeyHarness) {
				h.passkeyMethod = true
				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentMethods("passkey"))
			},
			request: httptest.NewRequestWithContext(t.Context(), http.MethodPost, passkeyBeginPath, nil),
			assert:  func(t *testing.T, out served) { reachedEndpoint(t, passkeyBeginPath, out) },
		},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newPasskeyHarness(t)
			if tc.setup != nil {
				tc.setup(h)
			}

			var s *session.Session
			if tc.recovered {
				s = h.recoveryPending(t)
			} else {
				s = h.enrolmentOnly(t, factor.Password)
			}

			chain := h.build(t, s)

			tc.assert(t, serve(t, chain, tc.request.WithContext(t.Context())))

			if tc.noneIssued {
				assert.Empty(t, h.verifier.creations, "a registration challenge was issued")
			}
		})
	}
}

// TestPasskeyEnrolmentAssembly pins how the enrolment path counts the
// passkey method among its enrolling methods, and refuses to assemble when it
// does and passkey registration is not enabled.
func TestPasskeyEnrolmentAssembly(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// passkeys enables passkey registration; onlyPasskey gives EnableMFA
		// the passkey method alone, without TOTP.
		passkeys    bool
		onlyPasskey bool
		enrolOpts   []httpsec.EnrolmentOption

		// lookalike puts a consumer method shaped like the passkey method
		// where the passkey method would go.
		lookalike bool

		assert func(t *testing.T, err error)
	}

	assembles := func(t *testing.T, err error) { require.NoError(t, err) }
	refused := func(t *testing.T, err error) { require.ErrorIs(t, err, httpsec.ErrConfig) }

	cases := []testCase{
		{name: "the passkey method enrolling without passkey registration", assert: refused},
		{
			name:      "the passkey method named without passkey registration",
			enrolOpts: []httpsec.EnrolmentOption{httpsec.WithEnrolmentMethods("totp", "passkey")},
			assert:    refused,
		},
		{
			name:      "TOTP named only, without passkey registration",
			enrolOpts: []httpsec.EnrolmentOption{httpsec.WithEnrolmentMethods("totp")},
			assert:    assembles,
		},
		{name: "the passkey method enrolling with passkey registration", passkeys: true, assert: assembles},
		{
			name: "the passkey method named alone", passkeys: true,
			enrolOpts: []httpsec.EnrolmentOption{httpsec.WithEnrolmentMethods("passkey")},
			assert:    assembles,
		},
		{name: "the passkey method the only one on the MFA slot", passkeys: true, onlyPasskey: true, assert: assembles},
		{name: "the passkey method the only one, without registration", onlyPasskey: true, assert: refused},
		{
			name:      "a consumer method shaped like the passkey method, beside TOTP, without registration",
			lookalike: true,
			assert:    assembles,
		},
		{
			name:      "a consumer method shaped like the passkey method, alone, is left out with its reason",
			lookalike: true, onlyPasskey: true,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), `"custom" does not implement mfa.Enroller`)
				assert.NotContains(t, err.Error(), "passkey registration is not enabled")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			pk := newPasskeyHarness(t)

			m, err := passkey.New(passkey.Deps{Verifier: pk.verifier.mock, Users: h.users, Sender: pk.notices},
				passkey.WithRepudiationContact("help@example.com"))
			require.NoError(t, err)

			var method mfa.Method = m.MFAMethod()
			if tc.lookalike {
				method = passkeyLookalike{}
			}

			if tc.onlyPasskey {
				h.method = method
			} else {
				h.extraMethods = []mfa.Method{method}
			}

			h.enrolOpts = tc.enrolOpts

			if tc.passkeys {
				h.extra = append(h.extra, httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: m, Sessions: h.sessions}))
			}

			_, err = httpsec.New(h.options(t, nil)...)
			tc.assert(t, err)
		})
	}
}

// TestPasskeyEnrolmentSharedSettings pins that a registration on an
// enrolment-only session follows the enrolment path's settings: its email
// confirmation, its contact resolver and its confirmation limiter.
func TestPasskeyEnrolmentSharedSettings(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T, h *passkeyHarness)
		act    func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served
		assert func(t *testing.T, h *passkeyHarness, s *session.Session, out served)
	}

	register := func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
		return h.register(t, chain, "cred-1")
	}

	cases := []testCase{
		{
			name: "email confirmation on: the passkey awaits the emailed code and the session stays confined",
			act:  register,
			assert: func(t *testing.T, h *passkeyHarness, s *session.Session, out served) {
				require.NoError(t, out.err)

				c := h.credential(t)
				assert.Equal(t, passkey.StatePending, c.State)
				assert.Equal(t, passkey.AwaitingEmailCode, c.Pending)
				assert.Equal(t, session.MFAEnrolmentPending, h.stored(t, s.ID).MFA)

				msg := h.notices.last(t)
				assert.Equal(t, enrolUsername, msg.To)
				assert.Regexp(t, sixDigits, msg.TextBody)
			},
		},
		{
			name: "email confirmation off: the passkey is active and the session moves on",
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithoutEmailConfirmation())
			},
			act: register,
			assert: func(t *testing.T, h *passkeyHarness, s *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, passkey.StateActive, h.credential(t).State)

				saved := h.stored(t, s.ID)
				assert.Equal(t, session.MFAPending, saved.MFA)
				assert.Equal(t, s.EnrolmentOriginDeadline, saved.EnrolmentOriginDeadline)
			},
		},
		{
			name: "the emailed code goes where the path's contact resolver says",
			setup: func(_ *testing.T, h *passkeyHarness) {
				h.enrolOpts = append(h.enrolOpts, httpsec.WithContactResolver(
					func(context.Context, *identity.Details) (string, error) { return "inbox@example.org", nil }))
			},
			act: register,
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, "inbox@example.org", h.notices.last(t).To)
			},
		},
		{
			name: "the emailed code activates the passkey and moves the session on",
			act: func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
				require.NoError(t, register(t, h, chain).err)

				code := sixDigits.FindString(h.notices.last(t).TextBody)

				return serve(t, chain, post(t.Context(), passkeyConfirmEmailPath, "code="+code))
			},
			assert: func(t *testing.T, h *passkeyHarness, s *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)
				assert.Equal(t, passkey.StateActive, h.credential(t).State)
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA)
			},
		},
		{
			name: "the path's confirmation limiter is asked, under the shared key",
			setup: func(t *testing.T, h *passkeyHarness) {
				limiter := NewMockLimiter(gomock.NewController(t))
				limiter.EXPECT().Exceeded(gomock.Any(), passkey.EmailConfirmThrottleKey(testMFAUser)).Return(true, nil)
				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentConfirmLimiter(limiter))
			},
			act: func(t *testing.T, h *passkeyHarness, chain *httpsec.Chain) served {
				require.NoError(t, register(t, h, chain).err)

				return serve(t, chain, post(t.Context(), passkeyConfirmEmailPath, "code=000000"))
			},
			assert: func(t *testing.T, h *passkeyHarness, _ *session.Session, out served) {
				require.ErrorIs(t, out.err, mfa.ErrEnrolmentThrottled)
				assert.Equal(t, passkey.StatePending, h.credential(t).State)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newPasskeyHarness(t)
			h.passkeyMethod = true
			if tc.setup != nil {
				tc.setup(t, h)
			}

			s := h.enrolmentOnly(t, factor.Password)
			chain := h.build(t, s)

			tc.assert(t, h, s, tc.act(t, h, chain))
		})
	}
}

// TestPasskeyRecoveryBinding pins that passkey registration, with the
// passkey method on the MFA slot, is a way to bind a recovered session, and
// that either half alone is not.
func TestPasskeyRecoveryBinding(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		passkeys bool
		method   bool

		// lookalike serves a consumer method shaped like the passkey method
		// in its place.
		lookalike bool

		// recOpts are further recovery options.
		recOpts []httpsec.RecoveryOption

		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{name: "registration and the method", passkeys: true, method: true,
			assert: func(t *testing.T, err error) { require.NoError(t, err) }},
		{name: "registration without the method", passkeys: true,
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, httpsec.ErrConfig) }},
		{name: "the method without registration", method: true,
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, httpsec.ErrConfig) }},
		{name: "neither",
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, httpsec.ErrConfig) }},
		{name: "registration and a method shaped like the passkey method", passkeys: true, method: true, lookalike: true,
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, httpsec.ErrConfig) }},
		{name: "a registration path is the recovery complete path", passkeys: true, method: true,
			recOpts: []httpsec.RecoveryOption{httpsec.WithRecoveryCompletePath(passkeyBeginPath)},
			assert:  func(t *testing.T, err error) { require.ErrorIs(t, err, httpsec.ErrConfig) }},
		{name: "a registration path is the recovery start path", passkeys: true, method: true,
			recOpts: []httpsec.RecoveryOption{httpsec.WithRecoveryStartPath(passkeyFinishPath)},
			assert:  func(t *testing.T, err error) { require.ErrorIs(t, err, httpsec.ErrConfig) }},
		{name: "a registration path is the saved-codes path", passkeys: true, method: true,
			recOpts: []httpsec.RecoveryOption{httpsec.WithRecoveryCodesPath(passkeyConfirmPath)},
			assert:  func(t *testing.T, err error) { require.ErrorIs(t, err, httpsec.ErrConfig) }},
		{name: "the credentials listing is the recovery cancel path", passkeys: true, method: true,
			recOpts: []httpsec.RecoveryOption{httpsec.WithRecoveryCancelPath(passkeyListPath)},
			assert:  func(t *testing.T, err error) { require.ErrorIs(t, err, httpsec.ErrConfig) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t)
			h.noBinding = true

			v := newPasskeyVerifierStub(t)
			m, err := passkey.New(passkey.Deps{Verifier: v.mock, Users: h.users, Sender: h.sender},
				passkey.WithRepudiationContact("help@example.com"))
			require.NoError(t, err)

			if tc.method {
				var method mfa.Method = m.MFAMethod()
				if tc.lookalike {
					method = passkeyLookalike{}
				}

				h.chainOpts = append(h.chainOpts,
					httpsec.EnableMFA([]mfa.Method{h.totp, method}, httpsec.WithMFATokens(h.tokens)))
			}

			if tc.passkeys {
				h.chainOpts = append(h.chainOpts,
					httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: m, Sessions: h.sessions}))
			}

			h.recOpts = append(h.recOpts, tc.recOpts...)

			_, err = httpsec.New(h.options(t)...)
			tc.assert(t, err)
		})
	}
}

// TestPasskeyEnrolmentEndToEnd runs a required user with no second factor
// through the enrolment path by passkey: a password login is challenged for
// enrolment, registers a passkey, confirms the emailed code, proves the
// passkey at the MFA slot, and ends with a full, rotated session.
func TestPasskeyEnrolmentEndToEnd(t *testing.T) {
	t.Parallel()

	d := newE2EDeployment(t)
	v := newPasskeyVerifierStub(t)

	pm, err := passkey.New(passkey.Deps{Verifier: v.mock, Users: d.users, Sender: d.sender},
		passkey.WithRepudiationContact("help@example.com"))
	require.NoError(t, err)

	method := pm.MFAMethod()

	lookups, err := mfa.LookupsFor(d.totp, method)
	require.NoError(t, err)

	challenge, err := policy.NewMFAPolicy(lookups)
	require.NoError(t, err)

	requirement, err := policy.NewMFARequirementPolicy(d.required, lookups, policy.WithMFAEnrolmentPath())
	require.NoError(t, err)

	authn, err := authenticate.NewUsernamePasswordAuthenticator(d.users,
		authenticate.WithPasswordEncoder(e2eEncoder(t)))
	require.NoError(t, err)

	d.chain, err = httpsec.New(
		httpsec.WithPolicyEngine(engineOf(t, challenge, requirement)),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn, Sessions: d.sessions, Tokens: d.tokens, Attempts: policy.NewMemoryAttemptStore(),
		}),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: d.tokens, Sessions: d.sessions, Users: d.users}),
		httpsec.EnableMFA([]mfa.Method{d.totp, method}, httpsec.WithMFATokens(d.tokens)),
		httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: d.users, Sender: d.sender}),
		httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: pm, Sessions: d.sessions}),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: d.sessions}),
	)
	require.NoError(t, err)

	credential := enrolmentChallenged(t, d.login(t))
	d.confined(t, credential)

	bearer := func(req *http.Request) *http.Request {
		req.Header.Set("Authorization", "Bearer "+credential)

		return req
	}

	begun := serve(t, d.chain, bearer(jsonPost(t.Context(), passkeyBeginPath, "")))
	require.NoError(t, begun.err)

	finished := serve(t, d.chain, bearer(jsonPost(t.Context(), passkeyFinishPath,
		registrationBody(v.lastCreation(t), "cred-1"))))
	require.NoError(t, finished.err)

	var doc passkeyFinishDocument
	require.NoError(t, json.Unmarshal(finished.rec.Body.Bytes(), &doc))
	require.Equal(t, []string{"email_code"}, doc.Pending)

	d.confined(t, credential)

	confirmed := d.send(t, passkeyConfirmEmailPath, credential, url.Values{"code": {d.lastEmailed(t)}})
	require.NoError(t, confirmed.err)
	require.Equal(t, http.StatusNoContent, confirmed.rec.Code)

	// Binding the passkey is not a second factor: the session now owes one,
	// and the challenge lists the passkey.
	var ch *httpsec.ChallengeError
	owed := d.invoices(t, credential)
	require.ErrorAs(t, owed.err, &ch)
	require.Equal(t, policy.ChallengeMFA, ch.Kind)

	names := make([]string, 0, len(ch.Methods))
	for _, m := range ch.Methods {
		names = append(names, m.Name)
	}
	assert.Contains(t, names, passkey.MethodName)

	mfaBegun := serve(t, d.chain, bearer(jsonPost(t.Context(), httpsec.DefaultMFABeginPrefix+"/passkey", "")))
	require.NoError(t, mfaBegun.err)

	verified := serve(t, d.chain, bearer(jsonPost(t.Context(), httpsec.DefaultMFAVerifyPrefix+"/passkey",
		assertionBody(v.lastRequest(t), "cred-1"))))
	require.NoError(t, verified.err)
	require.Equal(t, http.StatusOK, verified.rec.Code)

	rotated := accessTokenFrom(t, verified)
	require.NotEqual(t, credential, rotated)

	d.reached(t, rotated)
}
