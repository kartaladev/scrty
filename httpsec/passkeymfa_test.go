package httpsec_test

import (
	"log/slog"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// The passkey method's MFA paths under the default prefixes.
const (
	passkeyMFABeginPath  = httpsec.DefaultMFABeginPrefix + "/" + passkey.MethodName
	passkeyMFAVerifyPath = httpsec.DefaultMFAVerifyPrefix + "/" + passkey.MethodName
)

// enrolTOTP enrols the user on the deployment's TOTP method.
func (d *pwlDeployment) enrolTOTP(t *testing.T) {
	t.Helper()

	prov, err := d.totp.BeginEnrolment(t.Context(), e2eUser, e2eAddress)
	require.NoError(t, err)

	code, err := totp.GenerateCode(prov.Secret, d.totpClock.Now())
	require.NoError(t, err)

	require.NoError(t, d.totp.ConfirmEnrolment(t.Context(), e2eUser, code))
}

// passwordLogin logs the user in with their password through form login.
func (d *pwlDeployment) passwordLogin(t *testing.T) served {
	t.Helper()

	return serve(t, d.chain, postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {e2ePassword},
	}))
}

// challenged requires out to be a second-factor challenge and returns it.
func challenged(t *testing.T, out served) *httpsec.ChallengeError {
	t.Helper()

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, out.err, &ch)
	require.Equal(t, policy.ChallengeMFA, ch.Kind)
	require.NotEmpty(t, ch.Token)

	return ch
}

// mfaBegun begins the passkey method's challenge with the pending session's
// token and returns the challenge the request options carry.
func (d *pwlDeployment) mfaBegun(t *testing.T, tok string) string {
	t.Helper()

	out := serve(t, d.chain, bearerPost(t.Context(), passkeyMFABeginPath, tok))
	require.NoError(t, out.err)
	require.Equal(t, http.StatusOK, out.rec.Code)

	return d.verifier.lastRequest(t)
}

// mfaVerify posts body to the passkey method's verify path with tok.
func (d *pwlDeployment) mfaVerify(t *testing.T, tok, body string) served {
	t.Helper()

	return serve(t, d.chain, bearerJSON(t.Context(), passkeyMFAVerifyPath, tok, body))
}

// limiterCounting is an MFA verification limiter that never refuses and
// expects exactly failures recorded failures.
func limiterCounting(t *testing.T, failures int) *MockLimiter {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).Times(failures)

	return l
}

// TestPasskeyMFA drives the passkey MFA method through the MFA slot, after a
// password login, and after a passkey login.
func TestPasskeyMFA(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T, d *pwlDeployment)
		act    func(t *testing.T, d *pwlDeployment) served
		assert func(t *testing.T, d *pwlDeployment, out served)
	}

	// stillPending asserts the challenge was not resolved: the session the
	// challenge's token names still owes it.
	stillPending := func(t *testing.T, d *pwlDeployment, tok string) {
		t.Helper()

		assert.Equal(t, session.MFAPending, d.sessionOf(t, tok).MFA, "the challenge stays pending")
	}

	cases := []testCase{
		{
			name: "a password login is challenged, and the passkey resolves it",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.mfaLimiter = limiterCounting(t, 0)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.enrolTOTP(t)
				d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				d.seed(t, e2eUser, "cred-2", passkey.StateSuspended)

				ch := challenged(t, d.passwordLogin(t))
				assert.Equal(t, []httpsec.MFAMethod{
					{Name: "totp", Channel: factor.AuthenticatorApp, Begins: false},
					{Name: passkey.MethodName, Channel: factor.PublicKey, Begins: true},
				}, ch.Methods)

				challenge := d.mfaBegun(t, ch.Token)

				d.verifier.mu.Lock()
				allowed := d.verifier.allowed[len(d.verifier.allowed)-1]
				d.verifier.mu.Unlock()
				require.Len(t, allowed, 1, "only the active passkey is allowed")
				assert.Equal(t, []byte("cred-1"), allowed[0].ID)

				out := d.mfaVerify(t, ch.Token, assertionBody(challenge, "cred-1"))

				rotated := accessTokenFrom(t, out)
				assert.NotEqual(t, ch.Token, rotated, "the session is rotated")
				assert.Equal(t, session.MFASatisfied, d.sessionOf(t, rotated).MFA)

				return out
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
		{
			name: "after a passkey login without user verification, the passkey is the same channel",
			setup: func(_ *testing.T, d *pwlDeployment) {
				d.pkOpts = append(d.pkOpts, passkey.WithUserVerification(passkey.UVPreferred))
				d.verifier.notUserVerified.Store(true)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.enrolTOTP(t)

				ch := challenged(t, d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive)))
				assert.Equal(t, []httpsec.MFAMethod{
					{Name: "totp", Channel: factor.AuthenticatorApp, Begins: false},
				}, ch.Methods, "the passkey is not offered as the passkey login's second factor")

				return d.mfaVerify(t, ch.Token, assertionBody("anything", "cred-1"))
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, mfa.ErrSameChannel)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "a suspected clone at verify is refused, forbidden and not counted",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.mfaLimiter = limiterCounting(t, 0)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.seedCounted(t, e2eUser, "cred-1", passkey.StateActive, 5)

				ch := challenged(t, d.passwordLogin(t))
				challenge := d.mfaBegun(t, ch.Token)

				out := d.mfaVerify(t, ch.Token, assertionBody(challenge, "cred-1"))
				stillPending(t, d, ch.Token)

				return out
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, passkey.ErrCloneSuspected)
				require.ErrorIs(t, out.err, mfa.ErrAuthenticatorRefused)
				assert.NotErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))

				list, err := d.creds.List(t.Context(), e2eUser)
				require.NoError(t, err)
				require.Len(t, list, 1)
				assert.Equal(t, passkey.StateSuspended, list[0].State, "the credential is suspended")
			},
		},
		{
			name: "a suspended passkey at verify is refused, forbidden and not counted",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.mfaLimiter = limiterCounting(t, 0)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				d.seed(t, e2eUser, "cred-2", passkey.StateSuspended)

				ch := challenged(t, d.passwordLogin(t))
				challenge := d.mfaBegun(t, ch.Token)

				out := d.mfaVerify(t, ch.Token, assertionBody(challenge, "cred-2"))
				stillPending(t, d, ch.Token)

				return out
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, passkey.ErrSuspended)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "an assertion over a challenge never issued is refused and counted",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.mfaLimiter = limiterCounting(t, 1)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.seed(t, e2eUser, "cred-1", passkey.StateActive)

				ch := challenged(t, d.passwordLogin(t))
				d.mfaBegun(t, ch.Token)

				out := d.mfaVerify(t, ch.Token, assertionBody("a-challenge-the-library-never-issued", "cred-1"))
				stillPending(t, d, ch.Token)

				return out
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "a wrong signature over an issued challenge is refused and counted",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.mfaLimiter = limiterCounting(t, 1)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.seed(t, e2eUser, "cred-1", passkey.StateActive)

				ch := challenged(t, d.passwordLogin(t))
				challenge := d.mfaBegun(t, ch.Token)

				d.verifier.refuseAssertions.Store(true)

				out := d.mfaVerify(t, ch.Token, assertionBody(challenge, "cred-1"))
				stillPending(t, d, ch.Token)

				return out
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "another user's passkey is an invalid code",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.mfaLimiter = limiterCounting(t, 1)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				d.seed(t, "u-2", "cred-other", passkey.StateActive)

				ch := challenged(t, d.passwordLogin(t))
				challenge := d.mfaBegun(t, ch.Token)

				out := d.mfaVerify(t, ch.Token, assertionBody(challenge, "cred-other"))
				stillPending(t, d, ch.Token)

				return out
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newPwlDeployment(t)
			if tc.setup != nil {
				tc.setup(t, d)
			}

			d.build(t)

			tc.assert(t, d, tc.act(t, d))
		})
	}
}

// TestPasskeyFlushRefusalLogs pins that flushing the chain's refusal logs
// reaches the passkey components: the passkey manager's sampler, and the
// passwordless begin's source guard.
func TestPasskeyFlushRefusalLogs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		arrange func(t *testing.T, d *pwlDeployment, log *slog.Logger)
		drive   func(t *testing.T, d *pwlDeployment)
		assert  func(t *testing.T, flushed []slog.Record)
	}

	cases := []testCase{
		{
			name: "the passkey manager's sampler",
			arrange: func(_ *testing.T, d *pwlDeployment, log *slog.Logger) {
				d.pkOpts = append(d.pkOpts, passkey.WithLogger(log), passkey.WithLogInterval(time.Hour))
			},
			drive: func(t *testing.T, d *pwlDeployment) {
				// Three finishes without a ceremony cookie: one refusal record
				// written, two held back.
				for range 3 {
					_, challenge := d.begun(t)
					out := d.finish(t, assertionBody(challenge, "cred-1"))
					require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, "passkey: records suppressed", "key", "refused|binding"))
			},
		},
		{
			name: "the passwordless begin's source guard",
			arrange: func(t *testing.T, d *pwlDeployment, _ *slog.Logger) {
				d.settings = append(d.settings, httpsec.PasswordlessLimiter(exceededLimiter(t)))
			},
			drive: func(t *testing.T, d *pwlDeployment) {
				for range 3 {
					out := serve(t, d.chain, postValues(t.Context(), passwordlessBeginPath, flushSource, url.Values{}))
					require.Error(t, out.err)
				}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryGuard, "flow", "passkey-login"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logs := &capturingHandler{}
			log := slog.New(logs)

			d := newPwlDeployment(t)
			d.extra = append(d.extra, httpsec.WithLogger(log))
			tc.arrange(t, d, log)
			d.build(t)

			tc.drive(t, d)
			before := len(logs.records())

			d.chain.FlushRefusalLogs()

			tc.assert(t, logs.records()[before:])
		})
	}
}
