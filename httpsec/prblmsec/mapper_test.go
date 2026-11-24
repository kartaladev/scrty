package prblmsec_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/kartaladev/prblm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/prblmsec"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// errConn stands for a dependency's own failure, such as a dropped database
// connection. Its text must never reach a problem.
var errConn = errors.New("dial tcp 10.0.0.7:5432: connection refused for alice@example.com")

// signalsMethodRefusal matches, through errors.Is, the core's unexported
// refusal of a non-GET request on the signal stream, by its text. It is the
// only way to reach a recognised 405 without a whole chain; the test asserts
// the 405 itself, so a change of that text fails here rather than passing
// vacuously.
type signalsMethodRefusal struct{}

func (signalsMethodRefusal) Error() string { return "signals method" }

func (signalsMethodRefusal) Is(target error) bool {
	return target != nil && target.Error() == "httpsec: the signal stream answers only GET"
}

func newProblems(t *testing.T, opts ...prblmsec.Option) *prblmsec.Problems {
	t.Helper()
	p, err := prblmsec.New(opts...)
	require.NoError(t, err)
	return p
}

func TestMapper_TypePerRefusal(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, err error, prob *prblm.Problem)
	}

	typed := func(sub string) func(t *testing.T, err error, prob *prblm.Problem) {
		return func(t *testing.T, err error, prob *prblm.Problem) {
			t.Helper()
			require.NotNil(t, prob)
			assert.Equal(t, prblmsec.DefaultTypePrefix+"/"+sub, prob.Type)
			assert.Equal(t, httpsec.StatusForError(err), prob.Status)
			assert.NotEmpty(t, prob.Title)
			assert.NotEmpty(t, prob.Detail)
			assert.ErrorIs(t, prob, err, "the cause stays reachable")
		}
	}
	blank := func(status int) func(t *testing.T, err error, prob *prblm.Problem) {
		return func(t *testing.T, err error, prob *prblm.Problem) {
			t.Helper()
			require.NotNil(t, prob)
			assert.Equal(t, status, prob.Status)
			assert.Equal(t, httpsec.StatusForError(err), prob.Status)
			assert.Equal(t, "about:blank", prob.EffectiveType())
			assert.Empty(t, prob.Detail)
			assert.ErrorIs(t, prob, err, "the cause stays reachable")
		}
	}

	wrap := func(err error) error { return fmt.Errorf("handler: %w", err) }
	challenge := func(kind policy.ChallengeKind) error { return &httpsec.ChallengeError{Kind: kind} }

	cases := []testCase{
		// 401
		{name: "authentication required", err: httpsec.ErrAuthenticationRequired, assert: typed("authentication-required")},
		{name: "authorize authentication required", err: authorize.ErrAuthenticationRequired, assert: typed("authentication-required")},
		{name: "session idle", err: policy.ErrSessionIdle, assert: typed("authentication-required")},
		{
			name:   "session expired",
			err:    errors.Join(httpsec.ErrAuthenticationRequired, session.ErrExpired),
			assert: typed("authentication-required"),
		},
		{name: "provider reauthentication", err: oidcprovider.ErrReauthenticate, assert: typed("authentication-required")},
		{name: "wrong password", err: authenticate.ErrAuthenticationFailed, assert: typed("authentication-failed")},
		{
			name:   "concealed lock",
			err:    errors.Join(authenticate.ErrAuthenticationFailed, lockout.ErrAccountLocked),
			assert: typed("authentication-failed"),
		},
		{
			name:   "concealed inactive account",
			err:    errors.Join(authenticate.ErrAuthenticationFailed, authenticate.ErrAccountInactive),
			assert: typed("authentication-failed"),
		},
		{
			name:   "user store unavailable",
			err:    fmt.Errorf("%w: %w", authenticate.ErrUnavailable, errConn),
			assert: typed("authentication-failed"),
		},
		{name: "throttled source", err: ratelimit.ErrThrottled, assert: typed("authentication-failed")},
		{name: "throttled recovery code", err: recovery.ErrCodeThrottled, assert: typed("authentication-failed")},
		{name: "refused recovery", err: recovery.ErrRefused, assert: typed("authentication-failed")},
		{name: "refused magic link", err: magiclink.ErrInvalidLink, assert: typed("authentication-failed")},
		{name: "invalid second-factor code", err: mfa.ErrInvalidCode, assert: typed("second-factor-failed")},
		{name: "throttled verification", err: mfa.ErrVerifyThrottled, assert: typed("second-factor-failed")},
		{name: "throttled enrolment", err: mfa.ErrEnrolmentThrottled, assert: typed("second-factor-failed")},
		{name: "throttled passkey registration", err: passkey.ErrRegistrationThrottled, assert: typed("second-factor-failed")},
		{name: "dpop nonce required", err: httpsec.ErrDPoPNonceRequired, assert: typed("proof-of-possession-failed")},
		{name: "invalid dpop proof", err: httpsec.ErrInvalidDPoPProof, assert: typed("proof-of-possession-failed")},
		{name: "certificate binding", err: httpsec.ErrCertificateBinding, assert: typed("proof-of-possession-failed")},
		{name: "mfa challenge", err: challenge(policy.ChallengeMFA), assert: typed("mfa-required")},
		{name: "consumer challenge", err: challenge(policy.ChallengeKind(100)), assert: typed("challenge-required")},
		{name: "none-kind challenge", err: challenge(policy.ChallengeNone), assert: typed("challenge-required")},

		// 403
		{name: "password change challenge", err: challenge(policy.ChallengePasswordChange), assert: typed("password-change-required")},
		{name: "mfa enrolment challenge", err: challenge(policy.ChallengeMFAEnrolment), assert: typed("mfa-enrolment-required")},
		{name: "account recovery challenge", err: challenge(policy.ChallengeAccountRecovery), assert: typed("account-recovery-required")},
		{name: "reauthentication required", err: httpsec.ErrReauthenticationRequired, assert: typed("reauthentication-required")},
		{
			name:   "recency guard",
			err:    &httpsec.ReauthenticationRequiredError{Window: 5 * time.Minute},
			assert: typed("reauthentication-required"),
		},
		{name: "recovery reauthentication", err: recovery.ErrReauthenticationRequired, assert: typed("reauthentication-required")},
		{name: "passkey reauthentication", err: passkey.ErrReauthenticationRequired, assert: typed("reauthentication-required")},
		{name: "cross-site request", err: httpsec.ErrCrossSiteRequest, assert: typed("cross-site-request")},
		{name: "cross-site stream", err: httpsec.ErrCrossSiteStream, assert: typed("cross-site-request")},
		{name: "automation challenge", err: httpsec.ErrChallengeRequired, assert: typed("automation-challenge-required")},
		{name: "disclosed inactive account", err: authenticate.ErrAccountInactive, assert: typed("account-inactive")},
		{name: "access denied", err: authorize.ErrAccessDenied, assert: typed("access-denied")},
		{name: "access denied wrapped", err: wrap(authorize.ErrAccessDenied), assert: typed("access-denied")},
		{name: "policy denied", err: policy.ErrDenied, assert: typed("access-denied")},
		{name: "reauthentication method not usable", err: httpsec.ErrReauthenticationMethodNotUsable, assert: typed("access-denied")},

		// 400, 404, 409, 413, 422
		{name: "malformed request", err: httpsec.ErrMalformedRequest, assert: typed("invalid-request")},
		{name: "credentials missing", err: httpsec.ErrCredentialsMissing, assert: typed("invalid-request")},
		{name: "unknown mfa method", err: httpsec.ErrUnknownMFAMethod, assert: typed("not-found")},
		{name: "renewal conflict", err: session.ErrRenewalConflict, assert: typed("conflict")},
		{name: "request too large", err: httpsec.ErrRequestTooLarge, assert: typed("request-too-large")},
		{name: "password rejected", err: password.RejectedError{Rule: password.RuleBreached}, assert: typed("password-rejected")},
		{name: "password reused", err: password.ErrReused, assert: typed("password-rejected")},

		// 429
		{name: "disclosed lock", err: lockout.ErrAccountLocked, assert: typed("account-locked")},
		{name: "held identifier", err: lockout.ErrAccountHeld, assert: typed("account-locked")},
		{name: "too many sessions", err: policy.ErrTooManySessions, assert: typed("limit-reached")},
		{name: "throttled provider endpoint", err: httpsec.ErrOIDCThrottled, assert: typed("limit-reached")},
		{name: "renewal throttled", err: httpsec.ErrRenewalThrottled, assert: typed("limit-reached")},

		// Precedence.
		{
			name:   "challenge wrapping access denied",
			err:    fmt.Errorf("%w: %w", challenge(policy.ChallengeMFA), authorize.ErrAccessDenied),
			assert: typed("mfa-required"),
		},
		{
			// StatusForError picks the challenge, 401; the mapper follows it.
			name:   "challenge joined with access denied",
			err:    errors.Join(authorize.ErrAccessDenied, challenge(policy.ChallengeMFA)),
			assert: typed("mfa-required"),
		},
		{
			// Whichever status StatusForError gives, the type is one of that
			// status's types, never the other refusal's.
			name: "joined across statuses",
			err:  errors.Join(httpsec.ErrCrossSiteRequest, mfa.ErrInvalidCode),
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				want := map[int]string{
					http.StatusUnauthorized: "second-factor-failed",
					http.StatusForbidden:    "cross-site-request",
				}[httpsec.StatusForError(err)]
				require.NotEmpty(t, want, "unexpected core status %d", httpsec.StatusForError(err))
				typed(want)(t, err, prob)
			},
		},

		// Recognised statuses without a type.
		{name: "recognised 500", err: fmt.Errorf("%w: %w", httpsec.ErrChallengeUnavailable, errConn), assert: blank(http.StatusInternalServerError)},
		{
			name:   "recognised dependency failure",
			err:    fmt.Errorf("%w: %w", password.ErrHistoryUnavailable, errConn),
			assert: blank(http.StatusInternalServerError),
		},
		{name: "recognised 405", err: signalsMethodRefusal{}, assert: blank(http.StatusMethodNotAllowed)},
		{name: "recognised 501", err: httpsec.ErrStreamingUnsupported, assert: blank(http.StatusNotImplemented)},

		// Not recognised.
		{
			name: "unrecognised",
			err:  errConn,
			assert: func(t *testing.T, _ error, prob *prblm.Problem) {
				t.Helper()
				assert.Nil(t, prob)
			},
		},
		{
			name: "nil",
			err:  nil,
			assert: func(t *testing.T, _ error, prob *prblm.Problem) {
				t.Helper()
				assert.Nil(t, prob)
			},
		},
	}

	p := newProblems(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			prob := p.Mapper().MapError(t.Context(), tc.err)
			tc.assert(t, tc.err, prob)
		})
	}
}
