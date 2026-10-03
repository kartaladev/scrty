package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/password"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

func TestStatusForError(t *testing.T) {
	t.Parallel()

	// A source guard's refusal of a check its shared limiter could not make
	// because the backend is down, exactly as the guard builds it.
	outage := guardRefusalOver(t, fmt.Errorf("dial: %w", ratelimit.ErrBackendUnavailable))

	type testCase struct {
		name string
		err  error
		want int
	}

	cases := []testCase{
		{name: "authentication required", err: httpsec.ErrAuthenticationRequired, want: 401},
		{name: "authorize's authentication required", err: authorize.ErrAuthenticationRequired, want: 401},
		{
			name: "the stage's wrap matches both identities",
			err:  fmt.Errorf("%w: %w", httpsec.ErrAuthenticationRequired, authorize.ErrAuthenticationRequired),
			want: 401,
		},
		{name: "authentication failed", err: authenticate.ErrAuthenticationFailed, want: 401},
		{name: "session idle", err: policy.ErrSessionIdle, want: 401},
		{name: "throttled source", err: ratelimit.ErrThrottled, want: 401},
		{
			name: "a source-guard refusal wrapping a backend outage reads as throttled",
			err:  outage,
			want: 401,
		},
		{name: "access denied", err: authorize.ErrAccessDenied, want: 403},
		{name: "reasonless policy deny", err: policy.ErrPolicyDenied, want: 403},
		{name: "second factor required", err: policy.ErrMFARequired, want: 403},
		{name: "second factor unsatisfiable", err: policy.ErrMFARequirementUnsatisfiable, want: 403},
		{name: "second factor enrolment required", err: policy.ErrMFAEnrollmentRequired, want: 403},
		{name: "second factor on the first factor's channel", err: policy.ErrSecondFactorSameChannel, want: 403},
		{name: "provider assurance not met", err: policy.ErrFederatedAssuranceNotMet, want: 403},
		{name: "invalid second-factor code", err: mfa.ErrInvalidCode, want: 401},
		{name: "throttled second-factor verification", err: mfa.ErrVerifyThrottled, want: 401},
		{name: "exhausted second-factor attempts", err: mfa.ErrVerifyAttemptsExhausted, want: 401},
		{name: "second-factor method on the first factor's channel", err: mfa.ErrSameChannel, want: 403},
		{name: "already enrolled", err: mfa.ErrAlreadyEnrolled, want: 403},
		{
			name: "authenticator itself refused",
			err:  fmt.Errorf("%w: suspected clone", mfa.ErrAuthenticatorRefused),
			want: 403,
		},
		{
			name: "an invalid, expired or voided emailed code, answered by the invalid-code row",
			err:  mfa.ErrEmailCodeInvalid,
			want: 401,
		},
		{name: "throttled enrolment", err: mfa.ErrEnrolmentThrottled, want: 401},
		{name: "wrapped invalid code", err: fmt.Errorf("verifying: %w", mfa.ErrInvalidCode), want: 401},
		{name: "malformed login", err: httpsec.ErrCredentialsMissing, want: 400},
		{name: "request too large", err: httpsec.ErrRequestTooLarge, want: 413},
		{name: "reused password", err: password.ErrPasswordReused, want: 422},
		{
			name: "wrapped reused password",
			err:  fmt.Errorf("change: %w", password.ErrPasswordReused),
			want: 422,
		},
		{name: "password history unavailable is a dependency failure", err: password.ErrHistoryUnavailable, want: 500},
		{name: "account locked", err: policy.ErrAccountLocked, want: 423},
		{name: "too many sessions", err: policy.ErrTooManySessions, want: 429},
		{name: "unknown identity provider", err: oidc.ErrUnknownProvider, want: 404},
		{name: "unknown MFA method", err: httpsec.ErrUnknownMFAMethod, want: 404},
		{name: "MFA method not usable", err: fmt.Errorf("x: %w", httpsec.ErrMFAMethodNotUsable), want: 403},
		{name: "no MFA challenge pending", err: fmt.Errorf("x: %w", httpsec.ErrNoMFAChallengePending), want: 403},
		{name: "invalid logout token", err: oidc.ErrInvalidLogoutToken, want: 400},
		{name: "invalid handoff is an authentication failure with no row", err: oidc.ErrInvalidHandoff, want: 401},
		{name: "wrapped invalid ID token", err: fmt.Errorf("x: %w", oidc.ErrInvalidIDToken), want: 401},

		{
			name: "wrapped sentinel keeps its status",
			err:  fmt.Errorf("evaluating the rule set: %w", authorize.ErrAccessDenied),
			want: 403,
		},
		{
			name: "joined verification failure keeps its status",
			err:  errors.Join(authenticate.ErrAuthenticationFailed, errors.New("token: signature invalid")),
			want: 401,
		},
		{
			name: "second-factor challenge",
			err:  &httpsec.ChallengeError{Kind: policy.ChallengeMFA},
			want: 401,
		},
		{
			name: "password-change challenge",
			err:  &httpsec.ChallengeError{Kind: policy.ChallengePasswordChange},
			want: 403,
		},
		{
			name: "enrolment challenge",
			err:  &httpsec.ChallengeError{Kind: policy.ChallengeMFAEnrolment},
			want: 403,
		},
		{
			name: "account-recovery challenge",
			err:  &httpsec.ChallengeError{Kind: policy.ChallengeAccountRecovery},
			want: 403,
		},
		{name: "refused recovery", err: recovery.ErrRefused, want: 401},
		{name: "wrapped refused recovery", err: fmt.Errorf("completing: %w", recovery.ErrRefused), want: 401},
		{name: "malformed recovery", err: recovery.ErrMalformed, want: 400},
		{name: "recovery not yet completable", err: recovery.ErrNotYetCompletable, want: 409},
		{name: "recovery cool-down", err: recovery.ErrCooldown, want: 403},
		{name: "reauthentication required", err: recovery.ErrReauthenticationRequired, want: 403},
		{name: "throttled saved-code presentation", err: recovery.ErrCodeThrottled, want: 401},
		{name: "suspected passkey clone", err: passkey.ErrCloneSuspected, want: 403},
		{name: "suspended passkey", err: passkey.ErrSuspended, want: 403},
		{name: "pending passkey", err: passkey.ErrPending, want: 403},
		{name: "passkey attestation refused", err: passkey.ErrAttestationRefused, want: 403},
		{name: "passkey limit reached", err: passkey.ErrLimitReached, want: 403},
		{name: "passkey reauthentication required", err: passkey.ErrReauthenticationRequired, want: 403},
		{name: "passkey not found", err: passkey.ErrNotFound, want: 404},
		{name: "wrapped passkey not found", err: fmt.Errorf("removing: %w", passkey.ErrNotFound), want: 404},
		{name: "throttled passkey registration begin", err: passkey.ErrRegistrationThrottled, want: 401},
		{
			// The chain answers an unreadable ceremony response as the
			// missing-credentials refusal, keeping the core's reachable.
			name: "unreadable passkey response", err: passkey.ErrMalformedResponse, want: 400,
		},
		{
			name: "a consumer's own challenge kind",
			err:  &httpsec.ChallengeError{Kind: policy.ChallengeKind(100)},
			want: 401,
		},
		{
			name: "a challenge reached through a wrap is still a challenge",
			err: fmt.Errorf("completing the login: %w",
				&httpsec.ChallengeError{Kind: policy.ChallengePasswordChange}),
			want: 403,
		},
		{
			name: "a challenge outranks a sentinel it wraps",
			err: fmt.Errorf("%w: %w",
				&httpsec.ChallengeError{Kind: policy.ChallengeMFA}, authorize.ErrAccessDenied),
			want: 401,
		},
		{
			name: "an unrecognised error is a server fault",
			err:  errors.New("connection refused to db-primary:5432"),
			want: 500,
		},
		{name: "nil is a server fault", err: nil, want: 500},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, httpsec.StatusForError(tc.err))
		})
	}
}

// denyPolicy denies with no reason at all, which is what a consumer policy
// that refuses without explaining itself looks like to the engine.
type denyPolicy struct{ phase policy.Phase }

func (denyPolicy) Name() string             { return "test: reasonless deny" }
func (p denyPolicy) Phases() []policy.Phase { return []policy.Phase{p.phase} }
func (denyPolicy) Evaluate(context.Context, *policy.Input) policy.Decision {
	return policy.Decision{Outcome: policy.Deny}
}

func TestPolicyDenyReason(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		phase  policy.Phase
		assert func(t *testing.T, reason error)
	}

	cases := []testCase{
		{
			name:  "a reasonless deny at login refuses with the engine's substituted sentinel",
			phase: policy.PostAuthentication,
			assert: func(t *testing.T, reason error) {
				require.ErrorIs(t, reason, policy.ErrPolicyDenied)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(reason))
				assert.NotEqual(t, http.StatusOK, httpsec.StatusForError(reason))
				assert.False(t, errors.Is(reason, authenticate.ErrAuthenticationFailed),
					"a policy deny must never read as a failed credential")
			},
		},
		{
			name:  "a reasonless deny per request refuses the same way",
			phase: policy.PerRequest,
			assert: func(t *testing.T, reason error) {
				require.ErrorIs(t, reason, policy.ErrPolicyDenied)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(reason))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			engine, err := policy.NewEngine(denyPolicy{phase: tc.phase})
			require.NoError(t, err)

			d := engine.EvaluatePhase(t.Context(), tc.phase, &policy.Input{Now: time.Now()})
			require.Equal(t, policy.Deny, d.Outcome)

			reason := httpsec.PolicyDenyReason(d)
			require.Error(t, reason, "a deny the engine reduced always carries a reason")
			tc.assert(t, reason)
		})
	}
}

// sentinelRegistry lists every exported refusal sentinel of the packages whose
// refusals reach a client through this chain. It is written out because
// reflection cannot enumerate package-level variables; declaredErrVars keeps it
// honest by failing when a package exports one that is not listed here.
var sentinelRegistry = map[string]map[string]error{
	"github.com/kartaladev/scrty/authenticate": {
		"authenticate.ErrAuthenticationFailed":    authenticate.ErrAuthenticationFailed,
		"authenticate.ErrConfig":                  authenticate.ErrConfig,
		"authenticate.ErrNoEligibleAuthenticator": authenticate.ErrNoEligibleAuthenticator,
		"authenticate.ErrUnsupportedCredentials":  authenticate.ErrUnsupportedCredentials,
	},
	"github.com/kartaladev/scrty/authorize": {
		"authorize.ErrAccessDenied":           authorize.ErrAccessDenied,
		"authorize.ErrAuthenticationRequired": authorize.ErrAuthenticationRequired,
		"authorize.ErrConfig":                 authorize.ErrConfig,
		"authorize.ErrInvalidAttributes":      authorize.ErrInvalidAttributes,
		"authorize.ErrUnsupportedAttributes":  authorize.ErrUnsupportedAttributes,
	},
	"github.com/kartaladev/scrty/mfa": {
		"mfa.ErrAlreadyEnrolled":         mfa.ErrAlreadyEnrolled,
		"mfa.ErrAuthenticatorRefused":    mfa.ErrAuthenticatorRefused,
		"mfa.ErrConfig":                  mfa.ErrConfig,
		"mfa.ErrEmailCodeInvalid":        mfa.ErrEmailCodeInvalid,
		"mfa.ErrEnrolmentThrottled":      mfa.ErrEnrolmentThrottled,
		"mfa.ErrInvalidCode":             mfa.ErrInvalidCode,
		"mfa.ErrSameChannel":             mfa.ErrSameChannel,
		"mfa.ErrVerifyAttemptsExhausted": mfa.ErrVerifyAttemptsExhausted,
		"mfa.ErrVerifyThrottled":         mfa.ErrVerifyThrottled,
	},
	"github.com/kartaladev/scrty/oidc": {
		"oidc.ErrConfig":              oidc.ErrConfig,
		"oidc.ErrDiscoveryFailed":     oidc.ErrDiscoveryFailed,
		"oidc.ErrExchangeFailed":      oidc.ErrExchangeFailed,
		"oidc.ErrFlowStoreFull":       oidc.ErrFlowStoreFull,
		"oidc.ErrFlowUnspent":         oidc.ErrFlowUnspent,
		"oidc.ErrHandoffNotFound":     oidc.ErrHandoffNotFound,
		"oidc.ErrInvalidHandoff":      oidc.ErrInvalidHandoff,
		"oidc.ErrInvalidIDToken":      oidc.ErrInvalidIDToken,
		"oidc.ErrInvalidLogoutToken":  oidc.ErrInvalidLogoutToken,
		"oidc.ErrInvalidState":        oidc.ErrInvalidState,
		"oidc.ErrLinkExists":          oidc.ErrLinkExists,
		"oidc.ErrLinkNotFound":        oidc.ErrLinkNotFound,
		"oidc.ErrNoLinkedAccount":     oidc.ErrNoLinkedAccount,
		"oidc.ErrProvisioningRefused": oidc.ErrProvisioningRefused,
		"oidc.ErrRetainSinceRequired": oidc.ErrRetainSinceRequired,
		"oidc.ErrUnknownProvider":     oidc.ErrUnknownProvider,
	},
	"github.com/kartaladev/scrty/passkey": {
		"passkey.ErrAttestationRefused":       passkey.ErrAttestationRefused,
		"passkey.ErrCloneSuspected":           passkey.ErrCloneSuspected,
		"passkey.ErrConfig":                   passkey.ErrConfig,
		"passkey.ErrDuplicateCredential":      passkey.ErrDuplicateCredential,
		"passkey.ErrLimitReached":             passkey.ErrLimitReached,
		"passkey.ErrMalformedResponse":        passkey.ErrMalformedResponse,
		"passkey.ErrNotFound":                 passkey.ErrNotFound,
		"passkey.ErrPending":                  passkey.ErrPending,
		"passkey.ErrReauthenticationRequired": passkey.ErrReauthenticationRequired,
		"passkey.ErrRegistrationThrottled":    passkey.ErrRegistrationThrottled,
		"passkey.ErrSuspended":                passkey.ErrSuspended,
	},
	"github.com/kartaladev/scrty/password": {
		"password.ErrConfig":             password.ErrConfig,
		"password.ErrHistoryUnavailable": password.ErrHistoryUnavailable,
		"password.ErrInvalidParameters":  password.ErrInvalidParameters,
		"password.ErrNoRandomSource":     password.ErrNoRandomSource,
		"password.ErrPasswordReused":     password.ErrPasswordReused,
		"password.ErrPasswordTooLong":    password.ErrPasswordTooLong,
		"password.ErrWeakParameters":     password.ErrWeakParameters,
	},
	"github.com/kartaladev/scrty/policy": {
		"policy.ErrAccountLocked":               policy.ErrAccountLocked,
		"policy.ErrConfig":                      policy.ErrConfig,
		"policy.ErrFederatedAssuranceNotMet":    policy.ErrFederatedAssuranceNotMet,
		"policy.ErrMFAEnrollmentRequired":       policy.ErrMFAEnrollmentRequired,
		"policy.ErrMFARequired":                 policy.ErrMFARequired,
		"policy.ErrMFARequirementLookupMissing": policy.ErrMFARequirementLookupMissing,
		"policy.ErrMFARequirementUnsatisfiable": policy.ErrMFARequirementUnsatisfiable,
		"policy.ErrPolicyDenied":                policy.ErrPolicyDenied,
		"policy.ErrReapUnsupported":             policy.ErrReapUnsupported,
		"policy.ErrRetainSinceRequired":         policy.ErrRetainSinceRequired,
		"policy.ErrSecondFactorSameChannel":     policy.ErrSecondFactorSameChannel,
		"policy.ErrSessionIdle":                 policy.ErrSessionIdle,
		"policy.ErrTooManySessions":             policy.ErrTooManySessions,
	},
	"github.com/kartaladev/scrty/ratelimit": {
		"ratelimit.ErrBackendUnavailable":   ratelimit.ErrBackendUnavailable,
		"ratelimit.ErrConfig":               ratelimit.ErrConfig,
		"ratelimit.ErrSourceEmpty":          ratelimit.ErrSourceEmpty,
		"ratelimit.ErrSourceNotAnIP":        ratelimit.ErrSourceNotAnIP,
		"ratelimit.ErrSourceUnattributable": ratelimit.ErrSourceUnattributable,
		"ratelimit.ErrSourceUnspecified":    ratelimit.ErrSourceUnspecified,
		"ratelimit.ErrThrottled":            ratelimit.ErrThrottled,
	},
	"github.com/kartaladev/scrty/recovery": {
		"recovery.ErrCodeThrottled":            recovery.ErrCodeThrottled,
		"recovery.ErrConfig":                   recovery.ErrConfig,
		"recovery.ErrCooldown":                 recovery.ErrCooldown,
		"recovery.ErrMalformed":                recovery.ErrMalformed,
		"recovery.ErrNotYetCompletable":        recovery.ErrNotYetCompletable,
		"recovery.ErrReauthenticationRequired": recovery.ErrReauthenticationRequired,
		"recovery.ErrRecordNotFound":           recovery.ErrRecordNotFound,
		"recovery.ErrRefused":                  recovery.ErrRefused,
	},
	"github.com/kartaladev/scrty/httpsec": {
		"httpsec.ErrAuthenticationRequired": httpsec.ErrAuthenticationRequired,
		"httpsec.ErrConfig":                 httpsec.ErrConfig,
		"httpsec.ErrCredentialsMissing":     httpsec.ErrCredentialsMissing,
		"httpsec.ErrMalformedRequest":       httpsec.ErrMalformedRequest,
		"httpsec.ErrMFAMethodNotUsable":     httpsec.ErrMFAMethodNotUsable,
		"httpsec.ErrNoMFAChallengePending":  httpsec.ErrNoMFAChallengePending,
		"httpsec.ErrRequestTooLarge":        httpsec.ErrRequestTooLarge,
		"httpsec.ErrUnknownMFAMethod":       httpsec.ErrUnknownMFAMethod,
	},
	"github.com/kartaladev/scrty/session": {
		"session.ErrConfig":            session.ErrConfig,
		"session.ErrSessionExpired":    session.ErrSessionExpired,
		"session.ErrSessionNotFound":   session.ErrSessionNotFound,
		"session.ErrSessionUnreadable": session.ErrSessionUnreadable,
	},
}

// TestStatusForErrorCoversEverySentinel fails when a mapped package exports a
// refusal sentinel StatusForError does not recognise. A new sentinel is then a
// deliberate decision about its status, not an accidental 500.
func TestStatusForErrorCoversEverySentinel(t *testing.T) {
	t.Parallel()

	// Sentinels that are deliberately unmapped, each with the reason. A
	// configuration error is a wiring fault the consumer sees at construction,
	// never a refusal a client is answered with.
	unmapped := map[string]string{ //nolint:gosec // G101 false positive: keys are sentinel names such as "password.ErrConfig", values are reasons, none is a credential.
		"authenticate.ErrConfig":                  "a wiring fault, refused at construction",
		"authenticate.ErrNoEligibleAuthenticator": "a wiring fault: nothing was configured to judge the credentials",
		"authenticate.ErrUnsupportedCredentials":  "internal dispatch between providers, never returned to a client",
		"authorize.ErrConfig":                     "a wiring fault, refused at construction",
		"httpsec.ErrConfig":                       "a wiring fault, refused at construction",
		"authorize.ErrUnsupportedAttributes":      "a misbuilt guard, deliberately 500 per design Decision 7",
		"authorize.ErrInvalidAttributes":          "a misbuilt guard, deliberately 500 per design Decision 7",
		"session.ErrConfig":                       "a wiring fault, refused at construction",
		"session.ErrSessionNotFound":              "converted to ErrAuthenticationRequired before it leaves the chain",
		"session.ErrSessionExpired":               "converted to ErrAuthenticationRequired before it leaves the chain",
		"session.ErrSessionUnreadable":            "converted to ErrAuthenticationRequired before it leaves the chain",
		"ratelimit.ErrConfig":                     "a wiring fault, refused at construction",
		"ratelimit.ErrBackendUnavailable": "returned by a limiter, never by a flow: every built-in caller wraps " +
			"or replaces it with a throttle sentinel before it leaves",
		"ratelimit.ErrSourceUnattributable":     "converted to authenticate.ErrAuthenticationFailed before it leaves the chain",
		"ratelimit.ErrSourceEmpty":              "converted to authenticate.ErrAuthenticationFailed before it leaves the chain",
		"ratelimit.ErrSourceNotAnIP":            "converted to authenticate.ErrAuthenticationFailed before it leaves the chain",
		"ratelimit.ErrSourceUnspecified":        "converted to authenticate.ErrAuthenticationFailed before it leaves the chain",
		"policy.ErrConfig":                      "a wiring fault, refused at construction",
		"policy.ErrReapUnsupported":             "a maintenance-path fault, not a request refusal",
		"policy.ErrRetainSinceRequired":         "a maintenance-path fault, not a request refusal",
		"policy.ErrMFARequirementLookupMissing": "a wiring fault, refused at construction",
		"mfa.ErrConfig":                         "a wiring fault, refused at construction",
		"oidc.ErrConfig":                        "a wiring fault, refused at construction",
		"oidc.ErrExchangeFailed":                "a provider failure, deliberately 500",
		"oidc.ErrDiscoveryFailed":               "a provider failure, deliberately 500",
		"oidc.ErrLinkNotFound":                  "a store outcome the library converts before it leaves oidc",
		"oidc.ErrLinkExists":                    "a store outcome the library converts before it leaves oidc",
		"oidc.ErrHandoffNotFound":               "a store outcome the library converts before it leaves oidc",
		"oidc.ErrRetainSinceRequired":           "a purge misuse, never a request outcome",
		"oidc.ErrFlowStoreFull":                 "capacity exhaustion, deliberately 500",
		"oidc.ErrFlowUnspent":                   "a marker joined onto another refusal, never returned alone",
		"password.ErrConfig":                    "a wiring fault, refused at construction",
		"password.ErrInvalidParameters":         "a wiring fault, refused at construction",
		"password.ErrNoRandomSource":            "a wiring fault, refused at construction",
		"password.ErrWeakParameters":            "a wiring fault, refused at construction",
		"password.ErrHistoryUnavailable":        "a dependency failure, deliberately 500",
		"password.ErrPasswordTooLong":           "the encoder's error is returned as is, and the consumer decides",
		"recovery.ErrConfig":                    "a wiring fault, refused at construction",
		"recovery.ErrRecordNotFound":            "a store outcome the recovery core converts to ErrRefused before it leaves the core",
		"passkey.ErrConfig":                     "a wiring fault, refused at construction",
		"passkey.ErrDuplicateCredential":        "a store outcome the passkey core converts to authenticate.ErrAuthenticationFailed before it leaves the core",
	}

	for _, pkg := range []string{
		"github.com/kartaladev/scrty/authenticate",
		"github.com/kartaladev/scrty/authorize",
		"github.com/kartaladev/scrty/httpsec",
		"github.com/kartaladev/scrty/mfa",
		"github.com/kartaladev/scrty/oidc",
		"github.com/kartaladev/scrty/passkey",
		"github.com/kartaladev/scrty/password",
		"github.com/kartaladev/scrty/policy",
		"github.com/kartaladev/scrty/ratelimit",
		"github.com/kartaladev/scrty/recovery",
		"github.com/kartaladev/scrty/session",
	} {
		for name, err := range exportedSentinels(t, pkg) {
			if _, ok := unmapped[name]; ok {
				continue
			}
			t.Run(name, func(t *testing.T) {
				assert.NotEqual(t, http.StatusInternalServerError, httpsec.StatusForError(err),
					"%s is exported as a refusal but StatusForError does not recognise it; "+
						"add it to statusTable, or to this test's unmapped map with the reason", name)
			})
		}
	}
}

// guardRefusalOver returns the refusal a source guard answers a check with when
// its limiter fails with err.
func guardRefusalOver(t *testing.T, err error) error {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, err)

	g, gErr := ratelimit.NewSourceGuard("status", l,
		ratelimit.WithSourceGuardLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, gErr)

	_, refusal := g.Check(t.Context(), "198.51.100.7")
	require.ErrorIs(t, refusal, ratelimit.ErrBackendUnavailable, "the outage stays reachable")

	return refusal
}

// exportedSentinels returns every exported Err* variable of pkg, keyed
// "<pkg>.<Name>". It cross-checks the registry against the package's source,
// so a sentinel added without being registered fails the test rather than
// being skipped.
func exportedSentinels(t *testing.T, pkg string) map[string]error {
	t.Helper()

	registered := sentinelRegistry[pkg]
	require.NotEmpty(t, registered, "no sentinels registered for %s", pkg)

	for _, name := range declaredErrVars(t, pkg) {
		_, ok := registered[path.Base(pkg)+"."+name]
		assert.True(t, ok, "%s.%s is exported but not registered in sentinelRegistry", pkg, name)
	}

	return registered
}

// declaredErrVars names the exported Err* package-level variables pkg declares,
// read from its source. It parses rather than reflecting because reflection
// cannot enumerate package-level variables, and it reads the files directly so
// this package gains no tooling dependency to do it.
func declaredErrVars(t *testing.T, pkg string) []string {
	t.Helper()

	const modulePrefix = "github.com/kartaladev/scrty/"
	require.True(t, strings.HasPrefix(pkg, modulePrefix), "%s is outside this module", pkg)
	dir := filepath.Join("..", filepath.FromSlash(strings.TrimPrefix(pkg, modulePrefix)))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "reading %s", dir)

	fset := token.NewFileSet()

	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		require.NoError(t, err, "parsing %s", name)

		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, ident := range vs.Names {
					if strings.HasPrefix(ident.Name, "Err") && ident.IsExported() {
						names = append(names, ident.Name)
					}
				}
			}
		}
	}

	require.NotEmpty(t, names, "no exported Err* variables found in %s", dir)
	return names
}
