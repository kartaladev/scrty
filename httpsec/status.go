package httpsec

import (
	"errors"
	"net/http"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/password"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
)

// statusRow is one refusal and the status it answers with. The table is
// ordered, and the first row whose sentinel the error matches decides, so two
// rows can never disagree about an error that wraps both.
type statusRow struct {
	err    error
	status int
}

var statusTable = []statusRow{
	{ErrAuthenticationRequired, http.StatusUnauthorized},
	{authorize.ErrAuthenticationRequired, http.StatusUnauthorized},
	{authenticate.ErrAuthenticationFailed, http.StatusUnauthorized},
	{policy.ErrSessionIdle, http.StatusUnauthorized},
	{ratelimit.ErrThrottled, http.StatusUnauthorized},

	// A wrong second-factor code, at verification or enrolment, and the
	// per-user throttles in front of them. The caller is asked to try again
	// with a credential, which is what 401 says. An invalid, expired or voided
	// emailed code is the same refusal as a wrong device code: its sentinel
	// wraps mfa.ErrInvalidCode, so this row answers it too.
	{mfa.ErrInvalidCode, http.StatusUnauthorized},
	{mfa.ErrVerifyThrottled, http.StatusUnauthorized},
	{mfa.ErrEnrolmentThrottled, http.StatusUnauthorized},

	// A refused recovery (recovery.ErrRefused) and a throttled saved-code
	// presentation (recovery.ErrCodeThrottled) need no rows: they wrap
	// authenticate.ErrAuthenticationFailed and ratelimit.ErrThrottled, so the
	// rows above answer them 401, exactly as a failed login.

	{ErrCredentialsMissing, http.StatusBadRequest},
	{ErrMalformedRequest, http.StatusBadRequest},

	// A passkey ceremony response the verifier could not read. The chain's
	// endpoints answer it as ErrCredentialsMissing, wrapping it; this row
	// answers it the same way where it reaches StatusForError alone.
	{passkey.ErrMalformedResponse, http.StatusBadRequest},
	{recovery.ErrMalformed, http.StatusBadRequest},
	{oidc.ErrInvalidLogoutToken, http.StatusBadRequest},
	{ErrRequestTooLarge, http.StatusRequestEntityTooLarge},

	// A new password refused as reused: the request is well formed and the
	// value is refused, so a client can show a field-level message. A history
	// that could not be read or recorded is a dependency failure, not a
	// refusal of the caller's input, and carries no row here: it falls through
	// to the unrecognised-error 500 below, like any other unrecognised error.
	{password.ErrPasswordReused, http.StatusUnprocessableEntity},

	{policy.ErrAccountLocked, http.StatusLocked},
	{policy.ErrTooManySessions, http.StatusTooManyRequests},

	// A held recovery presented before its hold ends: well formed and
	// authentic, but in conflict with the record's state. A client can retry
	// once the hold is over, which a 403 would not say.
	{recovery.ErrNotYetCompletable, http.StatusConflict},

	// A federated-login path segment naming no registered provider, and a
	// second-factor path segment naming no configured method. Which providers
	// and methods exist is configuration, not a secret.
	{oidc.ErrUnknownProvider, http.StatusNotFound},
	{ErrUnknownMFAMethod, http.StatusNotFound},

	// A passkey identifier naming no passkey of the session's user: another
	// user's and none at all are deliberately the same refusal.
	{passkey.ErrNotFound, http.StatusNotFound},

	{authorize.ErrAccessDenied, http.StatusForbidden},
	{policy.ErrPolicyDenied, http.StatusForbidden},
	{policy.ErrMFARequired, http.StatusForbidden},
	{policy.ErrMFARequirementUnsatisfiable, http.StatusForbidden},
	{policy.ErrMFAEnrollmentRequired, http.StatusForbidden},
	{policy.ErrSecondFactorSameChannel, http.StatusForbidden},
	{mfa.ErrSameChannel, http.StatusForbidden},
	{ErrMFAMethodNotUsable, http.StatusForbidden},
	{ErrNoMFAChallengePending, http.StatusForbidden},
	{mfa.ErrAlreadyEnrolled, http.StatusForbidden},

	// A second factor whose authenticator itself is refused: suspected to be
	// a clone, or suspended. The response was not a wrong guess, and trying
	// again with the same authenticator will not succeed, which 403 says.
	{mfa.ErrAuthenticatorRefused, http.StatusForbidden},
	{recovery.ErrCooldown, http.StatusForbidden},
	{recovery.ErrReauthenticationRequired, http.StatusForbidden},

	// Passkey refusals of an authenticated caller who must act differently,
	// not present credentials again: a passkey still pending its
	// confirmation, an attestation the policy refuses, a user at the passkey
	// limit, and a session too old or under-assured to change its passkeys.
	// A suspected clone and a suspended passkey need no rows: they wrap
	// mfa.ErrAuthenticatorRefused, answered 403 above. A throttled
	// registration begin needs none either: it wraps ratelimit.ErrThrottled,
	// answered 401.
	{passkey.ErrPending, http.StatusForbidden},
	{passkey.ErrAttestationRefused, http.StatusForbidden},
	{passkey.ErrLimitReached, http.StatusForbidden},
	{passkey.ErrReauthenticationRequired, http.StatusForbidden},
}

// StatusForError maps a refusal to the status it is answered with.
//
// It is the whole mapping contract: every default response this library
// writes, and every helper the integrations offer, goes through it, so a
// consumer's own error handler can fall back to it and agree with the library
// on everything it does not handle itself. It recognises wrapped and joined
// errors, and an error it does not recognise is a server fault, never a
// silent success.
//
// A challenge is checked first, so a challenge that also wraps a refusal
// sentinel is answered as the challenge: the caller can still satisfy it. A
// password-change, enrolment or account-recovery challenge is 403, because the
// caller is authenticated and must act rather than present credentials again;
// every other kind, a consumer's own included, is 401.
//
// A new password a consumer's password-change function refused as reused
// ([password.ErrPasswordReused]) is 422: the request is well formed and the
// value is refused, not 400 (malformed), 401 (authentication) or 403 (the
// password-change challenge itself, which would make the client unable to
// tell "you still owe a change" from "that password was used recently"). A
// history that could not be read or recorded ([password.ErrHistoryUnavailable])
// is a dependency failure, not a refusal of the caller's input, and maps to
// 500 like any other unrecognised error.
func StatusForError(err error) int {
	if err == nil {
		return http.StatusInternalServerError
	}

	var ch *ChallengeError
	if errors.As(err, &ch) {
		switch ch.Kind {
		case policy.ChallengePasswordChange, policy.ChallengeMFAEnrolment, policy.ChallengeAccountRecovery:
			return http.StatusForbidden
		default:
			return http.StatusUnauthorized
		}
	}

	for _, row := range statusTable {
		if errors.Is(err, row.err) {
			return row.status
		}
	}

	return http.StatusInternalServerError
}
