package httpsec

import (
	"errors"
	"net/http"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
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

	{ErrCredentialsMissing, http.StatusBadRequest},
	{oidc.ErrInvalidLogoutToken, http.StatusBadRequest},
	{ErrRequestTooLarge, http.StatusRequestEntityTooLarge},
	{policy.ErrAccountLocked, http.StatusLocked},
	{policy.ErrTooManySessions, http.StatusTooManyRequests},

	// A federated-login path segment naming no registered provider.
	{oidc.ErrUnknownProvider, http.StatusNotFound},

	{authorize.ErrAccessDenied, http.StatusForbidden},
	{policy.ErrPolicyDenied, http.StatusForbidden},
	{policy.ErrMFARequired, http.StatusForbidden},
	{policy.ErrMFARequirementUnsatisfiable, http.StatusForbidden},
	{policy.ErrMFAEnrollmentRequired, http.StatusForbidden},
	{policy.ErrSecondFactorSameChannel, http.StatusForbidden},
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
// sentinel is answered as the challenge: the caller can still satisfy it.
func StatusForError(err error) int {
	if err == nil {
		return http.StatusInternalServerError
	}

	var ch *ChallengeError
	if errors.As(err, &ch) {
		if ch.Kind == policy.ChallengePasswordChange {
			return http.StatusForbidden
		}
		return http.StatusUnauthorized
	}

	for _, row := range statusTable {
		if errors.Is(err, row.err) {
			return row.status
		}
	}

	return http.StatusInternalServerError
}
