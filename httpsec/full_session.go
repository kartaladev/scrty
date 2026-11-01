package httpsec

import (
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// fullSession reports whether s is a full session: one that owes nothing and
// is confined to nothing. It is the one check every endpoint that serves only
// a full session makes (re-proof admission, passkey management and saved-code
// regeneration), so the three cannot drift apart.
//
// A full session's second factor is satisfied or was never asked for, it owes
// no password change, and it carries no confinement marker
// (EnrolmentOriginDeadline), which the enrolment path and an account recovery
// set and only the upgrade that ends the confinement clears. RecoveredAt is
// history, not a marker, and is not read. A second-factor state outside the
// named ones is not a full session.
//
// It reads the session alone. A challenge the policy phase raised on the
// request (Exchange.RaisedChallenge) is never marked on the session, so each
// caller checks it beside this one: re-proof admission refuses it as
// authentication required, saved-code regeneration passes the request on to
// the gate enforcing it, and passkey management and registration refuse it
// with a ChallengeError of that kind (raisedChallengeRefusal). The marker is
// cleared by the binding, or the password change, that ends the confinement.
func fullSession(s *session.Session) bool {
	switch s.MFA {
	case session.MFANone, session.MFASatisfied:
	default:
		return false
	}

	return !s.PasswordChangePending && s.EnrolmentOriginDeadline.IsZero()
}

// owedChallenge is the built-in challenge s owes, which a later gate enforces,
// or policy.ChallengeNone when it owes none. A pending recovery, enrolment or
// second factor is judged before a pending password change. A session that is
// not a full session (fullSession) may still owe none: a confinement marker
// left without its state, or a state outside the named ones, which no library
// path produces.
func owedChallenge(s *session.Session) policy.ChallengeKind {
	switch {
	case s.MFA == session.MFARecoveryPending:
		return policy.ChallengeAccountRecovery
	case s.MFA == session.MFAEnrolmentPending:
		return policy.ChallengeMFAEnrolment
	case s.MFA == session.MFAPending:
		return policy.ChallengeMFA
	case s.PasswordChangePending:
		return policy.ChallengePasswordChange
	default:
		return policy.ChallengeNone
	}
}

// raisedChallengeRefusal refuses a request on which the per-request policy
// raised a challenge of the consumer's own (Exchange.RaisedChallenge) with a
// ChallengeError of that kind carrying s, and reports nil when it raised none.
// The gate enforcing such a challenge is the consumer's and may sit after the
// endpoint that checks this, which would otherwise serve the request first.
func raisedChallengeRefusal(ex *Exchange, s *session.Session) error {
	if kind := ex.RaisedChallenge(); kind != policy.ChallengeNone {
		return &ChallengeError{Kind: kind, Session: s}
	}

	return nil
}

// requireSessionUser refuses with ErrAuthenticationRequired a request whose
// resolved caller is not s's user: a consumer interceptor past the first factor
// published another principal. The second-factor verification and the
// second-factor re-proof both make it before anything is counted, verified or
// judged, so neither throttles, checks a code, or judges the post-authentication
// phase for a principal that is not the one the session belongs to.
//
// It reads the caller the endpoint's admission has already required, so it
// is called after that admission and never on its own.
func requireSessionUser(ex *Exchange, s *session.Session) error {
	if ex.Authentication.Principal.ID != s.UserID {
		return ErrAuthenticationRequired
	}

	return nil
}
