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
// caller checks it beside this one.
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
