package session

import (
	"time"

	"github.com/kartaladev/scrty/pkg/id"
)

// MarkEnrolmentPending records on s, in memory, that it may reach only
// enrolment: it sets the MFAEnrolmentPending state and the
// EnrolmentOriginDeadline marker, and lowers the session's deadlines so it
// ends no later than lifetime from now. The caller saves s, so the state and
// the deadlines land in one persisted change.
//
// The marker records the absolute deadline s held immediately before the
// mark, which is the latest RestoreEnrolmentDeadlines may give back. Marking a
// session that already carries the marker keeps the recorded value, since the
// deadline it now holds is already lowered.
//
// The absolute deadline becomes the earlier of its current value and now plus
// lifetime, so a mark near the end of a session never lengthens it. The idle
// deadline is clamped to that absolute deadline and never raised.
//
// It lowers the existing absolute deadline rather than keeping a separate
// enrolment deadline because every store already enforces that one: loading,
// the concurrent-session count and the expiry sweep all honour it, including
// in a consumer's own store that knows nothing of enrolment. A separate field
// that such a store ignored would keep an enrolment-only session alive for the
// full absolute timeout.
//
// A lifetime of zero or less leaves a session that has already expired; the
// caller validates the lifetime it configures.
func (m *Manager) MarkEnrolmentPending(s *Session, lifetime time.Duration) {
	if s.EnrolmentOriginDeadline.IsZero() {
		s.EnrolmentOriginDeadline = s.AbsoluteExpiresAt
	}

	if limit := m.clock.Now().Add(lifetime); limit.Before(s.AbsoluteExpiresAt) {
		s.AbsoluteExpiresAt = limit
	}
	if s.IdleExpiresAt.After(s.AbsoluteExpiresAt) {
		s.IdleExpiresAt = s.AbsoluteExpiresAt
	}

	s.MFA = MFAEnrolmentPending
}

// RestoreEnrolmentDeadlines undoes MarkEnrolmentPending on s, in memory, once
// its second factor has been satisfied. The caller persists s, normally by
// passing it to Rotate straight after, which carries the restored deadlines
// over as it carries every other field.
//
// The absolute deadline becomes the earlier of CreatedAt plus the manager's
// absolute timeout and the deadline recorded in EnrolmentOriginDeadline, the
// one s held before it was marked. It is therefore never later than either:
// not than the deadline a login would have had under this manager, and not
// than the deadline s actually held, even if the absolute timeout has since
// been raised. A fault here can only end a session early, never late. The
// idle deadline becomes the earlier of now plus the idle timeout and that
// absolute deadline. The marker and the EnrolmentGeneration are then cleared.
//
// A session already past either of its lowered deadlines is not revived: the
// result is ErrSessionExpired and s is left unchanged, so a caller that saves
// rather than rotates cannot bring it back. A caller treats that error as the
// session having ended.
//
// A session without the marker is left unchanged and the result is nil, so
// calling it on every satisfied session is safe. It does not change the
// second-factor state; marking the session satisfied is the caller's step.
func (m *Manager) RestoreEnrolmentDeadlines(s *Session) error {
	if s.EnrolmentOriginDeadline.IsZero() {
		return nil
	}

	now := m.clock.Now()
	if s.expired(now) {
		return ErrSessionExpired
	}

	absolute := s.CreatedAt.Add(m.absoluteTimeout)
	if s.EnrolmentOriginDeadline.Before(absolute) {
		absolute = s.EnrolmentOriginDeadline
	}
	idle := now.Add(m.idleTimeout)
	if idle.After(absolute) {
		idle = absolute
	}

	s.AbsoluteExpiresAt, s.IdleExpiresAt = absolute, idle
	s.EnrolmentOriginDeadline = time.Time{}
	s.EnrolmentGeneration = id.ID{}

	return nil
}
