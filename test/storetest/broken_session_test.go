package storetest_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// sessionDefect is one deliberate flaw a sessionStore can carry.
type sessionDefect string

const (
	sessionConforming sessionDefect = "conforming"
	// The active count judges the idle deadline only, so a session past its
	// absolute deadline still counts against the user.
	sessionCountIdleOnly sessionDefect = "count-idle-only"
	// Save writes a partial column list: the activity and second-factor
	// fields and Data, keeping the stored user, creation time, first factor,
	// absolute deadline and provider fields.
	sessionSavePartial sessionDefect = "save-partial"
	// Create keeps the caller's Data map rather than a copy of it.
	sessionCreateSharesData sessionDefect = "create-shares-data"
	// Load hands back the stored Data map rather than a copy of it.
	sessionLoadSharesData sessionDefect = "load-shares-data"
	// Save reads a nil or empty Data map, and an empty issuer, as "not given"
	// and keeps the stored map and provider fields, as a COALESCE would.
	sessionSaveKeepsUnset sessionDefect = "save-keeps-unset"
	// Load reads the zero second-factor state as pending, as a column
	// defaulting to the first non-zero state would.
	sessionLoadNoneAsPending sessionDefect = "load-none-as-pending"
	// Load hands back every instant truncated to the second, as a column of
	// second precision would.
	sessionLoadTruncatesSeconds sessionDefect = "load-truncates-seconds"
	// Save replaces the record whole but keeps the stored second-factor time.
	sessionSaveKeepsMFATime sessionDefect = "save-keeps-mfa-satisfied-at"
	// Load hands back every instant rounded to the microsecond, as PostgreSQL
	// does with text-format input. The contract allows it, so this conforms.
	sessionLoadRoundsMicro sessionDefect = "load-rounds-microseconds"
	// Create replaces invalid UTF-8 in data values with U+FFFD, as encoding
	// the map to JSON would.
	sessionCreateReplacesInvalidUTF8 sessionDefect = "create-replaces-invalid-utf8"
	// Create strips NUL bytes from data values.
	sessionCreateStripsNUL sessionDefect = "create-strips-nul-from-data"
	// Create strips NUL bytes from the user reference.
	sessionCreateStripsNULFromUser sessionDefect = "create-strips-nul-from-user"
	// Create refuses a NUL byte or invalid UTF-8 in data values or the user
	// reference, without echoing it. The contract allows it, so this conforms.
	sessionCreateRefusesText sessionDefect = "create-refuses-unstorable-text"
	// Create refuses such text, but quotes it in its error.
	sessionCreateRefusesEchoing sessionDefect = "create-refuses-echoing-value"
	// Save replaces invalid UTF-8 in data values with U+FFFD, as encoding the
	// map to JSON would.
	sessionSaveReplacesInvalidUTF8 sessionDefect = "save-replaces-invalid-utf8"
	// Save refuses a NUL byte or invalid UTF-8 in data values or the user
	// reference, without echoing it. The contract allows it, so this conforms.
	sessionSaveRefusesText sessionDefect = "save-refuses-unstorable-text"
	// Save strips NUL bytes from data values.
	sessionSaveStripsNUL sessionDefect = "save-strips-nul-from-data"
	// Save strips NUL bytes from the user reference.
	sessionSaveStripsNULFromUser sessionDefect = "save-strips-nul-from-user"
	// Save commits the non-text columns from the incoming session — activity,
	// second-factor state, PasswordChangePending — before checking whether
	// its text columns (Data, the user reference) can be stored, so a
	// refusal still leaves those columns changed: the call looks refused,
	// but live session state moved.
	sessionSaveRefusesTextAfterPartialWrite sessionDefect = "save-refuses-after-partial-write"
)

// unstorableText reports whether v holds what a PostgreSQL text column
// cannot: a NUL byte or invalid UTF-8.
func unstorableText(v string) bool {
	return strings.ContainsRune(v, 0) || !utf8.ValidString(v)
}

// refuseText returns the refusal the refusing defects make of sess, or nil
// when it holds nothing unstorable.
func refuseText(defect sessionDefect, sess *session.Session) error {
	values := []string{string(sess.UserID)}
	for _, v := range sess.Data {
		values = append(values, v)
	}
	for _, v := range values {
		if !unstorableText(v) {
			continue
		}
		if defect == sessionCreateRefusesEchoing {
			return fmt.Errorf("cannot store %q", v)
		}
		return errors.New("a session value holds text the store cannot keep")
	}
	return nil
}

// alterText rewrites the text of stored the way the altering defects do.
func alterText(defect sessionDefect, stored *session.Session) {
	switch defect {
	case sessionCreateReplacesInvalidUTF8:
		for k, v := range stored.Data {
			stored.Data[k] = strings.ToValidUTF8(v, "\uFFFD")
		}
	case sessionCreateStripsNUL:
		for k, v := range stored.Data {
			stored.Data[k] = strings.ReplaceAll(v, "\x00", "")
		}
	case sessionCreateStripsNULFromUser:
		stored.UserID = identity.UserID(strings.ReplaceAll(string(stored.UserID), "\x00", ""))
	case sessionSaveStripsNUL:
		for k, v := range stored.Data {
			stored.Data[k] = strings.ReplaceAll(v, "\x00", "")
		}
	case sessionSaveStripsNULFromUser:
		stored.UserID = identity.UserID(strings.ReplaceAll(string(stored.UserID), "\x00", ""))
	}
}

// sessionStore is a session store over process memory, written apart from
// the shipped store so a defect can reach state the shipped store never
// exposes. Without a defect it conforms.
type sessionStore struct {
	defect sessionDefect
	now    func() time.Time

	mu      sync.Mutex
	records map[string]*session.Session
}

var _ session.Store = (*sessionStore)(nil)

func newSessionStore(defect sessionDefect, now func() time.Time) *sessionStore {
	return &sessionStore{defect: defect, now: now, records: make(map[string]*session.Session)}
}

func cloneSession(sess *session.Session) *session.Session {
	out := *sess
	out.Data = maps.Clone(sess.Data)
	return &out
}

func expiredSession(sess *session.Session, now time.Time) bool {
	return !now.Before(sess.IdleExpiresAt) || !now.Before(sess.AbsoluteExpiresAt)
}

func (s *sessionStore) Create(_ context.Context, sess *session.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.records[sess.ID]; exists {
		return errors.New("identifier already stored")
	}
	if s.defect == sessionCreateRefusesText || s.defect == sessionCreateRefusesEchoing {
		if err := refuseText(s.defect, sess); err != nil {
			return err
		}
	}
	stored := cloneSession(sess)
	if s.defect == sessionCreateSharesData {
		stored.Data = sess.Data
	}
	alterText(s.defect, stored)
	s.records[sess.ID] = stored
	return nil
}

func (s *sessionStore) Save(_ context.Context, sess *session.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.records[sess.ID]
	if !exists {
		return session.ErrSessionNotFound
	}
	if s.defect == sessionSaveRefusesTextAfterPartialWrite {
		stored.LastAccessedAt = sess.LastAccessedAt
		stored.IdleExpiresAt = sess.IdleExpiresAt
		stored.AbsoluteExpiresAt = sess.AbsoluteExpiresAt
		stored.MFA = sess.MFA
		stored.MFASatisfiedAt = sess.MFASatisfiedAt
		stored.PasswordChangePending = sess.PasswordChangePending
		if err := refuseText(s.defect, sess); err != nil {
			return err
		}
		s.records[sess.ID] = cloneSession(sess)
		return nil
	}
	if s.defect == sessionSaveRefusesText {
		if err := refuseText(s.defect, sess); err != nil {
			return err
		}
	}
	switch s.defect {
	case sessionSavePartial:
	case sessionSaveReplacesInvalidUTF8:
		saved := cloneSession(sess)
		alterText(sessionCreateReplacesInvalidUTF8, saved)
		s.records[sess.ID] = saved
		return nil
	case sessionSaveStripsNUL, sessionSaveStripsNULFromUser:
		saved := cloneSession(sess)
		alterText(s.defect, saved)
		s.records[sess.ID] = saved
		return nil
	case sessionSaveKeepsUnset:
		saved := cloneSession(sess)
		if len(saved.Data) == 0 {
			saved.Data = stored.Data
		}
		if saved.ExternalIssuer == "" {
			saved.ExternalProvider, saved.ExternalIssuer = stored.ExternalProvider, stored.ExternalIssuer
			saved.ExternalSessionID, saved.ExternalIDToken = stored.ExternalSessionID, stored.ExternalIDToken
		}
		s.records[sess.ID] = saved
		return nil
	case sessionSaveKeepsMFATime:
		saved := cloneSession(sess)
		saved.MFASatisfiedAt = stored.MFASatisfiedAt
		s.records[sess.ID] = saved
		return nil
	default:
		s.records[sess.ID] = cloneSession(sess)
		return nil
	}
	stored.LastAccessedAt = sess.LastAccessedAt
	stored.IdleExpiresAt = sess.IdleExpiresAt
	stored.MFA = sess.MFA
	stored.MFASatisfiedAt = sess.MFASatisfiedAt
	stored.PasswordChangePending = sess.PasswordChangePending
	stored.Data = maps.Clone(sess.Data)
	return nil
}

func (s *sessionStore) Load(_ context.Context, sessionID string) (*session.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.records[sessionID]
	switch {
	case !exists:
		return nil, session.ErrSessionNotFound
	case expiredSession(stored, s.now()):
		return nil, session.ErrSessionExpired
	}
	out := cloneSession(stored)
	switch s.defect {
	case sessionLoadSharesData:
		out.Data = stored.Data
	case sessionLoadNoneAsPending:
		if out.MFA == session.MFANone {
			out.MFA = session.MFAPending
		}
	case sessionLoadTruncatesSeconds:
		for _, at := range []*time.Time{
			&out.CreatedAt, &out.LastAccessedAt, &out.IdleExpiresAt, &out.AbsoluteExpiresAt, &out.MFASatisfiedAt,
		} {
			*at = at.Truncate(time.Second)
		}
	case sessionLoadRoundsMicro:
		for _, at := range []*time.Time{
			&out.CreatedAt, &out.LastAccessedAt, &out.IdleExpiresAt, &out.AbsoluteExpiresAt, &out.MFASatisfiedAt,
		} {
			*at = at.Round(time.Microsecond)
		}
	}
	return out, nil
}

// removeWhere deletes every record matching match and reports how many went.
func (s *sessionStore) removeWhere(match func(*session.Session) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for key, sess := range s.records {
		if match(sess) {
			delete(s.records, key)
			n++
		}
	}
	return n
}

func (s *sessionStore) Delete(_ context.Context, sessionID string) error {
	s.removeWhere(func(sess *session.Session) bool { return sess.ID == sessionID })
	return nil
}

func (s *sessionStore) DeleteByUser(_ context.Context, user identity.UserID) error {
	s.removeWhere(func(sess *session.Session) bool { return sess.UserID == user })
	return nil
}

func (s *sessionStore) CountActiveByUser(_ context.Context, user identity.UserID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	n := 0
	for _, sess := range s.records {
		expired := expiredSession(sess, now)
		if s.defect == sessionCountIdleOnly {
			expired = !now.Before(sess.IdleExpiresAt)
		}
		if sess.UserID == user && !expired {
			n++
		}
	}
	return n, nil
}

func (s *sessionStore) DeleteExpired(_ context.Context) (int, error) {
	now := s.now()
	return s.removeWhere(func(sess *session.Session) bool { return expiredSession(sess, now) }), nil
}

func (s *sessionStore) DeleteByExternalSession(_ context.Context, issuer, sessionID string) (int, error) {
	if issuer == "" || sessionID == "" {
		return 0, nil
	}
	return s.removeWhere(func(sess *session.Session) bool {
		return sess.ExternalIssuer == issuer && sess.ExternalSessionID == sessionID
	}), nil
}

func (s *sessionStore) DeleteByUserAndExternalIssuer(
	_ context.Context, user identity.UserID, issuer string,
) (int, error) {
	if issuer == "" {
		return 0, nil
	}
	return s.removeWhere(func(sess *session.Session) bool {
		return sess.UserID == user && sess.ExternalIssuer == issuer
	}), nil
}
