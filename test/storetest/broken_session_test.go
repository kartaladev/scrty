package storetest_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// sessionDefect is one deliberate flaw a sessionStore can carry.
type sessionDefect string

const (
	sessionConforming sessionDefect = "conforming"
	// The active count judges the idle deadline only, so a session past its
	// absolute deadline still counts against the user.
	sessionCountIdleOnly sessionDefect = "count-idle-only"
	// DeleteByUserExcept ignores the identifier to keep and deletes every
	// session of the user.
	sessionExceptDeletesAll sessionDefect = "except-deletes-kept"
	// DeleteByUserExcept keeps the named session alone, as a delete of every
	// other identifier would, so the live successor of a named session inside
	// its renewal window goes.
	sessionExceptKeepsOnlyNamed sessionDefect = "except-keeps-only-named"
	// DeleteByUserExcept keeps every member of the named session's family,
	// superseded ones included, as a delete of every other family would.
	sessionExceptKeepsWholeFamily sessionDefect = "except-keeps-whole-family"
	// DeleteByUserExcept reads the named session's family's current member,
	// releases the lock, and deletes in a separate step, as a store reading
	// the family before a DELETE would: a successor written in between is
	// not the one it read, and goes.
	sessionExceptReadThenDelete sessionDefect = "except-read-then-delete"
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
	// Save writes every field but the enrolment-origin marker, which it
	// stores as none.
	sessionSaveDropsEnrolmentDeadline sessionDefect = "save-drops-enrolment-origin-deadline"
	// Save reads a zero marker and generation as "not given" and keeps the
	// stored ones, as a COALESCE would, so the upgrade never clears them.
	sessionSaveKeepsEnrolmentMarker sessionDefect = "save-keeps-enrolment-marker"
	// Load hands back no enrolment generation, as a column the read leaves
	// out would.
	sessionLoadDropsEnrolmentGeneration sessionDefect = "load-drops-enrolment-generation"
	// Create does not keep the second-factor-at-login marker.
	sessionCreateDropsMarker sessionDefect = "create-drops-second-factor-marker"
	// Save sets a stored marker that is unset when the incoming session
	// carries it, and otherwise keeps the stored one: a save sets it, never
	// clears it.
	sessionSaveSetsMarker sessionDefect = "save-sets-second-factor-marker"
	// Save clears a stored marker that is set when the incoming session does
	// not carry it, and otherwise keeps the stored one: a save clears it,
	// never sets it.
	sessionSaveClearsMarker sessionDefect = "save-clears-second-factor-marker"
	// CountActiveByUser counts a user's superseded records too, so a renewed
	// sign-in counts once for every session it has held.
	sessionCountSuperseded sessionDefect = "count-superseded"
	// RecordActivity writes the idle deadline it is given, whatever absolute
	// deadline is stored.
	sessionActivityPastAbsolute sessionDefect = "activity-past-absolute"
	// RecordActivity applies only when the stored last access is strictly
	// before the threshold, so a write at exactly the threshold is dropped.
	sessionActivityStrict sessionDefect = "activity-strict-threshold"
	// RecordActivity saves the whole copy the last Load handed out, with the
	// two activity fields set, as an activity interceptor saving the record
	// its request loaded would: a change saved in the meantime is lost.
	sessionWholeRecordActivity sessionDefect = "whole-record-activity"
	// Supersede checks the observed successor under the lock, releases it,
	// and then writes unconditionally, as a store reading the old record
	// before an unconditional UPDATE would.
	sessionReadThenWriteSupersede sessionDefect = "read-then-write-supersede"
	// Supersede does not check whether the observed successor has itself
	// been superseded, as an UPDATE of the old row alone would not.
	sessionSupersedeIgnoresSupersededSuccessor sessionDefect = "supersede-ignores-superseded-successor"
	// Supersede does not check that the observed successor is still stored,
	// as an UPDATE of the previous successor matching no row would not.
	sessionSupersedeIgnoresGoneSuccessor sessionDefect = "supersede-ignores-gone-successor"
	// Supersede ignores RequireUnpresentedSuccessor.
	sessionSupersedeIgnoresPresentation sessionDefect = "supersede-ignores-presentation"
	// Supersede refuses every supersession that requires an unpresented
	// successor, presented or not.
	sessionSupersedeRefusesRequired sessionDefect = "supersede-refuses-required-unpresented"
	// Supersede judges the stored successor before the observation, so a
	// stale observation of a successor that moved on reads as advanced rather
	// than as a lost race.
	sessionSupersedeAdvancedBeforeConflict sessionDefect = "supersede-advanced-before-conflict"
	// Supersede supersedes a superseded session observing no successor, as a
	// conditional UPDATE that tests the observed successor alone would, so a
	// knocked-out successor is renewed as if it were a fresh head.
	sessionSupersedeKnockedOut sessionDefect = "supersede-knocked-out-successor"
	// Create accepts a session in no family, so every such session shares
	// the nil family.
	sessionCreateAcceptsNoFamily sessionDefect = "create-accepts-nil-family"
	// Supersede retains Old and the previous successor to their own absolute
	// deadline rather than the retention deadline, as an UPDATE setting
	// retain_until = absolute_expires_at would.
	sessionSupersedeKeepsOwnDeadline sessionDefect = "supersede-keeps-own-deadline"
	// Supersede retains Old and the previous successor to the successor's
	// absolute deadline rather than the retention deadline.
	sessionSupersedeUsesSuccessorDeadline sessionDefect = "supersede-uses-successor-deadline"
	// Supersede retains Old only, leaving the previous successor it
	// supersedes with no retention deadline.
	sessionSupersedePreviousKeepsOwnDeadline sessionDefect = "supersede-previous-keeps-own-deadline"
	// Supersede also writes the retention deadline to every superseded
	// member of the family, as the family-wide raise it replaces did.
	sessionSupersedeRewritesFamily sessionDefect = "supersede-rewrites-superseded-family"
	// Supersede refuses a presented observed successor whether or not the
	// supersession requires an unpresented one, as a conditional UPDATE that
	// always tests first_presented_at would.
	sessionSupersedeAlwaysRequiresUnpresented sessionDefect = "supersede-always-requires-unpresented"
	// Supersede writes the retention deadline to the superseded sessions of
	// every family, as a family-wide UPDATE missing its family_id condition
	// would.
	sessionSupersedeRetainsEveryFamily sessionDefect = "supersede-retains-every-family"
	// Supersede writes the retention deadline to every member of the family,
	// superseded or not, as one missing its superseded_at condition would.
	sessionSupersedeRetainsUnsuperseded sessionDefect = "supersede-retains-unsuperseded"
	// Save writes the caller's authentication time rather than keeping the
	// one Create stored.
	sessionSaveMovesAuthenticatedAt sessionDefect = "save-moves-authenticated-at"
	// Supersede writes the retention deadline whatever the record holds, so a
	// retention below a stored one lowers it.
	sessionSupersedeLowersDeadline sessionDefect = "supersede-lowers-deadline"
	// Supersede also raises each of the record's own deadlines to the
	// retention deadline, separately, as the first round's raise did.
	sessionSupersedeRaisesEachDeadline sessionDefect = "supersede-raises-each-deadline"
	// Supersede also holds the record to one deadline, the later of its
	// absolute deadline and the retention, as both of its own deadlines: the
	// first round's raise, which a renewal then read as the session's own
	// lifetime.
	sessionSupersedeRaisesDeadlines sessionDefect = "supersede-raises-deadlines"
	// Supersede writes the retention deadline to the previous successor
	// whatever it holds, though it never lowers Old's.
	sessionSupersedePreviousLowers sessionDefect = "supersede-previous-lowers-deadline"
	// Load judges a superseded record by its own deadlines, not its
	// retention deadline, as a WHERE clause left unchanged would.
	sessionLoadSupersededByDeadlines sessionDefect = "load-superseded-by-deadlines"
	// DeleteExpired sweeps a superseded record by its own deadlines, not its
	// retention deadline.
	sessionSweepSupersededByDeadlines sessionDefect = "sweep-superseded-by-deadlines"
	// Save writes the caller's retention deadline rather than keeping the
	// one Supersede stored, as a column left in the UPDATE would.
	sessionSaveMovesRetention sessionDefect = "save-moves-retention"
	// Supersede accepts a retention deadline before the window's end.
	sessionSupersedeAcceptsEarlyRetention sessionDefect = "supersede-accepts-early-retention"
	// Supersede inserts a successor in no family.
	sessionSupersedeAcceptsNoFamilySuccessor sessionDefect = "supersede-accepts-nil-family-successor"
	// Delete leaves the session counted in its family, as a family member
	// count kept apart from the records would.
	sessionDeleteKeepsFamilyMember sessionDefect = "delete-keeps-family-member"
	// MarkPresented records the first presentation of a superseded session,
	// as an UPDATE testing first_presented_at alone would.
	sessionMarkPresentedSuperseded sessionDefect = "mark-presented-superseded"
	// SuccessorPresented reads a successor that is no longer stored as used,
	// as a NOT EXISTS of an unused successor row would.
	sessionSuccessorGoneAsUsed sessionDefect = "successor-gone-as-used"
	// SuccessorPresented answers for a record past its retention deadline
	// that has not been swept, as a query without the staleness predicate
	// Load applies would.
	sessionSuccessorReadsStaleRecord sessionDefect = "successor-reads-stale-record"
	// SuccessorPresented counts a successor past its own deadlines that has
	// not been swept as used, as a query that does not judge the successor
	// as Load does would.
	sessionSuccessorIgnoresStaleness sessionDefect = "successor-ignores-staleness"
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
	clock  clock.Clock

	mu      sync.Mutex
	records map[string]*session.Session
	// loaded is the copy the last Load handed out per identifier, which only
	// sessionWholeRecordActivity reads.
	loaded map[string]*session.Session
	// strayMembers counts, per family, the sessions Delete removed, which
	// only sessionDeleteKeepsFamilyMember keeps counting.
	strayMembers map[id.ID]int
}

var _ session.Store = (*sessionStore)(nil)

func newSessionStore(defect sessionDefect, clk clock.Clock) *sessionStore {
	return &sessionStore{
		defect:  defect,
		clock:   clk,
		records: make(map[string]*session.Session),
		loaded:  make(map[string]*session.Session),
	}
}

func cloneSession(sess *session.Session) *session.Session {
	out := *sess
	out.Data = maps.Clone(sess.Data)
	out.SuccessorDigest = slices.Clone(sess.SuccessorDigest)
	return &out
}

// keepLibraryState copies onto sess the authentication time and the family,
// supersession (retention included) and presentation fields stored holds,
// which only Create, Supersede and MarkPresented write, and both deadlines of
// a superseded record.
func keepLibraryState(sess, stored *session.Session) {
	sess.AuthenticatedAt = stored.AuthenticatedAt
	sess.FamilyID, sess.FamilyCreatedAt = stored.FamilyID, stored.FamilyCreatedAt
	sess.SupersededAt, sess.AcceptUntil = stored.SupersededAt, stored.AcceptUntil
	sess.RetainUntil = stored.RetainUntil
	sess.SuccessorDigest = slices.Clone(stored.SuccessorDigest)
	sess.FirstPresentedAt = stored.FirstPresentedAt
	if !stored.SupersededAt.IsZero() {
		sess.IdleExpiresAt, sess.AbsoluteExpiresAt = stored.IdleExpiresAt, stored.AbsoluteExpiresAt
	}
}

func expiredSession(sess *session.Session, now time.Time) bool {
	return !now.Before(sess.IdleExpiresAt) || !now.Before(sess.AbsoluteExpiresAt)
}

// staleSession reports whether a store may forget sess at now: a superseded
// record once its retention deadline passes, any other, and a superseded one
// with none, once one of its own deadlines does. byDeadlines judges every
// record by its own deadlines, as the defects that ignore retention do.
func staleSession(sess *session.Session, now time.Time, byDeadlines bool) bool {
	if !byDeadlines && !sess.SupersededAt.IsZero() && !sess.RetainUntil.IsZero() {
		return !now.Before(sess.RetainUntil)
	}
	return expiredSession(sess, now)
}

func (s *sessionStore) Create(_ context.Context, sess *session.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sess.FamilyID.IsZero() && s.defect != sessionCreateAcceptsNoFamily {
		return errors.New("a session with no family cannot be stored")
	}
	if _, exists := s.records[sess.ID]; exists {
		return errors.New("identifier already stored")
	}
	if s.defect == sessionCreateRefusesText || s.defect == sessionCreateRefusesEchoing {
		if err := refuseText(s.defect, sess); err != nil {
			return err
		}
	}
	stored := cloneSession(sess)
	if s.defect == sessionCreateDropsMarker {
		stored.MFAAtFirstFactor = false
	}
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
	// Only Create writes the marker: a conforming save keeps the stored one.
	// Each marker defect lets one direction of change through, and only
	// that one.
	marker := stored.MFAAtFirstFactor
	switch {
	case s.defect == sessionSaveSetsMarker && !marker && sess.MFAAtFirstFactor:
		marker = true
	case s.defect == sessionSaveClearsMarker && marker && !sess.MFAAtFirstFactor:
		marker = false
	}
	kept := cloneSession(sess)
	kept.MFAAtFirstFactor = marker
	keepLibraryState(kept, stored)
	if s.defect == sessionSaveMovesAuthenticatedAt {
		kept.AuthenticatedAt = sess.AuthenticatedAt
	}
	if s.defect == sessionSaveMovesRetention {
		kept.RetainUntil = sess.RetainUntil
	}
	sess = kept
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
	case sessionSaveDropsEnrolmentDeadline:
		saved := cloneSession(sess)
		saved.EnrolmentOriginDeadline = time.Time{}
		s.records[sess.ID] = saved
		return nil
	case sessionSaveKeepsEnrolmentMarker:
		saved := cloneSession(sess)
		if saved.EnrolmentOriginDeadline.IsZero() {
			saved.EnrolmentOriginDeadline = stored.EnrolmentOriginDeadline
		}
		if saved.EnrolmentGeneration.IsZero() {
			saved.EnrolmentGeneration = stored.EnrolmentGeneration
		}
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
	case staleSession(stored, s.clock.Now(), s.defect == sessionLoadSupersededByDeadlines):
		return nil, session.ErrSessionExpired
	}
	out := cloneSession(stored)
	s.loaded[sessionID] = cloneSession(stored)
	switch s.defect {
	case sessionLoadSharesData:
		out.Data = stored.Data
	case sessionLoadDropsEnrolmentGeneration:
		out.EnrolmentGeneration = id.Nil
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
	if s.defect == sessionDeleteKeepsFamilyMember {
		s.mu.Lock()
		if rec, found := s.records[sessionID]; found {
			if s.strayMembers == nil {
				s.strayMembers = make(map[id.ID]int)
			}
			s.strayMembers[rec.FamilyID]++
		}
		s.mu.Unlock()
	}
	s.removeWhere(func(sess *session.Session) bool { return sess.ID == sessionID })
	return nil
}

func (s *sessionStore) DeleteByUser(_ context.Context, user identity.UserID) error {
	s.removeWhere(func(sess *session.Session) bool { return sess.UserID == user })
	return nil
}

func (s *sessionStore) DeleteByUserExcept(_ context.Context, user identity.UserID, keep string) (int, error) {
	if s.defect == sessionExceptDeletesAll {
		keep = ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// kept is the named session's family, when the user holds it: its
	// current member is kept with it, or, under the whole-family defect,
	// every member.
	var family *id.ID
	if rec, found := s.records[keep]; found && rec.UserID == user && s.defect != sessionExceptKeepsOnlyNamed {
		family = &rec.FamilyID
	}

	// current is the family's current member as read, which the
	// read-then-delete defect keeps in place of the member at delete time.
	var current string
	if s.defect == sessionExceptReadThenDelete && family != nil {
		for _, sess := range s.records {
			if sess.UserID == user && sess.FamilyID == *family && sess.SupersededAt.IsZero() {
				current = sess.ID
			}
		}
		// The window between the read and the delete that a real store's
		// round trips open.
		s.mu.Unlock()
		time.Sleep(time.Millisecond)
		s.mu.Lock()
	}

	n := 0
	for key, sess := range s.records {
		if sess.UserID != user || sess.ID == keep {
			continue
		}
		if s.defect == sessionExceptReadThenDelete {
			if family != nil && sess.ID == current {
				continue
			}
		} else if family != nil && sess.FamilyID == *family &&
			(sess.SupersededAt.IsZero() || s.defect == sessionExceptKeepsWholeFamily) {
			continue
		}
		delete(s.records, key)
		n++
	}
	return n, nil
}

func (s *sessionStore) CountActiveByUser(_ context.Context, user identity.UserID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now()
	n := 0
	for _, sess := range s.records {
		expired := expiredSession(sess, now)
		if s.defect == sessionCountIdleOnly {
			expired = !now.Before(sess.IdleExpiresAt)
		}
		if s.defect != sessionCountSuperseded && !sess.SupersededAt.IsZero() {
			continue
		}
		if sess.UserID == user && !expired {
			n++
		}
	}
	return n, nil
}

func (s *sessionStore) DeleteExpired(_ context.Context) (int, error) {
	now := s.clock.Now()
	byDeadlines := s.defect == sessionSweepSupersededByDeadlines
	return s.removeWhere(func(sess *session.Session) bool { return staleSession(sess, now, byDeadlines) }), nil
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

func (s *sessionStore) RecordActivity(
	ctx context.Context, sessionID string, lastAccessed, idleExpires, olderThan time.Time,
) error {
	s.mu.Lock()
	stored, exists := s.records[sessionID]
	if !exists {
		s.mu.Unlock()
		return session.ErrSessionNotFound
	}
	if s.defect == sessionWholeRecordActivity {
		whole := cloneSession(stored)
		if loaded, ok := s.loaded[sessionID]; ok {
			whole = cloneSession(loaded)
		}
		s.mu.Unlock()
		whole.LastAccessedAt, whole.IdleExpiresAt = lastAccessed, idleExpires
		return s.Save(ctx, whole)
	}
	defer s.mu.Unlock()

	tooFresh := stored.LastAccessedAt.After(olderThan) ||
		s.defect == sessionActivityStrict && stored.LastAccessedAt.Equal(olderThan)
	if !stored.SupersededAt.IsZero() || tooFresh {
		return nil
	}
	if s.defect != sessionActivityPastAbsolute && idleExpires.After(stored.AbsoluteExpiresAt) {
		idleExpires = stored.AbsoluteExpiresAt
	}
	stored.LastAccessedAt, stored.IdleExpiresAt = lastAccessed, idleExpires
	return nil
}

func (s *sessionStore) Supersede(_ context.Context, op session.Supersession) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if op.Successor.FamilyID.IsZero() && s.defect != sessionSupersedeAcceptsNoFamilySuccessor {
		return errors.New("a successor with no family cannot be stored")
	}
	if op.RetainUntil.Before(op.AcceptUntil) && s.defect != sessionSupersedeAcceptsEarlyRetention {
		return errors.New("a retention deadline cannot be before the window's end")
	}
	old, exists := s.records[op.Old]
	if !exists {
		return session.ErrSessionNotFound
	}
	if old.FamilyID.IsZero() {
		return errors.New("a session with no family cannot be superseded")
	}
	if s.defect != sessionSupersedeKnockedOut && len(op.ObservedSuccessor) == 0 && !old.SupersededAt.IsZero() {
		return session.ErrSessionRenewalConflict
	}
	if s.defect == sessionSupersedeAdvancedBeforeConflict && len(old.SuccessorDigest) > 0 {
		if current := s.successorOf(old); current == nil || !current.SupersededAt.IsZero() {
			return session.ErrSuccessorAdvanced
		}
	}
	if !bytes.Equal(old.SuccessorDigest, op.ObservedSuccessor) {
		return session.ErrSessionRenewalConflict
	}
	if err := s.successorAdvanced(old, op); err != nil {
		return err
	}
	if s.defect == sessionReadThenWriteSupersede {
		// The window between the read and the write that a real store's
		// round trips open.
		s.mu.Unlock()
		time.Sleep(time.Millisecond)
		s.mu.Lock()
		old, exists = s.records[op.Old]
		if !exists {
			return session.ErrSessionNotFound
		}
	}
	if _, taken := s.records[op.Successor.ID]; taken {
		return errors.New("identifier already stored")
	}
	s.retainOthers(old, op.RetainUntil)
	if previous := s.successorOf(old); previous != nil {
		previous.SupersededAt, previous.AcceptUntil = op.Now, op.Now
		switch s.defect {
		case sessionSupersedePreviousKeepsOwnDeadline:
		case sessionSupersedePreviousLowers:
			previous.RetainUntil = op.RetainUntil
		default:
			s.retain(previous, op)
		}
	}
	old.SupersededAt, old.AcceptUntil = op.Now, op.AcceptUntil
	old.SuccessorDigest = digestOf(op.Successor.ID)
	s.retain(old, op)
	s.records[op.Successor.ID] = cloneSession(op.Successor)
	return nil
}

// retain writes the retention deadline a supersession gives rec: the later
// of rec's stored one and op.RetainUntil, as the contract requires, leaving
// rec's own deadlines alone, unless a defect picks another. Callers hold s.mu.
func (s *sessionStore) retain(rec *session.Session, op session.Supersession) {
	until := op.RetainUntil
	switch s.defect {
	case sessionSupersedeKeepsOwnDeadline:
		until = rec.AbsoluteExpiresAt
	case sessionSupersedeUsesSuccessorDeadline:
		until = op.Successor.AbsoluteExpiresAt
	}
	switch s.defect {
	case sessionSupersedeLowersDeadline:
		rec.RetainUntil = until
		return
	case sessionSupersedeRaisesEachDeadline:
		if until.After(rec.IdleExpiresAt) {
			rec.IdleExpiresAt = until
		}
		if until.After(rec.AbsoluteExpiresAt) {
			rec.AbsoluteExpiresAt = until
		}
	case sessionSupersedeRaisesDeadlines:
		if until.After(rec.AbsoluteExpiresAt) {
			rec.AbsoluteExpiresAt = until
		}
		rec.IdleExpiresAt = rec.AbsoluteExpiresAt
	}
	if until.After(rec.RetainUntil) {
		rec.RetainUntil = until
	}
}

// retainOthers writes until to records the supersession of old does not
// supersede, as the defects that widen the write do. A conforming store
// writes none. Callers hold s.mu.
func (s *sessionStore) retainOthers(old *session.Session, until time.Time) {
	for _, rec := range s.records {
		sameFamily := rec.FamilyID == old.FamilyID
		superseded := !rec.SupersededAt.IsZero()
		if s.defect == sessionSupersedeRewritesFamily && sameFamily && superseded ||
			s.defect == sessionSupersedeRetainsEveryFamily && superseded ||
			s.defect == sessionSupersedeRetainsUnsuperseded && sameFamily {
			rec.RetainUntil = until
		}
	}
}

// successorAdvanced reports ErrSuccessorAdvanced when op observed a successor
// that has moved on, as the contract requires, unless a defect skips the
// check. Callers hold s.mu.
func (s *sessionStore) successorAdvanced(old *session.Session, op session.Supersession) error {
	if len(op.ObservedSuccessor) == 0 {
		return nil
	}
	if op.RequireUnpresentedSuccessor && s.defect == sessionSupersedeRefusesRequired {
		return session.ErrSuccessorAdvanced
	}
	current := s.successorOf(old)
	switch {
	case current == nil:
		if s.defect != sessionSupersedeIgnoresGoneSuccessor {
			return session.ErrSuccessorAdvanced
		}
	case !current.SupersededAt.IsZero():
		if s.defect != sessionSupersedeIgnoresSupersededSuccessor {
			return session.ErrSuccessorAdvanced
		}
	case (op.RequireUnpresentedSuccessor || s.defect == sessionSupersedeAlwaysRequiresUnpresented) &&
		!current.FirstPresentedAt.IsZero():
		if s.defect != sessionSupersedeIgnoresPresentation {
			return session.ErrSuccessorAdvanced
		}
	}
	return nil
}

// successorOf returns the stored record old's successor digest names, or nil.
// Callers hold s.mu.
func (s *sessionStore) successorOf(old *session.Session) *session.Session {
	if len(old.SuccessorDigest) == 0 {
		return nil
	}
	for key, rec := range s.records {
		if bytes.Equal(digestOf(key), old.SuccessorDigest) {
			return rec
		}
	}
	return nil
}

// digestOf is the SHA-256 of a session identifier.
func digestOf(sessionID string) []byte {
	sum := sha256.Sum256([]byte(sessionID))
	return sum[:]
}

func (s *sessionStore) DeleteFamily(_ context.Context, family id.ID) (int, error) {
	if family.IsZero() {
		return 0, errors.New("the nil family names no family")
	}
	n := s.removeWhere(func(sess *session.Session) bool { return sess.FamilyID == family })
	if s.defect == sessionDeleteKeepsFamilyMember {
		s.mu.Lock()
		n += s.strayMembers[family]
		delete(s.strayMembers, family)
		s.mu.Unlock()
	}
	return n, nil
}

func (s *sessionStore) MarkPresented(_ context.Context, sessionID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.records[sessionID]
	if !exists {
		return session.ErrSessionNotFound
	}
	if !stored.SupersededAt.IsZero() && s.defect != sessionMarkPresentedSuperseded {
		return session.ErrSessionSuperseded
	}
	if !stored.FirstPresentedAt.IsZero() {
		return nil
	}
	stored.FirstPresentedAt = at
	return nil
}

func (s *sessionStore) SuccessorPresented(_ context.Context, sessionID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now()
	stored, exists := s.records[sessionID]
	if !exists || (s.defect != sessionSuccessorReadsStaleRecord && staleSession(stored, now, false)) {
		return false, session.ErrSessionNotFound
	}
	if len(stored.SuccessorDigest) == 0 {
		return false, nil
	}
	successor := s.successorOf(stored)
	if successor == nil {
		return s.defect == sessionSuccessorGoneAsUsed, nil
	}
	if s.defect != sessionSuccessorIgnoresStaleness && staleSession(successor, now, false) {
		return s.defect == sessionSuccessorGoneAsUsed, nil
	}
	return !successor.FirstPresentedAt.IsZero() || !successor.SupersededAt.IsZero(), nil
}
