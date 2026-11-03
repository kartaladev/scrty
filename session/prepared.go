package session

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/kartaladev/scrty/identity"
)

// ErrAlreadyCommitted refuses a Prepared.Commit after the first, whether the
// first stored the session or failed. It is a caller's mistake, not a store's
// verdict, and no write is attempted.
var ErrAlreadyCommitted = errors.New("session: the prepared session was already committed")

// Prepared is a session built by Sessions.Prepare and not yet stored.
//
// It exists for the caller whose creation is complete only once it has acted
// on the session: marking a pending challenge on it, or issuing its
// credential, such as a signed token naming it. Until Commit stores it, the
// session loads nothing, so a credential issued for it authenticates nothing
// either, and a caller that abandons a Prepared, because its own step failed,
// has stored nothing and has nothing to clean up.
//
// Commit is the one creating write, and runs at most once. Session and
// Commit may be called from different goroutines, but changes to the session
// must be finished before Commit is called: Commit stores the session as it
// stands then.
type Prepared struct {
	m *Sessions
	s *Session

	// built is the session as Prepare built it, copied by value. Commit
	// compares the caller's session against it: the identity fields must be
	// as built and the deadlines no later.
	built Session

	// committed is set by the first Commit, before it writes, so a second
	// one, concurrent or later, is refused without reaching the store.
	committed atomic.Bool
}

// Prepare builds a session for user exactly as Create builds it, and stores
// nothing: the identifier, the family, the deadlines, the authentication time
// and the create options are all applied, and a lifetime the options leave
// outside the manager's maximum is refused here with ErrConfig. It takes no
// context because it touches no store.
//
// The caller then acts on Prepared.Session — marks it with
// Sessions.MarkEnrolmentPending or Sessions.MarkRecoveryPending, sets its
// attributes, issues its credential — and stores it with Prepared.Commit, in
// the one write that creates it. Until then its identifier loads nothing
// (ErrNotFound). A caller that does not commit simply drops the Prepared.
//
// Create is Prepare followed by Commit; CreateIssuing is the two with an
// issuing step between them.
func (m *Sessions) Prepare(user identity.UserID, opts ...CreateOption) (*Prepared, error) {
	id, err := m.newIdentifier()
	if err != nil {
		return nil, err
	}

	family, err := m.families.NewID()
	if err != nil {
		return nil, fmt.Errorf("session: generating a family identifier: %w", err)
	}
	if family.IsZero() {
		return nil, fmt.Errorf("%w: the family identifier generator returned the nil identifier", ErrConfig)
	}

	now := m.clock.Now()
	s := &Session{
		ID:                id,
		UserID:            user,
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(m.idleTimeout),
		AbsoluteExpiresAt: now.Add(m.absoluteTimeout),
		FamilyID:          family,
		FamilyCreatedAt:   now,
		// A sign-in is an authentication. Set before the options, so a
		// consumer's option may still choose another time.
		AuthenticatedAt: now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	if s.KeyBinding.both() {
		return nil, fmt.Errorf("%w: a key binding names either a DPoP key or a certificate, not both", ErrConfig)
	}
	if s.csrfRequested {
		s.csrfRequested = false
		if s.CSRFToken, err = m.newCSRFToken(); err != nil {
			return nil, err
		}
	}

	// Sign-in metadata is personal data, recorded only when the manager was
	// told to record it, whatever the creating call supplied.
	if !m.metadata {
		s.ClientIP, s.UserAgent = "", ""
	}

	// The lifetime is read back from the deadline the options left, so a
	// WithAbsoluteLifetime and any consumer option that sets the deadline are
	// judged the same way, before anything is stored.
	if err := m.checkLifetime(s); err != nil {
		return nil, err
	}
	if s.IdleExpiresAt.After(s.AbsoluteExpiresAt) {
		s.IdleExpiresAt = s.AbsoluteExpiresAt
	}

	return &Prepared{m: m, s: s, built: *s}, nil
}

// checkLifetime refuses a session whose absolute lifetime, counted from its
// creation, is not above zero and within the manager's maximum.
func (m *Sessions) checkLifetime(s *Session) error {
	if lifetime := s.AbsoluteExpiresAt.Sub(s.CreatedAt); lifetime <= 0 || lifetime > m.maxLifetime {
		return fmt.Errorf("%w: absolute lifetime %s is outside 0 to the maximum %s",
			ErrConfig, lifetime, m.maxLifetime)
	}

	return nil
}

// Session returns the built session, the one Commit stores and returns. The
// caller may mark it and set its attributes before committing, and reads its
// identifier to issue a credential for it. Changes made after Commit are not
// stored by it; persist them with Sessions.Save.
//
// The identifier, the user, the family and its start, the creation and
// authentication times, the key binding, the CSRF token and the sign-in
// metadata must not be changed: the credential the caller issues
// names them, and a session stored under other values is not the one that
// credential was issued for. The idle and absolute deadlines may only be
// shortened, as Sessions.MarkEnrolmentPending and
// Sessions.MarkRecoveryPending shorten them. Commit refuses a session whose
// identity fields differ from the ones Prepare built, or whose deadline is
// later than the one Prepare built (ErrConfig), and stores nothing.
func (p *Prepared) Session() *Session { return p.s }

// Commit stores the prepared session in the one write that creates it
// (Store.Create), with every mark and attribute the caller set on it, and
// returns it.
//
// A prepared session is committed at most once. A second Commit, concurrent
// or later, is refused with ErrAlreadyCommitted and writes nothing, whether
// the first stored the session or failed: a failed write may still have
// reached the store, so a retry is a fresh Prepare, with a fresh identifier
// and a fresh credential.
//
// Commit repeats the checks Prepare made on the deadlines, because the caller
// has had the session in hand since: an absolute lifetime that is not above
// zero or is beyond the manager's maximum, or an idle deadline after the
// absolute one, is refused with ErrConfig and nothing is written. A refusal
// of this kind is not a commit; the caller may correct the session and commit
// again.
//
// Commit also refuses, with ErrConfig and nothing written, a session whose
// identifier, user, family, family start, creation time, authentication
// time, key binding, CSRF token, client address or user agent differs from
// the one Prepare built (the error names the field, never its value), or
// whose idle or absolute deadline
// is later than the one Prepare built. Shortening a deadline, as the marks
// do, is allowed. Like the deadline checks above, such a refusal is not a
// commit.
//
// A store's failure is returned behind fixed text of this package, matching
// the store's error through errors.Is, as Create returns it. The session is
// then not stored, and a credential the caller issued for it names a session
// that loads nothing: the caller discards it with the error and never hands
// it out.
func (p *Prepared) Commit(ctx context.Context) (*Session, error) {
	if p.committed.Load() {
		return nil, ErrAlreadyCommitted
	}
	if err := p.checkBuilt(); err != nil {
		return nil, err
	}
	if err := p.m.checkLifetime(p.s); err != nil {
		return nil, err
	}
	if p.s.IdleExpiresAt.After(p.s.AbsoluteExpiresAt) {
		return nil, fmt.Errorf("%w: the idle deadline %s is after the absolute deadline %s",
			ErrConfig, p.s.IdleExpiresAt, p.s.AbsoluteExpiresAt)
	}
	if !p.committed.CompareAndSwap(false, true) {
		return nil, ErrAlreadyCommitted
	}

	if err := p.m.store.Create(ctx, p.s); err != nil {
		return nil, storeFailed(err, "session: the session could not be created")
	}

	return p.s, nil
}

// checkBuilt refuses a session that no longer is the one Prepare built, apart
// from its marks: an identity field that differs, or a deadline moved later.
// It names the field and never its value, which may be an identifier.
func (p *Prepared) checkBuilt() error {
	s, b := p.s, &p.built

	switch {
	case s.ID != b.ID:
		return fmt.Errorf("%w: the prepared session's identifier was changed", ErrConfig)
	case s.UserID != b.UserID:
		return fmt.Errorf("%w: the prepared session's user was changed", ErrConfig)
	case s.FamilyID != b.FamilyID:
		return fmt.Errorf("%w: the prepared session's family was changed", ErrConfig)
	case !s.FamilyCreatedAt.Equal(b.FamilyCreatedAt):
		return fmt.Errorf("%w: the prepared session's family start was changed", ErrConfig)
	case !s.CreatedAt.Equal(b.CreatedAt):
		return fmt.Errorf("%w: the prepared session's creation time was changed", ErrConfig)
	case !s.AuthenticatedAt.Equal(b.AuthenticatedAt):
		return fmt.Errorf("%w: the prepared session's authentication time was changed", ErrConfig)
	case s.KeyBinding != b.KeyBinding:
		return fmt.Errorf("%w: the prepared session's key binding was changed", ErrConfig)
	case s.CSRFToken != b.CSRFToken:
		return fmt.Errorf("%w: the prepared session's CSRF token was changed", ErrConfig)
	case s.ClientIP != b.ClientIP:
		return fmt.Errorf("%w: the prepared session's client address was changed", ErrConfig)
	case s.UserAgent != b.UserAgent:
		return fmt.Errorf("%w: the prepared session's user agent was changed", ErrConfig)
	case s.IdleExpiresAt.After(b.IdleExpiresAt):
		return fmt.Errorf("%w: the prepared session's idle deadline was lengthened", ErrConfig)
	case s.AbsoluteExpiresAt.After(b.AbsoluteExpiresAt):
		return fmt.Errorf("%w: the prepared session's absolute deadline was lengthened", ErrConfig)
	}

	return nil
}

// CreateIssuing is Create with a step of the caller's run on the session
// before it is stored, and returns the session and what that step issued.
//
// It exists for the caller whose sign-in is complete only once the holder has
// a credential for the session, such as a signed token naming it. With
// Create, a credential that cannot be issued after the session is stored
// leaves a live session nobody holds. Here issue is called once the session
// is built, with its identifier, and before anything is stored, so a
// credential is issued before its session is stored, and a credential that
// cannot be issued stores nothing.
//
// When issue fails, CreateIssuing returns its error as it is, so errors.Is
// and errors.As reach it, and has stored nothing. When issue succeeds, the
// session is stored as Create stores it, and a failure of that write is
// returned as Create returns it, with no session and no credential: the
// credential issue returned names a session that was never stored, so it
// authenticates nothing and is discarded with the error. A refusal decided
// while building, such as a lifetime outside the maximum (ErrConfig), never
// calls issue.
//
// issue is handed the session as it will be stored, which is also the session
// returned, and must not modify it. A caller that must mark the session
// before it is stored, such as with a pending challenge, uses Prepare, marks
// Prepared.Session, issues, and then commits. A nil issue runs no step and
// returns an empty credential, which is Create.
func (m *Sessions) CreateIssuing(
	ctx context.Context,
	user identity.UserID,
	issue func(s *Session) (string, error),
	opts ...CreateOption,
) (*Session, string, error) {
	p, err := m.Prepare(user, opts...)
	if err != nil {
		return nil, "", err
	}

	var tok string
	if issue != nil {
		if tok, err = issue(p.Session()); err != nil {
			return nil, "", err
		}
	}

	s, err := p.Commit(ctx)
	if err != nil {
		return nil, "", err
	}

	return s, tok, nil
}
