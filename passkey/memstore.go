package passkey

import (
	"bytes"
	"cmp"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

var _ CredentialStore = (*MemoryCredentialStore)(nil)

// MemoryCredentialStore keeps passkey credentials in process memory. It is
// the CredentialStore the library uses when a consumer supplies none, and it
// is safe for concurrent use.
//
// Its limit is stated: it holds this process's credentials only. A restart
// forgets every passkey, so users must register theirs again, and behind
// several replicas each keeps its own set, so a passkey registered on one is
// unknown to the others. Supply a durable, shared CredentialStore for anything
// beyond a single process.
//
// Every conditional write runs its check and its change under one lock, so it
// is decided by the write as the contract requires. The store keeps its own
// copies of every byte slice, transport list and emailed code, in and out, so
// nothing a caller holds can reach stored state. It keeps emailed codes in
// plain memory; there is nothing at rest to seal.
type MemoryCredentialStore struct {
	mu    sync.Mutex
	byID  map[id.ID]*Credential
	index map[string]id.ID // WebAuthn credential ID, as a string copy → library ID
}

// NewMemoryCredentialStore returns an empty in-memory store.
//
// It takes no configuration: a deployment that needs durability replaces the
// whole port rather than an option on this one.
func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{
		byID:  make(map[id.ID]*Credential),
		index: make(map[string]id.ID),
	}
}

// Insert stores a copy of c, refusing a credential ID or library ID already
// stored with ErrDuplicateCredential.
func (s *MemoryCredentialStore) Insert(_ context.Context, c *Credential) error {
	cp := copyCredential(c)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.index[string(cp.CredentialID)]; ok {
		return ErrDuplicateCredential
	}

	if _, ok := s.byID[cp.ID]; ok {
		return ErrDuplicateCredential
	}

	s.byID[cp.ID] = cp
	s.index[string(cp.CredentialID)] = cp.ID

	return nil
}

// FindByCredentialID returns a copy of the credential with credential ID
// credID, or ErrNotFound.
func (s *MemoryCredentialStore) FindByCredentialID(_ context.Context, credID []byte) (*Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cid, ok := s.index[string(credID)]
	if !ok {
		return nil, ErrNotFound
	}

	return copyCredential(s.byID[cid]), nil
}

// Find returns a copy of user's credential cid, or ErrNotFound.
func (s *MemoryCredentialStore) Find(_ context.Context, user identity.UserID, cid id.ID) (*Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := s.owned(user, cid)
	if c == nil {
		return nil, ErrNotFound
	}

	return copyCredential(c), nil
}

// List returns copies of user's credentials, oldest CreatedAt first, ties in
// library ID order.
func (s *MemoryCredentialStore) List(_ context.Context, user identity.UserID) ([]*Credential, error) {
	s.mu.Lock()

	var out []*Credential

	for _, c := range s.byID {
		if c.User == user {
			out = append(out, copyCredential(c))
		}
	}

	s.mu.Unlock()

	slices.SortFunc(out, func(a, b *Credential) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), bytes.Compare(a.ID[:], b.ID[:]))
	})

	return out, nil
}

// Count counts user's credentials.
func (s *MemoryCredentialStore) Count(_ context.Context, user identity.UserID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0

	for _, c := range s.byID {
		if c.User == user {
			n++
		}
	}

	return n, nil
}

// RecordAssertion records the counter, backup state and last use of an
// active credential whose stored counter is lower than signCount, or where
// both are zero, and reports whether this call did.
func (s *MemoryCredentialStore) RecordAssertion(
	_ context.Context, cid id.ID, signCount uint32, backupState bool, at time.Time,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.byID[cid]
	if !ok || c.State != StateActive {
		return false, nil
	}

	if c.SignCount >= signCount && (c.SignCount != 0 || signCount != 0) {
		return false, nil
	}

	c.SignCount = signCount
	c.BackupState = backupState
	c.LastUsedAt = at

	return true, nil
}

// Suspend moves an active credential to suspended, and reports whether this
// call did.
func (s *MemoryCredentialStore) Suspend(_ context.Context, cid id.ID) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.byID[cid]
	if !ok || c.State != StateActive {
		return false, nil
	}

	c.State = StateSuspended

	return true, nil
}

// ClearReason clears reason r of user's pending credential cid where it is
// set, activating the credential when no reason remains and dropping its
// emailed code when r includes AwaitingEmailCode.
func (s *MemoryCredentialStore) ClearReason(
	_ context.Context, user identity.UserID, cid id.ID, r PendingReason,
) (State, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := s.owned(user, cid)
	if c == nil || c.State != StatePending || c.Pending&r == 0 {
		return 0, false, nil
	}

	c.Pending &^= r
	if r&AwaitingEmailCode != 0 {
		c.EmailCode = nil
	}

	if c.Pending == 0 {
		c.State = StateActive
	}

	return c.State, true, nil
}

// ChargeEmailAttempt charges one attempt against the outstanding, unexpired
// emailed code of user's pending credential cid while fewer than
// MaxEmailCodeAttempts are charged, and returns a copy of the code.
func (s *MemoryCredentialStore) ChargeEmailAttempt(
	_ context.Context, user identity.UserID, cid id.ID, at time.Time,
) (*EmailCode, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := s.owned(user, cid)
	if c == nil || c.State != StatePending || c.Pending&AwaitingEmailCode == 0 || c.EmailCode == nil {
		return nil, false, nil
	}

	code := c.EmailCode
	if !at.Before(code.ExpiresAt) || code.Attempts >= MaxEmailCodeAttempts {
		return nil, false, nil
	}

	code.Attempts++
	out := *code

	return &out, true, nil
}

// Rename sets the name of user's credential cid, and reports whether it
// exists.
func (s *MemoryCredentialStore) Rename(_ context.Context, user identity.UserID, cid id.ID, name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := s.owned(user, cid)
	if c == nil {
		return false, nil
	}

	c.Name = name

	return true, nil
}

// Delete removes user's credential cid, and reports whether this call did.
func (s *MemoryCredentialStore) Delete(_ context.Context, user identity.UserID, cid id.ID) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := s.owned(user, cid)
	if c == nil {
		return false, nil
	}

	s.remove(c)

	return true, nil
}

// DeleteAwaitingSavedCodes removes user's credentials with AwaitingSavedCodes
// set, and reports how many.
func (s *MemoryCredentialStore) DeleteAwaitingSavedCodes(_ context.Context, user identity.UserID) (int, error) {
	return s.deleteWhere(func(c *Credential) bool {
		return c.User == user && c.Pending&AwaitingSavedCodes != 0
	}), nil
}

// DeleteUser removes every credential of user, and reports how many.
func (s *MemoryCredentialStore) DeleteUser(_ context.Context, user identity.UserID) (int, error) {
	return s.deleteWhere(func(c *Credential) bool { return c.User == user }), nil
}

// owned returns user's stored credential cid, or nil. The caller holds mu.
func (s *MemoryCredentialStore) owned(user identity.UserID, cid id.ID) *Credential {
	c, ok := s.byID[cid]
	if !ok || c.User != user {
		return nil
	}

	return c
}

// remove drops c from both maps. The caller holds mu.
func (s *MemoryCredentialStore) remove(c *Credential) {
	delete(s.byID, c.ID)
	delete(s.index, string(c.CredentialID))
}

func (s *MemoryCredentialStore) deleteWhere(match func(*Credential) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0

	for _, c := range s.byID {
		if match(c) {
			s.remove(c)
			n++
		}
	}

	return n
}

// copyCredential returns a deep copy of c: no slice or pointer is shared.
func copyCredential(c *Credential) *Credential {
	cp := *c
	cp.CredentialID = bytes.Clone(c.CredentialID)
	cp.PublicKey = bytes.Clone(c.PublicKey)
	cp.Transports = slices.Clone(c.Transports)
	cp.AAGUID = bytes.Clone(c.AAGUID)
	cp.AttestationStatement = bytes.Clone(c.AttestationStatement)

	if c.EmailCode != nil {
		code := *c.EmailCode
		cp.EmailCode = &code
	}

	return &cp
}
