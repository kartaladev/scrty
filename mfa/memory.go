package mfa

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
)

// MemoryEnrolmentStore keeps enrolments in this process and nowhere else.
//
// It is the default an MFA method uses when a consumer supplies no store, and
// it is what tests and single-process deployments want. Every enrolment is lost
// when the process exits, so a user who had enrolled comes back unenrolled.
//
// That loss fails closed rather than open, which is the only reason it is an
// acceptable default: the requirement to use a second factor lives with the
// user, not with the enrolment, so a user who must use MFA and whose enrolment
// vanished is refused and asked to enrol, never completed on their first
// factor. A deployment that runs more than one replica, or that restarts, wants
// a durable EnrolmentStore instead.
//
// It holds its own copy of every secret, in and out, so nothing a caller keeps
// a reference to can reach stored state. It is safe for concurrent use.
type MemoryEnrolmentStore struct {
	mu         sync.RWMutex
	enrolments map[identity.UserID]Enrolment
}

// NewMemoryEnrolmentStore returns an empty in-memory store.
//
// It takes no configuration: there is nothing to tune about a map, and a
// deployment that needs durability replaces the whole port rather than an
// option on this one.
func NewMemoryEnrolmentStore() *MemoryEnrolmentStore {
	return &MemoryEnrolmentStore{enrolments: make(map[identity.UserID]Enrolment)}
}

// Get returns the user's enrolment, with its own copy of the secret.
//
// The bool is false only for a user this store holds nothing for. This store
// cannot fail, so the error is always nil — a durable one returns its outage
// here rather than reporting the user as absent.
func (s *MemoryEnrolmentStore) Get(
	_ context.Context, user identity.UserID,
) (Enrolment, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, ok := s.enrolments[user]
	if !ok {
		return Enrolment{}, false, nil
	}

	return copyEnrolment(e), true, nil
}

// PutPending stores e as a pending enrolment.
//
// The decision and the write happen under one lock, which is what a durable
// store expresses as a conditional write: two concurrent begins cannot both
// find no confirmed enrolment and then both replace one.
func (s *MemoryEnrolmentStore) PutPending(_ context.Context, e Enrolment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.enrolments[e.User]; ok && !existing.ConfirmedAt.IsZero() {
		return ErrAlreadyEnrolled
	}

	stored := copyEnrolment(e)
	stored.ConfirmedAt = time.Time{}
	stored.LastStep = 0

	s.enrolments[e.User] = stored

	return nil
}

// Confirm marks a pending enrolment confirmed and records the step its code
// belonged to. An enrolment that is already confirmed reports false: there was
// no pending enrolment to confirm, and silently re-confirming one would reset
// the step that makes codes single-use.
func (s *MemoryEnrolmentStore) Confirm(
	_ context.Context, user identity.UserID, step int64, at time.Time,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	if !ok || !e.ConfirmedAt.IsZero() {
		return false, nil
	}

	e.ConfirmedAt = at
	e.LastStep = step
	s.enrolments[user] = e

	return true, nil
}

// AcceptStep records step for user, if and only if the enrolment is confirmed
// and its recorded step is strictly lower.
//
// The condition is evaluated and the write performed under one lock, so of any
// number of concurrent calls for one step, exactly one reports true. That is
// what makes a code single-use.
func (s *MemoryEnrolmentStore) AcceptStep(
	_ context.Context, user identity.UserID, step int64,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	if !ok || e.ConfirmedAt.IsZero() || e.LastStep >= step {
		return false, nil
	}

	e.LastStep = step
	s.enrolments[user] = e

	return true, nil
}

// Delete removes the user's enrolment, whether or not there was one.
func (s *MemoryEnrolmentStore) Delete(_ context.Context, user identity.UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.enrolments, user)

	return nil
}

// copyEnrolment clones the one field that aliases: without it a caller holds a
// slice into stored state, and writing through it would change a secret this
// store believes it owns.
func copyEnrolment(e Enrolment) Enrolment {
	e.Secret = bytes.Clone(e.Secret)

	return e
}
