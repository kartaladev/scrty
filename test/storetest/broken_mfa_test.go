package storetest_test

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
)

// mfaDefect is one deliberate flaw an mfaStore can carry.
type mfaDefect string

const (
	mfaConforming mfaDefect = "conforming"
	// AcceptStep records every step presented and reports whether it was
	// later than the one recorded before, so a refused earlier step moves the
	// recorded one backwards and reopens a spent one.
	mfaAcceptStepMovesBack mfaDefect = "accept-step-moves-back"
	// A begin over a pending enrolment copies the confirmation time and step
	// it is given, where a begin with none to replace starts afresh.
	mfaReplaceKeepsGiven mfaDefect = "replace-keeps-given"
)

// mfaStore is an enrolment store over process memory, written apart from the
// shipped store so a defect can reach state the shipped store never exposes.
// Without a defect it conforms.
type mfaStore struct {
	defect mfaDefect

	mu         sync.Mutex
	enrolments map[identity.UserID]mfa.Enrolment
}

var _ mfa.EnrolmentStore = (*mfaStore)(nil)

func newMFAStore(defect mfaDefect) *mfaStore {
	return &mfaStore{defect: defect, enrolments: make(map[identity.UserID]mfa.Enrolment)}
}

func (s *mfaStore) Get(_ context.Context, user identity.UserID) (mfa.Enrolment, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	e.Secret = bytes.Clone(e.Secret)
	return e, ok, nil
}

func (s *mfaStore) PutPending(_ context.Context, e mfa.Enrolment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, replacing := s.enrolments[e.User]
	if replacing && !existing.ConfirmedAt.IsZero() {
		return mfa.ErrAlreadyEnrolled
	}
	stored := mfa.Enrolment{User: e.User, Secret: bytes.Clone(e.Secret), CreatedAt: e.CreatedAt}
	if replacing && s.defect == mfaReplaceKeepsGiven {
		stored.ConfirmedAt, stored.LastStep = e.ConfirmedAt, e.LastStep
	}
	s.enrolments[e.User] = stored
	return nil
}

func (s *mfaStore) Confirm(_ context.Context, user identity.UserID, step int64, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	if !ok || !e.ConfirmedAt.IsZero() {
		return false, nil
	}
	e.ConfirmedAt, e.LastStep = at, max(e.LastStep, step)
	s.enrolments[user] = e
	return true, nil
}

func (s *mfaStore) AcceptStep(_ context.Context, user identity.UserID, step int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	if !ok || e.ConfirmedAt.IsZero() {
		return false, nil
	}
	if s.defect == mfaAcceptStepMovesBack {
		old := e.LastStep
		e.LastStep = step
		s.enrolments[user] = e
		return old < step, nil
	}
	if e.LastStep >= step {
		return false, nil
	}
	e.LastStep = step
	s.enrolments[user] = e
	return true, nil
}

func (s *mfaStore) Delete(_ context.Context, user identity.UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.enrolments, user)
	return nil
}
