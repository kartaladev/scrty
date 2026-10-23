package mfa_test

import (
	"context"
	"encoding/base32"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/id"
)

// interleavingStore runs a hook once, just before the first Confirm or
// AcceptStep reaches the store, so a test can land another session's writes
// between the method's read and its write.
type interleavingStore struct {
	mfa.EnrolmentStore

	beforeConfirm func()
	beforeAccept  func()

	confirmOnce, acceptOnce sync.Once
}

func (s *interleavingStore) Confirm(
	ctx context.Context, user identity.UserID, gen id.ID, step int64, at time.Time,
) (bool, error) {
	if s.beforeConfirm != nil {
		s.confirmOnce.Do(s.beforeConfirm)
	}

	return s.EnrolmentStore.Confirm(ctx, user, gen, step, at)
}

func (s *interleavingStore) AcceptStep(
	ctx context.Context, user identity.UserID, gen id.ID, step int64,
) (bool, error) {
	if s.beforeAccept != nil {
		s.acceptOnce.Do(s.beforeAccept)
	}

	return s.EnrolmentStore.AcceptStep(ctx, user, gen, step)
}

// rawSecret decodes the base32 secret a provisioning hands back.
func rawSecret(t *testing.T, secret string) []byte {
	t.Helper()

	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)

	return raw
}

// TestConfirmEnrolment_NeverConfirmsASecretTheCodeWasNotFor lands a new begin
// between ConfirmEnrolment's read of secret A and its write: the code was
// checked against A, so it must confirm nothing, and above all not B.
func TestConfirmEnrolment_NeverConfirmsASecretTheCodeWasNotFor(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	now := time.Date(2026, 9, 24, 10, 0, 15, 0, time.UTC)
	inner := mfa.NewMemoryEnrolmentStore()
	store := &interleavingStore{EnrolmentStore: inner}
	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(now)))
	require.NoError(t, err)

	first, err := m.BeginEnrolment(ctx, "u-1", "alice")
	require.NoError(t, err)

	var second mfa.Provisioning
	store.beforeConfirm = func() {
		var beginErr error
		second, beginErr = m.BeginEnrolment(ctx, "u-1", "alice")
		require.NoError(t, beginErr)
	}

	err = m.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, first.Secret, now))
	require.ErrorIs(t, err, mfa.ErrInvalidCode, "a code checked against A must not confirm B")

	got, ok, err := inner.Get(ctx, "u-1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.True(t, got.ConfirmedAt.IsZero(), "the enrolment must read as unconfirmed")
	assert.Equal(t, rawSecret(t, second.Secret), got.Secret, "the enrolment must hold secret B")
}

// TestVerify_RefusesCodeOfARemovedSecretAfterReEnrolment lands a removal and a
// confirmed re-enrolment between Verify's check of the old secret's code and
// its AcceptStep: the code belonged to a secret that no longer exists.
func TestVerify_RefusesCodeOfARemovedSecretAfterReEnrolment(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	now := time.Date(2026, 9, 24, 10, 0, 15, 0, time.UTC)
	before := now.Add(-30 * time.Second)
	inner := mfa.NewMemoryEnrolmentStore()
	store := &interleavingStore{EnrolmentStore: inner}
	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(now)))
	require.NoError(t, err)

	old, err := m.BeginEnrolment(ctx, "u-1", "alice")
	require.NoError(t, err)
	require.NoError(t, m.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, old.Secret, before)))

	store.beforeAccept = func() {
		require.NoError(t, m.RemoveEnrolment(ctx, "u-1"))
		renewed, beginErr := m.BeginEnrolment(ctx, "u-1", "alice")
		require.NoError(t, beginErr)
		require.NoError(t, m.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, renewed.Secret, before)))
	}

	err = m.Verify(ctx, "u-1", []byte(codeForSecret(t, old.Secret, now)))
	require.ErrorIs(t, err, mfa.ErrInvalidCode, "a code of the removed secret must not be accepted")
}
