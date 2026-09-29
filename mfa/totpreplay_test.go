package mfa_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
)

// failingEnrolmentStore is a store that is there but cannot answer: a
// connection refused, or a secret that will not open.
type failingEnrolmentStore struct{ err error }

func (s failingEnrolmentStore) Get(
	context.Context, identity.UserID,
) (mfa.Enrolment, bool, error) {
	return mfa.Enrolment{}, false, s.err
}

func (s failingEnrolmentStore) PutPending(context.Context, mfa.Enrolment) error { return s.err }

func (s failingEnrolmentStore) Confirm(
	context.Context, identity.UserID, int64, time.Time,
) (bool, error) {
	return false, s.err
}

func (s failingEnrolmentStore) AcceptStep(
	context.Context, identity.UserID, int64,
) (bool, error) {
	return false, s.err
}

func (s failingEnrolmentStore) Delete(context.Context, identity.UserID) error { return s.err }

func TestTOTPReplay(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(base)))
	require.NoError(t, err)

	secret := []byte(rfc6238SHA1Secret)
	enrolConfirmed(t, store, "u-1", secret)

	code := codeAt(t, secret, base, 6, 30*time.Second)

	require.NoError(t, m.Verify(ctx, "u-1", code), "the first presentation is accepted")
	assert.ErrorIs(t, m.Verify(ctx, "u-1", code), mfa.ErrInvalidCode,
		"the same code within its step is refused")
}

// TestTOTPVerifyStoreFailure pins the other half of the refusal rule: an outage
// is returned as itself, so a caller can tell a refusal from a failure and
// never reports the user as simply not enrolled.
func TestTOTPVerifyStoreFailure(t *testing.T) {
	t.Parallel()

	outage := errors.New("dial tcp: connection refused")

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	m, err := mfa.NewTOTP(failingEnrolmentStore{err: outage}, "Example",
		mfa.WithClock(clockwork.NewFakeClockAt(base)))
	require.NoError(t, err)

	err = m.Verify(t.Context(), "u-1", "123456")
	assert.ErrorIs(t, err, outage)
	assert.NotErrorIs(t, err, mfa.ErrInvalidCode)

	enrolled, err := m.Enrolled(t.Context(), "u-1")
	assert.ErrorIs(t, err, outage)
	assert.False(t, enrolled, "and the bool must not be read as an answer")
}

func TestTOTPVerifyRace(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(base)))
	require.NoError(t, err)

	secret := []byte(rfc6238SHA1Secret)
	enrolConfirmed(t, store, "u-1", secret)
	code := codeAt(t, secret, base, 6, 30*time.Second)

	const goroutines = 16

	var (
		wg       sync.WaitGroup
		accepted atomic.Int64
		start    = make(chan struct{})
	)

	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			<-start

			if m.Verify(ctx, "u-1", code) == nil {
				accepted.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), accepted.Load(), "exactly one of sixteen may succeed")
}

// The code that proved a device on the enrolment path must never be accepted
// again. The single-call confirm refuses a path-proven enrolment, but the
// store's Confirm can still reach it (the stated limit of that call: a proof
// landing between its read and its write) with the step before, which the
// window admits; that must not move the recorded step backwards below the
// proving one.
func TestTOTPProvingCodeNotReplayableAfterConfirm(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 24, 10, 0, 15, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()
	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(now)))
	require.NoError(t, err)

	_, gen, err := m.BeginEnrolmentGeneration(t.Context(), "u-1", "alice")
	require.NoError(t, err)
	e, _, err := store.Get(t.Context(), "u-1")
	require.NoError(t, err)

	proved, err := store.ProveDevice(t.Context(), "u-1", gen, now.Unix()/30, nil, time.Time{}, now)
	require.NoError(t, err)
	require.True(t, proved)

	previous := codeAt(t, e.Secret, now.Add(-30*time.Second), 6, 30*time.Second)
	require.ErrorIs(t, m.ConfirmEnrolment(t.Context(), "u-1", previous), mfa.ErrInvalidCode,
		"a path-proven enrolment completes only through the path")

	confirmed, err := store.Confirm(t.Context(), "u-1", now.Unix()/30-1, now)
	require.NoError(t, err)
	require.True(t, confirmed)

	proving := codeAt(t, e.Secret, now, 6, 30*time.Second)
	assert.Error(t, m.Verify(t.Context(), "u-1", proving),
		"the code that proved the device was accepted again")
}
