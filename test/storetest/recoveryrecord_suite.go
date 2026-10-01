package storetest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
)

// The fixed instants of the record suite: 28 September 2026 is a Monday.
var (
	recoveryMonday1000   = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	recoveryTuesday1100  = time.Date(2026, 9, 29, 11, 0, 0, 0, time.UTC)
	recoveryWednesday    = time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
	recoveryThursday0859 = time.Date(2026, 10, 1, 8, 59, 0, 0, time.UTC)
	recoveryThursday0900 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
)

// recoveryRecord returns the suite's n-th record: pending, of user,
// completable at notBefore, having proven a saved code and a password and
// reported a TOTP enrolment and a passkey whose identifier holds a colon.
func recoveryRecord(n int, user identity.UserID, notBefore time.Time) recovery.Record {
	return recovery.Record{
		ID:        suiteID(n),
		User:      user,
		StartedAt: notBefore.Add(-48 * time.Hour),
		NotBefore: notBefore,
		Proven:    []recovery.AuthenticatorRef{{Kind: "saved", ID: "code"}, {Kind: "password", ID: "password"}},
		Reported:  []recovery.AuthenticatorRef{{Kind: recovery.MFAKind, ID: "totp"}, {Kind: "passkey", ID: "cred:7"}},
	}
}

// insertRecords stores every record, failing the case at the first error.
func insertRecords(ctx context.Context, t *testing.T, s recovery.RecordStore, rs ...recovery.Record) {
	t.Helper()

	for _, r := range rs {
		require.NoError(t, s.Insert(ctx, r), "insert %s", r.ID)
	}
}

// findRecord finds a record that must exist.
func findRecord(ctx context.Context, t *testing.T, s recovery.RecordStore, rid id.ID) *recovery.Record {
	t.Helper()

	got, err := s.Find(ctx, rid)
	require.NoError(t, err, "record %s must be found", rid)
	require.NotNil(t, got, "a found record must not be nil")

	return got
}

// assertRecord compares a found record with want, field by field.
func assertRecord(t *testing.T, want recovery.Record, got *recovery.Record) {
	t.Helper()

	assert.Equal(t, want.ID, got.ID)
	assert.Equal(t, want.User, got.User, "the user must round-trip byte for byte")
	assertTimeEqual(t, want.StartedAt, got.StartedAt, "StartedAt")
	assertTimeEqual(t, want.NotBefore, got.NotBefore, "NotBefore")
	assertTimeEqual(t, want.CompletedAt, got.CompletedAt, "CompletedAt")
	assertTimeEqual(t, want.CancelledAt, got.CancelledAt, "CancelledAt")
	if len(want.Proven) == 0 {
		assert.Empty(t, got.Proven)
	} else {
		assert.Equal(t, want.Proven, got.Proven)
	}
	if len(want.Reported) == 0 {
		assert.Empty(t, got.Reported)
	} else {
		assert.Equal(t, want.Reported, got.Reported)
	}
	assert.Equal(t, want.SavedSpent, got.SavedSpent)
}

// assertPendingRecord requires the record to be neither completed nor
// cancelled.
func assertPendingRecord(t *testing.T, r *recovery.Record) {
	t.Helper()

	assert.True(t, r.CompletedAt.IsZero(), "completed at %s", r.CompletedAt)
	assert.True(t, r.CancelledAt.IsZero(), "cancelled at %s", r.CancelledAt)
}

// RunRecoveryRecordStoreSuite checks a recovery.RecordStore against the
// contract account recovery relies on: a record, pending or already
// completed, round-trips with every field, its authenticator lists in order,
// and is the caller's own copy; an existing identifier is not inserted over;
// a completion succeeds only on a pending record whose completable instant
// has been reached, a cancellation only on a pending one, each once, and of 8
// completions and 8 cancellations racing on one record exactly one succeeds;
// cancelling a user's pending records touches no other record; and the latest
// completion is the latest among the user's records, or none.
//
// newStore is called once per case and must return an empty store. The
// contract takes every time from the caller, so a store may ignore clk.
//
// Stored times may be truncated or rounded to the microsecond, and are
// compared by instant.
func RunRecoveryRecordStoreSuite(t *testing.T, newStore func(t *testing.T, clk clock.Clock) recovery.RecordStore) {
	t.Helper()

	type recordCase = suiteCase[recovery.RecordStore]

	cases := []recordCase{
		{
			name: "an inserted record is found with every field",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				r := recoveryRecord(1, "Alice@Example.COM ", recoveryThursday0900)
				r.SavedSpent = true
				insertRecords(ctx, t, s, r)

				assertRecord(t, r, findRecord(ctx, t, s, r.ID))
			},
		},
		{
			name: "a record with no proven or reported authenticators is found with none",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				r := recoveryRecord(1, "u-1", recoveryThursday0900)
				r.Proven, r.Reported = nil, nil
				insertRecords(ctx, t, s, r)

				assertRecord(t, r, findRecord(ctx, t, s, r.ID))
			},
		},
		{
			name: "record times keep at least microsecond precision",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				r := recoveryRecord(1, "u-1", preciseStart)
				r.StartedAt = preciseStart.Add(-time.Hour)
				r.CompletedAt = preciseStart.Add(time.Minute)
				insertRecords(ctx, t, s, r)

				got := findRecord(ctx, t, s, r.ID)
				assertTimeMicro(t, r.StartedAt, got.StartedAt, "StartedAt")
				assertTimeMicro(t, r.NotBefore, got.NotBefore, "NotBefore")
				assertTimeMicro(t, r.CompletedAt, got.CompletedAt, "CompletedAt")
			},
		},
		{
			name: "a found record is the caller's own copy",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				r := recoveryRecord(1, "u-1", recoveryThursday0900)
				insertRecords(ctx, t, s, r)
				r.Proven[0].ID = "changed-after-insert"

				got := findRecord(ctx, t, s, r.ID)
				got.Reported[0].ID = "changed-after-find"
				got.NotBefore = recoveryMonday1000

				assertRecord(t, recoveryRecord(1, "u-1", recoveryThursday0900), findRecord(ctx, t, s, r.ID))
			},
		},
		{
			name: "finding an unknown record is ErrRecordNotFound",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				insertRecords(ctx, t, s, recoveryRecord(1, "u-1", recoveryThursday0900))

				for _, unknown := range []id.ID{suiteID(2), id.Nil} {
					got, err := s.Find(ctx, unknown)
					require.ErrorIs(t, err, recovery.ErrRecordNotFound, "record %s", unknown)
					assert.Nil(t, got)
				}
			},
		},
		{
			name: "inserting an existing identifier is an error",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				original := recoveryRecord(1, "u-1", recoveryThursday0900)
				insertRecords(ctx, t, s, original)

				usurper := recoveryRecord(1, "u-2", recoveryMonday1000)
				require.Error(t, s.Insert(ctx, usurper), "inserting over a stored identifier must fail")

				assertRecord(t, original, findRecord(ctx, t, s, original.ID))
			},
		},
		{
			name: "completing before the completable instant is refused and the record stays pending",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				r := recoveryRecord(1, "u-1", recoveryThursday0900)
				insertRecords(ctx, t, s, r)

				ok, err := s.Complete(ctx, r.ID, recoveryThursday0859)
				require.NoError(t, err)
				assert.False(t, ok)
				assertPendingRecord(t, findRecord(ctx, t, s, r.ID))
			},
		},
		{
			name: "completing at exactly the completable instant succeeds",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				r := recoveryRecord(1, "u-1", recoveryThursday0900)
				insertRecords(ctx, t, s, r)

				ok, err := s.Complete(ctx, r.ID, recoveryThursday0900)
				require.NoError(t, err)
				assert.True(t, ok)

				r.CompletedAt = recoveryThursday0900
				assertRecord(t, r, findRecord(ctx, t, s, r.ID))
			},
		},
		{
			name: "a completed record is not completed again and keeps its completion time",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				r := recoveryRecord(1, "u-1", recoveryThursday0900)
				insertRecords(ctx, t, s, r)

				ok, err := s.Complete(ctx, r.ID, recoveryThursday0900)
				require.NoError(t, err)
				require.True(t, ok)

				ok, err = s.Complete(ctx, r.ID, recoveryThursday0900.Add(time.Hour))
				require.NoError(t, err)
				assert.False(t, ok)
				assertTimeEqual(t, recoveryThursday0900, findRecord(ctx, t, s, r.ID).CompletedAt, "CompletedAt")
			},
		},
		{
			name: "cancel then complete: the completion is refused",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				r := recoveryRecord(1, "u-1", recoveryThursday0900)
				insertRecords(ctx, t, s, r)

				n, err := s.Cancel(ctx, r.ID, recoveryThursday0859)
				require.NoError(t, err)
				assert.Equal(t, 1, n)

				ok, err := s.Complete(ctx, r.ID, recoveryThursday0900.Add(time.Hour))
				require.NoError(t, err)
				assert.False(t, ok)

				got := findRecord(ctx, t, s, r.ID)
				assert.True(t, got.CompletedAt.IsZero(), "completed at %s", got.CompletedAt)
				assertTimeEqual(t, recoveryThursday0859, got.CancelledAt, "CancelledAt")
			},
		},
		{
			name: "a cancelled record is not cancelled again and keeps its cancellation time",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				r := recoveryRecord(1, "u-1", recoveryThursday0900)
				insertRecords(ctx, t, s, r)

				n, err := s.Cancel(ctx, r.ID, recoveryThursday0859)
				require.NoError(t, err)
				require.Equal(t, 1, n)

				n, err = s.Cancel(ctx, r.ID, recoveryThursday0900)
				require.NoError(t, err)
				assert.Zero(t, n)
				assertTimeEqual(t, recoveryThursday0859, findRecord(ctx, t, s, r.ID).CancelledAt, "CancelledAt")
			},
		},
		{
			name: "a completed record is not cancelled",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				r := recoveryRecord(1, "u-1", recoveryThursday0900)
				insertRecords(ctx, t, s, r)

				ok, err := s.Complete(ctx, r.ID, recoveryThursday0900)
				require.NoError(t, err)
				require.True(t, ok)

				n, err := s.Cancel(ctx, r.ID, recoveryThursday0900.Add(time.Minute))
				require.NoError(t, err)
				assert.Zero(t, n)
				assert.True(t, findRecord(ctx, t, s, r.ID).CancelledAt.IsZero())
			},
		},
		{
			name: "completing or cancelling an unknown record changes nothing and is not an error",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				r := recoveryRecord(1, "u-1", recoveryThursday0900)
				insertRecords(ctx, t, s, r)

				ok, err := s.Complete(ctx, suiteID(2), recoveryThursday0900)
				require.NoError(t, err)
				assert.False(t, ok)

				n, err := s.Cancel(ctx, suiteID(2), recoveryThursday0900)
				require.NoError(t, err)
				assert.Zero(t, n)

				assertPendingRecord(t, findRecord(ctx, t, s, r.ID))
			},
		},
		{
			name: "the latest completion is the latest among the user's records",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				monday := recoveryRecord(1, "u-1", recoveryMonday1000)
				tuesday := recoveryRecord(2, "u-1", recoveryTuesday1100)
				pending := recoveryRecord(3, "u-1", recoveryThursday0900)
				other := recoveryRecord(4, "u-2", recoveryWednesday)
				insertRecords(ctx, t, s, tuesday, monday, pending, other)

				for _, c := range []struct {
					rid id.ID
					at  time.Time
				}{{tuesday.ID, recoveryTuesday1100}, {monday.ID, recoveryMonday1000}, {other.ID, recoveryWednesday}} {
					ok, err := s.Complete(ctx, c.rid, c.at)
					require.NoError(t, err)
					require.True(t, ok)
				}

				at, ok, err := s.LatestCompletion(ctx, "u-1")
				require.NoError(t, err)
				require.True(t, ok)
				assertTimeEqual(t, recoveryTuesday1100, at, "latest completion")
			},
		},
		{
			name: "a user with no completion reports none",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				cancelled := recoveryRecord(2, "u-1", recoveryThursday0900)
				insertRecords(ctx, t, s, recoveryRecord(1, "u-1", recoveryThursday0900), cancelled)
				_, err := s.Cancel(ctx, cancelled.ID, recoveryThursday0859)
				require.NoError(t, err)

				at, ok, err := s.LatestCompletion(ctx, "u-1")
				require.NoError(t, err)
				assert.False(t, ok)
				assert.True(t, at.IsZero(), "no completion is the zero time, got %s", at)

				_, ok, err = s.LatestCompletion(ctx, "u-unknown")
				require.NoError(t, err)
				assert.False(t, ok)
			},
		},
		{
			name: "an inserted completed record is immediately the latest completion",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				r := recoveryRecord(1, "u-1", recoveryTuesday1100)
				r.CompletedAt = recoveryTuesday1100
				insertRecords(ctx, t, s, r)

				at, ok, err := s.LatestCompletion(ctx, "u-1")
				require.NoError(t, err)
				require.True(t, ok)
				assertTimeEqual(t, recoveryTuesday1100, at, "latest completion")
				assertRecord(t, r, findRecord(ctx, t, s, r.ID))
			},
		},
		{
			name: "CancelPending cancels only the user's pending records and counts them",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				first := recoveryRecord(1, "u-1", recoveryThursday0900)
				second := recoveryRecord(2, "u-1", recoveryThursday0900.Add(time.Hour))
				completed := recoveryRecord(3, "u-1", recoveryMonday1000)
				completed.CompletedAt = recoveryMonday1000
				cancelled := recoveryRecord(4, "u-1", recoveryThursday0900)
				cancelled.CancelledAt = recoveryMonday1000
				other := recoveryRecord(5, "u-2", recoveryThursday0900)
				insertRecords(ctx, t, s, first, second, completed, cancelled, other)

				n, err := s.CancelPending(ctx, "u-1", recoveryWednesday)
				require.NoError(t, err)
				assert.Equal(t, 2, n)

				assertTimeEqual(t, recoveryWednesday, findRecord(ctx, t, s, first.ID).CancelledAt, "first CancelledAt")
				assertTimeEqual(t, recoveryWednesday, findRecord(ctx, t, s, second.ID).CancelledAt, "second CancelledAt")
				assertRecord(t, completed, findRecord(ctx, t, s, completed.ID))
				assertRecord(t, cancelled, findRecord(ctx, t, s, cancelled.ID))
				assertPendingRecord(t, findRecord(ctx, t, s, other.ID))

				n, err = s.CancelPending(ctx, "u-1", recoveryWednesday)
				require.NoError(t, err)
				assert.Zero(t, n)
			},
		},
		{
			name: "racing completions and cancellations: exactly one of 16 succeeds",
			assert: func(t *testing.T, ctx context.Context, s recovery.RecordStore, _ *clockwork.FakeClock) {
				r := recoveryRecord(1, "u-1", recoveryThursday0900)
				insertRecords(ctx, t, s, r)

				const each = 8
				at := recoveryThursday0900.Add(time.Minute)
				var (
					start     = make(chan struct{})
					wg        sync.WaitGroup
					successes atomic.Int32
					failures  atomic.Int32
				)
				for range each {
					wg.Go(func() {
						<-start
						ok, err := s.Complete(ctx, r.ID, at)
						if err != nil {
							failures.Add(1)
						}
						if ok {
							successes.Add(1)
						}
					})
					wg.Go(func() {
						<-start
						n, err := s.Cancel(ctx, r.ID, at)
						if err != nil {
							failures.Add(1)
						}
						successes.Add(int32(n)) //nolint:gosec // n is 0 or 1
					})
				}
				close(start)
				wg.Wait()

				assert.Zero(t, failures.Load(), "a refused completion or cancellation is not an error")
				assert.Equal(t, int32(1), successes.Load(), "successful completions and cancellations")
				got := findRecord(ctx, t, s, r.ID)
				assert.NotEqual(t, got.CompletedAt.IsZero(), got.CancelledAt.IsZero(),
					"exactly one of completed and cancelled is set")
			},
		},
	}

	runSuite(t, cases, newStore)
}
