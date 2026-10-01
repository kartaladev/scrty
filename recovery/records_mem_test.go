package recovery_test

// The record-store cases are a contract suite rather than one table over one
// call: each case seeds the store its own way and exercises a different
// operation, so each carries its own run closure. recordStoreCases is kept
// apart from the memory store so the same cases can run against any
// RecordStore.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
)

var (
	// recordMonday1000 and the times after it are the fixed instants of the
	// record-store cases: 28 September 2026 is a Monday.
	recordMonday1000   = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	recordTuesday1100  = time.Date(2026, 9, 29, 11, 0, 0, 0, time.UTC)
	recordThursday0859 = time.Date(2026, 10, 1, 8, 59, 0, 0, time.UTC)
	recordThursday0900 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	recordWednesday    = time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
)

// recordStoreCase is one contract case, run against a fresh, empty store.
type recordStoreCase struct {
	name string
	run  func(t *testing.T, ctx context.Context, store recovery.RecordStore)
}

// newRecordID draws a fresh record identifier.
func newRecordID(t *testing.T) id.ID {
	t.Helper()

	rid, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	return rid
}

// pendingRecord returns a pending record of user, completable at notBefore.
func pendingRecord(t *testing.T, user identity.UserID, notBefore time.Time) recovery.Record {
	t.Helper()

	return recovery.Record{
		ID:        newRecordID(t),
		User:      user,
		StartedAt: notBefore.Add(-48 * time.Hour),
		NotBefore: notBefore,
		Proven:    []recovery.AuthenticatorRef{{Kind: "saved", ID: "code"}},
		Reported:  []recovery.AuthenticatorRef{{Kind: recovery.MFAKind, ID: "totp"}},
	}
}

// insertRecord inserts r and fails the case on error.
func insertRecord(ctx context.Context, t *testing.T, store recovery.RecordStore, r recovery.Record) {
	t.Helper()
	require.NoError(t, store.Insert(ctx, r))
}

// findRecord finds a record that must exist.
func findRecord(ctx context.Context, t *testing.T, store recovery.RecordStore, rid id.ID) *recovery.Record {
	t.Helper()

	got, err := store.Find(ctx, rid)
	require.NoError(t, err)
	require.NotNil(t, got)

	return got
}

// assertInstant compares instants, not representations, since a durable store
// may return another location.
func assertInstant(t *testing.T, want, got time.Time) {
	t.Helper()
	assert.Truef(t, want.Equal(got), "want %s, got %s", want, got)
}

// assertPending asserts the record is neither completed nor cancelled.
func assertPending(t *testing.T, r *recovery.Record) {
	t.Helper()
	assert.True(t, r.CompletedAt.IsZero(), "completed at %s", r.CompletedAt)
	assert.True(t, r.CancelledAt.IsZero(), "cancelled at %s", r.CancelledAt)
}

// recordStoreCases is the RecordStore contract.
func recordStoreCases() []recordStoreCase {
	return []recordStoreCase{
		{
			name: "an inserted record is found with every field",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				r := pendingRecord(t, "u-1", recordThursday0900)
				r.SavedSpent = true
				insertRecord(ctx, t, store, r)

				got := findRecord(ctx, t, store, r.ID)
				assert.Equal(t, r.ID, got.ID)
				assert.Equal(t, r.User, got.User)
				assertInstant(t, r.StartedAt, got.StartedAt)
				assertInstant(t, r.NotBefore, got.NotBefore)
				assertPending(t, got)
				assert.Equal(t, r.Proven, got.Proven)
				assert.Equal(t, r.Reported, got.Reported)
				assert.True(t, got.SavedSpent)
			},
		},
		{
			name: "finding an unknown record is ErrRecordNotFound",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				got, err := store.Find(ctx, newRecordID(t))
				require.ErrorIs(t, err, recovery.ErrRecordNotFound)
				assert.Nil(t, got)
			},
		},
		{
			name: "inserting an existing identifier is an error",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				r := pendingRecord(t, "u-1", recordThursday0900)
				insertRecord(ctx, t, store, r)

				again := pendingRecord(t, "u-2", recordThursday0900)
				again.ID = r.ID
				require.Error(t, store.Insert(ctx, again))
				assert.Equal(t, identity.UserID("u-1"), findRecord(ctx, t, store, r.ID).User)
			},
		},
		{
			name: "completing before the completable instant is refused and the record stays pending",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				r := pendingRecord(t, "u-1", recordThursday0900)
				insertRecord(ctx, t, store, r)

				ok, err := store.Complete(ctx, r.ID, recordThursday0859)
				require.NoError(t, err)
				assert.False(t, ok)
				assertPending(t, findRecord(ctx, t, store, r.ID))
			},
		},
		{
			name: "completing at exactly the completable instant succeeds",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				r := pendingRecord(t, "u-1", recordThursday0900)
				insertRecord(ctx, t, store, r)

				ok, err := store.Complete(ctx, r.ID, recordThursday0900)
				require.NoError(t, err)
				assert.True(t, ok)

				got := findRecord(ctx, t, store, r.ID)
				assertInstant(t, recordThursday0900, got.CompletedAt)
				assert.True(t, got.CancelledAt.IsZero())
			},
		},
		{
			name: "a completed record is not completed again",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				r := pendingRecord(t, "u-1", recordThursday0900)
				insertRecord(ctx, t, store, r)

				ok, err := store.Complete(ctx, r.ID, recordThursday0900)
				require.NoError(t, err)
				require.True(t, ok)

				ok, err = store.Complete(ctx, r.ID, recordThursday0900.Add(time.Hour))
				require.NoError(t, err)
				assert.False(t, ok)
				assertInstant(t, recordThursday0900, findRecord(ctx, t, store, r.ID).CompletedAt)
			},
		},
		{
			name: "cancel then complete: the completion is refused",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				r := pendingRecord(t, "u-1", recordThursday0900)
				insertRecord(ctx, t, store, r)

				n, err := store.Cancel(ctx, r.ID, recordThursday0859)
				require.NoError(t, err)
				assert.Equal(t, 1, n)

				ok, err := store.Complete(ctx, r.ID, recordThursday0900.Add(time.Hour))
				require.NoError(t, err)
				assert.False(t, ok)

				got := findRecord(ctx, t, store, r.ID)
				assert.True(t, got.CompletedAt.IsZero())
				assertInstant(t, recordThursday0859, got.CancelledAt)
			},
		},
		{
			name: "a cancelled record is not cancelled again",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				r := pendingRecord(t, "u-1", recordThursday0900)
				insertRecord(ctx, t, store, r)

				n, err := store.Cancel(ctx, r.ID, recordThursday0859)
				require.NoError(t, err)
				require.Equal(t, 1, n)

				n, err = store.Cancel(ctx, r.ID, recordThursday0900)
				require.NoError(t, err)
				assert.Zero(t, n)
				assertInstant(t, recordThursday0859, findRecord(ctx, t, store, r.ID).CancelledAt)
			},
		},
		{
			name: "a completed record is not cancelled",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				r := pendingRecord(t, "u-1", recordThursday0900)
				insertRecord(ctx, t, store, r)

				ok, err := store.Complete(ctx, r.ID, recordThursday0900)
				require.NoError(t, err)
				require.True(t, ok)

				n, err := store.Cancel(ctx, r.ID, recordThursday0900.Add(time.Minute))
				require.NoError(t, err)
				assert.Zero(t, n)
				assert.True(t, findRecord(ctx, t, store, r.ID).CancelledAt.IsZero())
			},
		},
		{
			name: "completing or cancelling an unknown record changes nothing and is not an error",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				ok, err := store.Complete(ctx, newRecordID(t), recordThursday0900)
				require.NoError(t, err)
				assert.False(t, ok)

				n, err := store.Cancel(ctx, newRecordID(t), recordThursday0900)
				require.NoError(t, err)
				assert.Zero(t, n)
			},
		},
		{
			name: "the latest completion is the latest among the user's records",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				monday := pendingRecord(t, "u-1", recordMonday1000)
				tuesday := pendingRecord(t, "u-1", recordTuesday1100)
				pending := pendingRecord(t, "u-1", recordThursday0900)
				other := pendingRecord(t, "u-2", recordWednesday)
				for _, r := range []recovery.Record{tuesday, monday, pending, other} {
					insertRecord(ctx, t, store, r)
				}

				for _, c := range []struct {
					rid id.ID
					at  time.Time
				}{{tuesday.ID, recordTuesday1100}, {monday.ID, recordMonday1000}, {other.ID, recordWednesday}} {
					ok, err := store.Complete(ctx, c.rid, c.at)
					require.NoError(t, err)
					require.True(t, ok)
				}

				at, ok, err := store.LatestCompletion(ctx, "u-1")
				require.NoError(t, err)
				require.True(t, ok)
				assertInstant(t, recordTuesday1100, at)
			},
		},
		{
			name: "a user with no completion reports none",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				insertRecord(ctx, t, store, pendingRecord(t, "u-1", recordThursday0900))

				cancelled := pendingRecord(t, "u-1", recordThursday0900)
				insertRecord(ctx, t, store, cancelled)
				_, err := store.Cancel(ctx, cancelled.ID, recordThursday0859)
				require.NoError(t, err)

				at, ok, err := store.LatestCompletion(ctx, "u-1")
				require.NoError(t, err)
				assert.False(t, ok)
				assert.True(t, at.IsZero())

				_, ok, err = store.LatestCompletion(ctx, "u-unknown")
				require.NoError(t, err)
				assert.False(t, ok)
			},
		},
		{
			name: "an inserted completed record is immediately the latest completion",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				r := pendingRecord(t, "u-1", recordTuesday1100)
				r.CompletedAt = recordTuesday1100
				insertRecord(ctx, t, store, r)

				at, ok, err := store.LatestCompletion(ctx, "u-1")
				require.NoError(t, err)
				require.True(t, ok)
				assertInstant(t, recordTuesday1100, at)
			},
		},
		{
			name: "CancelPending cancels only the user's pending records and counts them",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				first := pendingRecord(t, "u-1", recordThursday0900)
				second := pendingRecord(t, "u-1", recordThursday0900.Add(time.Hour))
				completed := pendingRecord(t, "u-1", recordMonday1000)
				completed.CompletedAt = recordMonday1000
				cancelled := pendingRecord(t, "u-1", recordThursday0900)
				cancelled.CancelledAt = recordMonday1000
				other := pendingRecord(t, "u-2", recordThursday0900)
				for _, r := range []recovery.Record{first, second, completed, cancelled, other} {
					insertRecord(ctx, t, store, r)
				}

				n, err := store.CancelPending(ctx, "u-1", recordWednesday)
				require.NoError(t, err)
				assert.Equal(t, 2, n)

				assertInstant(t, recordWednesday, findRecord(ctx, t, store, first.ID).CancelledAt)
				assertInstant(t, recordWednesday, findRecord(ctx, t, store, second.ID).CancelledAt)
				assert.True(t, findRecord(ctx, t, store, completed.ID).CancelledAt.IsZero())
				assertInstant(t, recordMonday1000, findRecord(ctx, t, store, cancelled.ID).CancelledAt)
				assertPending(t, findRecord(ctx, t, store, other.ID))

				n, err = store.CancelPending(ctx, "u-1", recordWednesday)
				require.NoError(t, err)
				assert.Zero(t, n)
			},
		},
		{
			name: "racing completions and cancellations: exactly one succeeds",
			run: func(t *testing.T, ctx context.Context, store recovery.RecordStore) {
				r := pendingRecord(t, "u-1", recordThursday0900)
				insertRecord(ctx, t, store, r)

				const each = 8
				var (
					start     = make(chan struct{})
					wg        sync.WaitGroup
					successes atomic.Int32
					failures  atomic.Int32
				)

				for range each {
					wg.Add(2)
					go func() {
						defer wg.Done()
						<-start
						ok, err := store.Complete(ctx, r.ID, recordThursday0900.Add(time.Minute))
						if err != nil {
							failures.Add(1)
						}
						if ok {
							successes.Add(1)
						}
					}()
					go func() {
						defer wg.Done()
						<-start
						n, err := store.Cancel(ctx, r.ID, recordThursday0900.Add(time.Minute))
						if err != nil {
							failures.Add(1)
						}
						successes.Add(int32(n)) //nolint:gosec // n is 0 or 1
					}()
				}

				close(start)
				wg.Wait()

				assert.Zero(t, failures.Load())
				assert.Equal(t, int32(1), successes.Load())

				got := findRecord(ctx, t, store, r.ID)
				assert.NotEqual(t, got.CompletedAt.IsZero(), got.CancelledAt.IsZero(), "exactly one of completed and cancelled is set")
			},
		},
	}
}

func TestMemoryRecordStore(t *testing.T) {
	t.Parallel()

	for _, tc := range recordStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.run(t, t.Context(), recovery.NewMemoryRecordStore())
		})
	}
}

func TestMemoryRecordStore_KeepsItsOwnCopies(t *testing.T) {
	t.Parallel()

	store := recovery.NewMemoryRecordStore()
	r := pendingRecord(t, "u-1", recordThursday0900)
	insertRecord(t.Context(), t, store, r)

	r.Proven[0].ID = "changed-after-insert"
	got := findRecord(t.Context(), t, store, r.ID)
	assert.Equal(t, "code", got.Proven[0].ID)

	got.Reported[0].ID = "changed-after-find"
	got.NotBefore = recordMonday1000
	again := findRecord(t.Context(), t, store, r.ID)
	assert.Equal(t, "totp", again.Reported[0].ID)
	assertInstant(t, recordThursday0900, again.NotBefore)
}

func TestMemoryRecordStore_RefusesARecordBothCompletedAndCancelled(t *testing.T) {
	t.Parallel()

	store := recovery.NewMemoryRecordStore()
	r := pendingRecord(t, "u-1", recordThursday0900)
	r.CompletedAt = recordThursday0900
	r.CancelledAt = recordThursday0900

	require.Error(t, store.Insert(t.Context(), r))

	got, err := store.Find(t.Context(), r.ID)
	require.ErrorIs(t, err, recovery.ErrRecordNotFound)
	assert.Nil(t, got)
}
