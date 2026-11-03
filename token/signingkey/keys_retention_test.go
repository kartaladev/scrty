// The retention tests are not parallel, for the reason the lifecycle tests are
// not: goleak counts goroutines process-wide.
package signingkey_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/token/signingkey"
)

// errStoreDelete is what a store double refuses a delete or a listing with. Its
// text must never reach a hook's error or a log record.
var errStoreDelete = errors.New("delete refused: row (alice@example.com)")

// retentionOptions is the configuration every retention test runs on, with a
// default lifetime. One second runs housekeeping and nothing else, since reload
// and rotation are far longer.
func retentionOptions(clk clock.Timed, store signingkey.KeyStore) []signingkey.Option {
	return []signingkey.Option{
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithKeyLifetime(24 * time.Hour),
		signingkey.WithHousekeepingInterval(time.Second),
		signingkey.WithReloadInterval(30 * time.Minute),
		signingkey.WithRotateInterval(6 * time.Hour),
	}
}

// record returns a real key created offset from the epoch.
func record(t *testing.T, offset time.Duration) signingkey.Record {
	t.Helper()

	return realRecordFor(t, signingkey.EdDSA, epoch.Add(offset))
}

// storedKids is what mem holds, by kid.
func storedKids(t *testing.T, mem signingkey.KeyStore) []string {
	t.Helper()

	recs, err := mem.LoadAll(t.Context())
	require.NoError(t, err)

	return recordKids(recs)
}

// retentionFixture is one case's manager over one in-memory store, and what its
// failures were reported to.
type retentionFixture struct {
	km    *signingkey.Keys
	clk   *steppedClock
	mem   *signingkey.MemoryKeyStore // the store itself, past any double
	seed  []signingkey.Record
	hooks *failureReport
	log   *logRecorder
}

// run advances the clock by d with the loops parked, and returns once they have
// parked again, so everything the advance started has finished.
func (f *retentionFixture) run(t *testing.T, d time.Duration) {
	t.Helper()

	advance(t, f.clk.FakeClock, d, loopCount)
}

// age moves the clock's reading on 50 hours without firing a loop, so a key the
// manager holds is well past retiring and the next run is the first to see it.
func (f *retentionFixture) age(t *testing.T) {
	t.Helper()

	f.clk.back.Store(-int64(50 * time.Hour))
}

// assertHousekeepFailure requires exactly one record of a housekeeping failure,
// carrying the fixed reason and the type of the store's error but not its text,
// and exactly one hook call with an error that still reaches the store's error.
func (f *retentionFixture) assertHousekeepFailure(t *testing.T) {
	t.Helper()

	hooked, _ := f.hooks.snapshot()
	require.Len(t, hooked, 1, "the error hook is told about the failure")
	require.ErrorIs(t, hooked[0], errStoreDelete)
	assert.NotContains(t, hooked[0].Error(), "alice@example.com")

	records := f.log.records(t)
	require.Len(t, records, 1, "and the logger is")
	assert.Equal(t, "housekeep", records[0]["op"])
	assert.Equal(t, "signing-key-store", records[0]["reason"])
	assert.Equal(t, "*errors.errorString", records[0]["error_type"])
	assert.NotContains(t, records[0], "error")
}

// doubleOverMemory is a generated store double that serves stores and loads from
// mem. Each case states what it expects of Delete, so any other call to it fails
// the test.
func doubleOverMemory(t *testing.T, mem *signingkey.MemoryKeyStore) *MockKeyStore {
	t.Helper()

	store := NewMockKeyStore(gomock.NewController(t))
	store.EXPECT().Store(gomock.Any(), gomock.Any()).DoAndReturn(mem.Store).AnyTimes()
	store.EXPECT().LoadAll(gomock.Any()).DoAndReturn(mem.LoadAll).AnyTimes()

	return store
}

// TestHousekeeping_Retention drives what housekeeping does to the key store. The
// seed is the stored keys. A row that needs a key held and then long retired steps
// the clock's reading on (retentionFixture.age), since a key already that old at
// construction is never held.
func TestHousekeeping_Retention(t *testing.T) {
	type testCase struct {
		name string
		// seed returns the stored keys.
		seed func(t *testing.T) []signingkey.Record
		// store wraps the in-memory store in a double; nil uses it as it is.
		store func(t *testing.T, mem *signingkey.MemoryKeyStore, seed []signingkey.Record) signingkey.KeyStore
		opts  []signingkey.Option
		// assert drives the loops and asserts on the result.
		assert func(t *testing.T, f *retentionFixture)
	}

	// seeded returns a seed of keys created at the offsets from the epoch.
	seeded := func(offsets ...time.Duration) func(t *testing.T) []signingkey.Record {
		return func(t *testing.T) []signingkey.Record {
			t.Helper()

			recs := make([]signingkey.Record, 0, len(offsets))
			for _, offset := range offsets {
				recs = append(recs, record(t, offset))
			}

			return recs
		}
	}
	// foreign returns a seed of ES256 keys, an algorithm no row's manager signs
	// with, created at the offsets from the epoch.
	foreign := func(offsets ...time.Duration) func(t *testing.T) []signingkey.Record {
		return func(t *testing.T) []signingkey.Record {
			t.Helper()

			recs := make([]signingkey.Record, 0, len(offsets))
			for _, offset := range offsets {
				recs = append(recs, realRecordFor(t, signingkey.ES256, epoch.Add(offset)))
			}

			return recs
		}
	}

	// retiring is a held key that f.age(t) takes well past retiring, beside the
	// current key that replaced it.
	retiring := seeded(-time.Hour, 0)

	cases := []testCase{
		{
			name: "Old key removed",
			seed: retiring,
			assert: func(t *testing.T, f *retentionFixture) {
				old, current := f.seed[0], f.seed[1]
				require.True(t, publishes(t, f.km, old.Kid), "the key is published to begin with")

				f.age(t)
				f.run(t, time.Second)

				assert.False(t, publishes(t, f.km, old.Kid), "the key is no longer published")
				assert.Equal(t, []string{current.Kid}, storedKids(t, f.mem), "and no longer in the key store")
				assert.Zero(t, f.hooks.hooks(), "and nothing failed")
			},
		},
		{
			name: "Consumer keeps retired keys",
			seed: retiring,
			opts: []signingkey.Option{signingkey.WithRetiredKeysKept()},
			assert: func(t *testing.T, f *retentionFixture) {
				old, current := f.seed[0], f.seed[1]
				require.True(t, publishes(t, f.km, old.Kid), "the key is published to begin with")

				f.age(t)
				f.run(t, time.Second)

				assert.False(t, publishes(t, f.km, old.Kid), "the key is no longer published")
				assert.Equal(t, []string{old.Kid, current.Kid}, storedKids(t, f.mem), "and is still in the key store")
			},
		},
		{
			name: "Failed delete retried",
			seed: retiring,
			store: func(t *testing.T, mem *signingkey.MemoryKeyStore, seed []signingkey.Record) signingkey.KeyStore {
				t.Helper()

				store := doubleOverMemory(t, mem)
				first := store.EXPECT().Delete(gomock.Any(), seed[0].Kid).Return(errStoreDelete)
				store.EXPECT().Delete(gomock.Any(), seed[0].Kid).DoAndReturn(mem.Delete).After(first.Call)

				return store
			},
			assert: func(t *testing.T, f *retentionFixture) {
				old, current := f.seed[0], f.seed[1]

				f.age(t)
				f.run(t, time.Second)

				f.assertHousekeepFailure(t)
				assert.Equal(t, old.Kid, f.log.records(t)[0]["kids"], "the record names the key, which is public")
				assert.False(t, publishes(t, f.km, old.Kid), "the key stays unpublished")
				assert.Equal(t, []string{old.Kid, current.Kid}, storedKids(t, f.mem), "and is still in the store")

				f.run(t, time.Second)

				assert.Equal(t, []string{current.Kid}, storedKids(t, f.mem), "the next run deletes it")
				assert.False(t, publishes(t, f.km, old.Kid))
				f.assertHousekeepFailure(t) // the retry succeeded, so nothing more was reported
			},
		},
		{
			name: "A delete that keeps failing does not republish the key at a reload",
			seed: retiring,
			store: func(t *testing.T, mem *signingkey.MemoryKeyStore, seed []signingkey.Record) signingkey.KeyStore {
				t.Helper()

				store := doubleOverMemory(t, mem)
				store.EXPECT().Delete(gomock.Any(), seed[0].Kid).Return(errStoreDelete).MinTimes(2)

				return store
			},
			assert: func(t *testing.T, f *retentionFixture) {
				old := f.seed[0]

				f.age(t)
				f.run(t, time.Second)
				f.run(t, 30*time.Minute) // a reload and a housekeeping run, in either order
				f.run(t, 30*time.Minute)

				assert.False(t, publishes(t, f.km, old.Kid), "a reload does not bring it back")
				assert.Contains(t, storedKids(t, f.mem), old.Kid)
			},
		},
		{
			name: "Store cannot list during housekeeping",
			seed: retiring,
			store: func(t *testing.T, mem *signingkey.MemoryKeyStore, seed []signingkey.Record) signingkey.KeyStore {
				t.Helper()

				store := NewMockKeyStore(gomock.NewController(t))
				store.EXPECT().Store(gomock.Any(), gomock.Any()).DoAndReturn(mem.Store).AnyTimes()
				construction := store.EXPECT().LoadAll(gomock.Any()).DoAndReturn(mem.LoadAll)
				refused := store.EXPECT().LoadAll(gomock.Any()).Return(nil, errStoreDelete).After(construction.Call)
				store.EXPECT().LoadAll(gomock.Any()).DoAndReturn(mem.LoadAll).AnyTimes().After(refused)
				store.EXPECT().Delete(gomock.Any(), seed[0].Kid).DoAndReturn(mem.Delete)

				return store
			},
			assert: func(t *testing.T, f *retentionFixture) {
				old, current := f.seed[0], f.seed[1]

				f.age(t)
				f.run(t, time.Second)

				f.assertHousekeepFailure(t)
				assert.False(t, publishes(t, f.km, old.Kid), "unpublishing does not depend on the store")
				assert.Contains(t, storedKids(t, f.mem), old.Kid, "and nothing is deleted")

				f.run(t, time.Second)

				assert.Equal(t, []string{current.Kid}, storedKids(t, f.mem), "the next run deletes it")
			},
		},
		{
			name: "A run with nothing to retire asks for no delete",
			seed: seeded(-time.Hour, 0),
			store: func(t *testing.T, mem *signingkey.MemoryKeyStore, _ []signingkey.Record) signingkey.KeyStore {
				t.Helper()

				return doubleOverMemory(t, mem) // expects no Delete, so a call fails the test
			},
			assert: func(t *testing.T, f *retentionFixture) {
				f.run(t, time.Second)

				assert.Len(t, storedKids(t, f.mem), 2)
				assert.Zero(t, f.hooks.hooks())
			},
		},
		{
			name: "Key past its lifetime at start is deleted",
			seed: seeded(-30*24*time.Hour, -29*24*time.Hour),
			assert: func(t *testing.T, f *retentionFixture) {
				old, current := f.seed[0], f.seed[1]
				require.False(t, publishes(t, f.km, old.Kid), "construction never held it")

				f.run(t, time.Second)

				assert.Equal(t, []string{current.Kid}, storedKids(t, f.mem))
			},
		},
		{
			name: "A key whose age is exactly the lifetime stays published",
			// The first key is the proof that the run happened, beside the key that
			// replaced it. The sweep at the epoch plus a second sees the third key
			// exactly 24 hours and a reload interval old, and the fourth replaced it
			// on time, so that is its retire time.
			seed: seeded(-80*time.Hour, -74*time.Hour, time.Second-24*time.Hour-30*time.Minute, time.Second-18*time.Hour-30*time.Minute, 0),
			assert: func(t *testing.T, f *retentionFixture) {
				stale, boundary := f.seed[0], f.seed[2]

				f.run(t, time.Second)

				require.NotContains(t, storedKids(t, f.mem), stale.Kid, "the run happened")
				assert.True(t, publishes(t, f.km, boundary.Kid), "it has not outlived the lifetime and the margin")

				f.run(t, time.Second)

				assert.False(t, publishes(t, f.km, boundary.Kid), "and a sweep later it has")
				assert.Contains(t, storedKids(t, f.mem), boundary.Kid, "and it waits out the grace")
			},
		},
		{
			name: "A key exactly one grace past its retire time stays stored",
			// As the row above, one default grace further on: the second key
			// retired exactly 24 hours before the sweep.
			seed: seeded(-50*time.Hour, time.Second-48*time.Hour-30*time.Minute, time.Second-42*time.Hour-30*time.Minute, 0),
			assert: func(t *testing.T, f *retentionFixture) {
				stale, boundary := f.seed[0], f.seed[1]

				f.run(t, time.Second)

				require.NotContains(t, storedKids(t, f.mem), stale.Kid, "the run happened")
				assert.Contains(t, storedKids(t, f.mem), boundary.Kid, "it has not passed the grace")

				f.run(t, time.Second)

				assert.NotContains(t, storedKids(t, f.mem), boundary.Kid, "and a sweep later it has")
			},
		},
		{
			name: "Retired key of an unconfigured algorithm",
			seed: foreign(-51*time.Hour, -50*time.Hour),
			opts: []signingkey.Option{signingkey.WithAlgs(signingkey.RS256)},
			assert: func(t *testing.T, f *retentionFixture) {
				older, newer := f.seed[0], f.seed[1]

				f.run(t, time.Second)

				assert.False(t, publishes(t, f.km, older.Kid), "neither is published")
				assert.False(t, publishes(t, f.km, newer.Kid))
				assert.NotContains(t, storedKids(t, f.mem), older.Kid, "the older is no longer stored")
				assert.Contains(t, storedKids(t, f.mem), newer.Kid, "the newer stays: another replica may sign with it")
				assert.Zero(t, f.hooks.hooks())
			},
		},
		{
			name: "A future-dated key of an unconfigured algorithm does not take the newest key's place",
			seed: foreign(-51*time.Hour, -50*time.Hour, 365*24*time.Hour),
			assert: func(t *testing.T, f *retentionFixture) {
				older, signing, ahead := f.seed[0], f.seed[1], f.seed[2]

				f.run(t, time.Second)

				assert.False(t, publishes(t, f.km, ahead.Kid), "the future-dated key is not published")
				assert.Contains(t, storedKids(t, f.mem), ahead.Kid, "and stays stored")
				assert.Contains(t, storedKids(t, f.mem), signing.Kid,
					"the key a replica would sign with is the newest not dated in the future")
				assert.NotContains(t, storedKids(t, f.mem), older.Kid)
			},
		},
		{
			name: "Current key kept",
			// The first key is the proof that housekeeping ran; the second is the
			// one the current key replaced.
			seed: seeded(-50*time.Hour, -49*time.Hour, -25*time.Hour),
			assert: func(t *testing.T, f *retentionFixture) {
				older, current := f.seed[0], f.seed[2]
				require.Equal(t, current.Kid, currentKid(t, f.km, signingkey.EdDSA))

				f.run(t, time.Second)

				assert.NotContains(t, storedKids(t, f.mem), older.Kid, "the older key went")
				assert.Contains(t, storedKids(t, f.mem), current.Kid, "and the current key is still in the key store")
				assert.True(t, publishes(t, f.km, current.Kid), "it is still published")
				assert.Equal(t, current.Kid, currentKid(t, f.km, signingkey.EdDSA), "and still signs")
			},
		},
		{
			name: "A current key a newer stored key has yet to displace is kept until it has",
			seed: seeded(-50 * time.Hour),
			assert: func(t *testing.T, f *retentionFixture) {
				current := f.seed[0]
				newer := record(t, -49*time.Hour) // another replica's rotation, not yet reloaded here
				require.NoError(t, f.mem.Store(t.Context(), newer))

				f.run(t, time.Second)

				assert.Equal(t, []string{current.Kid, newer.Kid}, storedKids(t, f.mem),
					"this replica still signs with it")
				assert.Equal(t, current.Kid, currentKid(t, f.km, signingkey.EdDSA))

				f.run(t, 30*time.Minute) // the reload that makes the newer key current
				f.run(t, time.Second)

				assert.Equal(t, newer.Kid, currentKid(t, f.km, signingkey.EdDSA))
				assert.Equal(t, []string{newer.Kid}, storedKids(t, f.mem), "and the next run deletes it")
			},
		},
		{
			name: "Newest stored key not yet loaded",
			seed: seeded(-60 * time.Hour),
			assert: func(t *testing.T, f *retentionFixture) {
				current := f.seed[0]
				// The key that signs on the replica that wrote it, whose rotation
				// has not run since. Nothing newer has displaced it there.
				newest := record(t, -55*time.Hour)
				require.NoError(t, f.mem.Store(t.Context(), newest))

				f.run(t, time.Second)

				assert.Equal(t, []string{current.Kid, newest.Kid}, storedKids(t, f.mem), "neither key is deleted")
				assert.Equal(t, current.Kid, currentKid(t, f.km, signingkey.EdDSA))
			},
		},
		{
			name: "A held key the listing has not caught up with does not displace the newest listed key",
			seed: seeded(-50*time.Hour, -49*time.Hour),
			store: func(t *testing.T, mem *signingkey.MemoryKeyStore, seed []signingkey.Record) signingkey.KeyStore {
				t.Helper()

				// The run's listing was read before rotation stored the key this
				// replica holds, so the older key is the newest the listing shows.
				// Delete has no expectation: a call to it fails the test.
				store := NewMockKeyStore(gomock.NewController(t))
				construction := store.EXPECT().LoadAll(gomock.Any()).DoAndReturn(mem.LoadAll)
				store.EXPECT().LoadAll(gomock.Any()).Return(seed[:1], nil).AnyTimes().After(construction.Call)

				return store
			},
			assert: func(t *testing.T, f *retentionFixture) {
				held := f.seed[1]
				require.Equal(t, held.Kid, currentKid(t, f.km, signingkey.EdDSA))

				f.run(t, time.Second)

				assert.Equal(t, []string{f.seed[0].Kid, held.Kid}, storedKids(t, f.mem), "the listing's newest stays, so nothing is deleted")
			},
		},
		{
			name: "A held key the store no longer lists does not displace the newest stored key",
			// Construction holds the newer key. The older is far enough past its
			// retire time to go, were it not the newest the store shows once the
			// newer is removed. The hourly interval lets two reloads pass first, so the
			// manager has reloaded the store without the removed key before the run.
			seed: seeded(-80*time.Hour, -49*time.Hour),
			opts: []signingkey.Option{signingkey.WithHousekeepingInterval(time.Hour)},
			assert: func(t *testing.T, f *retentionFixture) {
				held, stored := f.seed[1], f.seed[0]
				require.Equal(t, held.Kid, currentKid(t, f.km, signingkey.EdDSA))
				// A backup restore, or a manual removal, took the held key away.
				require.NoError(t, f.mem.Delete(t.Context(), held.Kid))

				f.run(t, 30*time.Minute)
				f.run(t, 30*time.Minute)

				assert.Equal(t, []string{stored.Kid}, storedKids(t, f.mem), "the newest stored key is not deleted")
			},
		},
		{
			name: "Key removed from the store since the last reload",
			// As the row above, with no reload between the removal and the run, so the
			// run lists a store the manager's last reload has not seen.
			seed: seeded(-80*time.Hour, -49*time.Hour),
			assert: func(t *testing.T, f *retentionFixture) {
				held, stored := f.seed[1], f.seed[0]
				require.Equal(t, held.Kid, currentKid(t, f.km, signingkey.EdDSA))
				require.NoError(t, f.mem.Delete(t.Context(), held.Kid))

				f.run(t, time.Second)

				assert.Equal(t, []string{stored.Kid}, storedKids(t, f.mem), "the newest stored key is not deleted")
			},
		},
		{
			name: "A reload leaves a retired key the store still lists to housekeeping",
			// The first key is exactly at its retire time, so construction holds it,
			// and it has passed that by the reload.
			seed: seeded(-24*time.Hour-30*time.Minute, -23*time.Hour-30*time.Minute),
			opts: []signingkey.Option{signingkey.WithHousekeepingInterval(12 * time.Hour)},
			assert: func(t *testing.T, f *retentionFixture) {
				old := f.seed[0]
				proof := record(t, 0) // published by the reload, which is how the row knows it ran
				require.NoError(t, f.mem.Store(t.Context(), proof))

				f.run(t, 30*time.Minute)

				require.True(t, publishes(t, f.km, proof.Kid), "the reload ran")
				assert.True(t, publishes(t, f.km, old.Kid), "and did not drop a key the store still lists")

				f.run(t, 12*time.Hour)

				assert.False(t, publishes(t, f.km, old.Kid), "housekeeping does")
			},
		},
		{
			name: "Held key within its retire time is kept when the store does not list it",
			seed: seeded(-time.Hour, 0),
			assert: func(t *testing.T, f *retentionFixture) {
				held, current := f.seed[0], f.seed[1]
				proof := realRecordFor(t, signingkey.ES256, epoch) // published by the reload, which is how the row knows it ran
				require.NoError(t, f.mem.Delete(t.Context(), held.Kid, current.Kid))
				require.NoError(t, f.mem.Store(t.Context(), proof))

				f.run(t, 30*time.Minute)

				require.True(t, publishes(t, f.km, proof.Kid), "the reload ran")
				assert.True(t, publishes(t, f.km, held.Kid), "the replica still publishes the key")
				assert.True(t, publishes(t, f.km, current.Kid))
				assert.Equal(t, current.Kid, currentKid(t, f.km, signingkey.EdDSA), "and a current key stays current")
			},
		},
		{
			name: "Far-future key removed",
			// The first key is the proof that housekeeping ran, and the last is
			// dated two days ahead.
			seed: seeded(-50*time.Hour, -49*time.Hour, 48*time.Hour),
			assert: func(t *testing.T, f *retentionFixture) {
				old, current, ahead := f.seed[0], f.seed[1], f.seed[2]

				f.run(t, time.Second)

				assert.False(t, publishes(t, f.km, ahead.Kid), "the key is no longer published")
				assert.Equal(t, []string{current.Kid, ahead.Kid}, storedKids(t, f.mem),
					"and is still in the key store, while the old key went")
				assert.NotContains(t, storedKids(t, f.mem), old.Kid)
			},
		},
		{
			name: "A held key that a clock stepping back dates far ahead is unpublished, never deleted",
			seed: retiring,
			assert: func(t *testing.T, f *retentionFixture) {
				ahead, current := f.seed[0], f.seed[1]
				require.True(t, publishes(t, f.km, ahead.Kid), "the key is published to begin with")

				f.clk.back.Store(int64(72 * time.Hour)) // the key is now dated nearly three days ahead
				f.run(t, time.Second)

				assert.False(t, publishes(t, f.km, ahead.Kid), "the key is no longer published")
				assert.Equal(t, []string{ahead.Kid, current.Kid}, storedKids(t, f.mem), "and is still stored")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &retentionFixture{
				clk:   &steppedClock{FakeClock: newClock()},
				mem:   signingkey.NewMemoryKeyStore(),
				seed:  tc.seed(t),
				hooks: &failureReport{},
			}
			for _, rec := range f.seed {
				require.NoError(t, f.mem.Store(t.Context(), rec))
			}
			var store signingkey.KeyStore = f.mem
			if tc.store != nil {
				store = tc.store(t, f.mem, f.seed)
			}

			recorder, logger := newLogRecorder()
			f.log = recorder

			var km *signingkey.Keys
			opts := append(retentionOptions(f.clk, store),
				signingkey.WithLogger(logger),
				signingkey.WithErrorHook(func(err error) {
					// The hook is promised it can read the manager, which a lock
					// held across the failure would deadlock.
					_, _ = km.VerificationKeys(t.Context())
					f.hooks.hook(err)
				}),
			)
			km, err := signingkey.New(t.Context(), append(opts, tc.opts...)...)
			require.NoError(t, err)
			f.km = km
			shutdownAndVerify(t, km)
			require.NoError(t, km.Start(t.Context()))

			tc.assert(t, f)
		})
	}
}

// TestHousekeeping_FailedDeleteSurvivesARestart pins that a key whose delete
// failed is deleted by the next process too. The first process holds the key and
//
//	ages it, as the clock moves on. Construction never holds a key that old, so a
//
// retry that remembered it only in memory would forget it for good.
// Standalone: it runs two managers, one after the other, over one store.
func TestHousekeeping_FailedDeleteSurvivesARestart(t *testing.T) {
	clk := &steppedClock{FakeClock: newClock()}
	mem := signingkey.NewMemoryKeyStore()
	old, current := record(t, -23*time.Hour), record(t, -22*time.Hour)
	require.NoError(t, mem.Store(t.Context(), old))
	require.NoError(t, mem.Store(t.Context(), current))

	failing := doubleOverMemory(t, mem)
	failing.EXPECT().Delete(gomock.Any(), old.Kid).Return(errStoreDelete).AnyTimes()

	recorder, logger := newLogRecorder()
	first, err := signingkey.New(t.Context(), append(retentionOptions(clk, failing), signingkey.WithLogger(logger))...)
	require.NoError(t, err)
	require.True(t, publishes(t, first, old.Kid), "the first process holds the key")
	require.NoError(t, first.Start(t.Context()))
	clk.back.Store(-int64(50 * time.Hour)) // the key is now well past retiring
	advance(t, clk.FakeClock, time.Second, loopCount)
	shutdownWithin(t, first, parkTimeout, "the first process ends")
	require.NotZero(t, recorder.written(), "its delete failed")
	require.Contains(t, storedKids(t, mem), old.Kid)

	// A clock of its own, reading the same time: the first process's loops left
	// their waits pending on the old one, which would count as this one's loops.
	restarted := clockwork.NewFakeClockAt(clk.Now())
	second, err := signingkey.New(t.Context(), retentionOptions(restarted, mem)...)
	require.NoError(t, err)
	shutdownAndVerify(t, second)
	require.False(t, publishes(t, second, old.Kid), "the next process does not publish it")
	require.NoError(t, second.Start(t.Context()))
	advance(t, restarted, time.Second, loopCount)

	assert.Equal(t, []string{current.Kid}, storedKids(t, mem), "and its first run deletes it")
}

// TestHousekeeping_LeavesSigningAvailableDuringASlowDelete pins that the keyring
// lock is not held across the store: signing and verification must not queue
// behind a delete on a slow network.
// Standalone: it holds a housekeeping run inside a blocking store delete.
func TestHousekeeping_LeavesSigningAvailableDuringASlowDelete(t *testing.T) {
	clk := newClock()
	mem := signingkey.NewMemoryKeyStore()
	old, current := record(t, -50*time.Hour), record(t, -49*time.Hour)
	require.NoError(t, mem.Store(t.Context(), old))
	require.NoError(t, mem.Store(t.Context(), current))

	deleting, release := make(chan struct{}), make(chan struct{})
	store := doubleOverMemory(t, mem)
	store.EXPECT().Delete(gomock.Any(), old.Kid).DoAndReturn(func(ctx context.Context, kids ...string) error {
		close(deleting)
		<-release // ignores ctx on purpose: released below, or by the cleanup
		return mem.Delete(ctx, kids...)
	})

	km, err := signingkey.New(t.Context(), retentionOptions(clk, store)...)
	require.NoError(t, err)
	shutdownAndVerify(t, km)
	var released sync.Once
	releaseOnce := func() { released.Do(func() { close(release) }) }
	t.Cleanup(releaseOnce)
	require.NoError(t, km.Start(t.Context()))

	awaitParked(t, clk, loopCount)
	clk.Advance(time.Second)
	select {
	case <-deleting:
	case <-time.After(parkTimeout):
		t.Fatal("housekeeping never reached the store's delete")
	}

	served := make(chan string, 1)
	go func() {
		kid, _, _ := km.Signer(t.Context(), signingkey.EdDSA)
		_, _ = km.VerificationKeys(t.Context())
		served <- kid
	}()
	select {
	case kid := <-served:
		assert.Equal(t, current.Kid, kid)
	case <-time.After(parkTimeout):
		t.Fatal("signing queued behind the store's delete: the keyring lock was held across it")
	}

	releaseOnce()
	awaitParked(t, clk, loopCount)
}

// rendezvousStore holds every Delete until need have arrived, so that with a need
// of two, two replicas are certain to have both listed the key and both asked for
// it to go. The wait is bounded so a replica that never arrives fails the test's
// assertion rather than hanging it.
type rendezvousStore struct {
	*signingkey.MemoryKeyStore

	need     int
	mu       sync.Mutex
	arrivals int
	met      chan struct{}
}

func (s *rendezvousStore) Delete(ctx context.Context, kids ...string) error {
	s.mu.Lock()
	s.arrivals++
	if s.arrivals == s.need {
		close(s.met)
	}
	s.mu.Unlock()

	select {
	case <-s.met:
	case <-time.After(parkTimeout):
	}

	return s.MemoryKeyStore.Delete(ctx, kids...)
}

func (s *rendezvousStore) deletes() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.arrivals
}

// TestHousekeeping_Replicas runs two managers over one store and one clock. Each
// row seeds an old key, the key that replaced it on time, and the current key.
func TestHousekeeping_Replicas(t *testing.T) {
	type testCase struct {
		name string
		// offsets are the three keys' creation times from the epoch.
		offsets [3]time.Duration
		// deleters is how many replicas are expected to ask for the delete.
		deleters int
		// both and second are options over retentionOptions: both replicas', and
		// the second replica's alone.
		both, second []signingkey.Option
		assert       func(t *testing.T, f *replicaFixture)
	}

	cases := []testCase{
		{
			name:     "Replicas delete the same retired key",
			offsets:  [3]time.Duration{-50 * time.Hour, -44 * time.Hour, 0},
			deleters: 2,
			assert: func(t *testing.T, f *replicaFixture) {
				advance(t, f.clk, time.Second, 2*loopCount)

				assert.Zero(t, f.hooks.hooks(), "no failure reaches a hook")
				assert.Zero(t, f.log.written(), "or a logger")
				assert.Equal(t, 2, f.store.deletes(), "both replicas asked for the same delete")
				assert.NotContains(t, storedKids(t, f.store), f.old.Kid, "and the key is gone")
				assert.Contains(t, storedKids(t, f.store), f.current.Kid)
			},
		},
		{
			name: "Deleted key not republished on reload",
			// One lifetime old and replaced on time, so both replicas hold it when
			// they are built, and it has retired an hour later. A grace of
			// zero lets the first replica delete it then, and the second replica's
			// housekeeping is a day away, so only its reload can stop it publishing
			// that key.
			offsets:  [3]time.Duration{-24 * time.Hour, -18 * time.Hour, 0},
			deleters: 1,
			both:     []signingkey.Option{signingkey.WithRetiredKeyGrace(0)},
			second:   []signingkey.Option{signingkey.WithHousekeepingInterval(24 * time.Hour)},
			assert: func(t *testing.T, f *replicaFixture) {
				require.True(t, publishes(t, f.other, f.old.Kid), "the second replica holds the key to begin with")

				advance(t, f.clk, time.Hour, 2*loopCount)
				require.NotContains(t, storedKids(t, f.store), f.old.Kid, "the first replica deleted the key")

				advance(t, f.clk, 30*time.Minute, 2*loopCount) // a reload, after the delete

				assert.False(t, publishes(t, f.other, f.old.Kid), "the reloading replica does not publish it")
				assert.True(t, publishes(t, f.other, f.current.Kid), "and goes on publishing the key that signs")
				assert.Equal(t, f.current.Kid, currentKid(t, f.other, signingkey.EdDSA))
				assert.Zero(t, f.hooks.hooks())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &replicaFixture{
				clk: clockwork.NewFakeClockAt(epoch),
				store: &rendezvousStore{
					MemoryKeyStore: signingkey.NewMemoryKeyStore(),
					need:           tc.deleters,
					met:            make(chan struct{}),
				},
				old:     record(t, tc.offsets[0]),
				current: record(t, tc.offsets[2]),
				hooks:   &failureReport{},
			}
			require.NoError(t, f.store.Store(t.Context(), f.old))
			require.NoError(t, f.store.Store(t.Context(), record(t, tc.offsets[1])))
			require.NoError(t, f.store.Store(t.Context(), f.current))

			recorder, logger := newLogRecorder()
			f.log = recorder
			reporting := []signingkey.Option{signingkey.WithLogger(logger), signingkey.WithErrorHook(f.hooks.hook)}

			common := append(append(retentionOptions(f.clk, f.store), reporting...), tc.both...)
			first, err := signingkey.New(t.Context(), common...)
			require.NoError(t, err)
			second, err := signingkey.New(t.Context(), append(slices.Clone(common), tc.second...)...)
			require.NoError(t, err)
			f.other = second

			ignore := goleak.IgnoreCurrent()
			t.Cleanup(func() {
				shutdownWithin(t, first, parkTimeout, "the first replica's work should end once shut down")
				shutdownWithin(t, second, parkTimeout, "the second replica's work should end once shut down")
				goleak.VerifyNone(t, ignore)
			})
			require.NoError(t, first.Start(t.Context()))
			require.NoError(t, second.Start(t.Context()))

			tc.assert(t, f)
		})
	}
}

// replicaFixture is two managers sharing one store, of which other is the second.
type replicaFixture struct {
	clk          *clockwork.FakeClock
	store        *rendezvousStore
	other        *signingkey.Keys
	old, current signingkey.Record
	hooks        *failureReport
	log          *logRecorder
}
