// The shutdown tests are not parallel: goleak counts goroutines process-wide.
package signingkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/token/signingkey"
)

// storeCall is one store call a background loop makes, and what it takes to reach
// it: the keys and options that make only that loop's call the one in question, and
// how far the clock moves to start it.
type storeCall struct {
	op    string // the operation a failure of it is recorded under
	seed  []time.Duration
	opts  []signingkey.Option
	every time.Duration
	// expect has store answer the call with answer, and serve the rest from mem.
	expect func(store *MockKeyStore, mem *signingkey.MemoryKeyStore, seed []signingkey.Record, answer func(context.Context) error)
}

// storeCallFixture is one case's started manager, and what its failures were
// reported to. entered is closed once the store call has begun.
type storeCallFixture struct {
	km      *signingkey.Keys
	clk     *clockwork.FakeClock
	call    storeCall
	entered chan struct{}
	hooks   *failureReport
	log     *logRecorder
}

// errorRecords is every ERROR record written so far.
func (f *storeCallFixture) errorRecords(t *testing.T) []map[string]any {
	t.Helper()

	var errored []map[string]any
	for _, rec := range f.log.records(t) {
		if rec["level"] == "ERROR" {
			errored = append(errored, rec)
		}
	}
	return errored
}

// TestShutdown_StoreCallIsNotReported drives one store call of each loop two ways:
// ended by Shutdown, when the store's context error is not a failure, and failing
// with that same error while the work is live, when it is one. The manager can only
// tell them apart by its own context.
func TestShutdown_StoreCallIsNotReported(t *testing.T) {
	rotation := storeCall{
		op:    "rotate",
		seed:  []time.Duration{0},
		every: 6 * time.Hour,
		expect: func(store *MockKeyStore, mem *signingkey.MemoryKeyStore, _ []signingkey.Record, answer func(context.Context) error) {
			store.EXPECT().LoadAll(gomock.Any()).DoAndReturn(mem.LoadAll).AnyTimes()
			store.EXPECT().Store(gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, _ signingkey.Record) error { return answer(ctx) })
		},
	}
	reload := storeCall{
		op:   "reload",
		seed: []time.Duration{0},
		// Housekeeping stays parked, so the one load after construction is the reload's.
		opts:  []signingkey.Option{signingkey.WithHousekeepingInterval(12 * time.Hour)},
		every: 30 * time.Minute,
		expect: func(store *MockKeyStore, mem *signingkey.MemoryKeyStore, _ []signingkey.Record, answer func(context.Context) error) {
			construction := store.EXPECT().LoadAll(gomock.Any()).DoAndReturn(mem.LoadAll)
			store.EXPECT().LoadAll(gomock.Any()).DoAndReturn(
				func(ctx context.Context) ([]signingkey.Record, error) { return nil, answer(ctx) }).
				After(construction.Call)
		},
	}
	housekeeping := storeCall{
		op:    "housekeep",
		seed:  []time.Duration{-50 * time.Hour, -49 * time.Hour},
		every: time.Second,
		expect: func(store *MockKeyStore, mem *signingkey.MemoryKeyStore, seed []signingkey.Record, answer func(context.Context) error) {
			store.EXPECT().LoadAll(gomock.Any()).DoAndReturn(mem.LoadAll).AnyTimes()
			store.EXPECT().Delete(gomock.Any(), seed[0].Kid).DoAndReturn(
				func(ctx context.Context, _ ...string) error { return answer(ctx) })
		},
	}

	// housekeepingListing reaches the listing that opens a delete run, which has no
	// delete to make once it fails.
	housekeepingListing := storeCall{
		op:    "housekeep",
		seed:  []time.Duration{-50 * time.Hour, -49 * time.Hour},
		every: time.Second,
		expect: func(store *MockKeyStore, mem *signingkey.MemoryKeyStore, _ []signingkey.Record, answer func(context.Context) error) {
			construction := store.EXPECT().LoadAll(gomock.Any()).DoAndReturn(mem.LoadAll)
			store.EXPECT().LoadAll(gomock.Any()).DoAndReturn(
				func(ctx context.Context) ([]signingkey.Record, error) { return nil, answer(ctx) }).
				After(construction.Call)
		},
	}

	// untilEnded is a store whose call lasts until its context ends.
	untilEnded := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	// canceledAtOnce is a store whose own client was cancelled, on a live context.
	canceledAtOnce := func(context.Context) error { return context.Canceled }

	notReported := func(t *testing.T, f *storeCallFixture) {
		t.Helper()

		awaitParked(t, f.clk, loopCount)
		f.clk.Advance(f.call.every)
		select {
		case <-f.entered:
		case <-time.After(parkTimeout):
			t.Fatalf("the %s run never reached the store", f.call.op)
		}

		shutdownWithin(t, f.km, parkTimeout, "the store call ends with its context")

		// Shutdown has returned, so the loops have ended and this is everything.
		hooked, _ := f.hooks.snapshot()
		assert.Empty(t, hooked, "the error hook hears nothing of it")
		assert.Empty(t, f.errorRecords(t), "and nor does the logger")
	}
	reported := func(t *testing.T, f *storeCallFixture) {
		t.Helper()

		awaitParked(t, f.clk, loopCount)
		f.clk.Advance(f.call.every)
		awaitParked(t, f.clk, loopCount)

		hooked, _ := f.hooks.snapshot()
		require.Len(t, hooked, 1, "the error hook hears of it")
		require.ErrorIs(t, hooked[0], context.Canceled)

		records := f.errorRecords(t)
		require.Len(t, records, 1, "and so does the logger")
		assert.Equal(t, f.call.op, records[0]["op"])
		assert.Equal(t, "signing-key-store", records[0]["reason"])
	}

	type testCase struct {
		name   string
		call   storeCall
		answer func(context.Context) error
		assert func(t *testing.T, f *storeCallFixture)
	}

	cases := []testCase{
		{name: "Shutdown during a store call, rotation", call: rotation, answer: untilEnded, assert: notReported},
		{name: "Shutdown during a store call, reload", call: reload, answer: untilEnded, assert: notReported},
		{name: "Shutdown during a store call, housekeeping", call: housekeeping, answer: untilEnded, assert: notReported},
		{name: "Shutdown during a store call, housekeeping's listing", call: housekeepingListing, answer: untilEnded, assert: notReported},
		{name: "Store failure before shutdown, rotation", call: rotation, answer: canceledAtOnce, assert: reported},
		{name: "Store failure before shutdown, reload", call: reload, answer: canceledAtOnce, assert: reported},
		{name: "Store failure before shutdown, housekeeping", call: housekeeping, answer: canceledAtOnce, assert: reported},
		{name: "Store failure before shutdown, housekeeping's listing", call: housekeepingListing, answer: canceledAtOnce, assert: reported},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mem := signingkey.NewMemoryKeyStore()
			seed := make([]signingkey.Record, 0, len(tc.call.seed))
			for _, offset := range tc.call.seed {
				rec := record(t, offset)
				require.NoError(t, mem.Store(t.Context(), rec))
				seed = append(seed, rec)
			}

			entered := make(chan struct{})
			store := NewMockKeyStore(gomock.NewController(t))
			tc.call.expect(store, mem, seed, func(ctx context.Context) error {
				close(entered)
				return tc.answer(ctx)
			})

			clk := newClock()
			recorder, logger := newLogRecorder()
			hooks := &failureReport{}
			opts := append(retentionOptions(clk, store),
				signingkey.WithLogger(logger),
				signingkey.WithErrorHook(hooks.hook),
			)
			km, err := signingkey.New(t.Context(), append(opts, tc.call.opts...)...)
			require.NoError(t, err)
			shutdownAndVerify(t, km)
			require.NoError(t, km.Start(t.Context()))

			tc.assert(t, &storeCallFixture{
				km: km, clk: clk, call: tc.call, entered: entered, hooks: hooks, log: recorder,
			})
		})
	}
}
