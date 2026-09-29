// The stop tests are not parallel: goleak counts goroutines process-wide.
package signingkey_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/signingkey"
)

// TestStopWaitsForAnInFlightStoreWrite holds a rotation inside the store write
// and then stops the manager. Stop has to block until that write has landed:
// returning earlier would let a write escape a manager the consumer has already
// shut down.
func TestStopWaitsForAnInFlightStoreWrite(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	var (
		writing      = make(chan struct{}) // closed once a rotation is inside the write
		release      = make(chan struct{}) // closed to let that write finish
		writes       atomic.Int32
		stopReturned atomic.Bool
		lateWrite    atomic.Bool
	)

	store := NewMockKeyStore(gomock.NewController(t))
	store.EXPECT().LoadAll(gomock.Any()).Return(nil, nil).AnyTimes()
	store.EXPECT().Store(gomock.Any(), gomock.Any()).DoAndReturn(
		func(context.Context, signingkey.Record) error {
			if stopReturned.Load() {
				lateWrite.Store(true)
			}
			// The first write is construction's, which must not block; the
			// second is the first rotation's, which is the one held.
			if writes.Add(1) == 2 {
				close(writing)
				<-release
			}
			return nil
		}).AnyTimes()

	clk := newClock()
	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, km.Start(t.Context()))

	awaitParked(t, clk, loopCount)
	clk.Advance(time.Hour)
	<-writing // a rotation is now inside the store write

	stopped := make(chan error, 1)
	go func() { stopped <- km.Stop() }()

	select {
	case err := <-stopped:
		t.Fatalf("Stop returned while a store write was in flight: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	require.NoError(t, <-stopped)
	stopReturned.Store(true)

	clk.Advance(24 * time.Hour) // every loop has ended, so nothing receives what fires
	assert.Never(t, lateWrite.Load, 100*time.Millisecond, 10*time.Millisecond,
		"no store write may land after Stop has returned")

	assert.GreaterOrEqual(t, writes.Load(), int32(2), "the held write did complete")
	require.NoError(t, km.Stop(), "stopping again is a no-op")
	goleak.VerifyNone(t, ignore)
}

// TestStopAfterSeveralLoopRuns pins that Stop returns only once the loops have
// ended, after they have each run several times.
//
// What a loop does last, as it ends, is account for the failures the sampler
// still holds back. The reloads here keep failing inside one sampling window,
// so there is always something to account for, and the record that does so is
// the loops' own proof of having ended. It is read at once, with no retry, the
// moment Stop returns: a Stop that returned before its loops had ended would
// find it not yet written. goleak then confirms that nothing else was left.
func TestStopAfterSeveralLoopRuns(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	const rounds = 3

	clk := newClock()
	recorder, logger := newLogRecorder()
	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(failingStore(t, &failureReport{}, opReload)),
		signingkey.WithClock(clk),
		signingkey.WithLogger(logger),
		signingkey.WithLogSampleWindow(24*time.Hour),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(30*time.Minute),
		signingkey.WithLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, km.Start(t.Context()))

	kid := currentKid(t, km, signingkey.EdDSA)
	for round := range rounds {
		advance(t, clk, time.Hour, loopCount) // returns with every loop parked
		next := currentKid(t, km, signingkey.EdDSA)
		require.NotEqual(t, kid, next, "round %d rotates", round)
		kid = next
	}
	require.Equal(t, 1, recorder.written(),
		"only the first reload failure is written; the later ones are held back")

	require.NoError(t, km.Stop())
	require.Equal(t, 2, recorder.written(),
		"when Stop returns, the loops have ended and accounted for what was held back")

	records := recorder.records(t)
	assert.Equal(t, opReload, records[1]["op"])
	assert.Equal(t, float64(rounds-1), records[1]["suppressed"])
	goleak.VerifyNone(t, ignore) // and nothing else was left running
}

// neverClock is a consumer Timed whose After returns a nil channel, which never
// delivers. It is a legal value of the type, so the manager has to survive it.
type neverClock struct{}

func (neverClock) Now() time.Time { return epoch }

func (neverClock) After(time.Duration) <-chan time.Time { return nil }

// TestStopReturnsOnANilAfterClock pins that a consumer clock whose After never
// fires leaves the loops idle, and that Stop still ends them promptly: the
// context, not the clock, is what a loop waits on to end.
func TestStopReturnsOnANilAfterClock(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	store := newCountingStore()
	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(neverClock{}),
		signingkey.WithAlgs(signingkey.EdDSA),
	)
	require.NoError(t, err)
	store.zero()

	require.NoError(t, km.Start(t.Context()))
	stopWithin(t, km, 2*time.Second, "a loop waiting on a nil channel must still see its context end")

	assert.Zero(t, store.stores(), "the clock never fired, so nothing rotated")
	assert.Zero(t, store.loads(), "and nothing reloaded")
	goleak.VerifyNone(t, ignore)
}

// stopWithin stops km and fails the test if that takes longer than bound. A
// Stop that cannot return is the failure being tested for, so it must show up
// as a failed assertion rather than as a hung package.
func stopWithin(t *testing.T, km *signingkey.KeyManager, bound time.Duration, why string) {
	t.Helper()

	stopped := make(chan error, 1)
	go func() { stopped <- km.Stop() }()

	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(bound):
		t.Fatalf("Stop did not return within %s: %s", bound, why)
	}
}
