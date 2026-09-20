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

	clock := newFakeClock(epoch)
	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clock),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, km.Start(t.Context()))

	clock.Advance(time.Hour)
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

	clock.Advance(24 * time.Hour) // every ticker is released, so nothing fires
	assert.Never(t, lateWrite.Load, 100*time.Millisecond, 10*time.Millisecond,
		"no store write may land after Stop has returned")

	assert.GreaterOrEqual(t, writes.Load(), int32(2), "the held write did complete")
	require.NoError(t, km.Stop(), "stopping again is a no-op")
	goleak.VerifyNone(t, ignore)
}

// TestStopAfterSeveralLoopRuns pins that Stop returns only once the loops have
// ended, after they have each run several times: every loop releases its ticker
// as it returns, so a live ticker is a loop that is still running.
func TestStopAfterSeveralLoopRuns(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	clock := newFakeClock(epoch)
	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
		signingkey.WithClock(clock),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(30*time.Minute),
		signingkey.WithLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, km.Start(t.Context()))

	kid := currentKid(t, km, signingkey.EdDSA)
	for range 3 {
		clock.Advance(time.Hour)
		kid = waitForRotation(t, km, signingkey.EdDSA, kid)
	}

	require.NoError(t, km.Stop())
	assert.Zero(t, clock.tickerCount(), "Stop returned after every loop had ended")
	goleak.VerifyNone(t, ignore)
}
