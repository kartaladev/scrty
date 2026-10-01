package recovery_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
)

// TestRecoverer_RacingRecoveries releases 16 recoveries of ana at once, all
// presenting the same saved and issued codes, over the real in-memory stores.
// Exactly one may succeed. Run it with -race -count=3.
func TestRecoverer_RacingRecoveries(t *testing.T) {
	t.Parallel()

	const racers = 16

	e := newRecoverEnv(t)
	e.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(anaDetails(), nil).AnyTimes()
	e.kind.EXPECT().Held(gomock.Any(), anaID).Return([]recovery.AuthenticatorRef{refTOTP}, nil).AnyTimes()

	// A limit no racer reaches, so losing is decided by the spends alone.
	limiter, err := ratelimit.NewMemoryLimiter(1000, time.Hour)
	require.NoError(t, err)

	r, err := recovery.NewRecoverer(e.deps(), e.opts(recovery.WithUserLimiter(limiter))...)
	require.NoError(t, err)

	req := recovery.Request{Username: anaUsername, Saved: e.saved[0], Issued: e.issued}

	var (
		start     = make(chan struct{})
		wg        sync.WaitGroup
		successes atomic.Int32
		refusals  atomic.Int32
		others    atomic.Int32
	)

	for range racers {
		wg.Go(func() {
			<-start

			_, err := recoverOnce(t.Context(), r, req)

			switch {
			case err == nil:
				successes.Add(1)
			case assert.ErrorIs(t, err, recovery.ErrRefused):
				refusals.Add(1)
			default:
				others.Add(1)
			}
		})
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), successes.Load(), "exactly one recovery succeeds")
	assert.Equal(t, int32(racers-1), refusals.Load(), "every other recovery is refused")
	assert.Zero(t, others.Load())
	assert.False(t, e.savedUsable(t.Context(), t, e.saved[0]))
	assert.False(t, e.issuedUsable(t.Context(), t, r, anaID, e.issued))
}
