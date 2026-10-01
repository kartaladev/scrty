package recovery_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/recovery"
)

// TestRecoverer_FinishCancelRace releases 8 finishes and 8 cancels of one
// held recovery at once, after its hold, over the real in-memory stores.
// Exactly one of the sixteen may take effect: a finish that returns a result,
// or a cancel, seen through the Cancelled notice only the effective cancel
// sends. Run it with -race -count=3.
func TestRecoverer_FinishCancelRace(t *testing.T) {
	t.Parallel()

	const racers = 8

	e := newCompleteEnv(t)
	r := e.recoverer(t, holdFor(72*time.Hour)...)

	h := heldRecovery(t.Context(), t, r, savedAndIssuedReq(e))
	cancelToken := e.cancelToken(t)
	e.clock.Advance(73 * time.Hour)

	var (
		start    = make(chan struct{})
		wg       sync.WaitGroup
		finished atomic.Int32
		refused  atomic.Int32
		others   atomic.Int32
	)

	for range racers {
		wg.Go(func() {
			<-start

			_, err := r.Finish(t.Context(), h.CompletionToken)

			switch {
			case err == nil:
				finished.Add(1)
			case assert.ErrorIs(t, err, recovery.ErrRefused):
				refused.Add(1)
			default:
				others.Add(1)
			}
		})
		wg.Go(func() {
			<-start

			r.Cancel(t.Context(), cancelToken)
		})
	}

	close(start)
	wg.Wait()

	cancelled := len(e.out.cancelledNotices())
	assert.Equal(t, 1, int(finished.Load())+cancelled, "exactly one finish or cancel takes effect")
	assert.Equal(t, int32(racers)-finished.Load(), refused.Load(), "every other finish is refused")
	assert.Zero(t, others.Load())

	_, completed, err := e.records.LatestCompletion(t.Context(), anaID)
	require.NoError(t, err)
	assert.Equal(t, finished.Load() == 1, completed, "the record is completed only when a finish won")
	assert.Len(t, e.out.recoveredNotices(), int(finished.Load()))

	if cancelled == 1 {
		assert.Equal(t, []recovery.AuthenticatorRef{refTOTP, refEmail}, e.held.snapshot(), "a cancel changes nothing")
	} else {
		assert.Empty(t, e.held.snapshot())
	}
}
