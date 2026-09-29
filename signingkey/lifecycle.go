package signingkey

import (
	"context"
	"time"
)

// Start launches the rotation, reload and housekeeping loops.
//
// It is idempotent: starting a manager whose loops are running launches nothing
// and returns nil, and so does starting a manager that has been stopped — a
// stopped manager stays stopped, so a late Start cannot resurrect background
// work the consumer has shut down.
//
// The loops end when ctx is cancelled or Stop is called. Whichever happens
// first, Stop is what waits for them; cancelling ctx alone ends the work but
// does not block until it has ended.
//
// Cancelling ctx is not terminal. Stop was never called, so the manager is not
// stopped, and a Start under a fresh context launches the loops again — which
// is the only way a consumer whose request-scoped context ended by mistake can
// get rotation back without constructing a new manager. Such a Start first
// waits for the cancelled run's loops to finish, an in-flight store write
// included, exactly as Stop does.
//
// Start returns before the loops have begun waiting on the clock: each calls
// the clock's After from its own goroutine. A caller driving a controlled clock
// (WithClock) waits for all three to be waiting before advancing it — with
// clockwork's fake, BlockUntilContext(ctx, 3) — or its advance may land before
// a loop starts counting and never fire that loop.
func (km *KeyManager) Start(ctx context.Context) error {
	km.lifecycle.Lock()
	defer km.lifecycle.Unlock()

	if km.stopped || km.runningLocked() {
		return nil
	}
	// A previous run whose context was cancelled is over, or is ending. Reaping
	// it leaves the WaitGroup at zero, so the loops launched below are the only
	// ones a later Stop waits for.
	km.reapLocked()

	loops := []struct {
		every time.Duration
		step  func(context.Context)
	}{
		{km.rotateEvery, km.rotateAll},
		{km.reloadEvery, km.reload},
		{km.housekeepEvery, km.housekeep},
	}

	loopCtx, cancel := context.WithCancel(ctx)
	km.cancel = cancel
	km.runDone = loopCtx.Done()

	km.wg.Add(len(loops))
	for _, loop := range loops {
		go km.loop(loopCtx, loop.every, loop.step)
	}

	return nil
}

// runningLocked reports whether the loops of the last run launched are still
// live, which is true until that run's context is cancelled. Callers hold
// km.lifecycle.
func (km *KeyManager) runningLocked() bool {
	if km.runDone == nil {
		return false
	}
	select {
	case <-km.runDone:
		return false
	default:
		return true
	}
}

// reapLocked ends the run last launched, if there is one, and returns only once
// its loops have ended. Callers hold km.lifecycle.
//
// Waiting under the lifecycle lock is safe, and is what makes concurrent Start
// and Stop race-free: no loop ever takes this lock, so none of them can be
// blocked on it while the wait is in progress.
func (km *KeyManager) reapLocked() {
	if km.cancel == nil {
		return
	}

	km.cancel()
	km.wg.Wait()
	km.cancel, km.runDone = nil, nil
}

// loop runs step one interval after the previous step finished, until the
// context ends. Waiting on the clock's After, rather than on a ticker, is what
// lets a controlled clock drive the loop, and is what makes the cadence
// fixed-delay: a slow run pushes the next one back rather than eating into its
// interval.
//
// It ends with return, never with break: a break inside the select would leave
// the select but not the for.
func (km *KeyManager) loop(ctx context.Context, every time.Duration, step func(context.Context)) {
	defer km.wg.Done()
	// Flushing here rather than in Stop accounts for the suppressed failures
	// on every shutdown path, including a caller who only cancels the context.
	// It runs before wg.Done, so a Stop that is waiting still returns after
	// the last record has been written.
	defer km.sampler.Flush()

	for {
		select {
		case <-ctx.Done():
			return
		case <-km.clock.After(every):
			step(ctx)
		}
	}
}

// Stop ends the background work and returns only once it has ended, an
// in-flight key generation and store write included — so no store write lands
// after Stop returns.
//
// It is idempotent, and returns at once for a manager that was never started. A
// stopped manager stays stopped: a later Start launches nothing.
func (km *KeyManager) Stop() error {
	km.lifecycle.Lock()
	defer km.lifecycle.Unlock()

	km.stopped = true
	km.reapLocked()

	return nil
}
