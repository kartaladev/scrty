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

	// The tickers are taken here rather than inside each goroutine, so that
	// once Start returns, every loop's cadence is already registered with the
	// clock. A test that advances a fake clock straight after Start therefore
	// cannot race ahead of the loop that has not asked for its ticker yet.
	//
	// They are also taken before the WaitGroup counts them and before any
	// goroutine is launched. TickerClock is an advertised override point, so a
	// consumer clock that panics partway through is reachable; counting three
	// loops first would leave the counter above the number running, and every
	// later Stop would wait for a goroutine that was never launched — forever,
	// holding the lock Start and Stop both need. Unwinding here instead leaves
	// the manager as it was: no ticker held, and no run to wait for.
	tickers := make([]Ticker, 0, len(loops))
	launched := false
	defer func() {
		if launched {
			return
		}
		cancel()
		for _, ticker := range tickers {
			ticker.Stop()
		}
	}()

	for _, loop := range loops {
		tickers = append(tickers, km.newTicker(loop.every))
	}

	km.cancel = cancel
	km.runDone = loopCtx.Done()

	km.wg.Add(len(loops))
	for i, loop := range loops {
		go km.loop(loopCtx, tickers[i], loop.step)
	}
	launched = true

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

// newTicker paces a loop from the configured clock where it offers a ticker,
// and from the system clock otherwise, so a consumer supplying a bare Clock
// still gets working loops.
func (km *KeyManager) newTicker(every time.Duration) Ticker {
	if clock, ok := km.clock.(TickerClock); ok {
		return clock.NewTicker(every)
	}
	return systemClock{}.NewTicker(every)
}

// loop runs step on every tick until the context ends.
//
// It ends with return, never with break: a break inside the select would leave
// the select but not the for, and the goroutine would spin on a dead ticker
// until the process exited.
func (km *KeyManager) loop(ctx context.Context, ticker Ticker, step func(context.Context)) {
	defer km.wg.Done()
	// Flushing here rather than in Stop accounts for the suppressed failures
	// on every shutdown path, including a caller who only cancels the context.
	// It runs before wg.Done, so a Stop that is waiting still returns after
	// the last record has been written.
	defer km.sampler.Flush()
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
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
