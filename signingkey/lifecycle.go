package signingkey

import (
	"context"
	"time"
)

// Start launches the rotation, reload and housekeeping loops.
//
// It is idempotent: starting an already-started manager launches nothing and
// returns nil, and so does starting a manager that has been stopped — a stopped
// manager stays stopped, so a late Start cannot resurrect background work the
// consumer has shut down.
//
// The loops end when ctx is cancelled or Stop is called. Whichever happens
// first, Stop is what waits for them; cancelling ctx alone ends the work but
// does not block until it has ended.
func (km *KeyManager) Start(ctx context.Context) error {
	km.lifecycle.Lock()
	defer km.lifecycle.Unlock()

	if km.started || km.stopped {
		return nil
	}

	loopCtx, cancel := context.WithCancel(ctx)
	km.cancel = cancel
	km.started = true

	// The tickers are taken here rather than inside each goroutine, so that
	// once Start returns, every loop's cadence is already registered with the
	// clock. A test that advances a fake clock straight after Start therefore
	// cannot race ahead of the loop that has not asked for its ticker yet.
	km.wg.Add(3)
	go km.loop(loopCtx, km.newTicker(km.rotateEvery), km.rotateAll)
	go km.loop(loopCtx, km.newTicker(km.reloadEvery), km.reload)
	go km.loop(loopCtx, km.newTicker(km.housekeepEvery), km.housekeep)

	return nil
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
	if !km.started {
		return nil
	}

	km.cancel()
	// Waiting under the lifecycle lock is safe, and is what makes concurrent
	// Start and Stop race-free: no loop ever takes this lock, so none of them
	// can be blocked on it while Stop waits for them.
	km.wg.Wait()
	km.started = false
	return nil
}
