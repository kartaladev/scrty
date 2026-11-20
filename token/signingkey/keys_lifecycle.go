package signingkey

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/internal/lifecycle"
	"github.com/kartaladev/scrty/internal/recovered"
)

// errNilAfter is the failure of a clock whose After returned no channel.
var errNilAfter = errors.New("signingkey: the clock's After returned a nil channel")

// ErrAlreadyStarted is returned by Start on a manager whose background work has
// already been launched.
var ErrAlreadyStarted = errors.New("signingkey: already started")

// ErrAlreadyShutdown is returned by Start on a manager that has been shut down.
// Shutdown is terminal: the background work of a shut-down manager never runs
// again.
var ErrAlreadyShutdown = errors.New("signingkey: already shut down")

// Start launches the rotation, reload and housekeeping loops.
//
// The loops run under a context derived from ctx that keeps its values, such
// as trace and log fields, but not its cancellation or deadline: cancelling ctx
// does not end them, so a request-scoped context passed by mistake cannot stop
// rotation. Only Shutdown ends the work.
//
// A nil ctx is refused with an error wrapping ErrConfig, and nothing is
// launched or changed: a later Start with a real context still works.
//
// A manager is started at most once. Starting a manager whose loops have been
// launched returns ErrAlreadyStarted, and starting one that has been shut down
// returns ErrAlreadyShutdown; neither launches anything.
//
// Start returns before the loops have begun waiting on the clock: each calls
// the clock's After from its own goroutine. A caller driving a controlled clock
// (WithClock) waits for all three to be waiting before advancing it — with
// clockwork's fake, BlockUntilContext(ctx, 3) — or its advance may land before
// a loop starts counting and never fire that loop.
//
// The loop keeps the values of ctx for its whole life, including a store transaction
// attached to it; start it from a context with no transaction attached.
func (km *Keys) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: Start needs a non-nil context", ErrConfig)
	}

	km.lifecycleMu.Lock()
	defer km.lifecycleMu.Unlock()

	switch {
	case km.shutdown:
		return ErrAlreadyShutdown
	case km.started:
		return ErrAlreadyStarted
	}
	km.started = true

	loops := []struct {
		op    string
		every time.Duration
		step  func(context.Context)
	}{
		{"rotate", km.rotateEvery, km.rotateAll},
		{"reload", km.reloadEvery, km.reload},
		{opHousekeep, km.housekeepEvery, km.housekeep},
	}

	workCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	km.cancel = cancel

	done := make(chan struct{})
	km.done = done

	km.wg.Add(len(loops))
	for _, loop := range loops {
		go km.loop(workCtx, loop.op, loop.every, loop.step)
	}
	// Turning the WaitGroup into a channel lets Shutdown wait for the work
	// inside a select on its own context. This goroutine is part of the work:
	// it ends the moment the last loop has.
	go func() {
		km.wg.Wait()
		close(done)
	}()

	return nil
}

// loop runs step one interval after the previous step finished, until the
// context ends. Waiting on the clock's After, rather than on a ticker, is what
// lets a controlled clock drive the loop, and is what makes the cadence
// fixed-delay: a slow run pushes the next one back rather than eating into its
// interval.
//
// It ends with return, never with break: a break inside the select would leave
// the select but not the for.
//
// The wait is the consumer's clock. If its After panics, the panic is
// recovered, the failure is reported under op, and the loop waits that one
// interval on the system timer instead, then runs its step as usual: it
// neither stops nor spins.
func (km *Keys) loop(ctx context.Context, op string, every time.Duration, step func(context.Context)) {
	defer km.wg.Done()
	// Flushing as the loop ends accounts for the failures the sampler still
	// holds back. It runs before wg.Done, so a Shutdown that sees the work end
	// returns after the last record has been written.
	defer km.sampler.Flush()

	for {
		tick, stop := km.nextRun(ctx, op, every)

		select {
		case <-ctx.Done():
			stop()

			return
		case <-tick:
			stop()
			step(ctx)
		}
	}
}

// nextRun returns the channel the loop waits on for its next run, and the
// function that releases it. It is the clock's After. When that panics, it is
// the system timer for the same interval, after the failure is reported, so a
// clock that cannot be waited on costs the loop its controlled time and
// nothing else.
func (km *Keys) nextRun(ctx context.Context, op string, every time.Duration) (<-chan time.Time, func()) {
	var tick <-chan time.Time

	err := recovered.Call(ctx, km.logger, whatClockAfter, func() error {
		tick = km.clock.After(every)

		return nil
	})
	if err == nil && tick == nil {
		// A nil channel never fires: waiting on it would stop the loop silently.
		err = errNilAfter
	}

	if err == nil {
		return tick, func() {}
	}

	km.report(ctx, op, "", clockFailure(err, "signingkey: wait for the next "+op+" run"))

	timer := time.NewTimer(every)

	return timer.C, func() { timer.Stop() }
}

// Shutdown ends the background work and waits for it to end, an in-flight key
// generation and store write included, so no store write lands after a
// Shutdown that returned nil. It waits no longer than ctx allows: it returns
// nil once the work has ended, or ctx's error if ctx is done first. When the
// work has already ended, it returns nil even if ctx is done.
//
// A nil ctx is refused with an error wrapping ErrConfig, and nothing is
// changed: the manager is not marked shut down and its work keeps running.
//
// Shutdown is terminal. The background work never runs again, and a later
// Start returns ErrAlreadyShutdown. A later Shutdown waits again under its own
// context, so a caller whose first wait ran out may call it again to wait for
// the rest. Shutting down a manager that was never started returns nil at
// once.
//
// Shutdown ends the background work only. A shut-down manager keeps serving
// Signer, VerificationKeys and JWKS from the keys it holds; it no longer
// rotates, reloads or sweeps them.
//
// Do not call Shutdown from inside the work, such as from the error hook
// (WithErrorHook) or a logger's handler (WithLogger). It would wait for the
// loop it is running on, so it can only return when its own ctx ends, with
// that context's error. Call it from outside the work.
func (km *Keys) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: Shutdown needs a non-nil context", ErrConfig)
	}

	km.lifecycleMu.Lock()
	km.shutdown = true
	if km.cancel != nil {
		km.cancel()
	}
	done := km.done
	km.lifecycleMu.Unlock()

	if done == nil {
		return nil // never started: there is no work to wait for
	}

	// Work that has already ended wins over a ctx that is already done.
	return lifecycle.Await(ctx, done)
}
