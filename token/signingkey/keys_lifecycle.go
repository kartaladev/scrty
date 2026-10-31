package signingkey

import (
	"context"
	"errors"
	"fmt"
	"time"
)

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
func (km *Keys) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: Start needs a non-nil context", ErrConfig)
	}

	km.lifecycle.Lock()
	defer km.lifecycle.Unlock()

	switch {
	case km.shutdown:
		return ErrAlreadyShutdown
	case km.started:
		return ErrAlreadyStarted
	}
	km.started = true

	loops := []struct {
		every time.Duration
		step  func(context.Context)
	}{
		{km.rotateEvery, km.rotateAll},
		{km.reloadEvery, km.reload},
		{km.housekeepEvery, km.housekeep},
	}

	workCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	km.cancel = cancel

	done := make(chan struct{})
	km.done = done

	km.wg.Add(len(loops))
	for _, loop := range loops {
		go km.loop(workCtx, loop.every, loop.step)
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
func (km *Keys) loop(ctx context.Context, every time.Duration, step func(context.Context)) {
	defer km.wg.Done()
	// Flushing as the loop ends accounts for the failures the sampler still
	// holds back. It runs before wg.Done, so a Shutdown that sees the work end
	// returns after the last record has been written.
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

	km.lifecycle.Lock()
	km.shutdown = true
	if km.cancel != nil {
		km.cancel()
	}
	done := km.done
	km.lifecycle.Unlock()

	if done == nil {
		return nil // never started: there is no work to wait for
	}

	// Completion is checked on its own first, so that work which has already
	// ended wins over a ctx that is already done, rather than leaving the
	// result to whichever ready case select happens to pick.
	select {
	case <-done:
		return nil
	default:
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
