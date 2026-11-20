package sweep

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/jonboulle/clockwork"

	"github.com/kartaladev/scrty/internal/recovered"
)

// gocron calls the consumer's locker, clock and logger on goroutines of its own
// and recovers nothing there: a panic in any of them ends the process. (It
// recovers a job function's panic only for a job carrying the
// AfterJobRunsWithPanic listener, and the task, which is the expiry runner's to
// recover, never reaches it.) The wrappers below put each consumer call inside
// recovered.Call, so the call that panicked is reported failed and the
// scheduler goes on. Each panic writes one Error record to the sweeper's
// logger, with the call named by the constants below and never the panic's
// value.
const (
	whatLock      = "locker.Lock"
	whatUnlock    = "locker.Unlock"
	whatNow       = "clock.Now"
	whatAfterFunc = "clock.AfterFunc"
	whatNewTimer  = "clock.NewTimer"
	whatTimer     = "clock.Timer"
	whatLogger    = "logger"
)

// errNoLock is what a locker that returned neither a lock nor an error is
// reported as. gocron would otherwise call Unlock on the nil lock on its own
// goroutine.
var errNoLock = errors.New("sweep: the locker returned no lock and no error")

// guardedLocker recovers a panic in the consumer's locker. A Lock that panics
// is a lock that failed: gocron skips the run and calls the lock failure
// listener, with recovered.ErrPanicked as the error.
//
// A Lock that panics after it took the lock leaves that lock held: the sweeper
// is handed no lock to release, so the release is the locker's own (a lease or
// TTL on the lock). The next tick asks again.
type guardedLocker struct {
	inner gocron.Locker
	log   *slog.Logger
}

func (g guardedLocker) Lock(ctx context.Context, key string) (gocron.Lock, error) {
	var lock gocron.Lock

	err := recovered.Call(ctx, g.log, whatLock, func() error {
		var err error

		lock, err = g.inner.Lock(ctx, key)

		return err
	})
	if err != nil {
		return nil, err
	}

	if isNil(lock) {
		return nil, errNoLock
	}

	return guardedLock{inner: lock, log: g.log}, nil
}

// guardedLock recovers a panic in the consumer's Unlock. gocron discards
// Unlock's error, so the panic's only outcome is its record.
type guardedLock struct {
	inner gocron.Lock
	log   *slog.Logger
}

func (g guardedLock) Unlock(ctx context.Context) error {
	return recovered.Call(ctx, g.log, whatUnlock, func() error { return g.inner.Unlock(ctx) })
}

// guardedClock recovers a panic in the three clock methods gocron calls: Now,
// AfterFunc and NewTimer, and in the timers they return. When one panics, or
// AfterFunc or NewTimer returns no timer, the call is answered by the system
// clock, so the schedule is late or early by the consumer clock's offset at
// worst, instead of stopping. The other methods of clockwork.Clock are
// promoted unguarded: gocron calls none of them.
type guardedClock struct {
	clockwork.Clock

	system clockwork.Clock
	log    *slog.Logger
}

func newGuardedClock(inner clockwork.Clock, log *slog.Logger) *guardedClock {
	return &guardedClock{Clock: inner, system: clockwork.NewRealClock(), log: log}
}

func (c *guardedClock) call(what string, f func() error) error {
	return recovered.Call(context.Background(), c.log, what, f)
}

func (c *guardedClock) Now() time.Time {
	var now time.Time

	if err := c.call(whatNow, func() error {
		now = c.Clock.Now()

		return nil
	}); err != nil {
		return c.system.Now()
	}

	return now
}

func (c *guardedClock) AfterFunc(d time.Duration, f func()) clockwork.Timer {
	return c.timer(whatAfterFunc, d,
		func() clockwork.Timer { return c.Clock.AfterFunc(d, f) },
		func() clockwork.Timer { return c.system.AfterFunc(d, f) })
}

func (c *guardedClock) NewTimer(d time.Duration) clockwork.Timer {
	return c.timer(whatNewTimer, d,
		func() clockwork.Timer { return c.Clock.NewTimer(d) },
		func() clockwork.Timer { return c.system.NewTimer(d) })
}

// timer returns build's timer, guarded, or fallback's when make panics or
// returns none. A missing timer is no panic, so it writes its own record: a
// schedule that silently ran on another clock would look healthy.
func (c *guardedClock) timer(what string, d time.Duration, build, fallback func() clockwork.Timer) clockwork.Timer {
	var t clockwork.Timer

	err := c.call(what, func() error {
		t = build()

		return nil
	})
	if err == nil && isNil(t) {
		c.logNoTimer(what)
	}

	if err != nil || isNil(t) {
		t = fallback()
	}

	return &guardedTimer{inner: t, clock: c, d: d}
}

func (c *guardedClock) logNoTimer(what string) {
	logGuarded(context.Background(), c.log, slog.LevelError,
		"sweep: the clock returned no timer; the system timer is used", slog.String("what", what))
}

// guardedTimer recovers a panic in a timer's methods. Stop and Reset report
// false. A Chan that panics, or returns no channel, would hand gocron a channel
// that never fires, and gocron reads Chan in the waits that bound a shutdown,
// so a hung purge would hang the shutdown with it: Chan answers with the
// channel of a system timer of the same duration instead, one record per
// panic. That system timer is made once and kept, so repeated reads wait on one
// deadline.
type guardedTimer struct {
	inner clockwork.Timer
	clock *guardedClock

	mu       sync.Mutex
	d        time.Duration
	fallback clockwork.Timer
}

func (t *guardedTimer) Chan() <-chan time.Time {
	var ch <-chan time.Time

	err := t.clock.call(whatTimer, func() error {
		ch = t.inner.Chan()

		return nil
	})
	if err == nil && ch != nil {
		return ch
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.fallback == nil {
		t.fallback = t.clock.system.NewTimer(t.d)
	}

	return t.fallback.Chan()
}

func (t *guardedTimer) Reset(d time.Duration) bool {
	t.mu.Lock()
	t.d = d

	if t.fallback != nil {
		t.fallback.Reset(d)
	}

	t.mu.Unlock()

	var ok bool

	_ = t.clock.call(whatTimer, func() error {
		ok = t.inner.Reset(d)

		return nil
	})

	return ok
}

func (t *guardedTimer) Stop() bool {
	t.mu.Lock()
	if t.fallback != nil {
		t.fallback.Stop()
	}
	t.mu.Unlock()

	var ok bool

	_ = t.clock.call(whatTimer, func() error {
		ok = t.inner.Stop()

		return nil
	})

	return ok
}

// logGuarded writes one record to log. A handler that panics is the consumer's
// code panicking on gocron's goroutine, so the write is recovered; the
// recovery's own record goes to the same handler and is swallowed if that
// panics too.
func logGuarded(ctx context.Context, log *slog.Logger, level slog.Level, msg string, attrs ...slog.Attr) {
	_ = recovered.Call(ctx, log, whatLogger, func() error {
		log.LogAttrs(ctx, level, msg, attrs...)

		return nil
	})
}
