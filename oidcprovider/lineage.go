package oidcprovider

import (
	"context"
	"sync"
	"time"

	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/session"
)

// RefreshTokenStore is where a provider keeps refresh-token lineages. It is a type and
// not an interface so that a sign-in's session.Store can never be given in its place:
// a lineage kept among sign-ins would let a refresh token be accepted as a sign-in.
//
// Only scrty's own modules can build one: each SQL adapter's NewRefreshTokenStore does,
// over a table no sign-in reads. A caller outside scrty's import path cannot, by a
// literal, a conversion or an interface, as the compiler refuses all of them. Its zero
// value compiles, and WithRefreshTokenStore refuses it. The line this does not hold
// past is package unsafe, which no Go type can stand against.
type RefreshTokenStore = oplineage.Store

// lineageClock lets a provider's clock, which need only read the time, drive a session
// store that wants a clock it can also wait on. The store waits only once started, and
// the provider never starts its own, so After is there to satisfy the type.
type lineageClock struct {
	clock.Clock
}

// After implements clock.Timed.
func (lineageClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// sweepingLineages is the provider's default lineage store: a session.MemoryStore of
// its own, which no sign-in path can reach, kept bounded by its writes. A memory store
// sweeps only once started, which would need a goroutine the provider has no lifecycle
// to stop, so a write that adds a record forgets what has expired instead, at most once
// per minute.
type sweepingLineages struct {
	session.Store

	mu    sync.Mutex
	sweep memorySweep
}

// newDefaultLineages builds the default lineage store on clk.
func newDefaultLineages(clk clock.Clock) (RefreshTokenStore, error) {
	timed, ok := clk.(clock.Timed)
	if !ok {
		timed = lineageClock{clk}
	}
	memory, err := session.NewMemoryStore(session.WithMemoryStoreClock(timed))
	if err != nil {
		return RefreshTokenStore{}, err
	}

	return oplineage.New(&sweepingLineages{Store: memory, sweep: memorySweep{clock: clk}}), nil
}

// sweepIfDue forgets what has expired, when a sweep is due.
func (s *sweepingLineages) sweepIfDue(ctx context.Context) error {
	s.mu.Lock()
	_, due := s.sweep.due()
	s.mu.Unlock()
	if !due {
		return nil
	}
	_, err := s.DeleteExpired(ctx)

	return err
}

// Create implements session.Store.
func (s *sweepingLineages) Create(ctx context.Context, rec *session.Session) error {
	if err := s.sweepIfDue(ctx); err != nil {
		return err
	}

	return s.Store.Create(ctx, rec)
}

// Supersede implements session.Store.
func (s *sweepingLineages) Supersede(ctx context.Context, op session.Supersession) error {
	if err := s.sweepIfDue(ctx); err != nil {
		return err
	}

	return s.Store.Supersede(ctx, op)
}
