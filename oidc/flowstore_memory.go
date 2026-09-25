package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/kartaladev/scrty/internal/nilcheck"
)

// DefaultMaxFlows is how many unexpired flows a MemoryFlowStore holds before
// it refuses new ones, when WithMaxFlows is not given.
const DefaultMaxFlows = 100_000

// ErrFlowStoreFull is returned by MemoryFlowStore.Begin when the store already
// holds its maximum of unexpired flows.
var ErrFlowStoreFull = errors.New("oidc: flow store full")

// MemoryFlowStore keeps login flows in process memory. It is the FlowStore a
// Manager uses when WithFlowStore is not given, and it is safe for concurrent
// use.
//
// Complete decides existence, the provider and state bindings, single
// completion and expiry under one mutex, compares the state in constant time,
// and removes the flow only when every check passed, so a forged or mistaken
// callback cannot spend someone else's flow.
//
// It is per process and not durable: a flow begun on one instance cannot be
// completed on another, and a restart forgets every flow. A deployment of
// several instances without sticky routing supplies a shared FlowStore
// through WithFlowStore instead.
//
// Nothing runs in the background. Expired flows are pruned when Begin finds
// the store at its maximum, and by DeleteExpired; an expired flow still held is
// never completed. At its maximum of unexpired flows, Begin refuses with
// ErrFlowStoreFull rather than evicting one, since eviction would let whoever
// can start logins delete other people's flows.
type MemoryFlowStore struct {
	mu    sync.Mutex
	flows map[string]Flow
	// pruneAfter is no later than the earliest expiry among the held flows,
	// so a Begin at capacity before it knows, without scanning, that nothing
	// can be pruned.
	pruneAfter time.Time

	max    int
	now    func() time.Time
	random io.Reader
}

// errFlowHandleTaken is returned by MemoryFlowStore.Begin when the handle it
// drew is already held: overwriting it would replace another login's flow.
var errFlowHandleTaken = errors.New("oidc: a login flow with this handle is already stored")

// MemoryFlowStoreOption customises a MemoryFlowStore at construction.
type MemoryFlowStoreOption func(*MemoryFlowStore) error

// WithMaxFlows sets how many unexpired flows the store holds before Begin
// refuses with ErrFlowStoreFull. The default is DefaultMaxFlows (100,000).
func WithMaxFlows(n int) MemoryFlowStoreOption {
	return func(s *MemoryFlowStore) error {
		if n <= 0 {
			return fmt.Errorf("%w: WithMaxFlows must be positive, got %d", ErrConfig, n)
		}
		s.max = n
		return nil
	}
}

// WithMemoryFlowStoreClock replaces the clock expiry is judged against. The
// default is time.Now.
func WithMemoryFlowStoreClock(now func() time.Time) MemoryFlowStoreOption {
	return func(s *MemoryFlowStore) error {
		if now == nil {
			return fmt.Errorf("%w: WithMemoryFlowStoreClock was given nil", ErrConfig)
		}
		s.now = now
		return nil
	}
}

// WithMemoryFlowStoreRandom replaces the source flow handles are drawn from.
// The default is crypto/rand.Reader. The reader must be safe for concurrent
// use, as crypto/rand.Reader is.
func WithMemoryFlowStoreRandom(r io.Reader) MemoryFlowStoreOption {
	return func(s *MemoryFlowStore) error {
		if nilcheck.IsNil(r) {
			return fmt.Errorf("%w: WithMemoryFlowStoreRandom was given nil", ErrConfig)
		}
		s.random = r
		return nil
	}
}

// NewMemoryFlowStore returns an empty in-memory flow store.
//
// With no options it holds at most DefaultMaxFlows unexpired flows, judges
// expiry by time.Now and draws handles of 32 bytes from crypto/rand.Reader.
// NewManager builds one with its own clock and random source when no
// WithFlowStore is given.
//
// An option given a meaningless value (a maximum of zero or less, a nil clock
// or a nil random source) is a wiring mistake: NewMemoryFlowStore returns a
// nil store and an error wrapping ErrConfig, before the store takes any
// traffic. A nil option is ignored.
func NewMemoryFlowStore(opts ...MemoryFlowStoreOption) (*MemoryFlowStore, error) {
	s := &MemoryFlowStore{flows: make(map[string]Flow), max: DefaultMaxFlows, now: time.Now, random: rand.Reader}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// Begin stores f under a fresh random handle and returns the handle.
//
// When the store holds its maximum of flows it first prunes the expired ones;
// if none has expired it refuses with ErrFlowStoreFull and evicts nothing.
func (s *MemoryFlowStore) Begin(_ context.Context, f Flow) (string, error) {
	h, err := randomURLToken(s.random, flowSecretBytes)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.flows) >= s.max {
		s.pruneLocked(s.now())
		if len(s.flows) >= s.max {
			return "", ErrFlowStoreFull
		}
	}
	if _, taken := s.flows[h]; taken {
		return "", errFlowHandleTaken
	}
	s.flows[h] = f
	if len(s.flows) == 1 || f.ExpiresAt.Before(s.pruneAfter) {
		s.pruneAfter = f.ExpiresAt
	}

	return h, nil
}

// pruneLocked removes the flows expired at now, unless none can have. Call it
// with mu held.
func (s *MemoryFlowStore) pruneLocked(now time.Time) {
	if now.Before(s.pruneAfter) {
		return
	}

	var earliest time.Time
	for h, f := range s.flows {
		if !now.Before(f.ExpiresAt) {
			delete(s.flows, h)
			continue
		}
		if earliest.IsZero() || f.ExpiresAt.Before(earliest) {
			earliest = f.ExpiresAt
		}
	}
	s.pruneAfter = earliest
}

// Complete returns the flow named by handle and removes it, if and only if it
// exists, was begun for provider, carries state, and has not expired. Every
// refusal is ErrInvalidState and leaves the store unchanged. An empty state
// never matches.
//
// The checks and the removal happen under one lock, so of several callers
// racing on one flow exactly one succeeds. A flow is expired from its
// ExpiresAt instant on.
func (s *MemoryFlowStore) Complete(_ context.Context, handle, provider, state string) (Flow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, found := s.flows[handle]
	if !found || f.Provider != provider || state == "" ||
		subtle.ConstantTimeCompare([]byte(state), []byte(f.State)) != 1 ||
		!s.now().Before(f.ExpiresAt) {
		return Flow{}, ErrInvalidState
	}
	delete(s.flows, handle)

	return f, nil
}

// DeleteExpired removes the flows whose expiry is before the cutoff and
// returns how many it removed. It judges expiry against the cutoff alone,
// never the store's clock.
//
// A zero cutoff is refused with ErrRetainSinceRequired and nothing is removed:
// the zero time is what a caller who forgot to compute a cutoff passes.
func (s *MemoryFlowStore) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	if before.IsZero() {
		return 0, ErrRetainSinceRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var removed int
	for h, f := range s.flows {
		if f.ExpiresAt.Before(before) {
			delete(s.flows, h)
			removed++
		}
	}

	return removed, nil
}

var _ FlowStore = (*MemoryFlowStore)(nil)
