package httpsec

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// This file is the replica's registry of open streams and its caps.

// errStreamsClosed is what signalRegistry.admit returns after a close. The endpoint
// answers it 200 with only a retry.
var errStreamsClosed = errors.New("httpsec: the signal streams are closed")

// errStreamNotAdmissible is what signalRegistry.admit returns for a nil stream, or one
// already registered. The endpoint never asks for either, so it is no cap's refusal and is
// not counted as one.
var errStreamNotAdmissible = errors.New("httpsec: a signal stream is nil or already registered")

// signalLimits are the caps the registry enforces. perSource is 0 when off.
// A stream with an empty source is not counted under perSource, so one whose client address
// could not be read skips that cap, and still counts under the others.
type signalLimits struct {
	perSignIn, perUser, total, perSource int
}

// signalRegistry is every open stream of this replica, by user, by family and by
// upstream digest, behind one mutex.
//
// A stream holding no user, family, upstream digest or source is under no key of that kind,
// so none of them can be delivered to or share a cap, and the total still counts it. A
// sign-in is its family, so the streams under a family are the per-sign-in count, and those
// under a user the per-user count.
type signalRegistry struct {
	limits signalLimits

	// mu guards everything down to drained. No send happens under it: a delivery copies its
	// targets, and sends after releasing it.
	mu         sync.Mutex
	streams    streamSet
	byUser     map[identity.UserID]streamSet
	byFamily   map[id.ID]streamSet
	byUpstream map[string]streamSet
	bySource   map[string]int
	closed     bool

	// drained is closed once, when the registry is closed and holds no stream. Nothing can
	// be admitted after a close, so that moment comes once.
	drained chan struct{}

	// open and refused are counters, so reading them takes no lock.
	open    atomic.Int64
	refused atomic.Uint64
}

// streamSet is a set of registered streams.
type streamSet map[*signalStream]struct{}

// newSignalRegistry builds an empty registry.
func newSignalRegistry(limits signalLimits) *signalRegistry {
	return &signalRegistry{
		limits:     limits,
		streams:    streamSet{},
		byUser:     map[identity.UserID]streamSet{},
		byFamily:   map[id.ID]streamSet{},
		byUpstream: map[string]streamSet{},
		bySource:   map[string]int{},
		drained:    make(chan struct{}),
	}
}

// admit checks every cap and registers st under one lock, so two requests racing for the
// last place cannot both get it. It returns ErrTooManyStreams over a cap, and
// errStreamsClosed after a close, and registers nothing then. A cap's refusal charges
// nothing, closes no stream, and is counted.
//
// release frees the place. It may be called any number of times and from any goroutine,
// after a close too, and needs nothing held. Whatever admit returns, release is not nil, and
// without a place it does nothing.
func (r *signalRegistry) admit(st *signalStream) (release func(), err error) {
	if st == nil {
		return func() {}, errStreamNotAdmissible
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return func() {}, errStreamsClosed
	}

	if _, registered := r.streams[st]; registered {
		return func() {}, errStreamNotAdmissible
	}

	if r.overCap(st) {
		r.refused.Add(1)

		return func() {}, ErrTooManyStreams
	}

	r.register(st)

	return sync.OnceFunc(func() { r.unregister(st) }), nil
}

// overCap reports whether st would pass any cap. The caller holds mu.
func (r *signalRegistry) overCap(st *signalStream) bool {
	switch {
	case len(r.streams) >= r.limits.total:
		return true
	case !st.family.IsZero() && len(r.byFamily[st.family]) >= r.limits.perSignIn:
		return true
	case st.user != "" && len(r.byUser[st.user]) >= r.limits.perUser:
		return true
	case r.limits.perSource > 0 && st.source != "" && r.bySource[st.source] >= r.limits.perSource:
		return true
	}

	return false
}

// register takes st's place under every key it holds. The caller holds mu.
func (r *signalRegistry) register(st *signalStream) {
	r.streams[st] = struct{}{}
	r.open.Add(1)

	if st.user != "" {
		addStream(r.byUser, st.user, st)
	}

	if !st.family.IsZero() {
		addStream(r.byFamily, st.family, st)
	}

	if st.upstream != "" {
		addStream(r.byUpstream, st.upstream, st)
	}

	if st.source != "" {
		r.bySource[st.source]++
	}
}

// unregister frees st's place and removes every key left empty, and is the one thing that
// can finish a close that was waiting.
func (r *signalRegistry) unregister(st *signalStream) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.streams, st)
	r.open.Add(-1)

	if st.user != "" {
		removeStream(r.byUser, st.user, st)
	}

	if !st.family.IsZero() {
		removeStream(r.byFamily, st.family, st)
	}

	if st.upstream != "" {
		removeStream(r.byUpstream, st.upstream, st)
	}

	if st.source != "" {
		r.bySource[st.source]--
		if r.bySource[st.source] == 0 {
			delete(r.bySource, st.source)
		}
	}

	if r.closed && len(r.streams) == 0 {
		close(r.drained)
	}
}

// addStream adds st to the set under key.
func addStream[K comparable](index map[K]streamSet, key K, st *signalStream) {
	set, ok := index[key]
	if !ok {
		set = streamSet{}
		index[key] = set
	}

	set[st] = struct{}{}
}

// removeStream removes st from the set under key, and the key with its last stream.
func removeStream[K comparable](index map[K]streamSet, key K, st *signalStream) {
	delete(index[key], st)

	if len(index[key]) == 0 {
		delete(index, key)
	}
}

// targets copies the streams under key, so that a delivery sends with the lock released. An
// empty key has none, since register adds none. A delivery can therefore reach a stream
// released since, which is harmless: its sends never block, and nothing reads them.
func targets[K comparable](r *signalRegistry, index map[K]streamSet, key K) []*signalStream {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Collect(maps.Keys(index[key]))
}

// deliverSignal offers sig (signalStream.offer) to each stream of user that wants its name
// (signalFilter.wants), copying the targets under the lock and sending after releasing it.
// It returns how many streams dropped it, their queues being full, for the caller to log
// with sampling.
func (r *signalRegistry) deliverSignal(user identity.UserID, sig queuedSignal) (dropped int) {
	for _, st := range targets(r, r.byUser, user) {
		if st.wanted.wants(sig.name) && !st.offer(sig) {
			dropped++
		}
	}

	return dropped
}

// deliverEndToFamily wakes the streams of family with the notice (signalStream.noteEnd). A
// notice only wakes a stream: the store decides, when it reloads.
func (r *signalRegistry) deliverEndToFamily(family id.ID, n endNotice) {
	for _, st := range targets(r, r.byFamily, family) {
		st.noteEnd(n)
	}
}

// deliverEndToUser wakes every stream of user but those of kept with the notice. A nil kept
// spares nothing, a stream holding no family included.
func (r *signalRegistry) deliverEndToUser(user identity.UserID, kept id.ID, n endNotice) {
	for _, st := range targets(r, r.byUser, user) {
		if kept.IsZero() || st.family != kept {
			st.noteEnd(n)
		}
	}
}

// deliverEndToUpstream wakes the streams holding the upstream digest with the notice. An
// empty digest reaches none, though many streams hold none.
func (r *signalRegistry) deliverEndToUpstream(digest string, n endNotice) {
	for _, st := range targets(r, r.byUpstream, digest) {
		st.noteEnd(n)
	}
}

// close closes every stream's closing channel, once, so that later admits are refused, and
// returns when every place has been released or ctx ends, with ctx's error then. A second
// call ends nothing new, and waits on its own ctx for what a first call timed out on.
//
// It does not call the bodies: a place is freed by its release, which never waits on close.
func (r *signalRegistry) close(ctx context.Context) error {
	r.shut()

	select {
	case <-r.drained:
		return nil
	case <-ctx.Done():
		// Both may be ready, and a registry that has drained has nothing to report.
		select {
		case <-r.drained:
			return nil
		default:
			return ctx.Err()
		}
	}
}

// shut refuses later admits and signals every stream. Only the first call does anything, and
// the admission of a stream either finished before it, so that stream is signalled, or
// starts after it, and is refused.
func (r *signalRegistry) shut() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}

	r.closed = true

	for st := range r.streams {
		close(st.closing)
	}

	if len(r.streams) == 0 {
		close(r.drained)
	}
}

// isClosed says close has been called, so that nothing more is admitted.
func (r *signalRegistry) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.closed
}

// stats is how many streams are open and how many a cap has refused. It backs
// Chain.SessionSignalStats, which takes no lock on the delivery path, so both are counters.
func (r *signalRegistry) stats() (open int, refused uint64) {
	return int(r.open.Load()), r.refused.Load()
}
