package httpsec

import (
	"context"
	"errors"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// This file is the replica's registry of open streams and its caps. Dispatch C4a owns it.
// Everything here but the declarations is a stub.

// errStreamsClosed is what signalRegistry.admit returns after a close. The endpoint
// answers it 200 with only a retry.
var errStreamsClosed = errors.New("httpsec: the signal streams are closed")

// signalLimits are the caps the registry enforces. perSource is 0 when off.
type signalLimits struct {
	perSignIn, perUser, total, perSource int
}

// signalRegistry is every open stream of this replica, by user, by family and by
// upstream digest, behind one mutex.
type signalRegistry struct {
	limits signalLimits
}

// newSignalRegistry builds an empty registry.
func newSignalRegistry(limits signalLimits) *signalRegistry {
	return &signalRegistry{limits: limits}
}

// admit checks every cap and registers st under one lock, so two requests racing for the
// last place cannot both get it. It returns ErrTooManyStreams over a cap, and
// errStreamsClosed after a close, and registers nothing then. release frees the place, and
// is safe to call more than once. The stub always admits.
func (r *signalRegistry) admit(*signalStream) (release func(), err error) {
	return func() {}, nil
}

// deliverSignal offers sig (signalStream.offer) to each stream of user that wants its name
// (signalFilter.wants), copying the targets under the lock and sending after releasing it.
// It returns how many streams dropped it, their queues being full, for the caller to log
// with sampling. The stub delivers nothing.
func (r *signalRegistry) deliverSignal(identity.UserID, queuedSignal) (dropped int) {
	return 0
}

// deliverEndToFamily wakes the streams of family with the notice (signalStream.noteEnd).
// The stub wakes nothing.
func (r *signalRegistry) deliverEndToFamily(id.ID, endNotice) {}

// deliverEndToUser wakes every stream of user but those of kept with the notice. A nil
// kept spares nothing. The stub wakes nothing.
func (r *signalRegistry) deliverEndToUser(identity.UserID, id.ID, endNotice) {}

// deliverEndToUpstream wakes the streams holding the upstream digest with the notice. The
// stub wakes nothing.
func (r *signalRegistry) deliverEndToUpstream(string, endNotice) {}

// close closes every stream's closing channel, once, so that later admits are refused, and
// returns when every place has been released or ctx ends, with ctx's error then. A second
// call ends nothing new, and waits on its own ctx for what a first call timed out on. The
// stub has nothing to wait for.
func (r *signalRegistry) close(context.Context) error {
	return nil
}

// stats is how many streams are open and how many a cap has refused. It backs
// Chain.SessionSignalStats, which takes no lock on the delivery path, so both are counters.
// The stub reports none.
func (r *signalRegistry) stats() (open int, refused uint64) {
	return 0, 0
}
