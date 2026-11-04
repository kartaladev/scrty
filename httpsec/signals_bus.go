package httpsec

import (
	"context"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/session"
)

// This file is the hub every signal is raised through, and its bus. Dispatch C4b owns it.
// raise, start, deliver, close and stats are stubs. settle builds the hub with a keyed
// literal and wire sets log and sampler, so a field added here touches no other file.

// signalHub is where every signal is raised, the session manager's end reports (it is the
// manager's session.EndObserver) included, and where a bus hands them back to this
// replica's registry. It starts nothing until first used.
type signalHub struct {
	registry *signalRegistry

	// bus is the consumer's, and nil for the in-process default, which needs no queue, no
	// timeout and no goroutine. queue and timeout are SessionSignals.BusQueue and
	// BusTimeout, settled only for a consumer's bus.
	bus     SignalBus
	queue   int
	timeout time.Duration

	// clock stamps a notice's local receipt. log and sampler are the chain's, set by wire.
	clock   clock.Timed
	log     *slog.Logger
	sampler *logsample.Sampler
}

// SignInsEnded raises what an end report says. It is called inside the caller's
// transaction, so raise never blocks.
func (h *signalHub) SignInsEnded(_ context.Context, r session.EndReport) {
	if e, ok := envelopeForEnd(r); ok {
		// A report's end has happened whatever the bus does, and the heartbeat ends
		// the stream if this one is dropped.
		_ = h.raise(e)
	}
}

// raise hands e to the bus, and never blocks: observers run inside the caller's
// transaction, so it must not hold a logout up. It returns ErrSignalsBusy when a consumer's
// bus has fallen so far behind that e was dropped, which a consumer's signal returns to its
// caller and an end report ignores. It does nothing after a close. The stub drops e.
func (h *signalHub) raise(SignalEnvelope) error {
	return nil
}

// start starts what a consumer's bus needs, the publisher and the one subscription, once,
// at the first stream or the first raised signal, and never blocks. The default bus starts
// nothing. The stub starts nothing.
func (h *signalHub) start() {}

// deliver routes an envelope a bus handed back to this replica's registry, and is what
// SignalBus.Subscribe is given, so it never blocks and is safe from several goroutines. An
// envelope is untrusted: session_ended only wakes the streams it names, with a reason
// checked against the known ones and stamped with local receipt time, and anything else is
// checked again (validAppSignalName, validSignalData). It does nothing after a close. The
// stub drops e.
func (h *signalHub) deliver(SignalEnvelope) {}

// close makes raise and deliver do nothing and ends what start started. It signals and
// does not wait, so a consumer's bus that ignores its context cannot hold a shutdown. The
// stub has nothing to end.
func (h *signalHub) close() {}

// stats is whether a consumer's bus subscription is up, how many signals were dropped
// waiting for it, and how many Publish calls failed. It backs Chain.SessionSignalStats, so
// all three are counters read with no lock. The stub reports none.
func (h *signalHub) stats() (subscribed bool, dropped, failures uint64) {
	return false, 0, 0
}
