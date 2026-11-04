package httpsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/session"
)

// This file is the hub every signal is raised through, and its bus. settle builds the hub
// with a keyed literal and wire sets log and sampler, so a field added here touches no other
// file.

const (
	// busBackoffFirst and busBackoffLongest bound the wait between attempts at a bus that failed,
	// which doubles from the one to the other.
	busBackoffFirst   = time.Second
	busBackoffLongest = 30 * time.Second

	// busHealthyAfter is how long a subscription stays up before a later failure is a new
	// outage, whose backoff starts over. It is the longest wait, so that a bus failing
	// about as often as it is retried never counts as healthy.
	busHealthyAfter = busBackoffLongest

	// busFlow is the flow attribute of the bus's records, and what their sampling keys
	// start with. No key holds anything from an envelope, which a bus's sender chooses.
	busFlow = "session-signals-bus"

	// panicFrameLimit bounds the frames a panic's record names.
	panicFrameLimit = 32

	// panicPhaseBus is the phase of a panic in a consumer's bus, or on the hub's goroutines.
	panicPhaseBus = "bus"
)

// The records of the bus. None holds an envelope's data, an identifier, or a bus's error
// text, which can quote a broker's address or what it was handed.
const (
	msgBusPublishFailed     = "httpsec: session signal bus: Publish failed"
	msgBusSubscribeFailed   = "httpsec: session signal bus: Subscribe failed"
	msgBusSubscribeReturned = "httpsec: session signal bus: Subscribe returned early with no error"
	msgBusQueueFull         = "httpsec: session signal bus: a signal was dropped: the queue is full"
	msgBusStreamQueueFull   = "httpsec: session signal bus: a signal was dropped: a stream's queue is full"
	msgBusEnvelopeDropped   = "httpsec: session signal bus: an envelope was dropped"
	msgBusPanicked          = "httpsec: session signal bus: a panic was recovered"
)

// Why deliver drops an envelope: the why attribute of the record, and part of its sampling
// key, so the sender of an envelope cannot choose how many records it writes.
const (
	dropUnknownName      = "unknown_name"
	dropInvalidKind      = "invalid_credential_change"
	dropInvalidAppSignal = "invalid_app_signal"
)

// The kinds a credential_changed names on the wire.
const (
	credentialKindPassword     = "password"
	credentialKindPasskey      = "passkey"
	credentialKindSecondFactor = "second_factor"
)

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

	// clock stamps a notice's local receipt and times the backoff. log and sampler are the
	// chain's, set by wire.
	clock   clock.Timed
	log     *slog.Logger
	sampler *logsample.Sampler

	// launched runs launch at most once, and close uses it up when nothing has started, so
	// nothing can start afterwards. outbox and cancel are set inside it, and read only
	// after going through it, which is what orders those reads after the writes.
	launched sync.Once
	outbox   chan SignalEnvelope
	cancel   context.CancelFunc

	closed atomic.Bool

	// subscribed, dropped, streamDropped and failures back stats, which takes no lock. dropped
	// counts what a consumer's bus could not take, and streamDropped what a stream's own queue
	// dropped, on either bus, so that one stalled tab does not read as a bus falling behind.
	subscribed    atomic.Bool
	dropped       atomic.Uint64
	streamDropped atomic.Uint64
	failures      atomic.Uint64
}

// SignInsEnded raises what an end report says. It is called inside the caller's
// transaction, so raise never blocks.
func (h *signalHub) SignInsEnded(_ context.Context, r session.EndReport) {
	if e, ok := envelopeForEnd(r); ok {
		// A report's end has happened whatever the bus does, and the heartbeat ends
		// the stream if this one is dropped.
		_ = h.raise(e) //nolint:contextcheck // detached on purpose: a bus outlives the request
	}
}

// raise hands e to the bus, and never blocks: observers run inside the caller's
// transaction, so it must not hold a logout up.
//
// The default bus delivers inline, with non-blocking sends, and reaches only this chain's
// streams. A consumer's bus is fed from a bounded queue, and raise returns ErrSignalsBusy
// when that is full and e was dropped, which a consumer's signal returns to its caller and an
// end report ignores. A signal raised after a close goes nowhere, and raise returns
// ErrSignalsBusy for that too, on either bus, because nil would tell a consumer its signal
// was sent. It counts no drop then: nothing has fallen behind.
func (h *signalHub) raise(e SignalEnvelope) error {
	if h.closed.Load() {
		return ErrSignalsBusy
	}

	if h.bus == nil {
		h.deliver(e)

		return nil
	}

	h.start()

	// A consumer's signal may hold a slice its caller goes on using, and this outlives
	// the call.
	e.Data = slices.Clone(e.Data)

	select {
	case h.outbox <- e:
		return nil
	default:
	}

	// A close racing this one leaves the queue nil or unread, which is no drop.
	if !h.closed.Load() {
		h.dropped.Add(1)
		h.logSampled(slog.LevelWarn, "queue-full", msgBusQueueFull)
	}

	return ErrSignalsBusy
}

// start starts what a consumer's bus needs, the publisher and the one subscription, once,
// at the first stream or the first raised signal, and never blocks. The default bus starts
// nothing, and neither does a hub that is closed. It is safe from any goroutine.
func (h *signalHub) start() {
	if h.bus != nil {
		h.launched.Do(h.launch)
	}
}

// launch starts the two goroutines on a context of their own, which holds none of the
// values of the request that happened to come first.
func (h *signalHub) launch() {
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.outbox = make(chan SignalEnvelope, h.queue)

	go h.publishLoop(ctx)
	go h.subscribeLoop(ctx)
}

// publishLoop calls Publish with what was queued, one at a time, until ctx ends. A failed
// Publish costs its envelope and nothing else. A panicking one does too, and also waits out
// a backoff before the next, since a bus that panics has no error to say why. Its envelope is
// not tried again, so that an envelope it panics on cannot hold up every other.
//
// A Publish that ignores its context holds this goroutine for as long as it hangs. The queue
// then fills and later signals are dropped and counted, which is the most that can be done
// while Publish stays on one goroutine, as SignalBus promises.
func (h *signalHub) publishLoop(ctx context.Context) {
	defer h.recoverLoop() //nolint:contextcheck // detached on purpose: a bus outlives the request

	delay := busBackoffFirst

	for {
		select {
		case <-ctx.Done():
			return
		case e := <-h.outbox:
			// Both may have been ready, and nothing is published after a close.
			if ctx.Err() != nil {
				return
			}

			if !h.publish(ctx, e) {
				delay = busBackoffFirst

				continue
			}

			if !h.backoff(ctx, delay) {
				return
			}

			delay = nextBusBackoff(delay)
		}
	}
}

// publish makes one Publish, under the timeout, and reports whether it panicked. What a
// close cut short is no failure. Whether it timed out is read from the context it ran under,
// never from the bus's error, whose methods are the consumer's and could panic here, outside
// guarded.
func (h *signalHub) publish(ctx context.Context, e SignalEnvelope) (panicked bool) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	var err error

	panicked = h.guarded(func() { err = h.bus.Publish(ctx, e) }) //nolint:contextcheck // detached on purpose: a bus outlives the request

	switch {
	case panicked:
		h.failures.Add(1)
	case err != nil && !h.closed.Load():
		h.failures.Add(1)
		h.logSampled(slog.LevelWarn, "publish-failed", msgBusPublishFailed, //nolint:contextcheck // detached on purpose: a bus outlives the request
			slog.String("error_type", fmt.Sprintf("%T", err)),
			slog.Bool("timed_out", errors.Is(ctx.Err(), context.DeadlineExceeded)),
		)
	}

	return panicked
}

// subscribeLoop keeps one subscription up until ctx ends. A Subscribe that fails, returns
// early with no error, or panics is tried again after a backoff, which starts over once a
// subscription has stayed up for busHealthyAfter.
func (h *signalHub) subscribeLoop(ctx context.Context) {
	defer h.recoverLoop() //nolint:contextcheck // detached on purpose: a bus outlives the request

	delay := busBackoffFirst

	for ctx.Err() == nil {
		began := h.clock.Now()

		h.subscribe(ctx)

		if ctx.Err() != nil {
			return
		}

		if h.clock.Now().Sub(began) >= busHealthyAfter {
			delay = busBackoffFirst
		}

		if !h.backoff(ctx, delay) {
			return
		}

		delay = nextBusBackoff(delay)
	}
}

// subscribe makes one Subscribe and logs how it ended, unless it was ctx that ended it.
func (h *signalHub) subscribe(ctx context.Context) {
	h.subscribed.Store(true)
	defer h.subscribed.Store(false)

	var err error

	if h.guarded(func() { err = h.bus.Subscribe(ctx, h.deliver) }) || ctx.Err() != nil { //nolint:contextcheck // detached on purpose: a bus outlives the request
		return
	}

	if err == nil {
		h.logSampled(slog.LevelWarn, "subscribe-returned", msgBusSubscribeReturned) //nolint:contextcheck // detached on purpose: a bus outlives the request

		return
	}

	h.logSampled(slog.LevelWarn, "subscribe-failed", msgBusSubscribeFailed, //nolint:contextcheck // detached on purpose: a bus outlives the request
		slog.String("error_type", fmt.Sprintf("%T", err)))
}

// backoff waits delay on the chain's clock, and reports false if ctx ended first.
func (h *signalHub) backoff(ctx context.Context, delay time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-h.clock.After(delay):
		return true
	}
}

// nextBusBackoff doubles delay, up to the longest wait.
func nextBusBackoff(delay time.Duration) time.Duration {
	return min(delay*2, busBackoffLongest)
}

// deliver routes an envelope a bus handed back to this replica's registry, and is what
// SignalBus.Subscribe is given, so it never blocks and is safe from several goroutines. It
// does nothing after a close.
//
// An envelope is untrusted. session_ended only wakes the streams it names, never through a
// stream's queue, with a reason checked against the known ones and stamped with local
// receipt time, and the store then decides. credential_changed needs a known kind in valid
// data, and is rebuilt to hold only that. A consumer's signal is checked again
// (validAppSignalName, validSignalData) and is otherwise unchanged. Any other name is
// dropped: session_expiring and assurance_lapsed come only from a stream's own timer.
//
// Its own code cannot panic, and logSampled recovers its own, but the chain's clock is the
// consumer's, and a consumer's bus may call this on a goroutine of its own, where nothing else
// could recover it.
func (h *signalHub) deliver(e SignalEnvelope) {
	defer func() {
		if v := recover(); v != nil {
			h.logPanicSampled(v)
		}
	}()

	if h.closed.Load() {
		return
	}

	switch {
	case e.Name == string(SignalSessionEnded):
		h.deliverEnd(e)
	case e.Name == string(SignalCredentialChanged):
		h.deliverCredentialChange(e)
	case strings.HasPrefix(e.Name, appSignalPrefix):
		if !validAppSignalName(e.Name) || !validSignalData(e.Data) {
			h.logDropped(dropInvalidAppSignal)

			return
		}

		h.deliverToUser(e, slices.Clone(e.Data))
	default:
		h.logDropped(dropUnknownName)
	}
}

// deliverEnd wakes the streams an end names, by the narrowest key it holds. A family is one
// sign-in, so a report naming a user as well reaches only that sign-in's streams. A digest is
// one upstream session. Only then does a user mean all that user's streams, but for Kept. An
// end naming none of them reaches no stream, and the heartbeat ends those.
func (h *signalHub) deliverEnd(e SignalEnvelope) {
	n := endNotice{reason: knownEndReason(e.Reason), at: h.clock.Now()}

	switch {
	case !e.Family.IsZero():
		h.registry.deliverEndToFamily(e.Family, n)
	case e.Upstream != "":
		h.registry.deliverEndToUpstream(e.Upstream, n)
	case e.User != "":
		h.registry.deliverEndToUser(e.User, e.Kept, n)
	}
}

// knownEndReason is reason when it is one a report can carry, and otherwise no reason: the end
// still wakes the stream, and the store decides. expired is not among them, because no report
// carries it: a stream decides that locally, and a bus's sender cannot choose it.
func knownEndReason(reason string) string {
	switch reason {
	case reasonLogout, reasonEnded, reasonReuse, reasonAllEnded, reasonProviderLogout:
		return reason
	default:
		return ""
	}
}

// deliverCredentialChange queues a credential change holding a known kind, rebuilt from that
// kind, so that what a bus's sender adds beside it never reaches a browser.
func (h *signalHub) deliverCredentialChange(e SignalEnvelope) {
	data, ok := credentialChangeData(e.Data)
	if !ok {
		h.logDropped(dropInvalidKind)

		return
	}

	h.deliverToUser(e, data)
}

// credentialChangeData is the data a stream sends for raw, and false when raw is not valid
// signal data naming a known kind.
func credentialChangeData(raw json.RawMessage) (json.RawMessage, bool) {
	if !validSignalData(raw) {
		return nil, false
	}

	var change struct {
		Kind string `json:"kind"`
	}

	if err := json.Unmarshal(raw, &change); err != nil {
		return nil, false
	}

	switch change.Kind {
	case credentialKindPassword, credentialKindPasskey, credentialKindSecondFactor:
	default:
		return nil, false
	}

	data, err := json.Marshal(change)

	return data, err == nil
}

// deliverToUser offers a signal to the user's streams, and counts and logs what their full
// queues dropped. data must be the hub's own, since it stays queued after a bus has returned,
// and a bus may reuse its buffer.
func (h *signalHub) deliverToUser(e SignalEnvelope, data json.RawMessage) {
	if n := h.registry.deliverSignal(e.User, queuedSignal{name: e.Name, data: data}); n > 0 {
		h.streamDropped.Add(uint64(n))
		h.logSampled(slog.LevelWarn, "stream-queue-full", msgBusStreamQueueFull, slog.Int("streams", n))
	}
}

// close makes raise and deliver do nothing and ends what start started. It signals and does
// not wait, so a consumer's bus that ignores its context cannot hold a shutdown: its goroutine
// stays until that call returns, and then ends. A second call does nothing more. The hub stays
// on its session manager, inert, as AddEndObserver documents.
func (h *signalHub) close() {
	h.closed.Store(true)

	// This returns only when no launch is running, and leaves none to run.
	h.launched.Do(func() {})

	if h.cancel != nil {
		h.cancel()
	}
}

// stats is whether a consumer's bus subscription is up, how many signals its bus could not
// take because the queue for it was full (dropped), how many a stream's own full queue dropped
// (streamDropped, which a default bus counts too), and how many Publish calls failed, a timeout
// or a panic included. It backs Chain.SessionSignalStats, so all are counters read with no lock. A
// subscription close ended is not up, even while a bus that ignores its context has not returned.
func (h *signalHub) stats() (subscribed bool, dropped, streamDropped, failures uint64) {
	return h.subscribed.Load() && !h.closed.Load(), h.dropped.Load(), h.streamDropped.Load(), h.failures.Load()
}

// logDropped logs an envelope deliver refused, with nothing from the envelope.
func (h *signalHub) logDropped(why string) {
	h.logSampled(slog.LevelWarn, "dropped"+sampleKeySeparator+why, msgBusEnvelopeDropped, slog.String("why", why))
}

// logSampled writes one of the bus's records through the chain's sampler. The logger, its
// sampler's reporter and the clock are the consumer's, and this runs in a caller's
// transaction and on goroutines nothing else recovers, so a panic in them goes no further.
func (h *signalHub) logSampled(level slog.Level, key, msg string, attrs ...slog.Attr) {
	defer func() { _ = recover() }()

	attrs = append(attrs, slog.String("flow", busFlow))
	logSampled(context.Background(), h.sampler, h.log, level, h.clock.Now(), busFlow+sampleKeySeparator+key, msg, attrs...)
}

// guarded calls fn, a call into a consumer's bus, and reports whether it panicked. A panic is
// logged and goes no further: a consumer's bus cannot end the process.
func (h *signalHub) guarded(fn func()) (panicked bool) {
	defer func() {
		if v := recover(); v != nil {
			panicked = true

			h.logPanic(v)
		}
	}()

	fn()

	return false
}

// recoverLoop is a goroutine's last line, for a panic outside a call to the bus. Only the
// consumer's clock or logger can raise one there. It ends that goroutine rather than the
// process, and the heartbeat goes on ending streams.
func (h *signalHub) recoverLoop() {
	if v := recover(); v != nil {
		h.logPanic(v)
	}
}

// logPanic logs a recovered panic. It is unsampled, because a bus's panic waits out a backoff
// and a goroutine's ends it, so neither can flood the log. deliver's has no backoff and uses
// logPanicSampled. A logger that panics as well goes no further.
func (h *signalHub) logPanic(value any) {
	defer func() { _ = recover() }()

	h.log.LogAttrs(context.Background(), slog.LevelError, msgBusPanicked, panicAttrs(panicPhaseBus, value)...)
}

// logPanicSampled logs a recovered panic through the sampler, for deliver, which a bus calls
// once per envelope with no backoff between, so that a panic in it could write a record for each.
func (h *signalHub) logPanicSampled(value any) {
	defer func() { _ = recover() }()

	logSampled(context.Background(), h.sampler, h.log, slog.LevelError, h.panicTime(),
		busFlow+sampleKeySeparator+"deliver-panic", msgBusPanicked, panicAttrs(panicPhaseBus, value)...)
}

// panicTime is the chain's clock reading, or the zero time when that clock is what panicked.
// The zero time still samples: it never advances, so one record is written and the rest are
// counted until the clock answers again.
func (h *signalHub) panicTime() (now time.Time) {
	defer func() { _ = recover() }()

	return h.clock.Now()
}

// panicAttrs says where a panic happened from within the deferred call that recovered it: the
// phase, the value's type, and the frames as function, file and line. It never holds the value,
// which can quote a secret from a consumer's bus or loader, nor debug.Stack, whose output
// quotes arguments.
func panicAttrs(phase string, value any) []slog.Attr {
	pcs := make([]uintptr, panicFrameLimit)

	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])

	var named []string

	for {
		frame, more := frames.Next()
		named = append(named, fmt.Sprintf("%s %s:%d", frame.Function, frame.File, frame.Line))

		if !more {
			break
		}
	}

	return []slog.Attr{
		slog.String("phase", phase),
		slog.String("panic_type", fmt.Sprintf("%T", value)),
		slog.String("frames", strings.Join(named, "; ")),
	}
}
