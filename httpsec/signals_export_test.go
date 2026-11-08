package httpsec

import (
	"context"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// ResolvedSessionSignals is the configuration the chain's stream settled on, its
// defaults filled, and false on a chain without a stream.
func ResolvedSessionSignals(c *Chain) (SessionSignals, bool) {
	e := c.signalsEndpoint()
	if e == nil {
		return SessionSignals{}, false
	}

	cfg := e.cfg
	cfg.Path = e.path.declared

	return cfg, true
}

// SignalHubOf is the observer the chain's stream added to its session manager.
func SignalHubOf(c *Chain) session.EndObserver { return c.signalsEndpoint().hub }

// EnvelopeForEnd is what an end report raises, and false for one naming no one.
func EnvelopeForEnd(r session.EndReport) (SignalEnvelope, bool) { return envelopeForEnd(r) }

// UpstreamDigest is what routes a provider's logout of one upstream session.
func UpstreamDigest(issuer, upstream string) string { return upstreamDigest(issuer, upstream) }

// SignalsSlotOf is the slot the chain registered its stream's endpoint at.
func SignalsSlotOf(c *Chain) Order {
	for _, r := range c.registrations {
		if _, ok := r.interceptor.(*sessionSignals); ok {
			return r.order
		}
	}

	return 0
}

// SignalHubSharesSampler reports whether the hub logs through the chain's own sampler.
func SignalHubSharesSampler(c *Chain) bool {
	hub := c.signalsEndpoint().hub

	return hub.sampler != nil && hub.sampler == c.sampler
}

// StreamByCookie reports whether the exchange's stream is judged as one a browser sends its
// credential for on its own.
func StreamByCookie(ex *Exchange) bool { return streamByCookie(ex) }

// StreamStartView is what a stream's body would start from.
type StreamStartView struct {
	// Upstream is the digest the stream holds, and State the first read it starts from.
	Upstream string
	State    session.SignInState

	// Everything prints every field, so a test can look for a value in all of them.
	Everything string
}

// StreamStartFor builds what a body starts from, for the sign-in s and the first read state.
func StreamStartFor(ctx context.Context, ex *Exchange, s *session.Session, state session.SignInState) StreamStartView {
	start := newStreamStart(ctx, ex, s, signalFilter{}, state)

	return StreamStartView{
		Upstream: start.stream.upstream,
		State:    start.state,
		Everything: fmt.Sprintf("%+v %v %v %q %q %+v", start, start.stream.user, start.stream.family,
			start.stream.upstream, start.stream.source, start.stream.wanted),
	}
}

// SignalStreamProbe drives one stream's shared half, as the registry and the stream's loop
// do.
type SignalStreamProbe struct{ s *signalStream }

// NewSignalStreamProbe builds a stream that is not registered.
func NewSignalStreamProbe() *SignalStreamProbe {
	return &SignalStreamProbe{s: newSignalStream("u-1", id.Nil, "", "", signalFilter{})}
}

// NoteEnd is signalStream.noteEnd.
func (p *SignalStreamProbe) NoteEnd(reason string, at time.Time) {
	p.s.noteEnd(endNotice{reason: reason, at: at})
}

// Offer is signalStream.offer of a signal called name.
func (p *SignalStreamProbe) Offer(name string) bool { return p.s.offer(queuedSignal{name: name}) }

// Queued is how many signals wait on the stream's queue.
func (p *SignalStreamProbe) Queued() int { return len(p.s.queue) }

// TakeWake reports whether the stream was woken, and takes the wake-up as its loop would.
func (p *SignalStreamProbe) TakeWake() bool {
	select {
	case <-p.s.wake:
		return true
	default:
		return false
	}
}

// Notice is the reason and time of the notice kept for every reason but reuse, "" for none.
func (p *SignalStreamProbe) Notice() (string, time.Time) { return readNotice(p.s.notice.Load()) }

// Reuse is the reason and time of the notice kept for reuse, "" for none.
func (p *SignalStreamProbe) Reuse() (string, time.Time) { return readNotice(p.s.reuse.Load()) }

func readNotice(n *endNotice) (string, time.Time) {
	if n == nil {
		return "", time.Time{}
	}

	return n.reason, n.at
}

// StreamQueueSize is how many signals a stream's queue holds.
const StreamQueueSize = streamQueueSize
