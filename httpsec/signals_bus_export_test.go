package httpsec

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/logsample"
)

// SignalHubSetup is what a hub under test is built with.
type SignalHubSetup struct {
	Bus     SignalBus
	Queue   int
	Timeout time.Duration
	Clock   clock.Timed
	Log     *slog.Logger
	Sampler *logsample.Sampler
}

// SignalHubProbe drives a hub as the session manager, the endpoint and a bus do.
type SignalHubProbe struct{ h *signalHub }

// NewSignalHubProbe builds a hub with an empty registry that caps nothing a test reaches, as
// settle and wire build one.
func NewSignalHubProbe(setup SignalHubSetup) *SignalHubProbe {
	return &SignalHubProbe{h: &signalHub{
		registry: newSignalRegistry(signalLimits{perSignIn: 64, perUser: 64, total: 64}),
		bus:      setup.Bus,
		queue:    setup.Queue,
		timeout:  setup.Timeout,
		clock:    setup.Clock,
		log:      setup.Log,
		sampler:  setup.Sampler,
	}}
}

// SignalHubProbeOf drives the hub of a chain's stream.
func SignalHubProbeOf(c *Chain) *SignalHubProbe {
	return &SignalHubProbe{h: c.signalsEndpoint().hub}
}

// Registry is the hub's registry.
func (p *SignalHubProbe) Registry() *SignalRegistryProbe {
	return &SignalRegistryProbe{r: p.h.registry}
}

// Settings is the queue and the timeout the hub was given.
func (p *SignalHubProbe) Settings() (queue int, timeout time.Duration) {
	return p.h.queue, p.h.timeout
}

// Raise is signalHub.raise.
func (p *SignalHubProbe) Raise(e SignalEnvelope) error { return p.h.raise(e) }

// Start is signalHub.start.
func (p *SignalHubProbe) Start() { p.h.start() }

// Deliver is signalHub.deliver.
func (p *SignalHubProbe) Deliver(e SignalEnvelope) { p.h.deliver(e) }

// Close is signalHub.close.
func (p *SignalHubProbe) Close() { p.h.close() }

// SignalHubStats is signalHub.stats.
type SignalHubStats struct {
	Subscribed                       bool
	Dropped, StreamDropped, Failures uint64
}

// Stats is signalHub.stats.
func (p *SignalHubProbe) Stats() SignalHubStats {
	subscribed, dropped, streamDropped, failures := p.h.stats()

	return SignalHubStats{Subscribed: subscribed, Dropped: dropped, StreamDropped: streamDropped, Failures: failures}
}

// TakeQueuedData empties the stream's queue and returns its signals' data, each as the slice
// the queue held.
func (p *SignalStreamProbe) TakeQueuedData() []json.RawMessage {
	var taken []json.RawMessage

	for {
		select {
		case sig := <-p.s.queue:
			taken = append(taken, sig.data)
		default:
			return taken
		}
	}
}
