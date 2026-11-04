package httpsec

import (
	"context"
	"encoding/json"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// ErrStreamsClosed is errStreamsClosed.
var ErrStreamsClosed = errStreamsClosed

// RegistryCaps are the caps a registry under test enforces.
type RegistryCaps struct {
	PerSignIn, PerUser, Total, PerSource int
}

// RegistryStream says what a stream under test holds. Library names the chain's set, and
// Narrowed with Names is what a client's signals parameter left.
type RegistryStream struct {
	User     identity.UserID
	Family   id.ID
	Upstream string
	Source   string
	Library  []Signal
	Narrowed bool
	Names    []string
}

// NewRegistryStream builds a stream that is not registered.
func NewRegistryStream(spec RegistryStream) *SignalStreamProbe {
	wanted := signalFilter{chain: map[Signal]bool{}, narrowed: spec.Narrowed, names: map[string]bool{}}
	for _, s := range spec.Library {
		wanted.chain[s] = true
	}

	for _, n := range spec.Names {
		wanted.names[n] = true
	}

	return &SignalStreamProbe{s: newSignalStream(spec.User, spec.Family, spec.Upstream, spec.Source, wanted)}
}

// QueuedSignalView is one signal waiting on a stream's queue.
type QueuedSignalView struct {
	Name string
	Data string
}

// TakeQueued empties the stream's queue, as its loop would, and returns what it held in order.
func (p *SignalStreamProbe) TakeQueued() []QueuedSignalView {
	var taken []QueuedSignalView

	for {
		select {
		case sig := <-p.s.queue:
			taken = append(taken, QueuedSignalView{Name: sig.name, Data: string(sig.data)})
		default:
			return taken
		}
	}
}

// Woken reports whether a wake-up is waiting, without taking it.
func (p *SignalStreamProbe) Woken() bool { return len(p.s.wake) > 0 }

// Closing reports whether the registry has signalled the stream to close.
func (p *SignalStreamProbe) Closing() bool {
	select {
	case <-p.s.closing:
		return true
	default:
		return false
	}
}

// ClosingChan is what a stream's body would wait on for a close.
func (p *SignalStreamProbe) ClosingChan() <-chan struct{} { return p.s.closing }

// RegistryKeys is how many entries each of a registry's maps holds.
type RegistryKeys struct {
	Streams, Users, Families, Upstreams, Sources int
}

// SignalRegistryProbe drives a registry as the endpoint and the hub do.
type SignalRegistryProbe struct{ r *signalRegistry }

// NewSignalRegistryProbe builds an empty registry.
func NewSignalRegistryProbe(caps RegistryCaps) *SignalRegistryProbe {
	return &SignalRegistryProbe{r: newSignalRegistry(signalLimits{
		perSignIn: caps.PerSignIn,
		perUser:   caps.PerUser,
		total:     caps.Total,
		perSource: caps.PerSource,
	})}
}

// Admit is signalRegistry.admit. A nil probe admits a nil stream.
func (p *SignalRegistryProbe) Admit(stream *SignalStreamProbe) (func(), error) {
	if stream == nil {
		return p.r.admit(nil)
	}

	return p.r.admit(stream.s)
}

// DeliverSignal is signalRegistry.deliverSignal.
func (p *SignalRegistryProbe) DeliverSignal(user identity.UserID, name, data string) int {
	return p.r.deliverSignal(user, queuedSignal{name: name, data: json.RawMessage(data)})
}

// DeliverEndToFamily is signalRegistry.deliverEndToFamily.
func (p *SignalRegistryProbe) DeliverEndToFamily(family id.ID, reason string, at time.Time) {
	p.r.deliverEndToFamily(family, endNotice{reason: reason, at: at})
}

// DeliverEndToUser is signalRegistry.deliverEndToUser.
func (p *SignalRegistryProbe) DeliverEndToUser(user identity.UserID, kept id.ID, reason string, at time.Time) {
	p.r.deliverEndToUser(user, kept, endNotice{reason: reason, at: at})
}

// DeliverEndToUpstream is signalRegistry.deliverEndToUpstream.
func (p *SignalRegistryProbe) DeliverEndToUpstream(digest, reason string, at time.Time) {
	p.r.deliverEndToUpstream(digest, endNotice{reason: reason, at: at})
}

// Close is signalRegistry.close.
func (p *SignalRegistryProbe) Close(ctx context.Context) error { return p.r.close(ctx) }

// Stats is signalRegistry.stats.
func (p *SignalRegistryProbe) Stats() (int, uint64) { return p.r.stats() }

// Keys counts the entries of the registry's maps.
func (p *SignalRegistryProbe) Keys() RegistryKeys {
	p.r.mu.Lock()
	defer p.r.mu.Unlock()

	return RegistryKeys{
		Streams:   len(p.r.streams),
		Users:     len(p.r.byUser),
		Families:  len(p.r.byFamily),
		Upstreams: len(p.r.byUpstream),
		Sources:   len(p.r.bySource),
	}
}

// IfUnlocked calls fn holding the registry's lock, and reports whether it could take it. No
// critical section of the registry can overlap fn, so what fn reads, it reads between them.
func (p *SignalRegistryProbe) IfUnlocked(fn func()) bool {
	if !p.r.mu.TryLock() {
		return false
	}
	defer p.r.mu.Unlock()

	fn()

	return true
}
