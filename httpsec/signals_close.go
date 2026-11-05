package httpsec

import "context"

// SessionSignalStats is what a replica's signal streams have counted, since the chain was built. It
// is for an operator's metrics and alerts, and not for an untrusted caller: it says how many people
// are connected and how the session store is doing.
//
// Everything in it is per chain, so per replica, and reading it takes no lock on the delivery path.
// Open and BusSubscribed say how things are now, and the other fields only grow, but for
// ConsecutiveReloadFailures.
type SessionSignalStats struct {
	// Open is how many streams hold a place on this replica. A stream told to close holds its place
	// until its body has returned.
	Open int

	// RefusedByCap is how many requests a cap answered with only a retry. Such a request is 200 on
	// every dashboard that counts statuses, so this is where a cap being hit shows.
	RefusedByCap uint64

	// ReloadFailures is every read of a sign-in or its user that failed, timed out or panicked on an
	// open stream, and every request for the stream that a dependency failure answered with only a retry.
	// The second is 200 on a dashboard too, and it is where a tenant-scoped store with no
	// SessionSignals.ReloadContext shows, since no stream of that chain ever opens.
	ReloadFailures uint64

	// Throttled is how many requests for the stream a ratelimit.ErrThrottled on a published sign-in
	// answered with only a retry. Such a request is 200 on every dashboard that counts statuses, and
	// no dependency failed, so it is not in ReloadFailures.
	Throttled uint64

	// ConsecutiveReloadFailures is the reads in a row that failed, added up over the streams now open,
	// and zero when every open stream's last read succeeded. A single total that any success reset
	// would hide one user's unreadable session behind everyone else's streams. Being a sum, it scales
	// with the open streams, so an outage reads as streams times failures: judge it against Open.
	ConsecutiveReloadFailures uint64

	// BusDropped is how many signals a consumer's SessionSignals.Bus could not take, because
	// SessionSignals.BusQueue was full.
	BusDropped uint64

	// BusPublishFailures is how many calls to a consumer's Publish failed, timed out or panicked.
	BusPublishFailures uint64

	// StreamDropped is how many signals a stream's own queue of 32 dropped, on either bus, so that one
	// stalled tab does not read as a bus falling behind. It counts one per stream that dropped one.
	StreamDropped uint64

	// BusSubscribed says a consumer's bus has its subscription up. It is false with the default bus,
	// which has none, before the first stream or signal has started one, between retries, and after
	// CloseSessionSignals.
	BusSubscribed bool
}

// SessionSignalStats reads the counts of the chain's signal streams. On a chain without
// EnableSessionSignals it is the zero value.
func (c *Chain) SessionSignalStats() SessionSignalStats {
	e := c.signalsEndpoint()
	if e == nil {
		return SessionSignalStats{}
	}

	open, refused := e.registry.stats()
	subscribed, dropped, streamDropped, publishFailures := e.hub.stats()
	failures, inRow := e.reloadCounts()

	return SessionSignalStats{
		Open:                      open,
		RefusedByCap:              refused,
		ReloadFailures:            failures,
		Throttled:                 e.throttled.Load(),
		ConsecutiveReloadFailures: inRow,
		BusDropped:                dropped,
		BusPublishFailures:        publishFailures,
		StreamDropped:             streamDropped,
		BusSubscribed:             subscribed,
	}
}

// CloseSessionSignals ends the chain's open streams, for a server's shutdown, and returns when every
// stream's body has returned, or with ctx's error when ctx ends first. http.Server.Shutdown waits for
// active handlers and cancels nothing, so an open stream would otherwise hold it until its deadline.
// Register this with RegisterOnShutdown, which Go runs in a goroutine of its own and does not wait
// for: Shutdown itself is what then waits for the handlers.
//
// Each stream closes with no event, its last bytes a retry of its own between 1 second and 3 ×
// SessionSignals.ReconnectDelay, so that a drained replica's clients do not all come back at one
// moment, and a load balancer can send them to another replica. A stream requested afterwards gets
// 200 with only such a retry and Connection: close, is not registered, and is not logged or counted
// as a refusal: an EventSource gives up for good on a 503.
//
// It is bounded and repeatable. A body blocked in a write to a stalled client does not stop it
// returning when ctx ends, and that stream keeps its place until the write gives up. A second call
// ends nothing new, and waits on its own ctx for what a first call timed out on.
//
// It also ends what a consumer's SessionSignals.Bus was started with, and does not wait for a call
// into that bus to return. Signals raised afterwards go nowhere, and a signal still queued for the bus
// can be lost. A chain never closed keeps those two goroutines for as long as the process runs, because
// nothing else ends them. The session manager keeps the chain's observer, inert, since it can be given
// none back (session.Sessions.AddEndObserver).
//
// On a chain without EnableSessionSignals it returns ErrSessionSignalsDisabled.
func (c *Chain) CloseSessionSignals(ctx context.Context) error {
	e := c.signalsEndpoint()
	if e == nil {
		return ErrSessionSignalsDisabled
	}

	e.hub.close()

	return e.registry.close(ctx)
}
