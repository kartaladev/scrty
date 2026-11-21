package guardauth

import "context"

// runContextOf answers RunContext. The chain's package installs it once, from
// its init, before any request can reach an adapter; nothing writes it after,
// so reading it needs no lock.
var runContextOf func(exchange any) context.Context

// SetRunContext installs how RunContext reads the context of the run a chain
// made on an exchange. Only the chain's package calls it, once, from its init:
// the exchange's record of its run is not part of its public API, and the
// adapters reach it here, inside the module, instead. A nil f is refused with a
// panic, at init, so a wiring mistake cannot pass for "no run".
func SetRunContext(f func(exchange any) context.Context) {
	if f == nil {
		panic("guardauth: SetRunContext needs a function")
	}

	runContextOf = f
}

// RunContext returns the context of the outermost chain run made on exchange,
// which answers the chain's status lookup (LookupKey) and its logger, and nil
// when no run was made on it or exchange is not one.
//
// An adapter answers a refusal an interceptor made before the route ran after
// the chain's step has returned, by when the exchange's own context has been
// put back to the one the run began on and no longer answers either. It reads
// this instead, so the refusal is classified and reported as the chain would.
func RunContext(exchange any) context.Context {
	if runContextOf == nil {
		return nil
	}

	return runContextOf(exchange)
}
