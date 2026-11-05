package diag

import "context"

// EndedWriter is what a stream's body writes to when there is nothing to stream to. It has the
// shape of httpsec.EventWriter, which this package cannot import. Whatever it is given goes
// nowhere, and each call returns why, so a body that checks stops.
//
// It lives here because the net/http and fiber adapters both need it, and they share no other
// package a stream's helpers could sit in.
type EndedWriter struct {
	ctx context.Context //nolint:containedctx // what its calls report, and it lives no longer than the body
}

// NewEndedWriter returns an EndedWriter whose calls report ctx's error. Give it a context that
// has ended, or its calls report no error while writing nothing.
func NewEndedWriter(ctx context.Context) EndedWriter { return EndedWriter{ctx: ctx} }

// Write discards b, and returns the context's error.
func (e EndedWriter) Write([]byte) (int, error) { return 0, e.ctx.Err() }

// Flush returns the context's error.
func (e EndedWriter) Flush() error { return e.ctx.Err() }
