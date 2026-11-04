package httpsec

import (
	"errors"
	"io"
	"time"
)

// StreamWriteWindow is how far ahead an adapter sets the connection's write deadline
// while a response is streamed: when the stream starts, and before each write and each
// flush. It replaces, for that response only, whatever write timeout the server was
// configured with. A response that is not streamed keeps the server's deadline
// untouched, but for what a writer that turns out not to be able to stream leaves: see
// ErrStreamingUnsupported. Every adapter uses it, a consumer's included if it has a
// deadline to move (ResponseWriter.Stream).
//
// It is one fixed length, twice the largest heartbeat the signal stream allows,
// because the window has to outlast the gap between two writes rather than only
// cover a write in flight: an adapter is not told how often a stream writes, and
// Go's HTTP/2 server resets a stream when its write deadline passes even with
// no write in flight.
//
// It is therefore also how long a client that stops reading can hold its stream
// once the kernel's buffers are full, with the exceptions EventWriter lists. It has
// no override, as the rest of the adapter contract has none.
const StreamWriteWindow = 2 * time.Minute

// ErrStreamingUnsupported is what ResponseWriter.Stream returns when the writer
// cannot stream at all, having written nothing and without running the body. A
// consumer's own ResponseWriter over a framework that cannot deliver a response
// while it is still open returns it. So do the net/http and gin writers when the
// http.ResponseWriter they adapt cannot flush, which is not the same as a client
// leaving: a stream that treated it so would close at once, and a browser would
// reconnect for ever. An ordinary answer can still be written after it.
//
// A consumer's middleware that wraps the http.ResponseWriter (logging, metrics, gzip)
// therefore needs an Unwrap() http.ResponseWriter method, which is how
// http.ResponseController reaches the connection through it, or streams are refused
// behind it. A Flush or FlushError method alone is enough to stream, but then the write
// deadline cannot be moved, and a panic that a recovery middleware catches cannot cut
// the connection, so it can look like a complete response (see ResponseWriter.Stream).
// http.TimeoutHandler's writer has neither method, and cannot stream.
//
// A FlushError that returns http.ErrNotSupported is believed as well. It is asked before
// anything is sent only at the bottom of the Unwrap chain, on a writer with no
// SetWriteDeadline, and that has one rare cost:
//
//   - A wrapper with a FlushError and no Unwrap has its own WriteHeader skipped, because
//     the flush it was asked for has already sent the head.
//
// A FlushError anywhere else is reached only after a status has been named: one above an
// Unwrap, and a writer with a SetWriteDeadline and no Unwrap, which is taken for the
// connection. If one of those says so, the body still does not run and this is still
// returned, but a status has been sent, and the deadline has been moved.
//
// A chain of 32 wrappers or more, or one whose Unwrap never ends, counts as unable to
// flush.
var ErrStreamingUnsupported = errors.New("httpsec: response writer cannot stream")

// ErrStreamingStarted is what ResponseWriter.Stream returns when the response
// has already begun, through WriteHeader, Write or an earlier Stream, or, where the
// response is written after the chain has returned, when that has happened: the fiber
// writer of a chain that has returned. Nothing more is written. Write returns it too
// once a stream has started, so that nothing reaches the client except what the
// stream's body writes.
var ErrStreamingStarted = errors.New("httpsec: response already started")

// EventWriter is what the body of a stream writes through. It is only for the
// body it was handed to, and is not safe for use by several goroutines at once.
//
// Write queues bytes, and may hold them until Flush.
//
// Flush hands everything written so far on to be sent. A nil Flush does not promise
// delivery. On net/http and gin it goes through http.ResponseController, so the first
// wrapper with a Flush or a FlushError decides what happens next, and a Flush returns no
// error: a compression middleware's holds the head until its first write. Past the
// wrappers, the bytes have been accepted by the connection, which can mean only the
// kernel's buffers. On fiber they have reached an in-memory pipe that fasthttp drains to
// the connection on its own goroutine, so a failure comes back from a later call, if at
// all. A failed Flush or Write ends the body's context as well as returning the error.
//
// Every Write and every Flush first move the connection's write deadline to
// StreamWriteWindow from now, so a server's write timeout does not end the stream as
// long as the body writes more often than that.
//
// # A client that stops reading
//
// A client that closes or half-closes is seen at once (ResponseWriter.Stream). One
// that simply stops reading is not, and holds its stream until a write to it blocks.
// The kernel's buffers absorb writes first, and at one small heartbeat every 15
// seconds that can take days, so until then only what ends the session limits it.
// Once they are full:
//
//   - net/http and gin over HTTP/1.1, and a stream stopped by HTTP/2's flow control:
//     StreamWriteWindow, and over TLS up to 5 seconds more, because closing a TLS
//     connection sends its alert under a deadline of its own.
//   - fiber: up to about 5 of the body's flush intervals plus StreamWriteWindow,
//     because each flush the pipe accepts also moves the deadline of the socket write
//     that is stuck.
//   - net/http and gin over HTTP/2 when the TCP connection itself stalls: the adapter
//     cannot bound it, and the body stays blocked. Go's server sends nothing while a
//     frame write is blocked. Set HTTP2.WriteByteTimeout on the http.Server, which is
//     the consumer's.
type EventWriter interface {
	io.Writer
	Flush() error
}
