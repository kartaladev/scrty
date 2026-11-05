package fibersec

import (
	"bufio"
	"context"
	"net"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/kartaladev/scrty/httpsec"
)

// This file exposes what the package's tests need and consumers must not have.
// It is a test file, so nothing here reaches a production build.
//
// The adapters are unexported because a consumer reaches them through
// Middleware and never builds one: the chain owns the exchange, and a request
// or a writer built beside it would be one the chain never judged.

// NewRequest exposes the request adapter, so a test can read an accessor
// against a fiber context it holds itself.
func NewRequest(c fiber.Ctx) httpsec.Request { return request{c: c} }

// NewResponseWriter exposes the response adapter, for the same reason.
func NewResponseWriter(c fiber.Ctx) httpsec.ResponseWriter { return &responseWriter{c: c} }

// NewResponseWriterWithStreamWindow is NewResponseWriter with another write
// window, which is how a test shows what a stream's deadline does without waiting
// for the real one. A consumer has no such option: the window is one constant.
func NewResponseWriterWithStreamWindow(c fiber.Ctx, window time.Duration) httpsec.ResponseWriter {
	return &responseWriter{c: c, streamWindow: window}
}

// NewEventWriter exposes a stream's writer over what the test supplies, so that a
// failure can reach it alone, ahead of the reader that sees the client go.
func NewEventWriter(bw *bufio.Writer, conn net.Conn, window time.Duration, cancel context.CancelFunc) httpsec.EventWriter {
	return &eventWriter{bw: bw, conn: conn, window: window, cancel: cancel}
}
