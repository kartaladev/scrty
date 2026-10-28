package fibersec

import (
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
