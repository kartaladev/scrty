package ginsec

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// streamWriter keeps a stream from trusting gin's Flush, which sends the status and
// then looks only for an http.Flusher below it: over anything else it does nothing and
// returns no error, so a stream would seem to work and deliver nothing.
//
// What it cannot see through is described on Middleware.
type streamWriter struct{ gin.ResponseWriter }

// Unwrap is how http.ResponseController reaches the connection's deadline.
func (s streamWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// FlushError does what gin's Flush does, and reports what happened.
func (s streamWriter) FlushError() error {
	s.WriteHeaderNow()

	var below http.ResponseWriter = s.ResponseWriter
	if u, ok := below.(interface{ Unwrap() http.ResponseWriter }); ok {
		below = u.Unwrap()
	}

	return http.NewResponseController(below).Flush()
}
