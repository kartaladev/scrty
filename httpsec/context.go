package httpsec

import (
	"context"

	"github.com/kartaladev/scrty/session"
)

// sessionKey is this package's own context key for the session.
//
// The session package exports no context helper, so the chain owns the key.
// It is an unexported empty struct type, so no other package can collide with
// it or overwrite what the chain published, and nothing outside this package
// can put a value under it that a later interceptor would trust.
type sessionKey struct{}

// withSession publishes s on a context derived from ctx, so every later
// interceptor and the downstream handler read the session the chain resolved.
//
// It derives rather than replaces: everything already on ctx, including an
// upstream request identifier and the client's cancellation, is still there.
func withSession(ctx context.Context, s *session.Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// SessionFromContext returns the session the chain resolved for this request.
//
// It is how a handler reads the session without the consumer having to know
// how the chain stores it. An absent session is reported absent rather than as
// an empty one, and a nil session published by an interceptor reads the same
// way, so a caller that ignores ok is never handed something it could mistake
// for a live session.
func SessionFromContext(ctx context.Context) (*session.Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(*session.Session)
	return s, ok && s != nil
}
