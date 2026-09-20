package authenticate

import "context"

// contextKey is this package's own key type for context values.
//
// It is unexported and has no exported methods, so nothing outside this package
// can construct a value of it. That is what stops another package's key from
// colliding with this one and overwriting, or reading, the authentication a
// request carries.
type contextKey struct{}

// authenticationKey is the one key under which a request's authentication
// travels.
var authenticationKey contextKey

// WithAuthentication returns a copy of ctx carrying a.
//
// An authentication interceptor calls this once a Manager has resolved the
// caller, and everything downstream reads the result back rather than
// authenticating again.
//
// Attaching nothing is allowed and attaches nothing a reader will accept: see
// AuthenticationFromContext.
func WithAuthentication(ctx context.Context, a *Authentication) context.Context {
	return context.WithValue(ctx, authenticationKey, a)
}

// AuthenticationFromContext returns the authentication ctx carries, reporting
// whether one was present.
//
// It reports false for a context carrying nothing and for one carrying a nil
// result, so a caller that checks the second return value is never handed a nil
// to dereference, and a caller that ignores it gets nothing it could mistake for
// an authenticated caller. Returning a zero-valued Authentication instead would
// hand over exactly such a mistake: a result with no principal that no refusal
// ever produced.
func AuthenticationFromContext(ctx context.Context) (*Authentication, bool) {
	a, ok := ctx.Value(authenticationKey).(*Authentication)
	if !ok || a == nil {
		return nil, false
	}

	return a, true
}
