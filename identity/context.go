package identity

import "context"

// principalContextKey is unexported, so nothing outside this package can attach
// or overwrite the principal a context carries.
type principalContextKey struct{}

// WithPrincipal returns a copy of ctx carrying p.
//
// An authentication interceptor calls this once it has resolved the caller;
// everything downstream reads the principal back rather than re-resolving it.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}

// PrincipalFromContext returns the principal ctx carries, reporting whether one
// was present.
//
// It reports false for a context carrying a nil principal, so a caller that
// checks ok is never handed a nil to dereference.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(*Principal)

	return p, ok && p != nil
}

// MustPrincipalFromContext returns the principal ctx carries, and panics with
// ErrNoPrincipal when there is none.
//
// It is for handlers that run behind an authentication interceptor, where a
// missing principal is a wiring mistake rather than a runtime condition: the
// interceptor either resolved a caller or refused the request, so reaching a
// handler without one means the chain was assembled wrongly. Callers that can
// legitimately run unauthenticated use PrincipalFromContext instead.
func MustPrincipalFromContext(ctx context.Context) *Principal {
	p, ok := PrincipalFromContext(ctx)
	if !ok {
		panic(ErrNoPrincipal)
	}

	return p
}
