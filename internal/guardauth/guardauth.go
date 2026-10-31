// Package guardauth holds the one rule for where a route guard finds its
// authorizer.
//
// The guard adapters for net/http, gin and fiber share it, so the three cannot
// disagree about when guards may be built without an authorizer or about which
// authorizer judges a request. Each adapter keeps its own error text and its
// own way of answering a refusal; only the decision lives here.
package guardauth

import (
	"context"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// Fallback decides, at construction, the authorizer guards fall back on when a
// request carries none.
//
// A usable az is the fallback, whether or not the consumer also declared that
// the guards rely on the chain's authorizer. A nil az, or an interface holding
// a nil value, is no fallback at all and is returned as a plain nil, so a guard
// refuses rather than calling a method on a nil value. Guards may be built
// without a fallback only when chainDeclared says the consumer meant it; ok is
// false otherwise, and the caller refuses construction with its own error.
func Fallback(az authorize.Authorizer, chainDeclared bool) (fallback authorize.Authorizer, ok bool) {
	if nilcheck.IsNil(az) {
		return nil, chainDeclared
	}

	return az, true
}

// For returns the authorizer that judges the request ctx belongs to, reporting
// false when there is none and the guard must refuse.
//
// The authorizer the chain published on the request wins, so one wiring
// decides for every guard behind it, and fallback judges a request that
// carries none.
//
// Fallback already stores a typed nil as plain nil, yet fallback is checked
// again here: a later way of setting it could otherwise turn a refusal into a
// nil-method panic, and the check costs little next to a request.
func For(ctx context.Context, fallback authorize.Authorizer) (authorize.Authorizer, bool) {
	if az, ok := authorize.AuthorizerFromContext(ctx); ok {
		return az, true
	}

	if !nilcheck.IsNil(fallback) {
		return fallback, true
	}

	return nil, false
}
