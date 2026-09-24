package ginsec

import (
	"context"
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// Guards builds the per-endpoint authorization a consumer puts in front of one
// gin route, for the decisions that belong at the operation rather than in the
// chain's centralized rule set.
//
// A guard is enforced in addition to any rule: the chain decides what the whole
// deployment says about a request, and the guard decides what this one
// operation asks of the caller. Every guard fails closed — it refuses without
// calling the route whenever it cannot establish that the caller may proceed —
// so a route that is wired but not yet reasoned about is shut rather than open.
//
// A refusal is answered exactly as the chain's own are: the error on gin's
// error channel, the mapped status set but not committed, and the remaining gin
// handlers stopped. Handlers registered after a guard do not run for a refused
// request.
//
// Guards are safe for concurrent use and are built once, at wiring time.
type Guards struct {
	// authorizer is the fallback judge, for a guard used outside a chain or in
	// front of one that published none. The chain's own authorizer is preferred
	// whenever the request carries one.
	authorizer authorize.Authorizer

	// onError answers a refusal, and nil means the library's own default.
	onError func(gc *gin.Context, err error)
}

// GuardOption configures the guards a consumer builds. A nil option is skipped,
// so a consumer assembling the slice conditionally need not filter it.
type GuardOption func(*Guards)

// NewGuards returns the guards for one set of gin routes, judging through az.
//
// az is the fallback: a guard prefers the authorizer the chain published on the
// request, so a deployment that mounts the chain wires its authorizer once and
// may pass nil here. With neither, every guard refuses, because a guard that
// found no judge has not been told the request is allowed.
//
// It reports no error because there is nothing to misconfigure: a missing
// authorizer is a refusal at the guard rather than a fault at wiring time,
// since the chain may still supply one per request.
func NewGuards(az authorize.Authorizer, opts ...GuardOption) *Guards {
	g := &Guards{authorizer: az}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		opt(g)
	}

	return g
}

// WithGuardErrorHandler replaces what a guard's refusal answers with.
//
// Default: the refusal on gin's error channel and the status StatusForError
// gives, set but not committed, so the consumer's own gin error middleware
// still owns the status, the headers and the body. That middleware is the
// override most gin applications want, because it is where they already handle
// every other error; this option is for a guard used without one.
//
// A handler set here receives gin's context and the refusal, and owns the whole
// answer, including its status — nothing else is written for it. The refusal is
// still registered on gin's error channel first, so middleware that only logs
// errors still sees it, and the remaining gin handlers are still stopped, so
// the route never runs whoever writes the answer. A handler that writes nothing
// therefore answers 200, which is a refusal served as a success.
func WithGuardErrorHandler(fn func(gc *gin.Context, err error)) GuardOption {
	return func(g *Guards) { g.onError = fn }
}

// refuse answers a refusal and never calls the route.
func (g *Guards) refuse(gc *gin.Context, err error) {
	if g.onError != nil {
		// Registered first, so a consumer who renders here still has the
		// refusal on the channel their logging middleware reads.
		_ = gc.Error(err)

		g.onError(gc, err)
		gc.Abort()

		return
	}

	// The same answer the chain's own refusals get, from the same place, so a
	// chain refusal and a guard refusal are indistinguishable to a consumer.
	refuse(gc, err)
}

// authorizerFor is where every guard finds its judge.
//
// The chain's authorizer wins, so one wiring decides for every guard behind it,
// and the one the guard was built with is the fallback for a guard used outside
// a chain. When there is neither, the guard refuses.
func (g *Guards) authorizerFor(ctx context.Context) (authorize.Authorizer, bool) {
	if az, ok := authorize.AuthorizerFromContext(ctx); ok {
		return az, true
	}

	if !nilcheck.IsNil(g.authorizer) {
		return g.authorizer, true
	}

	return nil, false
}

// judgement is what one guard asks about a request once the caller and the
// judge have been established.
//
// req is the guard's own view of the request, so an extractor reads the path
// and the headers through the same abstraction the chain's interceptors read,
// and one extractor is written once for every framework.
type judgement func(ctx context.Context, req httpsec.Request, az authorize.Authorizer) error

// guard turns one judgement into gin middleware.
//
// The preamble is the same for every guard, and it is the fail-closed contract:
// a request with no caller is told to authenticate, a request with no judge is
// refused, and only then is the guard's own question asked. The handlers behind
// it run only when the judgement answered nil.
func (g *Guards) guard(judge judgement) gin.HandlerFunc {
	return func(gc *gin.Context) {
		ctx := gc.Request.Context()

		if _, ok := identity.PrincipalFromContext(ctx); !ok {
			g.refuse(gc, authenticationRequired())

			return
		}

		az, ok := g.authorizerFor(ctx)
		if !ok {
			g.refuse(gc, fmt.Errorf(
				"%w: no authorizer was wired for this route", authorize.ErrAccessDenied))

			return
		}

		if err := judge(ctx, httpsec.NewHTTPRequest(gc.Request), az); err != nil {
			// Handed on as it came. The extractor's error says the record could
			// not be identified and the authorizer's says what it decided or
			// what it could not reach, and rewriting either here would cost the
			// consumer the reason.
			g.refuse(gc, err)

			return
		}
	}
}

// authenticationRequired refuses a request that has not said who it is.
//
// The refusal matches both the chain's sentinel and the authorization core's,
// so a consumer who matches either identity reaches it and does not have to
// know whether the chain's stage or a per-endpoint guard refused.
func authenticationRequired() error {
	return fmt.Errorf("%w: %w",
		httpsec.ErrAuthenticationRequired, authorize.ErrAuthenticationRequired)
}

// RequireAuthenticated guards a route that any known caller may reach.
//
// It asks the authorizer nothing, because there is nothing to judge beyond who
// the caller is — but it still refuses a request with no authorizer at all,
// because that is a route whose wiring is incomplete rather than one whose
// caller has been cleared.
func (g *Guards) RequireAuthenticated() gin.HandlerFunc {
	return g.guard(func(context.Context, httpsec.Request, authorize.Authorizer) error { return nil })
}

// PrivilegeGuard names the resource a privilege guard is about. It is built by
// ResourcePrivileges and finished by one of its Require methods.
type PrivilegeGuard struct {
	guards *Guards

	group    string
	resource string
}

// ResourcePrivileges starts a guard over the named resource.
//
// group and resource are spelled as the consumer's own role data spells them:
// the library compares them and never parses them.
func (g *Guards) ResourcePrivileges(group, resource string) *PrivilegeGuard {
	return &PrivilegeGuard{guards: g, group: group, resource: resource}
}

// RequireOne guards a route with a single privilege on the resource.
func (p *PrivilegeGuard) RequireOne(privilege string) gin.HandlerFunc {
	return p.require(authorize.MatchAllOf, privilege)
}

// RequireAll guards a route with every one of the named privileges.
//
// It is the safe reading of a list, and it is what a guard naming no mode gets:
// a forgotten mode narrows what a caller may do rather than widening it.
func (p *PrivilegeGuard) RequireAll(privileges ...string) gin.HandlerFunc {
	return p.require(authorize.MatchAllOf, privileges...)
}

// RequireAny guards a route with any one of the named privileges.
func (p *PrivilegeGuard) RequireAny(privileges ...string) gin.HandlerFunc {
	return p.require(authorize.MatchAnyOf, privileges...)
}

// require builds the guard that asks for privileges in mode.
//
// The attributes are rebuilt per request rather than shared, so nothing a guard
// hands the authorizer can be mutated by another request in flight.
func (p *PrivilegeGuard) require(mode authorize.MatchMode, privileges ...string) gin.HandlerFunc {
	required := append([]string(nil), privileges...)

	return p.guards.guard(func(
		ctx context.Context, _ httpsec.Request, az authorize.Authorizer,
	) error {
		return az.Authorize(ctx, authorize.PrivilegeAttributes{
			Group:    p.group,
			Resource: p.resource,
			Required: append([]string(nil), required...),
			Mode:     mode,
		})
	})
}

// OwnershipGuard names the resource an ownership guard is about. It is built by
// ResourceOwnerships and finished by ForResource.
type OwnershipGuard[ID any] struct {
	guards *Guards

	group    string
	resource string
	checker  httpsec.OwnershipChecker[ID]
}

// ResourceOwnerships starts a guard over records of the named resource, owned
// as checker says they are.
//
// checker is the chain's own OwnershipChecker, so one consumer function serves
// the net/http guards and these alike.
//
// It is a function rather than a method because a method cannot introduce a
// type parameter of its own, and the identifier type belongs to the consumer's
// records rather than to the guards as a whole.
func ResourceOwnerships[ID any](
	g *Guards,
	group, resource string,
	checker httpsec.OwnershipChecker[ID],
) *OwnershipGuard[ID] {
	return &OwnershipGuard[ID]{guards: g, group: group, resource: resource, checker: checker}
}

// ForResource guards a route with ownership of the record extract names.
//
// extract reads the identifier from the request — a path segment, a query
// parameter, a header — and its error is the refusal, unchanged: a record that
// cannot be identified is not a caller who may not act, and the consumer sees
// which of the two happened. It runs before the authorizer is asked anything,
// so a malformed request costs no ownership lookup.
func (o *OwnershipGuard[ID]) ForResource(
	extract func(httpsec.Request) (ID, error),
) gin.HandlerFunc {
	return o.guards.guard(func(
		ctx context.Context, req httpsec.Request, az authorize.Authorizer,
	) error {
		id, err := extract(req)
		if err != nil {
			return err
		}

		return az.Authorize(ctx, authorize.OwnershipAttributes{
			Group:    o.group,
			Resource: o.resource,

			// The identifier is already in hand, so this only renders it: the
			// ownership authorizer carries the resolved identifier into its own
			// error messages, and the consumer's check is asked about the typed
			// value the extractor produced rather than about a string of it.
			ResolveID: func(context.Context) (string, error) { return fmt.Sprint(id), nil },
			OwnedBy: func(ctx context.Context, subject *identity.Principal, _ string) (bool, error) {
				return o.checker(ctx, subject, id)
			},
		})
	})
}
