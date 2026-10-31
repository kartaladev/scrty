package httpsec

import (
	"context"
	"fmt"
	"net/http"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/guardauth"
)

// Guards builds the per-endpoint authorization a consumer puts in front of one
// net/http route, for the decisions that belong at the operation rather than in
// the chain's centralized rule set.
//
// A guard is enforced in addition to any rule: the chain decides what the whole
// deployment says about a request, and the guard decides what this one
// operation asks of the caller. Every guard fails closed — it refuses without
// calling the route whenever it cannot establish that the caller may proceed —
// so a route that is wired but not yet reasoned about is shut rather than open.
//
// Guards are safe for concurrent use and are built once, at wiring time.
type Guards struct {
	// authorizer is the fallback judge, for a guard used outside a chain or in
	// front of one that published none. The chain's own authorizer is preferred
	// whenever the request carries one. It is never an interface holding a nil
	// value: NewGuards stores that as nil, so it is no judge rather than a
	// nil-method panic.
	authorizer authorize.Authorizer

	// chainAuthorizer is the consumer's declaration that the guards rely on
	// the authorizer the chain publishes on each request.
	chainAuthorizer bool

	// onError answers a refusal, and nil means the library's own default.
	onError func(w http.ResponseWriter, r *http.Request, err error)
}

// GuardOption configures the guards a consumer builds. A nil option is skipped,
// so a consumer assembling the slice conditionally need not filter it.
type GuardOption func(*Guards)

// NewGuards returns the guards for one set of routes, judging through az.
//
// A guard prefers the authorizer the chain published on the request, and az is
// the fallback for a request that carries none. Guards must be told where their
// judge comes from: az, WithChainAuthorizer, or both.
//
// It fails with an error wrapping ErrConfig when az is nil, or an interface
// holding a nil value, and WithChainAuthorizer was not given. Guards built with
// neither would refuse every request at run time, which looks the same as
// wiring that meant to rely on the chain; refusing here tells the two apart
// before traffic arrives. With WithChainAuthorizer, a nil az — typed or not —
// means no fallback, and a request the chain published no authorizer on is
// refused with authorize.ErrAccessDenied.
func NewGuards(az authorize.Authorizer, opts ...GuardOption) (*Guards, error) {
	g := &Guards{}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		opt(g)
	}

	// A nil az, typed or not, comes back as no fallback at all, so the guard
	// refuses rather than calling a method on a nil value.
	fallback, ok := guardauth.Fallback(az, g.chainAuthorizer)
	if !ok {
		return nil, newConfigError(
			"NewGuards needs an authorizer, or WithChainAuthorizer to rely on the chain's")
	}

	g.authorizer = fallback

	return g, nil
}

// WithChainAuthorizer declares that the guards rely on the authorizer the chain
// publishes on each request, as EnableAuthorization does.
//
// Default: NewGuards refuses a nil authorizer, because guards with no judge
// refuse every request. This option is the consumer's statement that the
// missing authorizer is deliberate. A guard then judges with the request's
// authorizer and refuses, with authorize.ErrAccessDenied, a request that
// carries none. Given beside a non-nil authorizer, it changes nothing: the
// request's authorizer is preferred and the one passed to NewGuards is the
// fallback.
func WithChainAuthorizer() GuardOption {
	return func(g *Guards) { g.chainAuthorizer = true }
}

// WithGuardErrorHandler replaces what a guard's refusal answers with.
//
// Default: the status StatusForError gives and no body, so nothing the guard
// knew reaches a client the consumer did not choose to send it to. A handler
// set here receives the response writer, the request and the refusal for every
// guard built from these Guards, and the default response is not written. Pass
// the same function to WithErrorHandler so a chain refusal and a guard refusal
// are rendered alike.
func WithGuardErrorHandler(fn func(w http.ResponseWriter, r *http.Request, err error)) GuardOption {
	return func(g *Guards) { g.onError = fn }
}

// refuse answers a refusal and never calls the route.
func (g *Guards) refuse(w http.ResponseWriter, r *http.Request, err error) {
	if g.onError != nil {
		g.onError(w, r, err)

		return
	}

	// The status and nothing else. A body here would either leak what the
	// refusal knew — a store's error text, whether a record exists — or invent
	// a format the consumer must then work around.
	w.WriteHeader(StatusForError(err))
}

// authorizerFor is where every guard finds its judge.
//
// The chain's authorizer wins, so one wiring decides for every guard behind it,
// and the one the guard was built with is the fallback for a guard used outside
// a chain. When there is neither, the guard refuses.
func (g *Guards) authorizerFor(ctx context.Context) (authorize.Authorizer, bool) {
	return guardauth.For(ctx, g.authorizer)
}

// judgement is what one guard asks about a request once the caller and the
// judge have been established.
//
// req is the guard's own view of the request, so an extractor reads the path
// and the headers through the same abstraction the chain's interceptors read.
type judgement func(ctx context.Context, req Request, az authorize.Authorizer) error

// guard turns one judgement into route middleware.
//
// The preamble is the same for every guard, and it is the fail-closed contract:
// a request with no caller is told to authenticate, a request with no judge is
// refused, and only then is the guard's own question asked. The route runs only
// when the judgement answered nil.
func (g *Guards) guard(judge judgement) func(http.Handler) http.Handler {
	return func(route http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			if _, ok := identity.PrincipalFromContext(ctx); !ok {
				g.refuse(w, r, authenticationRequired(nil))

				return
			}

			az, ok := g.authorizerFor(ctx)
			if !ok {
				g.refuse(w, r, fmt.Errorf(
					"%w: no authorizer was wired for this route", authorize.ErrAccessDenied))

				return
			}

			if err := judge(ctx, NewHTTPRequest(r), az); err != nil {
				// Handed on as it came. The extractor's error says the record
				// could not be identified and the authorizer's says what it
				// decided or what it could not reach, and rewriting either here
				// would cost the consumer the reason.
				g.refuse(w, r, err)

				return
			}

			route.ServeHTTP(w, r)
		})
	}
}

// RequireAuthenticated guards a route that any known caller may reach.
//
// It asks the authorizer nothing, because there is nothing to judge beyond who
// the caller is — but it still refuses a request with no authorizer at all,
// because that is a route whose wiring is incomplete rather than one whose
// caller has been cleared.
func (g *Guards) RequireAuthenticated() func(http.Handler) http.Handler {
	if g == nil {
		panic("httpsec: RequireAuthenticated needs non-nil Guards")
	}

	return g.guard(func(context.Context, Request, authorize.Authorizer) error { return nil })
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
	if g == nil {
		panic("httpsec: ResourcePrivileges needs non-nil Guards")
	}

	return &PrivilegeGuard{guards: g, group: group, resource: resource}
}

// RequireOne guards a route with a single privilege on the resource.
func (p *PrivilegeGuard) RequireOne(privilege string) func(http.Handler) http.Handler {
	return p.require(authorize.MatchAllOf, privilege)
}

// RequireAll guards a route with every one of the named privileges.
//
// It is the safe reading of a list, and it is what a guard naming no mode gets:
// a forgotten mode narrows what a caller may do rather than widening it.
func (p *PrivilegeGuard) RequireAll(privileges ...string) func(http.Handler) http.Handler {
	return p.require(authorize.MatchAllOf, privileges...)
}

// RequireAny guards a route with any one of the named privileges.
func (p *PrivilegeGuard) RequireAny(privileges ...string) func(http.Handler) http.Handler {
	return p.require(authorize.MatchAnyOf, privileges...)
}

// require builds the guard that asks for privileges in mode.
//
// The attributes are rebuilt per request rather than shared, so nothing a guard
// hands the authorizer can be mutated by another request in flight.
func (p *PrivilegeGuard) require(
	mode authorize.MatchMode,
	privileges ...string,
) func(http.Handler) http.Handler {
	required := append([]string(nil), privileges...)

	return p.guards.guard(func(ctx context.Context, _ Request, az authorize.Authorizer) error {
		return az.Authorize(ctx, authorize.PrivilegeAttributes{
			Group:    p.group,
			Resource: p.resource,
			Required: append([]string(nil), required...),
			Mode:     mode,
		})
	})
}

// OwnershipChecker reports whether subject owns the record id names.
//
// There is no default, and there can be none: it is the consumer's own
// function, over the consumer's own identifier type, because only they know
// what owning a record means in their data. A guard built without one has no
// question to ask, so ResourceOwnerships is the only way an ownership guard
// comes into being. An error means the question could not be answered, which is
// an outage on the authorization path and never a judgement about the caller.
type OwnershipChecker[ID any] func(ctx context.Context, subject *identity.Principal, id ID) (bool, error)

// OwnershipGuard names the resource an ownership guard is about. It is built by
// ResourceOwnerships and finished by ForResource.
type OwnershipGuard[ID any] struct {
	guards *Guards

	group    string
	resource string
	checker  OwnershipChecker[ID]
}

// ResourceOwnerships starts a guard over records of the named resource, owned
// as checker says they are.
//
// It is a function rather than a method because a method cannot introduce a
// type parameter of its own, and the identifier type belongs to the consumer's
// records rather than to the guards as a whole.
//
// It panics with "httpsec: ResourceOwnerships needs non-nil Guards" when g is
// nil, and with "httpsec: ResourceOwnerships needs a non-nil checker" when
// checker is nil. The checker has no default and no guard can work without it,
// so a nil one is a wiring mistake that must surface when the route is wired,
// not as a refusal of every request once traffic arrives. The builders return
// no error, so a panic is how they report it, as net/http's Handle does for a
// nil handler.
func ResourceOwnerships[ID any](
	g *Guards,
	group, resource string,
	checker OwnershipChecker[ID],
) *OwnershipGuard[ID] {
	if g == nil {
		panic("httpsec: ResourceOwnerships needs non-nil Guards")
	}
	if checker == nil {
		panic("httpsec: ResourceOwnerships needs a non-nil checker")
	}

	return &OwnershipGuard[ID]{guards: g, group: group, resource: resource, checker: checker}
}

// ForResource guards a route with ownership of the record extract names.
//
// extract reads the identifier from the request — a path segment, a query
// parameter, a header — and its error is the refusal, unchanged: a record that
// cannot be identified is not a caller who may not act, and the consumer sees
// which of the two happened. It runs before the authorizer is asked anything,
// so a malformed request costs no ownership lookup.
//
// It panics with "httpsec: ForResource needs a non-nil extractor" when extract
// is nil, for the reason ResourceOwnerships panics on a nil checker.
func (o *OwnershipGuard[ID]) ForResource(
	extract func(Request) (ID, error),
) func(http.Handler) http.Handler {
	if extract == nil {
		panic("httpsec: ForResource needs a non-nil extractor")
	}

	return o.guards.guard(func(ctx context.Context, req Request, az authorize.Authorizer) error {
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
