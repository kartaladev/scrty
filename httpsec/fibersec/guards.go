package fibersec

import (
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/eventsink"
	"github.com/kartaladev/scrty/internal/guardauth"
	"github.com/kartaladev/scrty/pkg/clock"
)

// Guards builds the per-endpoint authorization a consumer puts in front of one
// fiber route, for the decisions that belong at the operation rather than in
// the chain's centralized rule set.
//
// A guard is enforced in addition to any rule: the chain decides what the whole
// deployment says about a request, and the guard decides what this one
// operation asks of the caller. Every guard fails closed — it refuses without
// calling the route whenever it cannot establish that the caller may proceed —
// so a route that is wired but not yet reasoned about is shut rather than open.
//
// A refusal is answered exactly as the chain's own are: returned as a
// RefusalError, so the route and every fiber handler behind it are skipped and
// fiber's error handler decides what the client is told.
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

	// window is how recently a recency guard built without a window of its
	// own requires the identity to have been proved.
	window time.Duration

	// clock is where a recency guard reads the current time.
	clock clock.Clock

	// authTime replaces the session as where a recency guard finds when the
	// caller last proved their identity. It is used only when authTimeSet,
	// which tells an absent source the consumer passed from no option at all.
	authTime    func(ctx context.Context) (time.Time, bool)
	authTimeSet bool

	// recency judges every recency guard, built by NewGuards from the
	// options above.
	recency *guardauth.Recency
}

// GuardOption configures the guards a consumer builds. A nil option is skipped,
// so a consumer assembling the slice conditionally need not filter it.
//
// It has the shape of its net/http and gin counterparts, but carries no error
// handler option: on fiber, how a refusal is answered is already
// fiber.Config.ErrorHandler. A guard returns its refusal, and the consumer's own
// handler renders it. ErrorHandler is the library's default for that, and
// MapError is there for a handler that renders its own body.
type GuardOption func(*Guards)

// NewGuards returns the guards for one set of fiber routes, judging through az.
//
// It follows httpsec.NewGuards' construction rule. A guard prefers the
// authorizer the chain published on the request, and az is the fallback for a
// request that carries none. Guards must be told where their judge comes from:
// az, WithChainAuthorizer, or both.
//
// It fails with an error wrapping httpsec.ErrConfig when az is nil, or an
// interface holding a nil value, and WithChainAuthorizer was not given: guards
// with no judge would refuse every request, which looks the same as wiring
// that meant to rely on the chain. With WithChainAuthorizer, a nil az — typed
// or not — means no fallback, and a request the chain published no authorizer
// on is refused with authorize.ErrAccessDenied.
//
// It also fails with an error wrapping httpsec.ErrConfig when a recency option
// was given something no recency guard could judge with: a window of zero or
// less (WithRecentAuthenticationWindow), a nil or typed-nil clock
// (WithGuardClock), or a nil authentication-time source
// (WithAuthenticationTime). The message names the option.
//
// A wiring that is wrong in both ways reports the recency option first, on
// every adapter, so one mistake is one error whichever adapter builds the
// guards.
func NewGuards(az authorize.Authorizer, opts ...GuardOption) (*Guards, error) {
	g := &Guards{window: DefaultRecentAuthenticationWindow, clock: clock.System()}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		opt(g)
	}

	// The recency options are judged first, as the net/http and gin guards
	// judge them, so one wiring mistake is one error on every adapter.
	if err := g.buildRecency(); err != nil {
		return nil, err
	}

	// A nil az, typed or not, comes back as no fallback at all, so the guard
	// refuses rather than calling a method on a nil value.
	fallback, ok := guardauth.Fallback(az, g.chainAuthorizer)
	if !ok {
		return nil, fmt.Errorf(
			"%w: fibersec: NewGuards needs an authorizer, or WithChainAuthorizer to rely on the chain's",
			httpsec.ErrConfig)
	}

	g.authorizer = fallback

	return g, nil
}

// WithChainAuthorizer declares that the guards rely on the authorizer the chain
// publishes on each request, as httpsec.EnableAuthorization does.
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
// and the headers through the same abstraction the chain's interceptors read,
// and one extractor is written once for every framework.
type judgement func(ctx context.Context, req httpsec.Request, az authorize.Authorizer) error

// guard turns one judgement into fiber middleware.
//
// The preamble is the same for every guard, and it is the fail-closed contract:
// a request with no caller is told to authenticate, a request with no judge is
// refused, and only then is the guard's own question asked. The handlers behind
// it run only when the judgement answered nil.
func (g *Guards) guard(judge judgement) fiber.Handler {
	return func(fc fiber.Ctx) error {
		ctx := fc.Context()

		if _, ok := identity.PrincipalFromContext(ctx); !ok {
			return newRefusal(authenticationRequired())
		}

		az, ok := g.authorizerFor(ctx)
		if !ok {
			err := fmt.Errorf("%w: no authorizer was wired for this route", authorize.ErrAccessDenied)
			eventsink.GuardRefused(ctx, err)

			return newRefusal(err)
		}

		if err := judge(ctx, request{c: fc}, az); err != nil {
			eventsink.GuardRefused(ctx, err)

			// Wrapped, not rewritten. The extractor's error says the record
			// could not be identified and the authorizer's says what it decided
			// or what it could not reach, and either is still reachable through
			// the RefusalError.
			return newRefusal(err)
		}

		return fc.Next()
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
func (g *Guards) RequireAuthenticated() fiber.Handler {
	if g == nil {
		panic("fibersec: RequireAuthenticated needs non-nil Guards")
	}

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
	if g == nil {
		panic("fibersec: ResourcePrivileges needs non-nil Guards")
	}

	return &PrivilegeGuard{guards: g, group: group, resource: resource}
}

// RequireOne guards a route with a single privilege on the resource.
func (p *PrivilegeGuard) RequireOne(privilege string) fiber.Handler {
	return p.require(authorize.MatchAllOf, privilege)
}

// RequireAll guards a route with every one of the named privileges.
//
// It is the safe reading of a list, and it is what a guard naming no mode gets:
// a forgotten mode narrows what a caller may do rather than widening it.
func (p *PrivilegeGuard) RequireAll(privileges ...string) fiber.Handler {
	return p.require(authorize.MatchAllOf, privileges...)
}

// RequireAny guards a route with any one of the named privileges.
func (p *PrivilegeGuard) RequireAny(privileges ...string) fiber.Handler {
	return p.require(authorize.MatchAnyOf, privileges...)
}

// require builds the guard that asks for privileges in mode.
//
// The attributes are rebuilt per request rather than shared, so nothing a guard
// hands the authorizer can be mutated by another request in flight.
func (p *PrivilegeGuard) require(mode authorize.MatchMode, privileges ...string) fiber.Handler {
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

// DefaultRecentAuthenticationWindow is how recently a recency guard requires
// the caller to have proved their identity when neither
// WithRecentAuthenticationWindow nor RequireAuthenticationWithin says
// otherwise. It is the core guards' window, httpsec.DefaultRecentAuthenticationWindow,
// so a deployment on either adapter is judged alike.
const DefaultRecentAuthenticationWindow = httpsec.DefaultRecentAuthenticationWindow

// WithRecentAuthenticationWindow sets how recently every recency guard built
// from these Guards requires the caller to have proved their identity, unless
// the route names its own window with RequireAuthenticationWithin.
//
// Default: DefaultRecentAuthenticationWindow, 15 minutes. The window is fixed,
// counted from the caller's authentication time (the session's, or the one
// WithAuthenticationTime reports), and nothing but an authentication moves it:
// calling a guarded route does not extend it, nor does a session renewal. A
// window of zero or less fails NewGuards with httpsec.ErrConfig, since no
// caller could ever meet it. For a session, a window longer than its absolute
// lifetime (session.WithAbsoluteTimeout) is never reached: the session ends
// first, so the guard refuses only a caller with no recorded authentication
// time.
func WithRecentAuthenticationWindow(window time.Duration) GuardOption {
	return func(g *Guards) { g.window = window }
}

// WithGuardClock replaces where recency guards read the current time.
//
// Default: the system clock (clock.System). Guards are built outside the
// chain and see none of its configuration, so a consumer who gives the chain
// a clock with httpsec.WithClock passes the same one here; otherwise the
// guards judge a session's authentication time, which the chain recorded on
// its clock, against another. A nil clock, or an interface holding a nil
// value, fails NewGuards with httpsec.ErrConfig rather than falling back to
// the system clock.
func WithGuardClock(clock clock.Clock) GuardOption {
	return func(g *Guards) { g.clock = clock }
}

// WithAuthenticationTime replaces where recency guards find when the caller
// last proved their identity.
//
// Default: the authentication time of the request's session
// (httpsec.SessionFromContext), and a request with no session — a caller
// authenticated by an API key, HTTP Basic or a consumer's own first factor —
// is refused with httpsec.ErrReauthenticationRequired. fn receives the
// request's context, with the caller on it (identity.PrincipalFromContext),
// and reports the time and whether there is one; reporting none refuses the
// request. When given, fn replaces the session lookup entirely: a consumer
// who wants both reads the session inside fn. A nil fn fails NewGuards with
// httpsec.ErrConfig.
func WithAuthenticationTime(fn func(ctx context.Context) (time.Time, bool)) GuardOption {
	return func(g *Guards) {
		g.authTime = fn
		g.authTimeSet = true
	}
}

// buildRecency builds the recency judge from the options, refusing those no
// guard could judge with. The request's session is the time source unless
// WithAuthenticationTime was given.
func (g *Guards) buildRecency() error {
	authTime := g.authTime
	if !g.authTimeSet {
		authTime = guardauth.SessionAuthenticationTime(httpsec.SessionFromContext)
	}

	recency, reason := guardauth.NewRecency(g.window, g.clock, authTime)
	if reason != "" {
		return fmt.Errorf("%w: fibersec: %s", httpsec.ErrConfig, reason)
	}

	g.recency = recency

	return nil
}

// RequireRecentAuthentication guards a route that the caller may reach only
// if they proved their identity recently: within the window
// WithRecentAuthenticationWindow sets, DefaultRecentAuthenticationWindow
// (15 minutes) by default.
//
// It is RequireAuthenticationWithin with the guards' window, and judges
// exactly as that does: the authentication time from the request's session
// unless WithAuthenticationTime replaces it, now from the system clock unless
// WithGuardClock replaces it — pass the chain's clock there. Stack it inside
// the privilege and ownership guards, so that a caller who may not act is told
// access denied rather than to re-authenticate. A guards' window longer than
// the session's absolute lifetime is never reached. It panics at wiring when g
// is nil.
func (g *Guards) RequireRecentAuthentication() fiber.Handler {
	if g == nil {
		panic("fibersec: RequireRecentAuthentication needs non-nil Guards")
	}

	return g.recent(0)
}

// RequireAuthenticationWithin guards a route that the caller may reach only
// if they proved their identity no longer than window ago. The route's window
// takes precedence over the guards' (WithRecentAuthenticationWindow).
//
// Like every guard, it first refuses a request with no caller
// (httpsec.ErrAuthenticationRequired, 401) and one with no authorizer
// (authorize.ErrAccessDenied). It then finds the caller's authentication
// time — the request's session's, by default, or what WithAuthenticationTime
// reports — and refuses with a *httpsec.ReauthenticationRequiredError
// carrying window (httpsec.ErrReauthenticationRequired, 403) when there is
// none, or when it is longer than window before the guards' clock
// (WithGuardClock) reads now. The refusal is returned, so fiber's error
// handler renders it. The window is inclusive, an authentication time ahead of
// the clock counts as just now, and the window is fixed: calling the route
// does not extend it, and only a sign-in, a second factor at sign-in or a
// re-authentication moves the time.
//
// Stack it inside the privilege and ownership guards, so that it runs after
// them. A window longer than the session's absolute lifetime is never
// reached. It panics at wiring, with a message naming the window, when window
// is zero or less, and when g is nil, as the other builders do.
func (g *Guards) RequireAuthenticationWithin(window time.Duration) fiber.Handler {
	if g == nil {
		panic("fibersec: RequireAuthenticationWithin needs non-nil Guards")
	}

	if window <= 0 {
		panic(fmt.Sprintf("fibersec: RequireAuthenticationWithin needs a window above zero, got %s", window))
	}

	return g.recent(window)
}

// recent builds the recency guard over window, zero meaning the guards'.
func (g *Guards) recent(window time.Duration) fiber.Handler {
	return g.guard(func(ctx context.Context, _ httpsec.Request, _ authorize.Authorizer) error {
		if recent, judged := g.recency.Judge(ctx, window); !recent {
			return &httpsec.ReauthenticationRequiredError{Window: judged}
		}

		return nil
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
// checker is the chain's own httpsec.OwnershipChecker, so one consumer function
// serves the net/http guards, the gin guards and these alike.
//
// It is a function rather than a method because a method cannot introduce a
// type parameter of its own, and the identifier type belongs to the consumer's
// records rather than to the guards as a whole.
//
// It panics with "fibersec: ResourceOwnerships needs non-nil Guards" when guards is nil,
// and with "fibersec: ResourceOwnerships needs a non-nil checker" when checker is
// nil. The checker has no default and no guard can work without it, so a nil
// one is a wiring mistake that must surface when the route is wired, not as a
// refusal of every request once traffic arrives. There is no override: a
// consumer who wants no ownership check does not build an ownership guard.
func ResourceOwnerships[ID any](
	guards *Guards,
	group, resource string,
	checker httpsec.OwnershipChecker[ID],
) *OwnershipGuard[ID] {
	if guards == nil {
		panic("fibersec: ResourceOwnerships needs non-nil Guards")
	}
	if checker == nil {
		panic("fibersec: ResourceOwnerships needs a non-nil checker")
	}

	return &OwnershipGuard[ID]{guards: guards, group: group, resource: resource, checker: checker}
}

// ForResource guards a route with ownership of the record extract names.
//
// extract reads the identifier from the request — a path segment, a query
// parameter, a header — and its error is the refusal: a record that cannot be
// identified is not a caller who may not act, and the consumer sees which of
// the two happened. It runs before the authorizer is asked anything, so a
// malformed request costs no ownership lookup.
//
// It panics with "fibersec: ForResource needs a non-nil extractor" when extract
// is nil, for the reason ResourceOwnerships panics on a nil checker.
func (o *OwnershipGuard[ID]) ForResource(
	extract func(httpsec.Request) (ID, error),
) fiber.Handler {
	if extract == nil {
		panic("fibersec: ForResource needs a non-nil extractor")
	}

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
