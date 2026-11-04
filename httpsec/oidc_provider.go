package httpsec

import (
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"time"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/signingkey"
)

const optionOIDCProvider = "EnableOIDCProvider"

// The provider's two slots.
const (
	// OrderOIDCProvider is the provider's endpoints that authenticate a request
	// their own way, or not at all: authorization, token, UserInfo, revocation,
	// introspection, metadata, end-session and its confirmation. It is inside
	// CSRF protection and outside Basic, API key and bearer authentication, which
	// would otherwise refuse a client's credentials and access tokens as their own.
	OrderOIDCProvider Order = 250

	// OrderOIDCProviderSession is the provider's endpoints that need a sign-in the
	// chain has judged: the resume and the user's consents. It is inside the
	// bearer and every gate, so a session owing a step is refused as anywhere on
	// the chain, and inside the session-touch step, which records the activity. It
	// is outside the authorization stage, so a consumer's rules do not reach them.
	OrderOIDCProviderSession Order = 850
)

// oidcEndpoints is the provider on the chain: what the options settled, and what
// the endpoints share.
type oidcEndpoints struct {
	provider *oidcprovider.Provider

	prefix    string
	overrides map[OIDCEndpoint]string

	// paths is where each endpoint answers, settled once the options have applied.
	paths [oidcEndpointCount]string

	pagesCarryFrameAncestors bool

	// groups is the endpoint groups, one per file, in the order they are asked.
	groups []oidcEndpointGroup
	// sessions is the manager the chain's bearer resolves sessions through,
	// settled by wireOIDCProvider.
	sessions *session.Sessions
	// log is the chain's logger, handed over when the chain is wired.
	log *slog.Logger
	// now reads the chain's clock.
	now func() time.Time

	// The endpoint groups, each declared in the file that serves it.
	authorize     oidcAuthorizeGroup
	resume        oidcResumeGroup
	token         oidcTokenGroup
	revoke        oidcRevokeGroup
	userinfo      oidcUserInfoGroup
	metadata      oidcMetadataGroup
	endSession    oidcEndSessionGroup
	logoutConfirm oidcLogoutConfirmGroup
	consents      oidcConsentsGroup
}

// newOIDCEndpoints returns the provider's state with its groups bound, and the
// defaults its options replace.
func newOIDCEndpoints(p *oidcprovider.Provider, now func() time.Time) *oidcEndpoints {
	op := &oidcEndpoints{
		provider:  p,
		now:       now,
		prefix:    DefaultOIDCProviderPrefix,
		overrides: map[OIDCEndpoint]string{},
	}

	op.groups = []oidcEndpointGroup{
		&op.authorize, &op.resume, &op.token, &op.revoke, &op.userinfo,
		&op.metadata, &op.endSession, &op.logoutConfirm, &op.consents,
	}

	for _, g := range op.groups {
		g.bind(op)
	}

	return op
}

// oidcHandler is one endpoint's handler. It has the shape of an interceptor, so
// it can pass on a request it does not answer, such as a method it does not serve.
//
// A refusal the protocol lets it answer itself is written to ex.Writer, with nil
// returned. Any other error it returns goes to the chain's error handling, which
// answers StatusForError and no body unless the consumer replaced it.
type oidcHandler func(ex *Exchange, next Next) error

// oidcRoute is a path an endpoint group answers.
type oidcRoute struct {
	path string

	// inner answers at OrderOIDCProviderSession rather than OrderOIDCProvider:
	// behind the bearer and the gates, so the handler reads the sign-in from
	// ex.Session, which the chain has already judged.
	inner bool

	handle oidcHandler
}

// oidcEndpointGroup is the endpoints one file serves. It keeps what those
// endpoints need in its own type, so a group gains a field, an option or a
// limiter without touching what the other groups share.
//
// Embed oidcGroupBase, which supplies everything but routes.
type oidcEndpointGroup interface {
	// bind hands the group the provider's shared state, before any option runs.
	bind(op *oidcEndpoints)

	// routes names the paths the group answers, once the options have settled
	// them. Two routes on one path refuse the chain.
	routes() []oidcRoute

	// settle runs during assembly, once every option has been applied and before
	// CSRF protection reads what it needs: build a source guard here with
	// c.resolveSourceGuard, or register with another feature. An error refuses
	// the chain. op.sessions is set by then.
	settle(c *config) error

	// wire takes what exists only once the chain does. op.log is set by then.
	wire(ch *Chain)

	// flushRefusalLogs reports what the group's samplers hold back, for
	// Chain.FlushRefusalLogs.
	flushRefusalLogs() error
}

// oidcGroupBase is what a group embeds: the provider's shared state, as op, and
// nothing to do at each step until the group declares its own.
type oidcGroupBase struct{ op *oidcEndpoints }

func (b *oidcGroupBase) bind(op *oidcEndpoints) { b.op = op }

func (*oidcGroupBase) settle(*config) error { return nil }

func (*oidcGroupBase) wire(*Chain) {}

func (*oidcGroupBase) flushRefusalLogs() error { return nil }

// oidcRouter answers the routes it holds, and passes on everything else.
type oidcRouter struct {
	routes map[string]oidcHandler
}

// Intercept matches the path exactly. A handler judges the method, because what a
// wrong method is answered with differs by endpoint.
func (r *oidcRouter) Intercept(ex *Exchange, next Next) error {
	if h, ok := r.routes[ex.Request.Path()]; ok {
		return h(ex, next)
	}

	return next(ex)
}

// oidcOuterRouter is the router at OrderOIDCProvider, which also stands for the
// provider's groups when the chain flushes, so each is flushed once.
type oidcOuterRouter struct {
	oidcRouter

	op *oidcEndpoints
}

func (r *oidcOuterRouter) flushRefusalLogs() error {
	var errs []error

	for _, g := range r.op.groups {
		if err := g.flushRefusalLogs(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// wireOIDCProvider settles the provider's groups against the assembled
// configuration, once every option has been applied.
func (c *config) wireOIDCProvider() error {
	op := c.oidcProvider
	if op == nil {
		return nil
	}

	op.sessions = bearerSessions(c)

	for _, g := range op.groups {
		if err := g.settle(c); err != nil {
			return err
		}
	}

	return nil
}

// wire hands the provider and its groups what exists only once the chain does.
func (op *oidcEndpoints) wire(ch *Chain) {
	op.log = ch.logger

	for _, g := range op.groups {
		g.wire(ch)
	}
}

// EnableOIDCProvider puts the OpenID Provider p on the chain.
//
// Default: its endpoints under DefaultOIDCProviderPrefix, at the paths the
// OIDCEndpoint constants give (WithOIDCProviderPrefix, WithOIDCProviderPath).
//
// A chain that could not serve the provider correctly does not build. Each of
// these is a configuration error naming this option:
//
//   - no bearer mode, because a resume needs a sign-in credential;
//   - no EnableJWKSEndpoint, or one given a *signingkey.Keys the provider does not
//     sign with. A provider of any other type, such as a wrapper, cannot be
//     compared, and builds;
//   - enabling it twice;
//   - two of its paths equal, or one equal to another endpoint of the chain;
//   - a session manager on the chain that does not report sign-in ends to p
//     (session.WithEndObserver), because grants would then outlive a logout;
//   - oidcprovider.WithDPoP disagreeing with EnableDPoP;
//   - an oidcprovider.WithAssertionTokenEndpoint audience other than the path the
//     token endpoint is served on;
//   - no EnableSecurityHeaders, unless WithOIDCPagesCarryFrameAncestors states the
//     consumer's pages protect themselves.
func EnableOIDCProvider(p *oidcprovider.Provider, opts ...OIDCProviderOption) Option {
	return func(c *config) error {
		if err := requireDep(optionOIDCProvider, "provider", p); err != nil {
			return err
		}

		if c.oidcProvider != nil {
			return newConfigError("%s was given twice; one chain has one provider", optionOIDCProvider)
		}

		op := newOIDCEndpoints(p, c.now)

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(op); err != nil {
				return err
			}
		}

		if err := op.settlePaths(); err != nil {
			return err
		}

		outer, inner, err := op.routers()
		if err != nil {
			return err
		}

		c.oidcProvider = op
		c.register(outer, OrderOIDCProvider)
		c.register(inner, OrderOIDCProviderSession)
		c.wire(op.wire)

		// The token endpoint and UserInfo verify bound credentials, so DPoP has
		// something to verify for on a chain with only the provider.
		c.bindingVerifiers = append(c.bindingVerifiers, optionOIDCProvider)

		c.enable(optionOIDCProvider, func() error { return op.check(c) })
		c.checkAfterWiring(func() error { return op.checkReporting(c) })

		return nil
	}
}

// settlePaths works out where each endpoint answers, and refuses two on one path.
func (op *oidcEndpoints) settlePaths() error {
	taken := make(map[string]OIDCEndpoint, oidcEndpointCount)

	for e := range oidcEndpointCount {
		path, ok := op.overrides[e]
		if !ok {
			path = op.prefix + oidcEndpointNames[e].suffix
		}

		if other, clash := taken[path]; clash {
			return newConfigError("%s serves both %s and %s on %q; give each its own path",
				optionOIDCProvider, other, e, path)
		}

		taken[path] = e
		op.paths[e] = path
	}

	return nil
}

// routers gathers each group's routes into the two slots, and refuses two routes
// on one path, a group's own included.
func (op *oidcEndpoints) routers() (*oidcOuterRouter, *oidcRouter, error) {
	outer := &oidcOuterRouter{oidcRouter: oidcRouter{routes: map[string]oidcHandler{}}, op: op}
	inner := &oidcRouter{routes: map[string]oidcHandler{}}

	for _, g := range op.groups {
		for _, route := range g.routes() {
			_, atOuter := outer.routes[route.path]
			_, atInner := inner.routes[route.path]
			if atOuter || atInner {
				return nil, nil, newConfigError("%s has two endpoints on %q; give each its own path",
					optionOIDCProvider, route.path)
			}

			if route.inner {
				inner.routes[route.path] = route.handle
			} else {
				outer.routes[route.path] = route.handle
			}
		}
	}

	return outer, inner, nil
}

// check is what can be judged once every option has been applied.
func (op *oidcEndpoints) check(c *config) error {
	for _, check := range []func(*config) error{
		op.checkBearer,
		op.checkJWKS,
		op.checkCollisions,
		op.checkDPoP,
		op.checkAssertionEndpoint,
		op.checkFrameAncestors,
	} {
		if err := check(c); err != nil {
			return err
		}
	}

	return nil
}

// hasInterceptor reports whether an interceptor of type T is registered.
func hasInterceptor[T any](c *config) bool {
	return slices.ContainsFunc(c.registrations, func(r registration) bool {
		_, ok := r.interceptor.(T)

		return ok
	})
}

// checkBearer requires a bearer mode, whichever one: the resume is how a sign-in
// reaches the provider, and it reads the credential only through one.
func (op *oidcEndpoints) checkBearer(c *config) error {
	if !hasInterceptor[*bearerToken](c) && !hasInterceptor[*sessionBearer](c) {
		return newConfigError("%s needs a bearer mode, because a resume needs a sign-in credential: "+
			"enable EnableSessionBearer or EnableBearerToken", optionOIDCProvider)
	}

	return nil
}

// checkJWKS requires the key set endpoint, and refuses one that publishes other
// keys than the provider signs with, wherever that can be known.
func (op *oidcEndpoints) checkJWKS(c *config) error {
	var endpoints int

	err := eachInterceptor(c, func(j *jwksEndpoint) error {
		endpoints++

		keys, ok := j.keys.(*signingkey.Keys)
		if ok && !op.provider.SignsWith(keys) {
			return newConfigError("%s signs with other keys than EnableJWKSEndpoint publishes, so no "+
				"client could verify what the provider issues: give both the same manager",
				optionOIDCProvider)
		}

		return nil
	})
	if err != nil {
		return err
	}

	if endpoints == 0 {
		return newConfigError("%s needs EnableJWKSEndpoint, because clients verify what the provider "+
			"issues with the keys it publishes", optionOIDCProvider)
	}

	return nil
}

// checkCollisions refuses a provider path another endpoint of the chain answers:
// whichever matched first would swallow the other.
func (op *oidcEndpoints) checkCollisions(c *config) error {
	taken := c.oidcForeignPaths()
	prefixes := c.oidcForeignPrefixes()

	for _, g := range op.groups {
		for _, route := range g.routes() {
			if other, ok := taken[route.path]; ok {
				return newConfigError("%s answers on %q, which is already %s; whichever endpoint matched "+
					"first would swallow the other", optionOIDCProvider, route.path, other)
			}

			for _, prefix := range prefixes {
				if underPrefix(route.path, prefix) {
					return newConfigError("%s answers on %q, under %q, whose endpoint answers every POST "+
						"under it", optionOIDCProvider, route.path, prefix)
				}
			}
		}
	}

	return nil
}

// oidcForeignPaths is the exact paths of the chain's other endpoints, and what
// each is.
func (c *config) oidcForeignPaths() map[string]string {
	taken := map[string]string{}

	if l := c.formLogin(); l != nil {
		taken[l.path] = "the login path"
	}

	if c.logoutPath != "" {
		taken[c.logoutPath] = "the logout path"
	}

	_ = eachInterceptor(c, func(j *jwksEndpoint) error {
		taken[j.path] = "the key set path"

		return nil
	})
	_ = eachInterceptor(c, func(r *sessionRenewal) error {
		taken[r.path] = "the session renewal path"

		return nil
	})
	_ = eachInterceptor(c, func(g *passwordChangeGate) error {
		if g.change != nil {
			taken[g.path] = "the password-change resolve path"
		}

		return nil
	})
	_ = eachInterceptor(c, func(i *recoveryInterceptor) error {
		for _, r := range i.endpointPaths() {
			taken[r.path] = "the recovery " + r.name + " path"
		}

		return nil
	})

	if p := c.passkeysOf(); p != nil {
		for _, e := range p.paths() {
			taken[e.path] = "the passkey " + e.name + " path"
		}
	}

	return taken
}

// oidcForeignPrefixes is the prefixes other endpoints answer every POST under.
func (c *config) oidcForeignPrefixes() []string {
	var prefixes []string

	if m := c.mfaOf(); m != nil {
		prefixes = append(prefixes, m.verifyPrefix, m.beginPrefix)
	}

	_ = eachInterceptor(c, func(i *enrolmentInterceptor) error {
		prefixes = append(prefixes, i.prefixes()...)

		return nil
	})

	return prefixes
}

// checkDPoP refuses a provider and a chain that disagree about DPoP. The provider
// cannot be changed once built, so the consumer states it there too.
func (op *oidcEndpoints) checkDPoP(c *config) error {
	switch stated := op.provider.DPoPEnabled(); {
	case stated && !c.dpopEnabled:
		return newConfigError("%s was given a provider built with oidcprovider.WithDPoP on a chain "+
			"without EnableDPoP, so no proof would be verified: add EnableDPoP, or remove WithDPoP",
			optionOIDCProvider)
	case !stated && c.dpopEnabled:
		return newConfigError("%s was given a provider built without oidcprovider.WithDPoP on a chain "+
			"with EnableDPoP, so it would refuse every dpop_jkt: add WithDPoP, or remove EnableDPoP",
			optionOIDCProvider)
	}

	return nil
}

// checkAssertionEndpoint refuses an assertion audience the token endpoint is not
// served on. The provider has already held it to the issuer's origin, so only its
// path is left to compare, and a client naming it would otherwise be refused at
// every request.
func (op *oidcEndpoints) checkAssertionEndpoint(*config) error {
	endpoint := op.provider.AssertionTokenEndpoint()
	if endpoint == "" {
		return nil
	}

	u, err := url.Parse(endpoint)
	if err != nil || u.Path != op.paths[OIDCToken] {
		return newConfigError("%s serves the token endpoint on %q, but the provider accepts assertions "+
			"naming %q: state the served URL with oidcprovider.WithAssertionTokenEndpoint",
			optionOIDCProvider, op.paths[OIDCToken], endpoint)
	}

	return nil
}

// checkFrameAncestors requires the protection against framing the consumer's
// pages rest on, unless the consumer states those pages carry it themselves.
func (op *oidcEndpoints) checkFrameAncestors(c *config) error {
	if op.pagesCarryFrameAncestors || hasInterceptor[*securityHeaders](c) {
		return nil
	}

	return newConfigError("%s needs EnableSecurityHeaders, because the login and consent pages must not "+
		"be framed; if those pages carry frame-ancestors themselves, say so with "+
		"WithOIDCPagesCarryFrameAncestors", optionOIDCProvider)
}

// checkReporting refuses a session manager that does not report sign-in ends to
// the provider, because grants would then outlive a logout. It asks the manager,
// after the chain's wiring has run, because a manager can gain an observer then.
func (op *oidcEndpoints) checkReporting(c *config) error {
	if slices.ContainsFunc(c.sessionManagers, func(m *session.Sessions) bool {
		return !m.ReportsEndsTo(op.provider)
	}) {
		return newConfigError("%s found a session manager on the chain that does not report sign-in "+
			"ends to the provider, so grants would outlive a logout: build every manager with "+
			"session.WithEndObserver(provider)", optionOIDCProvider)
	}

	return nil
}
