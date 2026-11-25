package httpsec_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/signingkey"
)

// These examples compile the resource-server snippets of the README. They have
// no Output, so they are built and vetted but never run: each stands in for
// wiring a consumer does at start-up, with the consumer's own stores, keys and
// provider declared here as variables.

// ExampleEnableResourceServer_providerAndAPI is a chain that serves its own
// OpenID Provider and an API: the access tokens the provider issues open the
// routes under /api/, and the browser's session opens the rest.
func ExampleEnableResourceServer_providerAndAPI() {
	var (
		provider *oidcprovider.Provider
		sessions *session.Sessions
		keys     *signingkey.Keys
		users    identity.UserLoader
	)

	chain, err := httpsec.New(
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableJWKSEndpoint(keys),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableSecurityHeaders(),
		// Every source requires a token bound to a key or a certificate, so DPoP is on.
		httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "https://id.example.com"}),
		httpsec.EnableOIDCProvider(provider),
		httpsec.EnableResourceServer("https://api.example.com/orders",
			httpsec.WithPathPrefix("/api/"),
			// The provider is the chain's own: the grant is checked on every request, and the
			// caller is the local user the token's subject names, loaded again each time.
			httpsec.FromProvider(provider),
		),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	_ = chain
}

// ExampleEnableResourceServer_apiOnly is an application that is only an API: it
// trusts the JWT access tokens of an identity provider it does not run, and
// reads their scopes from the token.
func ExampleEnableResourceServer_apiOnly() {
	chain, err := httpsec.New(
		httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "https://api.example.com"}),
		httpsec.EnableResourceServer("https://api.example.com/orders",
			// The key set is found from the issuer's metadata, and the caller is a claims-only
			// caller named "<issuer>#<subject>" with the token's scopes and no role.
			httpsec.FromIssuer("https://idp.example.com"),
		),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	_ = chain
}

// ExampleEnableResourceServer_prefixes is two APIs on one chain, each confined
// to its own prefix and trusting its own sources. A token is judged by the
// resource server that covers the request's path.
func ExampleEnableResourceServer_prefixes() {
	chain, err := httpsec.New(
		httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "https://api.example.com"}),
		httpsec.EnableResourceServer("https://api.example.com/orders",
			httpsec.WithPathPrefix("/orders/"),
			// An issuer that names the API in another spelling is trusted per source.
			httpsec.FromIssuer("https://idp.example.com", httpsec.WithSourceAudience("orders")),
		),
		httpsec.EnableResourceServer("https://api.example.com/billing",
			httpsec.WithPathPrefix("/billing/"),
			httpsec.WithResourceAliases("https://billing.example.com"),
			httpsec.FromIssuer("https://idp.example.com"),
		),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	_ = chain
}

// ExampleFromIntrospection trusts opaque access tokens, asking the issuer's
// introspection endpoint on every request, and keeps an active answer for at
// most half a minute.
func ExampleFromIntrospection() {
	chain, err := httpsec.New(
		httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "https://api.example.com"}),
		httpsec.EnableResourceServer("https://api.example.com/orders",
			httpsec.FromIntrospection(
				"https://idp.example.com",
				"https://idp.example.com/oauth2/introspect",
				"orders-api",
				httpsec.WithIntrospectionSecret(os.Getenv("ORDERS_API_INTROSPECTION_SECRET")),
				httpsec.WithOpaquePrefix("op."),
				httpsec.WithIntrospectionCache(30*time.Second, 1000),
			),
		),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	_ = chain
}

// ExampleFromIssuer_unboundTokens opts one source out of the binding default,
// asks the issuer about every JWT it verifies, and throttles the refusals of
// the resource server.
func ExampleFromIssuer_unboundTokens() {
	chain, err := httpsec.New(
		httpsec.EnableResourceServer("https://api.example.com/orders",
			httpsec.FromIssuer("https://idp.example.com",
				httpsec.WithUnboundTokens(),
				httpsec.WithJWTIntrospection(httpsec.IntrospectionConfig{
					Endpoint: "https://idp.example.com/oauth2/introspect",
					ClientID: "orders-api",
					Secret:   os.Getenv("ORDERS_API_INTROSPECTION_SECRET"),
				}),
			),
		),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	_ = chain
}

// ExampleWithClaimsMapper derives the caller's roles from the token's claims,
// and declares the caller external because it names no local user.
func ExampleWithClaimsMapper() {
	source := httpsec.FromIssuer("https://idp.example.com",
		httpsec.WithClaimsMapper("corp-idp", func(_ context.Context, claims map[string]any) (httpsec.MappedCaller, error) {
			sub, _ := claims["sub"].(string)
			if sub == "" {
				return httpsec.MappedCaller{}, nil // a nil principal refuses the token
			}

			return httpsec.MappedCaller{
				Principal: &identity.Principal{
					ID:    identity.UserID("corp:" + sub),
					Roles: []*identity.AssignedRole{{ID: "reader", Name: "reader"}},
				},
				External: true,
			}, nil
		}),
	)

	_ = source
}

// ExampleWithLinkedUsers finds the local user through the identity links by
// issuer and subject, so a partner's subject "42" is never taken for local user
// "42".
func ExampleWithLinkedUsers() {
	var (
		links oidc.LinkStore
		users identity.UserLoader
	)

	source := httpsec.FromIssuer("https://idp.example.com",
		httpsec.WithLinkedUsers(links, "corp-idp", users),
	)

	_ = source
}

// ExampleAccessTokenFromContext reads what a handler may learn of the token that
// opened its route, beside the principal every other credential publishes.
func ExampleAccessTokenFromContext() {
	handle := func(ctx context.Context) {
		principal, ok := identity.PrincipalFromContext(ctx)
		if !ok {
			return
		}

		token, ok := httpsec.AccessTokenFromContext(ctx)
		if !ok {
			return // a session or an API key opened the route
		}

		fmt.Println(principal.ID, token.Issuer, token.ClientID, token.Scopes, token.AuthTime)
	}

	_ = handle
}

// ExampleWithInactiveDisclosure answers a correct password for an inactive
// account 403, in place of the 401 a wrong password gets.
func ExampleWithInactiveDisclosure() {
	chain, err := httpsec.New(
		httpsec.WithInactiveDisclosure(),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	_ = chain
}

// ExampleEnableFormLogin_passwordRule adds a password rule of the consumer's
// own: it runs after the built-in lists and before the breach lookup, and a
// refusal names it.
func ExampleEnableFormLogin_passwordRule() {
	policy, err := password.NewPolicy(
		password.WithRule("no-company-name", func(_ context.Context, candidate string, _ *identity.Details) (bool, error) {
			return !strings.Contains(strings.ToLower(candidate), "acme"), nil
		}),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	_ = policy
}
