package httpsec_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/signingkey"
)

// ExampleEnableResourceServer_twoChains is one binary that runs its OpenID
// Provider and its API. The provider needs the browser's sign-in, so it runs on
// the cookie chain at "/"; the API takes access tokens, so it runs on a token
// chain mounted at "/api/", whose resource server trusts the provider through
// FromProvider. The token chain runs no provider of its own, verifies each token
// through the provider with no network call, and loads the local user it names.
//
// Issuing a token takes a whole authorization-code flow, so the example sends
// the API a token the provider never issued, which the provider refuses.
func ExampleEnableResourceServer_twoChains() {
	ctx := context.Background()

	keys, err := signingkey.New(ctx, signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
	if err != nil {
		panic(err)
	}

	users := exampleUserLoader{details: &identity.Details{ID: "u-1", Username: "grace@example.com", Active: true}}

	provider, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: "https://app.example.com",
		Clients: []oidcprovider.Client{{
			ID: "orders-app", Type: oidcprovider.Public, RedirectURIs: []string{"https://app.example.com/cb"},
			Resources: []string{"https://app.example.com/api"},
		}},
		Keys:         keys,
		Users:        users,
		LoginURL:     "https://app.example.com/login",
		ConsentURL:   "https://app.example.com/consent",
		LogoutURL:    "https://app.example.com/logout-page",
		LoggedOutURL: "https://app.example.com/bye",
	}, oidcprovider.WithDPoP())
	if err != nil {
		panic(err)
	}

	// The provider learns of every session that ends, so it ends the sign-ins' grants too.
	sessions, err := session.New(session.WithEndObserver(provider))
	if err != nil {
		panic(err)
	}

	// Browsers: the cookie session, CSRF protection beside it, and the provider, whose token
	// endpoint binds the tokens it issues to the client's DPoP key.
	browsers, err := httpsec.New(
		httpsec.EnableCSRFProtection(),
		httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "https://app.example.com"}),
		httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableJWKSEndpoint(keys),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableOIDCProvider(provider),
	)
	if err != nil {
		panic(err)
	}

	// Native clients and third parties: DPoP-bound access tokens for the API.
	api, err := httpsec.New(
		httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "https://app.example.com"}),
		httpsec.EnableResourceServer("https://app.example.com/api",
			httpsec.WithPathPrefix("/api/"),
			// The provider is served by the cookie chain, not this one: the grant is still
			// checked on every request, and the caller is the local user the token names.
			httpsec.FromProvider(provider),
		),
	)
	if err != nil {
		panic(err)
	}

	whoami := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, ok := authenticate.AuthenticationFromContext(r.Context())
		if !ok {
			http.Error(w, "anonymous", http.StatusUnauthorized)

			return
		}

		_, _ = fmt.Fprint(w, auth.Principal.ID)
	})

	mux := http.NewServeMux()
	mux.Handle("/api/", api.Middleware()(whoami))
	mux.Handle("/", browsers.Middleware()(whoami))

	// The provider answers on the cookie chain.
	req := httptest.NewRequestWithContext(ctx, http.MethodGet,
		"https://app.example.com/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	fmt.Println("discovery:", rec.Code)

	// The API asks the provider about a token it never issued, and refuses it.
	req = httptest.NewRequestWithContext(ctx, http.MethodGet, "https://app.example.com/api/orders", nil)
	req.Header.Set("Authorization", "Bearer at.never-issued")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	fmt.Println("api:", rec.Code, rec.Header().Get("WWW-Authenticate"))

	// Output:
	// discovery: 200
	// api: 401 DPoP error="invalid_token", algs="ES256"
}
