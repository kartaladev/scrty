// Command conformanceop is an OpenID Provider built from scrty's defaults, for the OpenID
// Foundation's conformance suite to test.
//
// It serves over https on a certificate it makes for itself, because the suite's Config plan
// refuses http. Its login, consent and logout pages are plain server-rendered forms that resume
// through the provider's Go API, because the suite drives HtmlUnit and not a modern browser.
//
// It holds fixtures anyone can read (see the constants), keeps everything in memory, and is not
// meant to be exposed to anything but the suite.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/signingkey"
)

// config says where the provider is, and which suite instance it serves.
type config struct {
	// Issuer is the provider's public URL, an https origin.
	Issuer string
	// SuiteURL is the suite's public URL, an https origin.
	SuiteURL string
	// Alias is the alias the plans run under, which the suite puts in its callback paths.
	Alias string
}

// The fixtures the suite's configuration (test/conformance/oidcc.json) names. They are public on
// purpose: this provider exists to be tested, holds nothing, and is never exposed.
//
//nolint:gosec // G101: the secrets are fixtures, public by design
const (
	clientBasic  = "client"
	clientBasic2 = "client2"
	clientPost   = "client-post"
	clientBCL    = "client-bcl"

	secretBasic  = "conformance-secret-for-client-one-0000"
	secretBasic2 = "conformance-secret-for-client-two-0000"
	secretPost   = "conformance-secret-for-client-post-000"
	secretBCL    = "conformance-secret-for-client-bcl-0000"

	userName     = "conformance"
	userPassword = "conformance-password"
	userID       = "user-0001"
)

// loginACR is the authentication context class the form login states for its sign-ins. The
// library does not interpret it; the suite's acr_values module asks for "1" or "2" and wants one
// of them back.
const loginACR = "1"

// The pages the provider's metadata points the browser at. They are on the issuer's origin.
const (
	pathLogin     = "/login"
	pathConsent   = "/consent"
	pathLogout    = "/logout"
	pathLoggedOut = "/signed-out"
)

// server is the running provider.
type server struct {
	provider *oidcprovider.Provider
	sessions *session.Sessions
	handler  http.Handler
}

// newServer builds the provider from its defaults, plus what the suite needs: the clients it
// registers, a claim source that can say email_verified, and a delivery that trusts the suite's
// self-signed certificate.
func newServer(ctx context.Context, cfg config) (*server, error) {
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" {
		return nil, fmt.Errorf("conformanceop: the issuer %q must be an https origin", cfg.Issuer)
	}

	if cfg.Alias == "" || !strings.HasPrefix(cfg.SuiteURL, "https://") {
		return nil, errors.New("conformanceop: the suite URL must be https and the alias set")
	}

	keys, err := signingkey.New(ctx, signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
	if err != nil {
		return nil, fmt.Errorf("conformanceop: signing keys: %w", err)
	}

	s := &server{}

	provider, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       cfg.Issuer,
		Clients:      clients(cfg),
		Keys:         keys,
		Users:        fixtureUsers{},
		LoginURL:     cfg.Issuer + pathLogin,
		ConsentURL:   cfg.Issuer + pathConsent,
		LogoutURL:    cfg.Issuer + pathLogout,
		LoggedOutURL: cfg.Issuer + pathLoggedOut,
	},
		oidcprovider.WithClaimSource(fixtureClaims{}),
		oidcprovider.WithLogoutOutbound(outbound.WithHTTPClient(trustingClient())),
	)
	if err != nil {
		return nil, fmt.Errorf("conformanceop: provider: %w", err)
	}

	s.provider = provider

	s.sessions, err = session.New(session.WithEndObserver(provider))
	if err != nil {
		return nil, fmt.Errorf("conformanceop: sessions: %w", err)
	}

	chain, err := httpsec.New(
		httpsec.WithErrorHandler(refusalPage),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: s.sessions, Users: fixtureUsers{}}),
		httpsec.EnableJWKSEndpoint(keys),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableOIDCProvider(provider, httpsec.WithOIDCPagesCarryFrameAncestors()),
	)
	if err != nil {
		return nil, fmt.Errorf("conformanceop: chain: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(pathLogin, s.login)
	mux.HandleFunc(pathConsent, s.consent)
	mux.HandleFunc(pathLogout, s.logout)
	mux.HandleFunc(pathLoggedOut, s.loggedOut)
	mux.Handle("/", chain.Middleware()(http.NotFoundHandler()))

	s.handler = mux

	return s, nil
}

// Handler is the whole provider: its pages, and the chain in front of everything else.
func (s *server) Handler() http.Handler { return s.handler }

// Shutdown ends back-channel delivery, waiting for what is queued.
func (s *server) Shutdown(ctx context.Context) error {
	if err := s.provider.Shutdown(ctx); err != nil && !errors.Is(err, oidcprovider.ErrAlreadyShutdown) {
		return fmt.Errorf("conformanceop: shutdown: %w", err)
	}

	return nil
}

// clients are the four the suite is configured with. Each is a confidential client that may
// rely on the nonce instead of PKCE, because every Basic OP module but one sends no challenge
// (R1), and each is registered for the refresh grant and for the logout URLs the suite derives
// from its alias. Only the fourth is told of a logout: the plans that do not serve the
// back-channel path fail on a delivery they did not ask for, so the back-channel module is
// given that client by an override.
func clients(cfg config) []oidcprovider.Client {
	base := cfg.SuiteURL + "/test/a/" + cfg.Alias

	one := func(id, name, secret string, method oidcprovider.AuthMethod, backChannel string) oidcprovider.Client {
		return oidcprovider.Client{
			ID:                     id,
			Name:                   name,
			Type:                   oidcprovider.Confidential,
			AuthMethod:             method,
			PKCE:                   oidcprovider.PKCEOrNonce,
			Secret:                 []byte(secret),
			RedirectURIs:           []string{base + "/callback"},
			PostLogoutRedirectURIs: []string{base + "/post_logout_redirect"},
			BackChannelLogoutURI:   backChannel,
			Scopes:                 []string{"openid", "profile", "email", "address", "phone", "offline_access"},
			GrantTypes:             []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
		}
	}

	return []oidcprovider.Client{
		one(clientBasic, "Conformance client", secretBasic, oidcprovider.ClientSecretBasic, ""),
		one(clientBasic2, "Conformance client 2", secretBasic2, oidcprovider.ClientSecretBasic, ""),
		one(clientBCL, "Conformance client (back-channel logout)", secretBCL, oidcprovider.ClientSecretBasic, base+"/backchannel_logout"),
		one(clientPost, "Conformance client (secret post)", secretPost, oidcprovider.ClientSecretPost, ""),
	}
}

// trustingClient delivers back-channel logout to the suite, whose nginx holds a self-signed
// certificate nobody can chain to a root. It trusts any certificate, which is acceptable only
// because this provider talks to nothing but the suite.
func trustingClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true, //nolint:gosec // the suite's certificate is self-signed; see the function's comment
			},
		},
	}
}

// fixtureUsers holds the one user the suite signs in as.
type fixtureUsers struct{}

func (fixtureUsers) LoadByUsername(_ context.Context, name string) (*identity.Details, error) {
	if name != userName {
		return nil, identity.ErrUserNotFound
	}

	return fixtureUser(), nil
}

func (fixtureUsers) LoadByUserID(_ context.Context, id identity.UserID) (*identity.Details, error) {
	if id != userID {
		return nil, identity.ErrUserNotFound
	}

	return fixtureUser(), nil
}

func fixtureUser() *identity.Details {
	return &identity.Details{ID: userID, Name: "Conformance User", Username: userName, Active: true}
}

// fixtureClaims says what UserInfo and the ID token release. The default source never asserts
// email_verified, because a username proves nothing; this user's address and number are
// fixtures, so the suite's scope modules have verified values to read.
type fixtureClaims struct{}

func (fixtureClaims) Claims(_ context.Context, user identity.UserID, scopes []string) (map[string]any, error) {
	if user != userID {
		return nil, identity.ErrUserNotFound
	}

	out := map[string]any{}

	for _, scope := range scopes {
		switch scope {
		case "profile":
			out["name"] = "Conformance User"
			out["given_name"] = "Conformance"
			out["family_name"] = "User"
			out["middle_name"] = "Op"
			out["nickname"] = "conformance"
			out["preferred_username"] = userName
			out["profile"] = "https://example.com/conformance"
			out["picture"] = "https://example.com/conformance.png"
			out["website"] = "https://example.com"
			out["gender"] = "other"
			out["birthdate"] = "2000-01-01"
			out["zoneinfo"] = "Etc/UTC"
			out["locale"] = "en-US"
			out["updated_at"] = 1700000000
		case "email":
			out["email"] = "conformance@example.com"
			out["email_verified"] = true
		case "phone":
			out["phone_number"] = "+1 (555) 010-0000"
			out["phone_number_verified"] = true
		case "address":
			out["address"] = map[string]any{
				"formatted":      "1 Conformance Way\nTestville 00000\nUS",
				"street_address": "1 Conformance Way",
				"locality":       "Testville",
				"postal_code":    "00000",
				"country":        "US",
			}
		}
	}

	return out, nil
}
