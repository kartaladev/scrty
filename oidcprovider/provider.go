package oidcprovider

import (
	"fmt"
	"net/netip"
	"net/url"
	"reflect"
	"strings"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/origin"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/token/signingkey"
)

//go:generate mockgen -destination=keysource_mock_test.go -package=oidcprovider_test -typed github.com/kartaladev/scrty/token/signingkey KeySource
//go:generate mockgen -destination=userloader_mock_test.go -package=oidcprovider_test -typed github.com/kartaladev/scrty/identity UserLoader

// Deps holds what New requires.
type Deps struct {
	// Issuer is the provider's issuer identifier: an https URL with no query, fragment
	// or user information. It is required. WithLoopbackHTTPIssuer also permits http on
	// a loopback host.
	Issuer string

	// Clients are the configured clients, kept in an in-memory registry, which is the
	// default. Exactly one of Clients and Registry is set.
	Clients []Client

	// Registry replaces the in-memory registry, and its clients are validated as they
	// are read. Exactly one of Clients and Registry is set.
	Registry ClientRegistry

	// Keys signs what the provider issues. It is required, and the provider does not
	// generate keys of its own. It must be the source the chain's JWKS endpoint publishes.
	Keys signingkey.KeySource

	// Users loads the users tokens describe. It is required.
	Users identity.UserLoader

	// LoginURL and ConsentURL are the consumer's pages. Both are required,
	// absolute and on the issuer's origin.
	LoginURL, ConsentURL string

	// LogoutURL and LoggedOutURL are the consumer's logout pages: the one that asks
	// the user to confirm, and the one shown once signed out. Both are required,
	// absolute and on the issuer's origin.
	LogoutURL, LoggedOutURL string
}

// Provider is the embedded OpenID Provider. Build one with New.
type Provider struct {
	cfg    config
	issuer string
	keys   signingkey.KeySource
	users  identity.UserLoader

	registry ClientRegistry
	limits   keyLimits

	assertionIDs AssertionIDStore
	keySets      *clientKeySets
	stores       providerStores

	loginURL, consentURL, logoutURL, loggedOutURL string
}

// New builds a Provider. A wiring mistake fails with an error matching ErrConfig
// that names the setting. Every field of Deps is required, apart from the one of
// Clients and Registry left unset.
//
// With no options: an https issuer, browser sessions on, logout asking only when no
// valid hint names the browser's own sign-in, pending requests living 10 minutes, codes
// 60 seconds, client assertions at most 5 minutes with the issuer as their sole audience,
// assertion identifiers, pending requests, code records, consents and grants kept in
// memory, client key sets fetched through a default outbound.Client, kept 15 minutes and
// refetched for an unknown kid at most every 30 seconds, the system clock, slog.Default
// and crypto/rand. Each option names its default and its bound.
func New(d Deps, opts ...Option) (*Provider, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := d.validate(&cfg); err != nil {
		return nil, err
	}

	if cfg.assertionAudience == AudienceIssuerOrTokenEndpoint && !cfg.assertionTokenEndpointSet {
		cfg.assertionTokenEndpoint = strings.TrimSuffix(d.Issuer, "/") + tokenEndpointPath
	}

	limits := limitsOf(d.Keys)
	registry, err := d.buildRegistry(limits)
	if err != nil {
		return nil, err
	}

	out := cfg.outbound
	if !cfg.outboundSet {
		if out, err = outbound.New(); err != nil {
			return nil, fmt.Errorf("%w: the default outbound client: %w", ErrConfig, err)
		}
	}
	assertionIDs := cfg.assertionIDs
	if !cfg.assertionIDsSet {
		assertionIDs = newMemoryAssertionIDs(cfg.clock)
	}
	stores, err := cfg.buildStores()
	if err != nil {
		return nil, err
	}

	return &Provider{
		cfg:          cfg,
		stores:       stores,
		registry:     registry,
		limits:       limits,
		assertionIDs: assertionIDs,
		keySets: &clientKeySets{
			out:      out,
			clock:    cfg.clock,
			ttl:      cfg.keysTTL,
			cooldown: cfg.keysRefetchCooldown,
		},
		issuer:       d.Issuer,
		keys:         d.Keys,
		users:        d.Users,
		loginURL:     d.LoginURL,
		consentURL:   d.ConsentURL,
		logoutURL:    d.LogoutURL,
		loggedOutURL: d.LoggedOutURL,
	}, nil
}

// buildRegistry returns the registry to read clients from. Everything the library
// can see is checked here, because nothing else could report it before traffic. Only
// a consumer's own registry is left to be checked as it is read.
func (d *Deps) buildRegistry(limits keyLimits) (ClientRegistry, error) {
	if len(d.Clients) == 0 {
		if memory, ok := d.Registry.(*MemoryRegistry); ok {
			if err := memory.checkConfigured(limits); err != nil {
				return nil, err
			}
		}

		return d.Registry, nil
	}

	memory, err := NewMemoryRegistry(d.Clients)
	if err != nil {
		return nil, err
	}
	if err := memory.checkConfigured(limits); err != nil {
		return nil, err
	}
	// This registry is not handed out, so nothing could ever generate these clients
	// a secret.
	for _, c := range d.Clients {
		if rc := memory.clients[c.ID]; rc.usesSecret() && len(rc.Secrets) == 0 {
			return nil, rc.refuse("Secret", "a configured client using a secret must supply it; a MemoryRegistry passed as Registry can generate one")
		}
	}

	return memory, nil
}

func (d *Deps) validate(cfg *config) error {
	if err := validateIssuer(d.Issuer, cfg.loopbackHTTPIssuer); err != nil {
		return err
	}
	if nilcheck.IsNil(d.Keys) {
		return fmt.Errorf("%w: Keys: a key source is required", ErrConfig)
	}
	if nilcheck.IsNil(d.Users) {
		return fmt.Errorf("%w: Users: a user loader is required", ErrConfig)
	}

	hasRegistry := !nilcheck.IsNil(d.Registry)
	switch {
	case len(d.Clients) > 0 && hasRegistry:
		return fmt.Errorf("%w: Clients and Registry: set exactly one, got both", ErrConfig)
	case len(d.Clients) == 0 && !hasRegistry:
		return fmt.Errorf("%w: Clients and Registry: set exactly one, got neither", ErrConfig)
	}

	if cfg.assertionTokenEndpointSet {
		if err := validateTokenEndpoint(cfg.assertionTokenEndpoint, d.Issuer); err != nil {
			return err
		}
	}

	return d.validatePages()
}

// validateTokenEndpoint requires an audience URL on the issuer's origin that a client
// can compare exactly, so no query, fragment or user information.
func validateTokenEndpoint(raw, issuer string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || !origin.Same(raw, issuer) {
		return fmt.Errorf("%w: WithAssertionTokenEndpoint: must be an absolute URL on the issuer's origin", ErrConfig)
	}
	if u.User != nil || strings.ContainsAny(raw, "?#") {
		return fmt.Errorf("%w: WithAssertionTokenEndpoint: must have no query, fragment or user information", ErrConfig)
	}

	return nil
}

func (d *Deps) validatePages() error {
	if err := validatePage("LoginURL", d.LoginURL, d.Issuer); err != nil {
		return err
	}
	if err := validatePage("ConsentURL", d.ConsentURL, d.Issuer); err != nil {
		return err
	}

	if err := validatePage("LogoutURL", d.LogoutURL, d.Issuer); err != nil {
		return err
	}

	return validatePage("LoggedOutURL", d.LoggedOutURL, d.Issuer)
}

// validateIssuer takes no query or fragment, even an empty one, because the
// issuer is compared as a string and has paths appended to it. Neither message
// repeats the value, which could hold a credential in its user information.
func validateIssuer(raw string, allowLoopbackHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("%w: Issuer: must be an absolute URL", ErrConfig)
	}
	if strings.ContainsAny(raw, "?#") {
		return fmt.Errorf("%w: Issuer: must have no query or fragment", ErrConfig)
	}
	if u.User != nil {
		return fmt.Errorf("%w: Issuer: must have no user information", ErrConfig)
	}

	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && allowLoopbackHTTP && isLoopbackHost(u.Hostname()):
		return nil
	case allowLoopbackHTTP:
		return fmt.Errorf("%w: Issuer: must use https, or http on a loopback host", ErrConfig)
	default:
		return fmt.Errorf("%w: Issuer: must use https (WithLoopbackHTTPIssuer permits http on a loopback host)", ErrConfig)
	}
}

// validatePage requires a page on the issuer's origin (R9): the flow's cookies
// carry the __Host- prefix, so a page on any other origin could never read them.
func validatePage(name, raw, issuer string) error {
	if raw == "" {
		return fmt.Errorf("%w: %s: is required", ErrConfig, name)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %s: must be an absolute URL", ErrConfig, name)
	}
	if u.User != nil || strings.Contains(raw, "#") {
		return fmt.Errorf("%w: %s: must have no user information or fragment", ErrConfig, name)
	}
	if !origin.Same(raw, issuer) {
		return fmt.Errorf("%w: %s: must be absolute and on the issuer's origin", ErrConfig, name)
	}

	return nil
}

// isLoopbackHost reports whether host names this machine: the name localhost,
// or a loopback IP literal.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)

	return err == nil && addr.Unmap().IsLoopback()
}

// SignsWith reports whether keys is the very key source the provider signs with,
// so the chain can check that the JWKS endpoint publishes what the provider
// signs with (R6). A wrapped source is a different value and answers false, so
// the check is only as good as what it can see. A value that cannot be compared
// answers false rather than panicking.
func (p *Provider) SignsWith(keys any) bool {
	if keys == nil || !reflect.ValueOf(keys).Comparable() {
		return false
	}

	return any(p.keys) == keys
}
