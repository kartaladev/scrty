package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// ClientAuthMethod is how the client authenticates itself to a provider's
// token endpoint.
type ClientAuthMethod uint8

const (
	// ClientSecretPost sends the client id and secret in the form body. It is
	// the zero value, and so the default.
	ClientSecretPost ClientAuthMethod = iota

	// ClientSecretBasic sends the client id and secret in an HTTP Basic
	// Authorization header.
	ClientSecretBasic
)

// DefaultScopes are the scopes requested from a provider whose Scopes is nil.
var DefaultScopes = []string{"openid", "profile", "email"}

// defaultSigningAlgs are the algorithms accepted from a provider whose
// SigningAlgs is nil.
var defaultSigningAlgs = []string{"RS256"}

// asymmetricAlgs and symmetricAlgs are the signature algorithms a provider may
// list. A symmetric algorithm is accepted only when listed, never by default.
var (
	asymmetricAlgs = []string{
		"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
		"ES256", "ES384", "ES512", "EdDSA",
	}
	symmetricAlgs = []string{"HS256", "HS384", "HS512"}
)

// Provider is one OpenID provider the application trusts to log users in.
//
// Provider configuration is trusted operator input. Every URL must be absolute,
// with a host name and no credentials, and its scheme must be one the
// manager's outbound client allows: https by default, http only when the
// consumer's client adds it (NewManager checks this, since the registry cannot
// see the client). Beyond that the library does not filter where the URLs
// point: loopback, link-local and private-network hosts are accepted, because
// development and internal corporate providers live there. Whoever can write
// provider configuration can therefore direct the client secret, which is sent
// to the token endpoint, to any host they choose.
type Provider struct {
	// Name identifies the provider in paths and records. It must be non-empty
	// and usable as a single URL path segment unchanged.
	Name string

	// Issuer is the provider's issuer identifier: an absolute URL with no
	// query and no fragment, whose scheme the manager's outbound client allows
	// (https by default). It is where discovery starts and what every token's
	// iss must equal. It is trusted configuration: see Provider.
	Issuer string

	// ClientID is the client identifier the provider issued to the
	// application.
	ClientID string

	// ClientSecret authenticates the client at the token endpoint and, only
	// when a symmetric algorithm is listed in SigningAlgs, is the key that
	// verifies the provider's tokens. It never appears in an error or a log.
	ClientSecret string

	// RedirectURL is the application's callback URL: an absolute URL with no
	// fragment, whose scheme the manager's outbound client allows (https by
	// default). It is required and never derived from a request's Host, which
	// a client controls. It is trusted configuration: see Provider.
	RedirectURL string

	// Scopes are requested at authorization. Nil means DefaultScopes. A
	// non-nil list must include "openid", so an empty non-nil list is refused.
	Scopes []string

	// ClientAuth is how the client authenticates at the token endpoint. The
	// zero value is ClientSecretPost.
	ClientAuth ClientAuthMethod

	// AuthorizationEndpoint, TokenEndpoint and JWKSURI pin the provider's
	// endpoints. Either all three are set or none is. Pinned endpoints are
	// never discovered; unpinned ones come from the issuer's discovery
	// document. Each must be an absolute URL whose scheme the manager's
	// outbound client allows (https by default). They are trusted
	// configuration: see Provider.
	AuthorizationEndpoint, TokenEndpoint, JWKSURI string

	// EndSessionEndpoint is the provider's RP-initiated logout endpoint. It is
	// optional and outside the all-three-or-none rule. Empty means it comes
	// from discovery, or that the provider offers none. When set, it must be
	// an absolute URL whose scheme the manager's outbound client allows (https
	// by default). It is trusted configuration: see Provider.
	EndSessionEndpoint string

	// SigningAlgs are the signature algorithms accepted on the provider's
	// tokens. Nil means RS256 only; an empty non-nil list is refused. "none"
	// is always refused. A symmetric algorithm (HS256, HS384, HS512) is
	// accepted only when listed here, then uses ClientSecret as the key, and
	// so requires a non-empty ClientSecret.
	SigningAlgs []string
}

// Registry holds the providers the application trusts, validated. Build one
// with NewRegistry; it is immutable afterwards and safe for concurrent use.
type Registry struct {
	names     []string
	providers map[string]Provider
}

// NewRegistry validates the providers and returns a registry of them, in the
// order given.
//
// It returns an error wrapping ErrConfig, naming the provider and the field,
// when no provider is given, when two share a name, or when any provider is
// invalid: an empty name or one not usable as a single URL path segment; a
// missing issuer, client id or redirect URL; an issuer, redirect URL,
// end-session or pinned endpoint that is not an absolute URL with a scheme, a
// host name and no credentials; an issuer with a query or a fragment, or a
// redirect URL with a fragment; only some of the three endpoints pinned;
// configured scopes without "openid"; an empty or unknown algorithm list, one
// including "none", or a symmetric algorithm with no client secret; or an
// unknown client authentication method.
//
// It does not check the URLs' scheme: that follows the outbound client, which
// NewManager holds and checks against.
//
// Nil Scopes resolve to DefaultScopes, and nil SigningAlgs to RS256.
func NewRegistry(providers ...Provider) (*Registry, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("%w: no provider is registered", ErrConfig)
	}
	r := &Registry{
		names:     make([]string, 0, len(providers)),
		providers: make(map[string]Provider, len(providers)),
	}
	for _, p := range providers {
		if err := validateProvider(p); err != nil {
			return nil, err
		}
		if _, dup := r.providers[p.Name]; dup {
			return nil, fmt.Errorf("%w: duplicate provider name %q", ErrConfig, p.Name)
		}
		r.names = append(r.names, p.Name)
		r.providers[p.Name] = resolveProvider(p)
	}
	return r, nil
}

// Lookup returns the named provider with its defaults resolved. The returned
// value is a copy: changing it does not change the registry.
func (r *Registry) Lookup(name string) (Provider, bool) {
	p, ok := r.providers[name]
	if !ok {
		return Provider{}, false
	}
	return cloneProvider(p), true
}

// Names returns the registered provider names in registration order. The
// returned slice is the caller's own.
func (r *Registry) Names() []string { return slices.Clone(r.names) }

func resolveProvider(p Provider) Provider {
	if p.Scopes == nil {
		p.Scopes = DefaultScopes
	}
	if p.SigningAlgs == nil {
		p.SigningAlgs = defaultSigningAlgs
	}
	return cloneProvider(p)
}

func cloneProvider(p Provider) Provider {
	p.Scopes = slices.Clone(p.Scopes)
	p.SigningAlgs = slices.Clone(p.SigningAlgs)
	return p
}

func validateProvider(p Provider) error {
	if err := validateName(p.Name); err != nil {
		return err
	}
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: provider %q: %s", ErrConfig, p.Name, fmt.Sprintf(format, args...))
	}

	required := []struct{ field, value string }{
		{"issuer", p.Issuer}, {"client id", p.ClientID}, {"redirect URL", p.RedirectURL},
	}
	for _, f := range required {
		if f.value == "" {
			return refuse("%s is required", f.field)
		}
	}

	urls := []struct{ field, value string }{
		{"issuer", p.Issuer},
		{"redirect URL", p.RedirectURL},
		{"authorization endpoint", p.AuthorizationEndpoint},
		{"token endpoint", p.TokenEndpoint},
		{"key-set URI", p.JWKSURI},
		{"end-session endpoint", p.EndSessionEndpoint},
	}
	for _, f := range urls {
		if f.value == "" {
			continue // the required ones were checked above
		}
		u, err := parseAbsoluteURL(f.value)
		if err != nil {
			return refuse("%s: %v", f.field, err)
		}
		switch {
		case f.field == "issuer" && (u.RawQuery != "" || u.ForceQuery):
			return refuse("issuer: must not carry a query")
		case (f.field == "issuer" || f.field == "redirect URL") && (u.Fragment != "" || strings.Contains(f.value, "#")):
			return refuse("%s: must not carry a fragment", f.field)
		}
	}

	pinned := 0
	for _, v := range []string{p.AuthorizationEndpoint, p.TokenEndpoint, p.JWKSURI} {
		if v != "" {
			pinned++
		}
	}
	if pinned != 0 && pinned != 3 {
		return refuse("pin all three of the authorization, token and key-set endpoints, or none")
	}

	if p.Scopes != nil && !slices.Contains(p.Scopes, "openid") {
		return refuse("the configured scopes must include %q; leave them nil for the defaults", "openid")
	}

	if p.SigningAlgs != nil {
		if len(p.SigningAlgs) == 0 {
			return refuse("the signing algorithm list is empty; leave it nil for RS256")
		}
		for _, alg := range p.SigningAlgs {
			if strings.EqualFold(alg, "none") {
				return refuse("signing algorithm %q is never accepted", alg)
			}
			if !slices.Contains(asymmetricAlgs, alg) && !slices.Contains(symmetricAlgs, alg) {
				return refuse("unknown signing algorithm %q", alg)
			}
			if slices.Contains(symmetricAlgs, alg) && p.ClientSecret == "" {
				return refuse("signing algorithm %q needs a client secret as its key", alg)
			}
		}
	}

	switch p.ClientAuth {
	case ClientSecretPost, ClientSecretBasic:
	default:
		return refuse("unknown client authentication method %d", p.ClientAuth)
	}
	return nil
}

// validateName requires a name usable, unchanged, as one URL path segment.
func validateName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: a provider name is required", ErrConfig)
	case name == "." || name == "..", strings.Contains(name, "/"), url.PathEscape(name) != name:
		return fmt.Errorf("%w: provider name %q is not a single URL path segment", ErrConfig, name)
	}
	return nil
}

var errNotAbsolute = errors.New("must be an absolute URL with a scheme, a host name and no credentials")

// parseAbsoluteURL requires an absolute URL with a scheme, a host name and no
// user information. It deliberately checks neither the scheme, which follows
// the manager's outbound client, nor the host: see Provider.
func parseAbsoluteURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errNotAbsolute
	}
	// Hostname, not Host: a bare port such as "https://:8443" has a Host but
	// no host name.
	if u.Scheme == "" || u.Hostname() == "" || u.User != nil {
		return nil, errNotAbsolute
	}
	return u, nil
}
