package httpsec

import (
	"fmt"
	"strings"
)

// DefaultOIDCProviderPrefix is the prefix the OpenID Provider's endpoints answer
// under when the consumer names none.
const DefaultOIDCProviderPrefix = "/oauth2"

// OIDCEndpoint names one of the OpenID Provider's endpoints, for
// WithOIDCProviderPath.
type OIDCEndpoint uint8

// The provider's endpoints, each with the path it answers on under the prefix by
// default.
const (
	// OIDCAuthorize is the authorization endpoint, /authorize.
	OIDCAuthorize OIDCEndpoint = iota
	// OIDCResume is where the consumer's login and consent pages resume a
	// parked request, /authorize/resume.
	OIDCResume
	// OIDCToken is the token endpoint, /token.
	OIDCToken
	// OIDCUserInfo is the UserInfo endpoint, /userinfo.
	OIDCUserInfo
	// OIDCRevoke is the revocation endpoint, /revoke.
	OIDCRevoke
	// OIDCIntrospect is the introspection endpoint, /introspect.
	OIDCIntrospect
	// OIDCEndSession is the end-session endpoint, /logout.
	OIDCEndSession
	// OIDCLogoutConfirm is where the consumer's logout page answers, /logout/confirm.
	OIDCLogoutConfirm
	// OIDCConsents is the user's list of consents, /consents.
	OIDCConsents

	oidcEndpointCount
)

// oidcEndpointNames names each endpoint in an error, and gives its default path
// under the prefix.
var oidcEndpointNames = [oidcEndpointCount]struct{ name, suffix string }{
	OIDCAuthorize:     {"OIDCAuthorize", "/authorize"},
	OIDCResume:        {"OIDCResume", "/authorize/resume"},
	OIDCToken:         {"OIDCToken", "/token"},
	OIDCUserInfo:      {"OIDCUserInfo", "/userinfo"},
	OIDCRevoke:        {"OIDCRevoke", "/revoke"},
	OIDCIntrospect:    {"OIDCIntrospect", "/introspect"},
	OIDCEndSession:    {"OIDCEndSession", "/logout"},
	OIDCLogoutConfirm: {"OIDCLogoutConfirm", "/logout/confirm"},
	OIDCConsents:      {"OIDCConsents", "/consents"},
}

// String names the endpoint as its constant does.
func (e OIDCEndpoint) String() string {
	if e < oidcEndpointCount {
		return oidcEndpointNames[e].name
	}

	return fmt.Sprintf("OIDCEndpoint(%d)", uint8(e))
}

// OIDCProviderOption configures EnableOIDCProvider. Each replaces one of the
// defaults named there.
type OIDCProviderOption func(*oidcEndpoints) error

// WithOIDCProviderPrefix serves the provider's endpoints under prefix.
//
// Default: DefaultOIDCProviderPrefix, "/oauth2", which passes through once the
// consumer moves away from it. The prefix is within the base path
// (WithBasePath): "/auth" with the prefix "/op" serves the token endpoint at
// "/auth/op/token", and a prefix that repeats the base path, such as
// "/auth/op", fails New. One trailing slash is set aside, so "/op" and "/op/"
// are the same prefix. A prefix that is empty, does not start with "/", is "/", or
// holds a character that needs escaping in a URL path (a space, "?", "#" or "%",
// for instance), is refused: a path that needs escaping cannot be published and
// compared unescaped.
//
// An endpoint given its own path with WithOIDCProviderPath keeps that path.
func WithOIDCProviderPrefix(prefix string) OIDCProviderOption {
	const option = "WithOIDCProviderPrefix"

	return func(op *oidcEndpoints) error {
		if err := checkEndpointPath(option, prefix); err != nil {
			return err
		}

		op.prefix = strings.TrimSuffix(prefix, "/")
		op.declare(option, prefix)

		return nil
	}
}

// WithOIDCProviderPath serves one endpoint on path, in place of the prefix
// followed by that endpoint's default. The prefix does not apply to it,
// whichever option came first. With no base path it is the whole request path;
// under WithBasePath it is within the base path: "/auth" with
// WithOIDCProviderPath(OIDCToken, "/tokens") serves the token endpoint at
// "/auth/tokens", and a path that repeats the base path, such as
// "/auth/tokens", fails New.
//
// Default: each endpoint at its place under the prefix, as its constant says.
// A path not starting with "/", one holding a character that needs escaping in
// a URL path (a space, "?", "#" or "%", for instance), or an endpoint that does
// not exist, is refused: a path that needs escaping cannot be published and
// compared unescaped.
func WithOIDCProviderPath(endpoint OIDCEndpoint, path string) OIDCProviderOption {
	const option = "WithOIDCProviderPath"

	return func(op *oidcEndpoints) error {
		if endpoint >= oidcEndpointCount {
			return newConfigError("%s was given %s, which is no endpoint", option, endpoint)
		}

		setting := fmt.Sprintf("%s for %s", option, endpoint)
		if err := checkEndpointPath(setting, path); err != nil {
			return err
		}

		op.overrides[endpoint] = path
		op.declare(setting, path)

		return nil
	}
}

// WithOIDCPagesCarryFrameAncestors states that the consumer's login and consent
// pages carry frame-ancestors themselves, so the chain needs no security headers
// for them.
//
// Default: unstated, under which EnableOIDCProvider requires
// EnableSecurityHeaders, because those pages must not be framed (RFC 9700
// section 4.16). The chain takes the statement on trust: it does not serve those
// pages, and cannot look.
func WithOIDCPagesCarryFrameAncestors() OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		op.pagesCarryFrameAncestors = true

		return nil
	}
}

// WithoutOIDCIssuerBasePathCheck waives the check that, under WithBasePath, the
// provider's issuer covers the base path and everything the provider serves.
//
// Default: checked whenever WithBasePath is set. New then refuses a provider
// unless the issuer's path, one trailing slash aside, is the base path or lies
// under it, and every endpoint of the provider and the key set
// (EnableJWKSEndpoint) lie under the issuer's path. With no base path nothing is
// checked, and this option changes nothing.
//
// It is for a gateway that routes "/.well-known/*" to the chain, or a consumer
// who otherwise makes the URLs reachable. What it gives up:
//
//   - The OpenID configuration may then be served outside the base path: with
//     the issuer "https://id.example.com" and the base path "/auth", it answers
//     at "/.well-known/openid-configuration", which a gateway forwarding only
//     "/auth/*" never sends to the chain.
//   - The metadata may name URLs the chain does not serve: an issuer deeper than
//     the endpoints has its path put in front of each served path.
//
// The OAuth authorization server metadata is at the host root whatever the
// issuer (RFC 8414 section 3), so a proxy must route it in any case.
//
// The waiver does not lift the assertion endpoint check: a provider built with
// oidcprovider.AudienceIssuerOrTokenEndpoint and a root issuer accepts
// assertions naming the issuer followed by "/oauth2/token", which no longer
// matches the token endpoint published under the base path, and New refuses it
// until oidcprovider.WithAssertionTokenEndpoint states the published URL.
func WithoutOIDCIssuerBasePathCheck() OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		op.issuerBasePathWaived = true

		return nil
	}
}
