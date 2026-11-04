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
// Default: DefaultOIDCProviderPrefix, which passes through once the consumer
// moves away from it. A prefix that is empty, does not start with "/" or ends
// with one is refused, since no request path could match what it builds.
//
// An endpoint given its own path with WithOIDCProviderPath keeps that path.
func WithOIDCProviderPrefix(prefix string) OIDCProviderOption {
	const option = "WithOIDCProviderPrefix"

	return func(op *oidcEndpoints) error {
		if !strings.HasPrefix(prefix, "/") || strings.HasSuffix(prefix, "/") {
			return newConfigError("%s was given %q: a prefix starts with \"/\" and does not end with one",
				option, prefix)
		}

		op.prefix = prefix

		return nil
	}
}

// WithOIDCProviderPath serves one endpoint on path, in place of the prefix
// followed by that endpoint's default. The path is the whole request path, and
// the prefix does not apply to it, whichever option came first.
//
// Default: each endpoint at its place under the prefix, as its constant says. A
// path not starting with "/", or an endpoint that does not exist, is refused.
func WithOIDCProviderPath(endpoint OIDCEndpoint, path string) OIDCProviderOption {
	const option = "WithOIDCProviderPath"

	return func(op *oidcEndpoints) error {
		if endpoint >= oidcEndpointCount {
			return newConfigError("%s was given %s, which is no endpoint", option, endpoint)
		}

		if !strings.HasPrefix(path, "/") {
			return newConfigError("%s was given %q for %s: a path starts with \"/\"", option, path, endpoint)
		}

		op.overrides[endpoint] = path

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
