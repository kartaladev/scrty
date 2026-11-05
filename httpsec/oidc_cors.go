package httpsec

import (
	"maps"
	"slices"
	"strings"
)

// Header names the provider's client endpoints add to the CORS policy.
const headerAuthorization = "Authorization"

// corsScope is how the CORS layer treats one request path.
type corsScope uint8

const (
	// corsScopeConsumer is every path that is not the provider's: the policy applies as
	// the consumer wrote it.
	corsScopeConsumer corsScope = iota

	// corsScopeClient is an endpoint a browser client calls with a script: the policy's
	// allowlist applies, with the protocol's headers added and credentials never allowed.
	corsScopeClient

	// corsScopeBrowser is an endpoint the user's own browser is sent to. It carries no
	// CORS header.
	corsScopeBrowser
)

// oidcCORSBrowserEndpoints are the endpoints that never carry a CORS header: the
// authorization request is a navigation, the resume and the end-session pair are where
// the user's pages hand the browser back, and answering a script there would let a page
// on another origin read what is meant for the user (RFC 9700 section 2.6).
var oidcCORSBrowserEndpoints = []OIDCEndpoint{OIDCAuthorize, OIDCResume, OIDCEndSession, OIDCLogoutConfirm}

// oidcCORSClientEndpoints are the endpoints a browser client's script may call.
var oidcCORSClientEndpoints = []OIDCEndpoint{OIDCToken, OIDCUserInfo, OIDCRevoke, OIDCIntrospect}

// corsScope reports how the CORS layer treats path. It reads the paths the provider
// settled on each call, so it follows WithOIDCProviderPrefix and WithOIDCProviderPath, and
// treats every path as the consumer's when op is nil.
func (op *oidcEndpoints) corsScope(path string) corsScope {
	if op == nil {
		return corsScopeConsumer
	}

	for _, e := range oidcCORSBrowserEndpoints {
		if path == op.paths[e] {
			return corsScopeBrowser
		}
	}

	for _, e := range oidcCORSClientEndpoints {
		if path == op.paths[e] {
			return corsScopeClient
		}
	}

	if slices.Contains(op.metadata.wellKnownPaths(), path) {
		return corsScopeClient
	}

	return corsScopeConsumer
}

// deriveClientLists builds the lists the provider's client endpoints follow from the
// layer's own: Authorization and DPoP are allowed, and DPoP-Nonce and WWW-Authenticate
// exposed, unless WithoutAutomaticCORSHeaders turned the additions off. It runs once,
// after the layer's other additions.
func (l *corsLayer) deriveClientLists() {
	l.clientHeaders = maps.Clone(l.headers)

	exposed := slices.Clone(l.exposedNames)

	if !l.manual {
		for _, h := range []string{headerAuthorization, headerDPoP} {
			if _, ok := l.clientHeaders[strings.ToLower(h)]; !ok {
				l.clientHeaders[strings.ToLower(h)] = h
			}
		}

		for _, h := range []string{headerDPoPNonce, headerWWWAuthenticate} {
			if !slices.ContainsFunc(exposed, func(e string) bool { return strings.EqualFold(e, h) }) {
				exposed = append(exposed, h)
			}
		}
	}

	l.clientExposed = strings.Join(exposed, ", ")
}
