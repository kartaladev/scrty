package httpsec

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Where the two documents live, and what they are cached for.
const (
	optionOIDCMetadataMember   = "WithOIDCMetadataMember"
	optionOIDCMetadataCacheFor = "WithOIDCMetadataCacheLifetime"

	// oidcConfigurationSuffix is appended to the issuer for the OpenID Provider
	// configuration (OpenID Connect Discovery 1.0, section 4).
	oidcConfigurationSuffix = "/.well-known/openid-configuration"

	// oauthMetadataSuffix is inserted between the issuer's host and its path for the
	// authorization server metadata (RFC 8414, section 3).
	oauthMetadataSuffix = "/.well-known/oauth-authorization-server"

	// DefaultOIDCMetadataCacheLifetime is how long the documents may be cached.
	DefaultOIDCMetadataCacheLifetime = time.Hour
)

// oidcMetadataMembers is every member the provider's documents may carry, those a
// feature adds included. A consumer's member may not take one of these names, so a
// document never says what the provider does not do, whichever features are on.
var oidcMetadataMembers = map[string]struct{}{
	"issuer": {}, "authorization_endpoint": {}, "token_endpoint": {}, "userinfo_endpoint": {},
	"jwks_uri": {}, "revocation_endpoint": {}, "introspection_endpoint": {}, "end_session_endpoint": {},
	"scopes_supported": {}, "claims_supported": {}, "response_types_supported": {},
	"response_modes_supported": {}, "grant_types_supported": {}, "subject_types_supported": {},
	"id_token_signing_alg_values_supported":                    {},
	"token_endpoint_auth_methods_supported":                    {},
	"token_endpoint_auth_signing_alg_values_supported":         {},
	"revocation_endpoint_auth_methods_supported":               {},
	"revocation_endpoint_auth_signing_alg_values_supported":    {},
	"introspection_endpoint_auth_methods_supported":            {},
	"introspection_endpoint_auth_signing_alg_values_supported": {},
	"code_challenge_methods_supported":                         {},
	"request_parameter_supported":                              {}, "request_uri_parameter_supported": {},
	"claims_parameter_supported":                     {},
	"authorization_response_iss_parameter_supported": {},
	"backchannel_logout_supported":                   {}, "backchannel_logout_session_supported": {},
	"dpop_signing_alg_values_supported":          {},
	"tls_client_certificate_bound_access_tokens": {},
}

// oidcMetadataGroup serves the provider's two metadata documents, which carry the
// same content: the OpenID Provider configuration and the OAuth authorization server
// metadata. They are public, answer GET and HEAD, and are cacheable for
// DefaultOIDCMetadataCacheLifetime (WithOIDCMetadataCacheLifetime). Every endpoint
// URL in them comes from the same rule the rest of the provider publishes by, so a
// URL names an endpoint a client can reach.
//
// # Where each document is served
//
// For an issuer without a path, both are at the root: oidcConfigurationSuffix and
// oauthMetadataSuffix. For an issuer with a path (https://id.example.com/auth), the
// two specifications place them differently, and a router that strips the path
// changes what the chain sees:
//
//   - The OpenID configuration is the issuer with oidcConfigurationSuffix appended
//     (OpenID Connect Discovery 1.0, section 4), so its public path is
//     /auth/.well-known/openid-configuration. Behind a router that strips /auth, the
//     chain sees /.well-known/openid-configuration, and serves that. On a chain that is
//     not stripped, whose endpoint paths already include /auth (WithOIDCProviderPrefix),
//     it serves /auth/.well-known/openid-configuration. The chain tells the two apart
//     the way the endpoints' published URLs do: by whether the token endpoint's path
//     is under the issuer's path. It serves one form, never both, so it does not answer
//     for another issuer at the host's root.
//   - The OAuth metadata is the suffix inserted between host and path (RFC 8414,
//     section 3), so its public path is /.well-known/oauth-authorization-server/auth,
//     which is outside the issuer's path. A router that strips /auth does not send it
//     to the chain, so the consumer routes that one path to the chain unstripped. The
//     chain serves it at that path whichever way the rest is mounted.
//
// The members are derived from the configuration: DPoP algorithms and certificate-bound
// tokens only when those are enabled on the chain, the grant types and client
// authentication methods the provider supports, and offline_access only when a client
// may ask for it.
type oidcMetadataGroup struct {
	oidcGroupBase

	// members are the consumer's, already validated, kept as given.
	members map[string]json.RawMessage

	cache    time.Duration
	cacheSet bool

	// document is built by settle, and read only afterwards.
	document []byte
}

var _ oidcWellKnownPaths = (*oidcMetadataGroup)(nil)

// issuerPath is the issuer's path without a terminating slash, empty for none.
func (g *oidcMetadataGroup) issuerPath() string {
	u, err := url.Parse(g.op.provider.Issuer())
	if err != nil {
		return ""
	}

	return strings.TrimRight(u.EscapedPath(), "/")
}

// servedPaths are the paths the chain answers the OpenID configuration and the OAuth
// metadata on.
func (g *oidcMetadataGroup) servedPaths() (openid, oauth string) {
	base := g.issuerPath()

	openid = oidcConfigurationSuffix
	if base != "" && underPrefix(g.op.paths[OIDCToken], base) {
		openid = base + oidcConfigurationSuffix
	}

	return openid, oauthMetadataSuffix + base
}

func (g *oidcMetadataGroup) wellKnownPaths() []string {
	openid, oauth := g.servedPaths()

	return []string{openid, oauth}
}

func (g *oidcMetadataGroup) routes() []oidcRoute {
	openid, oauth := g.servedPaths()

	return []oidcRoute{{path: openid, handle: g.serve}, {path: oauth, handle: g.serve}}
}

// cacheControl is the header's value.
func (g *oidcMetadataGroup) cacheControl() string {
	lifetime := DefaultOIDCMetadataCacheLifetime
	if g.cacheSet {
		lifetime = g.cache
	}

	if lifetime == 0 {
		return "public, no-cache"
	}

	return "public, max-age=" + strconv.FormatInt(int64(lifetime/time.Second), 10)
}

// serve answers the document to anyone, and refuses any method but GET and HEAD.
func (g *oidcMetadataGroup) serve(ex *Exchange, _ Next) error {
	method := ex.Request.Method()
	if method != http.MethodGet && method != http.MethodHead {
		ex.Writer.SetHeader("Allow", "GET, HEAD")
		ex.Writer.WriteHeader(http.StatusMethodNotAllowed)

		return nil
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.SetHeader("Cache-Control", g.cacheControl())
	ex.Writer.WriteHeader(http.StatusOK)

	if method == http.MethodHead {
		return nil
	}

	_, err := ex.Writer.Write(g.document)

	return err
}

// settle builds the document from the configuration, now that every option has been
// applied.
func (g *oidcMetadataGroup) settle(c *config) error {
	op, p := g.op, g.op.provider
	caps := p.Capabilities()

	secretMethods := []string{"client_secret_basic", "client_secret_post", "private_key_jwt"}
	allMethods := append(slices.Clone(secretMethods), "none")

	doc := map[string]any{
		"issuer":                 p.Issuer(),
		"authorization_endpoint": op.publicURL(op.paths[OIDCAuthorize]),
		"token_endpoint":         op.publicURL(op.paths[OIDCToken]),
		"userinfo_endpoint":      op.publicURL(op.paths[OIDCUserInfo]),
		"revocation_endpoint":    op.publicURL(op.paths[OIDCRevoke]),
		"introspection_endpoint": op.publicURL(op.paths[OIDCIntrospect]),
		"end_session_endpoint":   op.publicURL(op.paths[OIDCEndSession]),

		"scopes_supported":                           caps.Scopes,
		"claims_supported":                           caps.Claims,
		"response_types_supported":                   []string{"code"},
		"response_modes_supported":                   []string{"query"},
		"grant_types_supported":                      []string{"authorization_code", "refresh_token"},
		"subject_types_supported":                    []string{"public"},
		"id_token_signing_alg_values_supported":      caps.IDTokenAlgs,
		"code_challenge_methods_supported":           []string{"S256"},
		"token_endpoint_auth_methods_supported":      allMethods,
		"revocation_endpoint_auth_methods_supported": allMethods,
		// A public client may not introspect, so none is not offered there.
		"introspection_endpoint_auth_methods_supported": secretMethods,

		// private_key_jwt is listed on all three, so the assertion algorithms are too.
		"token_endpoint_auth_signing_alg_values_supported":         caps.AssertionAlgs,
		"revocation_endpoint_auth_signing_alg_values_supported":    caps.AssertionAlgs,
		"introspection_endpoint_auth_signing_alg_values_supported": caps.AssertionAlgs,

		"request_parameter_supported":                    false,
		"request_uri_parameter_supported":                false,
		"claims_parameter_supported":                     false,
		"authorization_response_iss_parameter_supported": true,
		"backchannel_logout_supported":                   true,
		"backchannel_logout_session_supported":           true,
	}

	if j, ok := findInterceptor[*jwksEndpoint](c); ok {
		doc["jwks_uri"] = op.publicURL(j.path)
	}

	if c.dpopEnabled && c.dpop != nil {
		algs := make([]string, 0, len(c.dpop.algorithms))
		for name := range c.dpop.algorithms {
			algs = append(algs, name)
		}

		slices.Sort(algs)
		doc["dpop_signing_alg_values_supported"] = algs
	}

	if c.certBinding != nil {
		doc["tls_client_certificate_bound_access_tokens"] = true
	}

	for name, value := range g.members {
		doc[name] = value
	}

	body, err := json.Marshal(doc)
	if err != nil {
		return newConfigError("%s could not write its metadata: %v", optionOIDCProvider, err)
	}

	g.document = body

	return nil
}

// WithOIDCMetadataMember adds a member to both metadata documents, such as
// service_documentation or ui_locales_supported. The value is published as it is
// given, and its meaning is the consumer's.
//
// Default: none. A member the provider sets itself, those of a feature that is off
// included, is a configuration error, as is an empty name, a value JSON cannot
// hold, or a name given twice: the documents never say what the provider does not do.
func WithOIDCMetadataMember(name string, value any) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if name == "" {
			return newConfigError("%s was given no name, so no member could be published", optionOIDCMetadataMember)
		}

		if _, taken := oidcMetadataMembers[name]; taken {
			return newConfigError("%s was given %q, which the provider sets from its own configuration: "+
				"a document would otherwise say what the provider does not do", optionOIDCMetadataMember, name)
		}

		if _, twice := op.metadata.members[name]; twice {
			return newConfigError("%s was given %q twice; give each member once", optionOIDCMetadataMember, name)
		}

		raw, err := json.Marshal(value)
		if err != nil {
			return newConfigError("%s was given a value for %q that JSON cannot hold: %v",
				optionOIDCMetadataMember, name, err)
		}

		if op.metadata.members == nil {
			op.metadata.members = map[string]json.RawMessage{}
		}

		op.metadata.members[name] = raw

		return nil
	}
}

// WithOIDCMetadataCacheLifetime sets how long the documents may be cached, as the
// max-age of their Cache-Control header. A lifetime of zero has caches revalidate
// every time.
//
// Default: DefaultOIDCMetadataCacheLifetime. A negative lifetime, or one under a
// second, which would read as none, is a configuration error.
func WithOIDCMetadataCacheLifetime(d time.Duration) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if d < 0 || (d > 0 && d < time.Second) {
			return newConfigError("%s was given %s; use zero to have caches revalidate, or at least a second",
				optionOIDCMetadataCacheFor, d)
		}

		op.metadata.cache, op.metadata.cacheSet = d, true

		return nil
	}
}
