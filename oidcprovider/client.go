package oidcprovider

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/signingkey"
)

// ClientType says whether a client can keep a credential. It has no usable zero
// value, so every client states it.
type ClientType uint8

const (
	// Confidential clients can keep a credential.
	Confidential ClientType = iota + 1
	// Public clients cannot, and authenticate with no secret.
	Public
)

// ApplicationType says where a client runs, which decides its redirect URI
// rules. The default is Web.
type ApplicationType uint8

const (
	// Web is the default: https redirect URIs only.
	Web ApplicationType = iota
	// Native also allows a private-use scheme containing a period, and http to a
	// loopback IP literal.
	Native
)

// AuthMethod is a client's one token endpoint authentication method.
type AuthMethod string

const (
	// ClientSecretBasic is a confidential client's default.
	ClientSecretBasic AuthMethod = "client_secret_basic"
	// ClientSecretPost sends the secret in the form body.
	ClientSecretPost AuthMethod = "client_secret_post"
	// PrivateKeyJWT sends an assertion signed by a registered key.
	PrivateKeyJWT AuthMethod = "private_key_jwt"
	// AuthMethodNone is a public client's only method, and its default.
	AuthMethodNone AuthMethod = "none"
)

// OfflineAccess says when a client's offline access is asked about. The default
// is OfflineAskOnce.
type OfflineAccess uint8

const (
	// OfflineAskOnce asks the user, and is the default.
	OfflineAskOnce OfflineAccess = iota
	// OfflinePreAuthorized never asks, and is only for a first-party native
	// client.
	OfflinePreAuthorized
)

// BindingRequirement says which sender constraint a client's tokens must carry.
// The default is BindingOptional.
type BindingRequirement uint8

const (
	// BindingOptional binds a token when the client asks, and is the default.
	BindingOptional BindingRequirement = iota
	// BindingDPoP requires DPoP.
	BindingDPoP
	// BindingMTLS requires a certificate binding.
	BindingMTLS
)

// GrantType is a grant a client may use. The default is
// GrantAuthorizationCode alone.
type GrantType string

const (
	// GrantAuthorizationCode is the code flow.
	GrantAuthorizationCode GrantType = "authorization_code"
	// GrantRefreshToken is refreshing.
	GrantRefreshToken GrantType = "refresh_token"
)

// PKCERequirement says what an authorization request must carry. The default is
// PKCERequired.
type PKCERequirement uint8

const (
	// PKCERequired requires a code challenge, and is the default.
	PKCERequired PKCERequirement = iota
	// PKCEOrNonce accepts a code challenge or a nonce, and is only for a
	// confidential client.
	PKCEOrNonce
)

// redacted is what a SecretBytes prints and marshals as.
const redacted = "[REDACTED]"

// SecretBytes is a secret or a digest of one. It converts to and from []byte, so
// the package and its consumers read and set it as bytes, but it prints and
// marshals as a fixed redacted form under every fmt verb and encoding/json, so a
// log line, an error or a response body cannot carry it by accident. A consumer
// who needs the bytes converts: []byte(s).
type SecretBytes []byte

// String returns the redacted form.
func (SecretBytes) String() string { return redacted }

// GoString returns the redacted form.
func (SecretBytes) GoString() string { return redacted }

// Format writes the redacted form under every verb.
func (SecretBytes) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// MarshalJSON writes the redacted form as a JSON string, or null when it holds
// nothing.
func (s SecretBytes) MarshalJSON() ([]byte, error) {
	if len(s) == 0 {
		return []byte("null"), nil
	}

	return []byte(`"` + redacted + `"`), nil
}

// MarshalText writes the redacted form, for text-based encoders.
func (SecretBytes) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Client is one relying party's registration.
type Client struct {
	// ID is the client identifier, required, in printable ASCII.
	ID string
	// Name is shown to the user. It is optional.
	Name string
	// Type is required, and has no default.
	Type ClientType
	// ApplicationType defaults to Web.
	ApplicationType ApplicationType
	// AuthMethod defaults to ClientSecretBasic for a confidential client and
	// AuthMethodNone for a public one.
	AuthMethod AuthMethod
	// PKCE defaults to PKCERequired.
	PKCE PKCERequirement
	// Secret is a secret the consumer supplies, at least 32 bytes. It is nil once
	// registered, when only its digest is kept. It prints and marshals redacted.
	Secret SecretBytes
	// JWKS is the registered key set for PrivateKeyJWT, holding public keys only.
	// PrivateKeyJWT takes exactly one of JWKS and JWKSURI, and no other method takes
	// either.
	JWKS []byte
	// JWKSURI is where to fetch the key set for PrivateKeyJWT, over https, through the
	// provider's outbound client.
	JWKSURI string

	// RedirectURIs are required when the client uses the authorization endpoint.
	RedirectURIs []string
	// PostLogoutRedirectURIs follow the same rules as RedirectURIs. There are none by
	// default.
	PostLogoutRedirectURIs []string
	// BackChannelLogoutURI must be https. It is empty by default, and the client then
	// gets no back-channel logout.
	BackChannelLogoutURI string

	// Scopes are those the client may ask for. There are none by default.
	Scopes []string
	// Resources are those the client may ask for, each an absolute URI with no fragment. There
	// are none by default. They are an allowlist and never a default audience: a code granted
	// several of them and exchanged with none named is invalid_target, and a code granted one
	// makes it the audience, with no issuer, even for openid. A client that also wants the
	// issuer as an audience, to call UserInfo with the token, lists the issuer here and names
	// it beside the resource it asks for.
	Resources []string
	// DefaultAudience is the audience when a request names no resource and its code was granted
	// none, with the issuer added for an openid token so it stays usable at UserInfo. It is
	// empty by default, and a token is then for the issuer alone. Each value is an absolute URI
	// with no fragment. It does not apply once the code was granted a resource: one granted is
	// the audience instead, and several are refused. It is never made of Resources.
	DefaultAudience []string
	// ResourceIdentifier names this client as a resource server. It is empty by
	// default.
	ResourceIdentifier string
	// GrantTypes defaults to GrantAuthorizationCode alone.
	GrantTypes []GrantType

	// FirstParty changes only when consent is asked. It defaults to off.
	FirstParty bool
	// OfflineAccess defaults to OfflineAskOnce.
	OfflineAccess OfflineAccess

	// IDTokenAlg defaults to RS256, and must be one the keys can produce. The client's
	// JWT access tokens are signed with it too.
	IDTokenAlg string
	// IDTokenLifetime defaults to 5 minutes, within the key cap.
	IDTokenLifetime time.Duration
	// AccessTokenLifetime defaults to 5 minutes, within the key cap.
	AccessTokenLifetime time.Duration
	// OpaqueAccessTokens replaces JWT access tokens, which are the default.
	OpaqueAccessTokens bool
	// RequireBinding defaults to BindingOptional.
	RequireBinding BindingRequirement

	// RefreshGrace defaults to 30 seconds, at most session.MaxRenewalGrace.
	RefreshGrace time.Duration
	// GrantIdleTimeout defaults to 30 days, or the absolute lifetime when that is
	// shorter, and is at most the absolute lifetime.
	GrantIdleTimeout time.Duration
	// GrantAbsoluteLifetime defaults to 90 days.
	GrantAbsoluteLifetime time.Duration
	// DisableRotation turns off refresh token rotation, which is on by default. It is
	// only for a confidential client required to use sender-constrained tokens.
	DisableRotation bool
	// EndGrantsWithSignIn ends the client's grants with the sign-in they came
	// from. A public web client's default is on, and any other's is off.
	EndGrantsWithSignIn bool
	// KeepPublicWebGrantsPastSignIn overrides a public web client's default, and is
	// only for one. It contradicts EndGrantsWithSignIn.
	KeepPublicWebGrantsPastSignIn bool

	// Metadata belongs to the consumer, and is returned unchanged.
	Metadata map[string]string
}

// The defaults a client's settings take, and the bounds they meet. Each is named
// on its field.
const (
	minSuppliedSecret            = 32
	defaultTokenLifetime         = 5 * time.Minute
	defaultGrantIdleTimeout      = 30 * 24 * time.Hour
	defaultGrantAbsoluteLifetime = 90 * 24 * time.Hour
)

// clientError is a refused client registration. It matches ErrConfig, and names
// the client and the setting. Its reason never repeats a URI or a secret: a URI
// can hold a credential in its user information.
type clientError struct {
	client, setting, reason string
}

func (e *clientError) Error() string {
	return fmt.Sprintf("%s: client %q: %s: %s", ErrConfig, e.client, e.setting, e.reason)
}

func (e *clientError) Unwrap() error { return ErrConfig }

func (c *Client) refuse(setting, reason string) error {
	return &clientError{client: c.ID, setting: setting, reason: reason}
}

// keyLimits is what the provider's key source lets a client ask for.
type keyLimits struct {
	algs []signingkey.Alg
	// window is the longest token lifetime the keys allow, meaningful when capped.
	window time.Duration
	// capped says the source reports its lifetimes. One that does not gets no
	// lifetime check, as token's generator gives it none.
	capped bool
}

// limitsOf reads what keys can report about itself. A source that does not list
// its algorithms is taken to produce RS256 alone, because the provider cannot
// confirm any other, and the failure then comes at construction instead of at the
// first issue.
func limitsOf(keys signingkey.KeySource) keyLimits {
	limits := keyLimits{algs: []signingkey.Alg{signingkey.RS256}}
	if lister, ok := keys.(interface{ SupportedAlgs() []signingkey.Alg }); ok {
		limits.algs = lister.SupportedAlgs()
	}
	if reporter, ok := keys.(signingkey.LifetimeReporter); ok {
		limits.window = reporter.KeyLifetime() - reporter.RotateInterval()
		limits.capped = true
	}

	return limits
}

// checkKeys takes a client whose defaults are resolved.
func (c *Client) checkKeys(limits keyLimits) error {
	if !slices.Contains(limits.algs, c.IDTokenAlg) {
		return c.refuse("IDTokenAlg", fmt.Sprintf("the keys cannot produce %s", c.IDTokenAlg))
	}
	if !limits.capped {
		return nil
	}
	if c.IDTokenLifetime > limits.window {
		return c.refuse("IDTokenLifetime", fmt.Sprintf("%s exceeds the keys' usable window of %s", c.IDTokenLifetime, limits.window))
	}
	if c.AccessTokenLifetime > limits.window {
		return c.refuse("AccessTokenLifetime", fmt.Sprintf("%s exceeds the keys' usable window of %s", c.AccessTokenLifetime, limits.window))
	}

	return nil
}

// validateClient refuses a registration that cannot work, whatever the provider's
// keys are, and returns the client with its defaults resolved. Validating a
// resolved client changes nothing.
func validateClient(c Client) (Client, error) {
	for _, check := range []func(*Client) error{
		(*Client).validateKind,
		(*Client).validateCredentials,
		(*Client).validateGrantTypes,
		(*Client).validateURIs,
		(*Client).validateAudiences,
		(*Client).validatePolicies,
		(*Client).validateLifetimes,
		(*Client).validateGrantLifetimes,
	} {
		if err := check(&c); err != nil {
			return Client{}, err
		}
	}

	return c, nil
}

func (c *Client) validateKind() error {
	if c.ID == "" {
		return c.refuse("ID", "is required")
	}
	if !validClientID(c.ID) {
		return c.refuse("ID", "must be printable ASCII")
	}
	if c.Type != Confidential && c.Type != Public {
		return c.refuse("Type", "must be Confidential or Public")
	}
	if c.ApplicationType != Web && c.ApplicationType != Native {
		return c.refuse("ApplicationType", "must be Web or Native")
	}

	return c.validateMethod()
}

// validClientID says whether a client could be registered under id: not empty, and,
// by RFC 6749 appendix A, printable ASCII, so it is safe in a log and in Basic.
func validClientID(id string) bool {
	return id != "" && !strings.ContainsFunc(id, func(r rune) bool { return r < 0x20 || r > 0x7e })
}

func (c *Client) validateMethod() error {
	if c.AuthMethod == "" {
		c.AuthMethod = ClientSecretBasic
		if c.Type == Public {
			c.AuthMethod = AuthMethodNone
		}
	}

	switch c.AuthMethod {
	case ClientSecretBasic, ClientSecretPost, PrivateKeyJWT:
		if c.Type == Public {
			return c.refuse("AuthMethod", fmt.Sprintf("a public client cannot use %s", c.AuthMethod))
		}
	case AuthMethodNone:
		if c.Type == Confidential {
			return c.refuse("AuthMethod", "a confidential client must prove possession of a credential")
		}
	case "client_secret_jwt":
		return c.refuse("AuthMethod", "client_secret_jwt is not supported")
	default:
		return c.refuse("AuthMethod", fmt.Sprintf("unknown method %q", c.AuthMethod))
	}

	return nil
}

func (c *Client) usesSecret() bool {
	return c.AuthMethod == ClientSecretBasic || c.AuthMethod == ClientSecretPost
}

func (c *Client) validateCredentials() error {
	if len(c.Secret) > 0 {
		if !c.usesSecret() {
			return c.refuse("Secret", fmt.Sprintf("%s takes no secret", c.AuthMethod))
		}
		if len(c.Secret) < minSuppliedSecret {
			return c.refuse("Secret", fmt.Sprintf("a supplied secret must be at least %d bytes", minSuppliedSecret))
		}
	}

	if c.AuthMethod != PrivateKeyJWT {
		if len(c.JWKS) > 0 || c.JWKSURI != "" {
			return c.refuse("JWKS", "a key set is only for private_key_jwt")
		}

		return nil
	}

	switch {
	case len(c.JWKS) > 0 && c.JWKSURI != "":
		return c.refuse("JWKS", "set one of JWKS and JWKSURI, got both")
	case len(c.JWKS) == 0 && c.JWKSURI == "":
		return c.refuse("JWKS", "private_key_jwt needs JWKS or JWKSURI")
	case c.JWKSURI != "":
		return c.validateHTTPSEndpoint("JWKSURI", c.JWKSURI)
	}

	set, err := jwk.Parse(c.JWKS)
	if err != nil || set.Len() == 0 {
		return c.refuse("JWKS", "must be a key set holding at least one key")
	}

	return c.checkPublicKeys("JWKS", set)
}

// checkPublicKeys refuses a key set that holds a symmetric key, which a client
// assertion cannot use here, or any private material, which a key set the
// provider stores and serves must never carry. The reason names the position of the
// key and never its material.
func (c *Client) checkPublicKeys(setting string, set jwk.Set) error {
	for i := range set.Len() {
		key, _ := set.Key(i)
		if isSymmetricKey(key) {
			return c.refuse(setting, fmt.Sprintf("key %d is a symmetric key; only public keys are accepted", i))
		}
		if isPrivateKey(key) {
			return c.refuse(setting, fmt.Sprintf("key %d holds private material; only public keys are accepted", i))
		}
	}

	return nil
}

func isSymmetricKey(key jwk.Key) bool {
	_, symmetric := key.(jwk.SymmetricKey)

	return symmetric || key.Has("k")
}

func isPrivateKey(key jwk.Key) bool {
	private, err := jwk.IsPrivateKey(key)

	return (err == nil && private) || key.Has("d")
}

func (c *Client) validateGrantTypes() error {
	if len(c.GrantTypes) == 0 {
		c.GrantTypes = []GrantType{GrantAuthorizationCode}
	}
	for _, g := range c.GrantTypes {
		if g != GrantAuthorizationCode && g != GrantRefreshToken {
			return c.refuse("GrantTypes", fmt.Sprintf("unknown grant type %q", g))
		}
	}

	return nil
}

func (c *Client) validateURIs() error {
	if len(c.RedirectURIs) == 0 && slices.Contains(c.GrantTypes, GrantAuthorizationCode) {
		return c.refuse("RedirectURIs", "a client using the authorization endpoint needs one")
	}
	for i, uri := range c.RedirectURIs {
		if err := c.validateRedirectURI(fmt.Sprintf("RedirectURIs[%d]", i), uri); err != nil {
			return err
		}
	}
	for i, uri := range c.PostLogoutRedirectURIs {
		if err := c.validateRedirectURI(fmt.Sprintf("PostLogoutRedirectURIs[%d]", i), uri); err != nil {
			return err
		}
	}
	if c.BackChannelLogoutURI != "" {
		return c.validateHTTPSEndpoint("BackChannelLogoutURI", c.BackChannelLogoutURI)
	}

	return nil
}

// validResource says whether value could be a resource indicator (RFC 8707 §2): an absolute
// URI with no fragment, and no space around it, since a value of that kind can never be what a
// request names. An authorization request holds its resources to the same. Text that is not
// valid UTF-8 is refused too, since a request carrying it is refused before any match.
func validResource(value string) bool {
	if value == "" || !utf8.ValidString(value) || value != strings.TrimSpace(value) || strings.Contains(value, "#") {
		return false
	}
	u, err := url.Parse(value)

	return err == nil && u.IsAbs()
}

// validateAudiences refuses an audience or a resource that a token could never name, so the
// mistake fails at construction and not at the first exchange. The reason never repeats the
// value.
func (c *Client) validateAudiences() error {
	for _, field := range []struct {
		setting string
		values  []string
	}{
		{"DefaultAudience", c.DefaultAudience},
		{"Resources", c.Resources},
	} {
		for i, value := range field.values {
			if !validResource(value) {
				return c.refuse(fmt.Sprintf("%s[%d]", field.setting, i), "must be an absolute URI with no fragment")
			}
		}
	}

	return nil
}

// parseRegisteredURI applies what every registered URI must meet, and returns
// the parsed URI.
func (c *Client) parseRegisteredURI(setting, uri string) (*url.URL, error) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme == "" {
		return nil, c.refuse(setting, "must be an absolute URI")
	}
	if strings.Contains(uri, "#") {
		return nil, c.refuse(setting, "must have no fragment")
	}
	if strings.Contains(uri, "*") {
		return nil, c.refuse(setting, "must have no wildcard")
	}
	if u.User != nil {
		return nil, c.refuse(setting, "must have no user information")
	}

	return u, nil
}

func (c *Client) validateRedirectURI(setting, uri string) error {
	u, err := c.parseRegisteredURI(setting, uri)
	if err != nil {
		return err
	}

	if u.Scheme == "https" {
		if u.Hostname() == "" {
			return c.refuse(setting, "must name a host")
		}

		return nil
	}
	if c.ApplicationType == Web {
		return c.refuse(setting, "a web client must use https")
	}

	if u.Scheme == "http" {
		if host := u.Hostname(); host != "127.0.0.1" && host != "::1" {
			return c.refuse(setting, "a native client's http must go to 127.0.0.1 or [::1]")
		}

		return nil
	}
	// Schemes that run or read something in the browser (javascript, data, vbscript,
	// file) hold no period, so this rule keeps them out; a list would add nothing.
	if !strings.Contains(u.Scheme, ".") {
		return c.refuse(setting, "a private-use scheme must contain a period")
	}
	if u.Host == "" && u.Path == "" && u.Opaque == "" {
		return c.refuse(setting, "must name a path")
	}

	return nil
}

func (c *Client) validateHTTPSEndpoint(setting, uri string) error {
	u, err := c.parseRegisteredURI(setting, uri)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return c.refuse(setting, "must be an absolute https URL")
	}

	return nil
}

func (c *Client) validatePolicies() error {
	if c.PKCE != PKCERequired && c.PKCE != PKCEOrNonce {
		return c.refuse("PKCE", "must be PKCERequired or PKCEOrNonce")
	}
	if c.PKCE == PKCEOrNonce && c.Type != Confidential {
		return c.refuse("PKCE", "PKCEOrNonce is only for a confidential client")
	}

	switch c.OfflineAccess {
	case OfflineAskOnce:
	case OfflinePreAuthorized:
		if c.ApplicationType != Native || !c.FirstParty {
			return c.refuse("OfflineAccess", "OfflinePreAuthorized is only for a first-party native client")
		}
	default:
		return c.refuse("OfflineAccess", "must be OfflineAskOnce or OfflinePreAuthorized")
	}

	if c.RequireBinding > BindingMTLS {
		return c.refuse("RequireBinding", "must be BindingOptional, BindingDPoP or BindingMTLS")
	}
	if c.DisableRotation && (c.Type != Confidential || c.RequireBinding == BindingOptional) {
		return c.refuse("DisableRotation", "only for a confidential client required to use sender-constrained tokens")
	}

	publicWeb := c.Type == Public && c.ApplicationType == Web
	if c.KeepPublicWebGrantsPastSignIn {
		if !publicWeb {
			return c.refuse("KeepPublicWebGrantsPastSignIn", "only for a public web client")
		}
		if c.EndGrantsWithSignIn {
			return c.refuse("KeepPublicWebGrantsPastSignIn", "contradicts EndGrantsWithSignIn")
		}
	}
	if publicWeb && !c.KeepPublicWebGrantsPastSignIn {
		c.EndGrantsWithSignIn = true
	}

	return nil
}

func (c *Client) validateLifetimes() error {
	if c.IDTokenAlg == "" {
		c.IDTokenAlg = signingkey.RS256
	}
	if !signingkey.SupportedAlg(c.IDTokenAlg) {
		return c.refuse("IDTokenAlg", fmt.Sprintf("unsupported algorithm %q", c.IDTokenAlg))
	}

	for _, l := range []struct {
		setting string
		value   *time.Duration
	}{
		{"IDTokenLifetime", &c.IDTokenLifetime},
		{"AccessTokenLifetime", &c.AccessTokenLifetime},
	} {
		switch {
		case *l.value == 0:
			*l.value = defaultTokenLifetime
		case *l.value < 0:
			return c.refuse(l.setting, "must be positive")
		case *l.value%time.Second != 0:
			// Expiry is recorded in whole seconds.
			return c.refuse(l.setting, "must be a whole number of seconds")
		}
	}

	return nil
}

func (c *Client) validateGrantLifetimes() error {
	switch {
	case c.RefreshGrace == 0:
		c.RefreshGrace = session.DefaultRenewalGrace
	case c.RefreshGrace < 0 || c.RefreshGrace > session.MaxRenewalGrace:
		return c.refuse("RefreshGrace", fmt.Sprintf("must be positive and at most %s", session.MaxRenewalGrace))
	}

	switch {
	case c.GrantAbsoluteLifetime == 0:
		c.GrantAbsoluteLifetime = defaultGrantAbsoluteLifetime
	case c.GrantAbsoluteLifetime < 0:
		return c.refuse("GrantAbsoluteLifetime", "must be positive")
	}

	switch {
	case c.GrantIdleTimeout == 0:
		c.GrantIdleTimeout = min(defaultGrantIdleTimeout, c.GrantAbsoluteLifetime)
	case c.GrantIdleTimeout < 0 || c.GrantIdleTimeout > c.GrantAbsoluteLifetime:
		return c.refuse("GrantIdleTimeout", "must be positive and at most GrantAbsoluteLifetime")
	}

	return nil
}
