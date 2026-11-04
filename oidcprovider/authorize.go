package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// The authorization request's parameters.
const (
	paramRedirectURI         = "redirect_uri"
	paramResponseType        = "response_type"
	paramResponseMode        = "response_mode"
	paramScope               = "scope"
	paramState               = "state"
	paramNonce               = "nonce"
	paramCodeChallenge       = "code_challenge"
	paramCodeChallengeMethod = "code_challenge_method"
	paramResource            = "resource"
	paramRequest             = "request"
	paramRequestURI          = "request_uri"
	paramPrompt              = "prompt"
	paramMaxAge              = "max_age"
	paramDisplay             = "display"
	paramIDTokenHint         = "id_token_hint"
	paramDPoPJKT             = "dpop_jkt"
	paramLoginHint           = "login_hint"
	paramUILocales           = "ui_locales"
	paramClaimsLocales       = "claims_locales"
	paramACRValues           = "acr_values"
)

// The values the protocol names.
const (
	responseTypeCode  = "code"
	responseModeQuery = "query"
	challengeS256     = "S256"
	scopeOpenID       = "openid"
	scopeOffline      = "offline_access"
	promptNone        = "none"
	promptLogin       = "login"
	promptConsent     = "consent"
	promptSelect      = "select_account"
)

// The bounds a request meets beside RequestBounds.
const (
	maxOtherParam = 4 << 10
	maxResources  = 10
	minChallenge  = 43
	maxChallenge  = 128
)

// singleParams are the parameters the provider reads that a request may give only
// once. client_id and redirect_uri have the same rule, and an answer of their own.
// Anything not listed here, and not resource, is unknown, and ignored as the
// standards require, whatever its size and however often it is given.
var singleParams = []string{
	paramResponseType, paramResponseMode, paramScope, paramState, paramNonce,
	paramCodeChallenge, paramCodeChallengeMethod, paramRequest, paramRequestURI,
	paramPrompt, paramMaxAge, paramDisplay, paramIDTokenHint, paramDPoPJKT,
	paramLoginHint, paramUILocales, paramClaimsLocales, paramACRValues,
}

// AuthorizeInput is what the authorization endpoint hands the provider.
type AuthorizeInput struct {
	// Params are the request's parameters, from the query or the form body. A parameter
	// given more than once makes the request invalid, one with no value counts as
	// omitted, and an unknown one is ignored.
	Params url.Values

	// FlowSecret is the value of the browser's flow cookie, or empty when it sent none.
	// One the provider could have minted is kept, so a browser's parallel requests can
	// each be resumed. Anything else is replaced.
	FlowSecret string
}

// Format writes the redacted form under every verb. The input holds the browser's flow
// secret, so it prints and logs redacted too; read its fields to use it.
func (AuthorizeInput) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue is the redacted form.
func (AuthorizeInput) LogValue() slog.Value { return slog.StringValue(redacted) }

// AuthorizeResult says where the browser goes next. It carries the handle and the flow
// secret, so it prints and logs redacted; read its fields to use it.
type AuthorizeResult struct {
	// Location is where to send the browser, with status 303: the client's redirect URI
	// carrying the answer, or the consumer's login page carrying the handle.
	Location string

	// FlowSecret is the value to set the flow cookie to, and is empty unless the request
	// was parked.
	FlowSecret string
}

// Format writes the redacted form under every verb.
func (AuthorizeResult) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue is the redacted form.
func (AuthorizeResult) LogValue() slog.Value { return slog.StringValue(redacted) }

// Authorize answers an authorization request. It refuses with ErrInvalidAuthorization
// when the client or the redirect URI cannot be trusted, which the chain reports with no
// redirect whatever else the request holds, and fails with a dependency failure when a
// store, registry or key source does. Once the client and redirect URI are valid, every
// other refusal comes back as a Location at that redirect URI carrying error, the
// request's state and iss, and no error_description.
//
// A valid request is parked, and the Location is the consumer's login page with the
// handle in its req parameter. The page reads the request with PendingRequest, signs the
// user in, and hands the sign-in to Resume, whose answer says where the browser goes next. A
// prompt=none request is answered login_required, because nothing can answer it silently.
//
// Authorize does not judge TLS, and renders nothing: both are the chain's.
func (p *Provider) Authorize(ctx context.Context, in AuthorizeInput) (AuthorizeResult, error) {
	req, _, err := p.validate(ctx, in.Params)
	if err != nil {
		var refusal *redirectRefusal
		if errors.As(err, &refusal) {
			return AuthorizeResult{Location: refusal.location(p.issuer)}, nil
		}

		return AuthorizeResult{}, err
	}

	if slices.Contains(req.Prompt, promptNone) {
		refusal := redirectRefusal{code: CodeLoginRequired, redirectURI: req.RedirectURI, state: req.State}

		return AuthorizeResult{Location: refusal.location(p.issuer)}, nil
	}

	return p.park(ctx, req, in.FlowSecret)
}

// DPoPEnabled reports whether WithDPoP was given, so that the chain can check it agrees
// with what the chain verifies.
func (p *Provider) DPoPEnabled() bool { return p.cfg.dpopEnabled }

// redirectRefusal is a refusal the redirect URI may be told of. Its text is the code
// alone, because the redirect URI and the state are the requester's.
type redirectRefusal struct {
	code, redirectURI, state string
}

func (r *redirectRefusal) Error() string { return "oidcprovider: " + r.code }

func (r *redirectRefusal) location(issuer string) string {
	answer := url.Values{"error": {r.code}, "iss": {issuer}}
	if r.state != "" {
		answer.Set(paramState, r.state)
	}

	return withQuery(r.redirectURI, answer)
}

// withQuery appends q to uri. It works on the string rather than a parsed URL, so a
// registered URI's own query stays as it was registered, byte for byte.
func withQuery(uri string, q url.Values) string {
	separator := "?"
	if strings.Contains(uri, "?") {
		separator = "&"
		if strings.HasSuffix(uri, "?") || strings.HasSuffix(uri, "&") {
			separator = ""
		}
	}

	return uri + separator + q.Encode()
}

// validate reads an authorization request into a record ready to park. The client and
// redirect URI come first: nothing else a request holds can turn their refusal into a
// redirect, because until both are valid nothing says where a redirect could safely go.
//
// A refusal the redirect URI may hear of is a *redirectRefusal. Any other error is
// ErrInvalidAuthorization or a dependency failure, and sends the browser nowhere.
func (p *Provider) validate(ctx context.Context, params url.Values) (*PendingRequest, *RegisteredClient, error) {
	rc, redirectURI, err := p.validateTarget(ctx, params)
	if err != nil {
		return nil, nil, err
	}

	reading := &requestReading{
		params: params,
		client: rc,
		bounds: p.cfg.bounds,
		dpop:   p.cfg.dpopEnabled,
		req:    &PendingRequest{ClientID: rc.ID, RedirectURI: redirectURI},
	}
	code, err := p.readRequest(ctx, reading)
	switch {
	case err != nil:
		return nil, nil, err
	case code != "":
		return nil, nil, &redirectRefusal{code: code, redirectURI: redirectURI, state: reading.reflectableState()}
	}

	return reading.req, rc, nil
}

// validateTarget finds whom the request is from, and where it may be answered. It
// answers one fixed error for every refusal, holding no value from the request.
func (p *Provider) validateTarget(ctx context.Context, params url.Values) (*RegisteredClient, string, error) {
	ids, uris := params[paramClientID], params[paramRedirectURI]
	if len(ids) != 1 || len(uris) != 1 ||
		len(ids[0]) > maxOtherParam || len(uris[0]) > maxOtherParam {
		return nil, "", ErrInvalidAuthorization
	}

	rc, err := p.client(ctx, ids[0])
	switch {
	case errors.Is(err, ErrClientNotFound):
		return nil, "", ErrInvalidAuthorization
	case err != nil:
		return nil, "", err
	case !rc.MatchRedirectURI(uris[0]):
		return nil, "", ErrInvalidAuthorization
	}

	return rc, uris[0], nil
}

// readRequest runs the checks and answers the first refusal's code, or nothing. What no
// store could hold or a redirect should repeat goes first, so that every such value is
// invalid_request whichever parameter holds it. The rest follow the order the
// requirements state, with the hint last, because only it costs a lookup.
func (p *Provider) readRequest(ctx context.Context, r *requestReading) (string, error) {
	for _, step := range []func(*requestReading) string{
		(*requestReading).readRepeats,
		(*requestReading).readBounds,
		(*requestReading).readResponseType,
		(*requestReading).readPKCE,
		(*requestReading).readScopes,
		(*requestReading).readResources,
		(*requestReading).readRequestObjects,
		(*requestReading).readPrompt,
		(*requestReading).readMaxAge,
		(*requestReading).readBinding,
	} {
		if code := step(r); code != "" {
			return code, nil
		}
	}
	r.readKept()

	return p.readHint(ctx, r)
}

// requestReading is one request as it is read. Each read returns a refusal's code, or
// nothing, and adds what it accepted to req.
type requestReading struct {
	params url.Values
	client *RegisteredClient
	bounds RequestBounds
	dpop   bool
	req    *PendingRequest
}

func (r *requestReading) get(name string) string { return r.params.Get(name) }

// words splits a space-separated parameter on single spaces, dropping the empty items
// and the repeats. Any other separator stays part of a value.
func words(raw string) []string {
	var out []string
	for item := range strings.SplitSeq(raw, " ") {
		if item != "" && !slices.Contains(out, item) {
			out = append(out, item)
		}
	}

	return out
}

// reflectableState is what a refusal may send back: the state, unless it is what was
// at fault, so a value past the bound is never reflected, and neither of two is chosen.
func (r *requestReading) reflectableState() string {
	values := r.params[paramState]
	if len(values) != 1 || len(values[0]) > r.boundOf(paramState) || !storable(values[0]) {
		return ""
	}

	return values[0]
}

func (r *requestReading) readRepeats() string {
	for _, name := range singleParams {
		if len(r.params[name]) > 1 {
			return CodeInvalidRequest
		}
	}

	return ""
}

func (r *requestReading) readResponseType() string {
	switch r.get(paramResponseType) {
	case responseTypeCode:
		if !slices.Contains(r.client.GrantTypes, GrantAuthorizationCode) {
			return CodeUnauthorizedClient
		}
	case "":
		return CodeInvalidRequest
	default:
		return CodeUnsupportedResponseType
	}

	if mode := r.get(paramResponseMode); mode != "" && mode != responseModeQuery {
		return CodeInvalidRequest
	}

	return ""
}

func (r *requestReading) boundOf(name string) int {
	switch name {
	case paramState:
		return r.bounds.State
	case paramNonce:
		return r.bounds.Nonce
	case paramLoginHint:
		return r.bounds.LoginHint
	case paramScope:
		return r.bounds.Scope
	case paramResource:
		return r.bounds.Resource
	case paramIDTokenHint:
		return r.bounds.IDTokenHint
	default:
		return maxOtherParam
	}
}

// readBounds refuses what must not be stored or reflected: a value past its bound, and
// one a durable store could not hold, which would otherwise be answered as an outage of
// that store. Text columns hold neither a NUL nor invalid UTF-8.
func (r *requestReading) readBounds() string {
	for _, name := range singleParams {
		if value := r.get(name); len(value) > r.boundOf(name) || !storable(value) {
			return CodeInvalidRequest
		}
	}

	resources := r.params[paramResource]
	if len(resources) > maxResources {
		return CodeInvalidRequest
	}
	for _, value := range resources {
		if len(value) > r.boundOf(paramResource) || !storable(value) {
			return CodeInvalidRequest
		}
	}

	return ""
}

func storable(value string) bool {
	return utf8.ValidString(value) && !strings.Contains(value, "\x00")
}

// readPKCE holds every client to S256, with no default method: a method given without a
// challenge, or a challenge without a method, is not read as anything weaker.
//
// A PKCEOrNonce client may send a nonce instead, but only where an ID token will carry
// it back: the nonce is what the client checks, so with no ID token to check it in, it
// protects nothing.
func (r *requestReading) readPKCE() string {
	challenge, method := r.get(paramCodeChallenge), r.get(paramCodeChallengeMethod)
	if method != "" && method != challengeS256 {
		return CodeInvalidRequest
	}

	if challenge == "" {
		relyOnNonce := r.client.PKCE == PKCEOrNonce && method == "" && r.get(paramNonce) != "" &&
			slices.Contains(words(r.get(paramScope)), scopeOpenID)
		if !relyOnNonce {
			return CodeInvalidRequest
		}

		return ""
	}

	if method == "" || !validChallenge(challenge) {
		return CodeInvalidRequest
	}
	r.req.Challenge = challenge

	return ""
}

// validChallenge checks RFC 7636 section 4.2's shape.
func validChallenge(challenge string) bool {
	if len(challenge) < minChallenge || len(challenge) > maxChallenge {
		return false
	}

	return !strings.ContainsFunc(challenge, func(c rune) bool {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			return false
		case c == '-', c == '.', c == '_', c == '~':
			return false
		default:
			return true
		}
	})
}

// readScopes drops offline_access for a client with no refresh grant before anything
// else looks at it, so such a request proceeds as though it never asked. What is left
// must be a scope the client is allowed, and there must be something left.
func (r *requestReading) readScopes() string {
	scopes := words(r.get(paramScope))
	if !slices.Contains(r.client.GrantTypes, GrantRefreshToken) {
		scopes = slices.DeleteFunc(scopes, func(s string) bool { return s == scopeOffline })
	}
	if len(scopes) == 0 {
		return CodeInvalidRequest
	}
	for _, scope := range scopes {
		if !slices.Contains(r.client.Scopes, scope) {
			return CodeInvalidScope
		}
	}
	r.req.Scopes = scopes

	return ""
}

func (r *requestReading) readResources() string {
	var resources []string
	for _, value := range r.params[paramResource] {
		if value == "" || slices.Contains(resources, value) {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || !parsed.IsAbs() || strings.Contains(value, "#") || !slices.Contains(r.client.Resources, value) {
			return CodeInvalidTarget
		}
		resources = append(resources, value)
	}
	r.req.Resources = resources

	return ""
}

func (r *requestReading) readRequestObjects() string {
	switch {
	case r.get(paramRequest) != "":
		return CodeRequestNotSupported
	case r.get(paramRequestURI) != "":
		return CodeRequestURINotSupported
	default:
		return ""
	}
}

// readPrompt refuses none beside anything else, a value the provider does not define
// included, because the request then asks for two answers at once. Apart from that, an
// undefined value is ignored.
func (r *requestReading) readPrompt() string {
	values := words(r.get(paramPrompt))
	if slices.Contains(values, promptNone) && len(values) > 1 {
		return CodeInvalidRequest
	}
	r.req.Prompt = slices.DeleteFunc(values, func(v string) bool {
		return v != promptNone && v != promptLogin && v != promptConsent && v != promptSelect
	})

	return ""
}

// readMaxAge takes ASCII digits alone. What fits in 32 bits is 68 years, so nothing a
// client means is refused, and later arithmetic on it cannot overflow.
func (r *requestReading) readMaxAge() string {
	raw := r.get(paramMaxAge)
	if raw == "" {
		return ""
	}
	if strings.ContainsFunc(raw, func(c rune) bool { return c < '0' || c > '9' }) {
		return CodeInvalidRequest
	}
	seconds, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return CodeInvalidRequest
	}
	maxAge := int(seconds)
	r.req.MaxAge = &maxAge

	return ""
}

// readBinding refuses a dpop_jkt no one could honour. Ignoring it would leave the client
// holding an unbound code it believes is bound. A thumbprint is a SHA-256 digest in
// unpadded base64url (RFC 9449 section 10), the same shape as a secret the provider
// mints, so one that is not that shape names no key.
func (r *requestReading) readBinding() string {
	jkt := r.get(paramDPoPJKT)
	if jkt != "" && !r.dpop {
		return CodeInvalidRequest
	}
	if jkt != "" {
		if _, ok := decodeSecret(jkt); !ok {
			return CodeInvalidRequest
		}
	}
	r.req.DPoPJKT = jkt

	return ""
}

// readKept keeps what belongs to the consumer's page, and judges none of it.
func (r *requestReading) readKept() {
	r.req.State = r.get(paramState)
	r.req.Nonce = r.get(paramNonce)
	r.req.LoginHint = r.get(paramLoginHint)
	r.req.UILocales = words(r.get(paramUILocales))
	r.req.ClaimsLocales = words(r.get(paramClaimsLocales))
	r.req.ACRValues = words(r.get(paramACRValues))
}

// readHint judges an id_token_hint. One signed by a key no longer published cannot be
// judged, which is different from forged, so it counts as none, except that a silent
// request has no one to ask.
func (p *Provider) readHint(ctx context.Context, r *requestReading) (string, error) {
	raw := r.get(paramIDTokenHint)
	if raw == "" {
		return "", nil
	}

	subject, verdict, err := p.judgeHint(ctx, raw)
	switch {
	case err != nil:
		return "", err
	case verdict == hintRefused:
		return CodeInvalidRequest, nil
	case verdict == hintUnjudged && slices.Contains(r.req.Prompt, promptNone):
		return CodeLoginRequired, nil
	}
	r.req.IDTokenHintSubject = subject

	return "", nil
}

// errUnusableKey reports a published key the provider cannot verify with.
var errUnusableKey = fmt.Errorf("%w: a published key cannot verify", ErrDependency)

type hintVerdict uint8

const (
	hintRefused hintVerdict = iota
	hintAccepted
	hintUnjudged
)

// judgeHint accepts only an ID token of this provider, by its type, signature and
// issuer, with its expiry ignored, as OIDC Core section 3.1.2.2 allows. The key is chosen
// by kid from what the provider publishes, and the algorithm by that key, so the token's
// header cannot choose how a key is used.
//
// A key the provider cannot use says nothing about the token, so it is an outage, as
// signingkey.PublicKey asks, and never a refusal.
func (p *Provider) judgeHint(ctx context.Context, raw string) (string, hintVerdict, error) {
	msg, err := jws.ParseString(raw)
	if err != nil {
		return "", hintRefused, nil //nolint:nilerr // a token that does not parse is refused, and is no failure
	}
	header := msg.Signatures()[0].ProtectedHeaders()
	kid, _ := header.KeyID()
	if kid == "" {
		return "", hintRefused, nil
	}

	published, err := p.keys.VerificationKeys(ctx)
	if err != nil {
		return "", hintRefused, dependencyFailure(ctx, err, "oidcprovider: read the verification keys")
	}
	i := slices.IndexFunc(published, func(k signingkey.PublicKey) bool { return k.Kid == kid })
	if i < 0 {
		return "", hintUnjudged, nil
	}

	typ, _ := header.Type()
	if typ != token.TypeIDToken {
		return "", hintRefused, nil
	}

	signature, known := jwa.LookupSignatureAlgorithm(published[i].Alg)
	if !known {
		return "", hintRefused, errUnusableKey
	}
	key, err := jwk.Import[jwk.Key](published[i].Key)
	if err != nil {
		return "", hintRefused, errUnusableKey
	}
	tok, err := jwt.Parse([]byte(raw), jwt.WithKey(signature, key), jwt.WithValidate(false))
	if err != nil {
		return "", hintRefused, nil //nolint:nilerr // a signature that does not hold is refused, and is no failure
	}

	iss, _ := tok.Issuer()
	subject, _ := tok.Subject()
	if iss != p.issuer || subject == "" {
		return "", hintRefused, nil
	}

	return subject, hintAccepted, nil
}
