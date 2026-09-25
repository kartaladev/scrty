package httpsec

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/kartaladev/scrty/internal/origin"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

//go:generate mockgen -destination=handoffredeemer_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/httpsec HandoffRedeemer

// The conventions the federated-login endpoints follow when the consumer names
// none. They are constants rather than bare literals so a client, a test or a
// proxy rule naming the same endpoint names the same thing this package does.
//
// The three prefixes are followed by exactly one path segment, the provider's
// registered name: DefaultOIDCAuthorizePath + "corp" starts a login with the
// provider registered as "corp".
const (
	// DefaultOIDCAuthorizePath is the prefix a login is started under, by a
	// GET on the prefix followed by the provider's name.
	DefaultOIDCAuthorizePath = "/oauth2/authorization/"

	// DefaultOIDCCallbackPath is the prefix the provider redirects back to,
	// followed by the provider's name. A provider's registered redirect URL
	// has to point here.
	DefaultOIDCCallbackPath = "/login/oauth2/callback/"

	// DefaultOIDCHandoffPath is where a handoff code is redeemed, by POST.
	DefaultOIDCHandoffPath = "/login/oauth2/handoff"

	// DefaultOIDCBackchannelPath is the prefix a provider delivers
	// back-channel logout tokens to, by POST, followed by the provider's name.
	DefaultOIDCBackchannelPath = "/logout/oauth2/backchannel/"

	// DefaultOIDCFlowCookieName is the cookie that binds a callback to the
	// browser that started the login.
	DefaultOIDCFlowCookieName = "oidc_flow"

	// DefaultOIDCHandoffParam is the query parameter the callback appends
	// the handoff code under, and the form field redemption reads it from.
	DefaultOIDCHandoffParam = "handoff"

	// DefaultOIDCNextParam is the query parameter the authorize endpoint
	// reads the requested post-login destination from.
	DefaultOIDCNextParam = "next"
)

// The allowance a source gets before handoff redemptions are refused.
const (
	defaultHandoffFailureLimit  = 10
	defaultHandoffFailureWindow = 5 * time.Minute
)

// The flows the federated-login endpoints name their rate-limit buckets and
// refusal-log keys after, so a source that exhausts its redemption allowance
// still has its own allowance at every other endpoint, and the chain's sampled
// refusal log groups each endpoint's refusals under its own prefix.
const (
	oidcCallbackFlow    = "oidc.callback"
	oidcHandoffFlow     = "oidc.handoff"
	oidcBackchannelFlow = "oidc.backchannel"
)

// CallbackSuccess replaces the handoff conveyance at the end of a successful
// callback. It receives the verified, brokered login and the destination the
// redirect allowlist resolved, never the one the client requested, and writes
// the whole response itself. No handoff code is issued.
//
// An error it returns leaves the chain as the request's refusal.
type CallbackSuccess func(ex *Exchange, res oidc.CallbackResult, next string) error

// HandoffRedeemer is the redemption step the handoff endpoint calls,
// replaceable by a consumer.
//
// The default is the *oidc.HandoffManager given to EnableOIDCLogin, which
// runs every check before it consumes the code. A replacement takes on that
// contract: it must run the checks it is handed, return the first check's
// error unchanged, and consume the code only after every check passed.
type HandoffRedeemer interface {
	Redeem(ctx context.Context, code string, checks ...oidc.RedeemCheck) (oidc.HandoffResult, error)
}

// BackchannelLogoutScope is which of a user's sessions a back-channel logout
// token that names a subject but no session ends.
type BackchannelLogoutScope uint8

const (
	// IssuerSessions ends only the user's sessions that were created by a login
	// through the token's issuer. It is the default: a provider asserts a fact
	// about its own session, and has no authority over a password login or
	// another provider's session.
	IssuerSessions BackchannelLogoutScope = iota

	// AllSessions ends every session of the user, whatever created it. It
	// widens the provider's authority: a subject-only token from that provider
	// then ends sessions it did not establish, including the user's password
	// sessions and sessions opened through other providers. Choose it only
	// when the application trusts that provider to sign the user out
	// everywhere.
	AllSessions
)

// valid reports whether s is one of the defined scopes.
func (s BackchannelLogoutScope) valid() bool { return s <= AllSessions }

// oidcInterceptor answers the federated-login endpoints: the authorize
// redirect, the callback, handoff redemption and back-channel logout.
type oidcInterceptor struct {
	manager  *oidc.Manager
	handoffs *oidc.HandoffManager

	// redeemer is what redemption calls: WithHandoffRedeemer's, or the handoff
	// manager when the consumer supplied none. It stays nil only when neither
	// exists, which construction allows only with a CallbackSuccess conveying
	// the login instead, and then the redemption endpoint is not answered.
	redeemer        HandoffRedeemer
	callbackSuccess CallbackSuccess

	sessions *session.Manager
	tokens   token.Generator

	engine  *policy.Engine
	log     *slog.Logger
	sampler *logsample.Sampler
	guard   sourceGuard

	// limiter, limit and window are what the redemption source guard is built
	// from. A nil limiter means a dedicated in-memory one of limit per window.
	limiter       ratelimit.Limiter
	limit         int
	window        time.Duration
	countRefusals bool

	// The *Set fields record whether the option beside them ran, so check can
	// refuse it precisely when it was given beside WithCallbackSuccess,
	// which makes it meaningless: no handoff code is ever issued for a
	// redemption-only option to govern. A zero value cannot stand in for
	// "not given" here, because several of these options' zero values (the
	// default limit and window, DefaultOIDCHandoffPath, counting refusals)
	// are also values a consumer could pass back explicitly.
	handoffRedeemerSet      bool
	handoffLimiterSet       bool
	handoffRateLimitSet     bool
	handoffCountRefusalsSet bool
	handoffPathSet          bool

	redirects        *origin.Allowlist
	allowedRedirects []string
	allowedOrigins   []string

	now func() time.Time

	authorizePath   string
	callbackPath    string
	handoffPath     string
	backchannelPath string
	cookieName      string
	bodyLimit       int64

	scope    BackchannelLogoutScope
	rpLogout bool
}

// wire takes the settings the chain resolved, once every option has been
// applied, so a logger or an engine wired after EnableOIDCLogin is still the
// one these endpoints use.
func (i *oidcInterceptor) wire(c *Chain) {
	i.engine = c.engine
	i.log = c.logger
	i.sampler = c.sampler
}

// Intercept answers the federated-login endpoints and passes everything else
// through.
//
// A prefix endpoint answers only its prefix followed by exactly one non-empty
// path segment, which is the provider's name, taken as the request path gives
// it. A path with a further slash, an encoded one included once decoded, a
// trailing slash, or nothing after the prefix names no provider and is passed
// through; a segment that is not a registered name is refused by the manager
// as ErrUnknownProvider. No path is ever matched to a provider other than the
// one its segment names exactly.
//
// Starting a login and the callback are GET-only: both are top-level browser
// navigations. Any other method on those paths is passed through. Handoff
// redemption is POST-only on the handoff path, matched exactly, and only while
// redemption is on: with a CallbackSuccess conveying the login instead, no
// code is ever issued and that path is passed through to the application.
// Back-channel logout is POST-only under its prefix, and needs no credential:
// the signed logout token is the credential.
func (i *oidcInterceptor) Intercept(ex *Exchange, next Next) error {
	path := ex.Request.Path()

	if ex.Request.Method() == http.MethodPost {
		// Redemption spends a credential, so it is POST-only: nothing a link,
		// an image tag or a prefetch triggers may reach it. With redemption
		// off no code is ever issued, and the path is the application's.
		if i.redeemer != nil && path == i.handoffPath {
			return i.redeem(ex)
		}

		if provider := providerSegment(path, i.backchannelPath); provider != "" {
			return i.backchannel(ex, provider)
		}

		return next(ex)
	}

	if ex.Request.Method() != http.MethodGet {
		return next(ex)
	}

	if provider := providerSegment(path, i.authorizePath); provider != "" {
		return i.authorize(ex, provider)
	}

	if provider := providerSegment(path, i.callbackPath); provider != "" {
		return i.callback(ex, provider)
	}

	return next(ex)
}
