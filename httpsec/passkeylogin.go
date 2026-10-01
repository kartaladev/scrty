package httpsec

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// passwordlessFlow names the passwordless begin's rate-limit buckets and
// sampler keys, so a source that spends its begins still has its allowance
// at every other guarded endpoint.
const passwordlessFlow = "passkey-login"

// The allowance a source gets before passwordless begins are refused. Every
// begin is recorded, not only failures: a begin writes a challenge before
// anyone has authenticated.
const (
	defaultPasswordlessBeginLimit  = 30
	defaultPasswordlessBeginWindow = 15 * time.Minute
)

// passwordlessBindingSize is how many random bytes the ceremony cookie's
// value carries.
const passwordlessBindingSize = 32

// passwordlessConfig is what the passwordless settings configure.
type passwordlessConfig struct {
	cookieName   string
	limiter      ratelimit.Limiter
	tokens       token.Generator
	respond      LoginResponder
	respondBegin PasskeyBeginResponder
}

// PasswordlessSetting configures passwordless login, inside
// WithPasswordlessLogin. Each replaces one of the defaults named there.
type PasswordlessSetting func(*passwordlessConfig) error

// passwordlessInterceptor answers the passwordless begin and finish
// endpoints, as a first factor at OrderPasskeyLogin.
type passwordlessInterceptor struct {
	passwordlessConfig

	manager  *passkey.Manager
	users    identity.UserLoader
	sessions *session.Manager

	beginPath  string
	finishPath string

	guard sourceGuard

	// engine, log and sampler are handed over by wire, with the rest of
	// the login tail's settings.
	engine  *policy.Engine
	log     *slog.Logger
	sampler *logsample.Sampler

	enrolmentLifetime time.Duration
	enforced          map[policy.ChallengeKind]bool
	challengeMethods  challengeMethodsFunc

	// cancelHeld cancels the user's held account recoveries at login, set at
	// assembly when the chain's recovery may hold one, and nil otherwise.
	cancelHeld heldRecoveryCanceller

	now func() time.Time
}

// WithPasswordlessLogin serves passwordless passkey login on the chain, at
// OrderPasskeyLogin: after the one-time link slot and before Basic
// authentication, as a first factor. It is off unless this option is given.
//
// The endpoints answer POST only, under the passwordless prefix,
// DefaultPasswordlessPrefix by default (WithPasswordlessPrefix); any other
// method, and every other path, passes through untouched:
//
//   - "<prefix>/begin" is guarded by the chain's source throttle under the
//     flow "passkey-login", which records every begin: by default 30 per
//     source per 15 minutes in this process's memory (PasswordlessLimiter).
//     A source over the limit is refused with ratelimit.ErrThrottled, and an
//     address that cannot be attributed with
//     authenticate.ErrAuthenticationFailed, before anything is written. It
//     then draws 32 random bytes, starts the login bound to their base64url
//     form (passkey.Manager.BeginLogin), sets them in the ceremony cookie,
//     and answers 200 with {"publicKey":{…request options…}} and
//     Cache-Control: no-store (PasswordlessBeginResponder). The cookie is
//     DefaultPasswordlessCookieName (PasswordlessCookieName); HttpOnly,
//     Secure and SameSite=Strict; scoped to the finish path; and lives as
//     long as the challenge (passkey.Manager.ChallengeTTL).
//   - "<prefix>/finish" first clears the ceremony cookie, whatever the
//     outcome, with Max-Age=0 on the same path. It reads the assertion as a
//     JSON body of at most passkey.AssertionBodyLimit (16 KiB) and never from
//     the query: a body that is not JSON, or that the verifier cannot read, is
//     refused with ErrCredentialsMissing, and one over the limit with
//     ErrRequestTooLarge. It finishes the login bound to the cookie's value
//     (passkey.Manager.Authenticate); only the first cookie of that name the
//     request carries is read, so a request whose first such cookie does not
//     bind the challenge is refused even when a later one would. It loads the
//     credential's user (PasskeyDeps.Users) and refuses an unknown or disabled
//     one, then completes the login through the chain's login completion
//     step, recording the passkey first factor and the proof that a
//     user-verified passkey met the second factor. It answers as form login
//     does: by default 200 with {"access_token","refresh_token","valid_until"}
//     (PasswordlessResponder), the token from form login's generator
//     (PasswordlessTokens). A missing or mismatched cookie, an unknown
//     credential, a handle mismatch and a bad signature are all
//     authenticate.ErrAuthenticationFailed, and no refusal leaves a session.
//
// New refuses the chain when passwordless login is enabled and:
// PasskeyDeps.Users is missing; the passkey manager has no saved recovery
// codes wired (passkey.Deps.Recovery) and the optional mode
// (passkey.WithOptionalRecoveryCodes) is not chosen, since a passkey-only
// user would otherwise have no way back in; no token generator is given and
// the chain has no form login to take one from; or WithPasswordlessLogin is
// given twice. Its paths are checked with the other passkey paths (see
// EnablePasskeys).
func WithPasswordlessLogin(settings ...PasswordlessSetting) PasskeyOption {
	return func(p *passkeyInterceptor) error {
		if p.passwordless != nil {
			return newConfigError("WithPasswordlessLogin was given twice; one chain has one " +
				"passwordless login")
		}

		cfg := &passwordlessConfig{cookieName: DefaultPasswordlessCookieName}

		for _, set := range settings {
			if set == nil {
				continue
			}

			if err := set(cfg); err != nil {
				return err
			}
		}

		p.passwordless = cfg

		return nil
	}
}

// WithPasswordlessPrefix answers passwordless login under prefix instead:
// POST "<prefix>/begin" and "<prefix>/finish". The ceremony cookie is scoped
// to the moved finish path.
//
// Default: DefaultPasswordlessPrefix. It is validated as
// WithPasskeyRegistrationPrefix's is, and New refuses it when passwordless
// login is not enabled (WithPasswordlessLogin), since it would move nothing.
func WithPasswordlessPrefix(prefix string) PasskeyOption {
	return func(p *passkeyInterceptor) error {
		trimmed, err := passkeyPrefix("WithPasswordlessPrefix", prefix)
		if err != nil {
			return err
		}

		p.loginPrefix = trimmed
		p.loginPrefixSet = true

		return nil
	}
}

// PasswordlessCookieName names the ceremony cookie instead.
//
// Default: DefaultPasswordlessCookieName. An empty name, or one
// net/http would not send, is refused. The binding itself has no opt-out: a
// passkey ceremony starts and finishes in one browser.
func PasswordlessCookieName(name string) PasswordlessSetting {
	return func(cfg *passwordlessConfig) error {
		if err := (&http.Cookie{Name: name, Value: "v"}).Valid(); name == "" || err != nil { //nolint:gosec // G124: a probe for Valid(), never written to a response
			return newConfigError("PasswordlessCookieName was given %q, which is not a cookie "+
				"name a browser would send back", name)
		}

		cfg.cookieName = name

		return nil
	}
}

// PasswordlessLimiter counts passwordless begins per source in l instead.
//
// Default: an in-memory limiter of 30 begins per source per 15 minutes,
// which holds this process's counts only; behind several replicas, supply a
// shared limiter. The guard records every begin, so l's limit is a limit on
// begins, not on failures. A nil limiter is refused; omit the setting to keep
// the default.
func PasswordlessLimiter(l ratelimit.Limiter) PasswordlessSetting {
	return func(cfg *passwordlessConfig) error {
		if err := requireDep("PasswordlessLimiter", "limiter", l); err != nil {
			return err
		}

		cfg.limiter = l

		return nil
	}
}

// PasswordlessTokens issues the access token of a passwordless login with g
// instead.
//
// Default: the token generator given to EnableFormLogin. A chain without form
// login must give one. A nil generator is refused.
func PasswordlessTokens(g token.Generator) PasswordlessSetting {
	return func(cfg *passwordlessConfig) error {
		if err := requireDep("PasswordlessTokens", "token generator", g); err != nil {
			return err
		}

		cfg.tokens = g

		return nil
	}
}

// PasswordlessResponder replaces how a passwordless login is answered.
//
// Default: form login's responder (WithLoginResponder), or form login's
// default document when it has none or the chain has no form login. A nil
// function is refused; omit the setting to keep the default.
func PasswordlessResponder(fn LoginResponder) PasswordlessSetting {
	return func(cfg *passwordlessConfig) error {
		if fn == nil {
			return newConfigError("PasswordlessResponder was given no function; omit the " +
				"setting to keep the default")
		}

		cfg.respond = fn

		return nil
	}
}

// PasswordlessBeginResponder replaces how a passwordless begin is answered.
// The ceremony cookie is set before it runs.
//
// Default: 200 with {"publicKey":<options>} as JSON, and Cache-Control:
// no-store. A nil function is refused; omit the setting to keep the default.
func PasswordlessBeginResponder(fn PasskeyBeginResponder) PasswordlessSetting {
	return func(cfg *passwordlessConfig) error {
		if fn == nil {
			return newConfigError("PasswordlessBeginResponder was given no function; omit the " +
				"setting to keep the default document")
		}

		cfg.respondBegin = fn

		return nil
	}
}

// newPasswordless builds the passwordless endpoints p's settings describe.
func (p *passkeyInterceptor) newPasswordless() *passwordlessInterceptor {
	prefix := p.loginPrefix

	return &passwordlessInterceptor{
		passwordlessConfig: *p.passwordless,
		manager:            p.deps.Passkeys,
		users:              p.deps.Users,
		sessions:           p.deps.Sessions,
		beginPath:          prefix + passkeyBeginSegment,
		finishPath:         prefix + passkeyFinishSegment,
		now:                time.Now,
	}
}

// checkPasswordless reports what only the passkey dependencies can show
// about passwordless login: the user loader it loads users through, and the
// saved codes its users' way back depends on.
func (p *passkeyInterceptor) checkPasswordless(option string) error {
	if p.passwordless == nil {
		return nil
	}

	if err := requireDep(option, "user loader (PasskeyDeps.Users) for passwordless login",
		p.deps.Users); err != nil {
		return err
	}

	if p.deps.Passkeys.RequiresRecoveryCodes() {
		return newConfigError("%s enables passwordless login over a passkey manager with no "+
			"saved recovery codes wired (passkey.Deps.Recovery): a user signing in with "+
			"passkeys alone would have no way back in. Wire them, or choose "+
			"passkey.WithOptionalRecoveryCodes", option)
	}

	return nil
}

// resolve settles the passwordless endpoints' remaining collaborators
// against the assembled configuration: form login's token generator and
// responder when none was given, and the begin's source guard.
func (i *passwordlessInterceptor) resolve(option string, c *config) error {
	l := c.formLogin()

	if i.tokens == nil && l != nil {
		i.tokens = l.tokens
	}

	if nilcheck.IsNil(i.tokens) {
		return newConfigError("%s's passwordless login needs a token generator: give "+
			"PasswordlessTokens, or enable form login, whose generator it then uses", option)
	}

	if i.respond == nil {
		i.respond = writeLoginResult
		if l != nil && l.respond != nil {
			i.respond = l.respond
		}
	}

	if i.respondBegin == nil {
		i.respondBegin = writePasskeyBegin
	}

	guard, err := c.resolveSourceGuard(option, passwordlessFlow, i.limiter,
		defaultPasswordlessBeginLimit, defaultPasswordlessBeginWindow)
	if err != nil {
		return err
	}

	i.guard = guard

	return nil
}

// wire takes the settings the chain resolved, once every option has been
// applied.
func (i *passwordlessInterceptor) wire(c *Chain) {
	i.engine = c.engine
	i.log = c.logger
	i.sampler = c.sampler
	i.enrolmentLifetime = c.enrolmentLifetime
	i.enforced = c.enforced
	i.challengeMethods = c.challengeMethods
}

// flushRefusalLogs reports what the begin's source guard is holding back.
func (i *passwordlessInterceptor) flushRefusalLogs() {
	if i.guard != nil {
		i.guard.Flush()
	}
}

// Intercept answers the passwordless endpoints and passes everything else
// through.
func (i *passwordlessInterceptor) Intercept(ex *Exchange, next Next) error {
	if ex.Request.Method() != http.MethodPost {
		return next(ex)
	}

	switch ex.Request.Path() {
	case i.beginPath:
		return i.begin(ex)
	case i.finishPath:
		return i.finish(ex)
	default:
		return next(ex)
	}
}

// begin checks the source, records the begin, binds a fresh challenge to a
// fresh cookie value and answers the request options.
//
// The begin is recorded once the source is admitted and before anything is
// issued, so a begin that then fails still counts: the guard bounds how
// often one source may make the library write.
func (i *passwordlessInterceptor) begin(ex *Exchange) error {
	ctx := ex.Context()

	src, err := sourceThrottled(ctx, i.guard, ex.Request.ClientIP(), passwordlessFlow,
		i.sampler, i.log, i.now())
	if err != nil {
		return err
	}

	recordSourceFailure(ctx, i.guard, src)

	raw := make([]byte, passwordlessBindingSize)
	if _, err := rand.Read(raw); err != nil {
		return diag.Wrap(err, msgPasswordlessBindingUnavailable)
	}

	binding := base64.RawURLEncoding.EncodeToString(raw)

	options, err := i.manager.BeginLogin(ctx, binding)
	if err != nil {
		return err
	}

	ex.Writer.SetCookie(i.cookie(binding, int(i.manager.ChallengeTTL().Seconds())))

	return i.respondBegin(ex, options)
}

// msgPasswordlessBindingUnavailable is the fixed text of a begin whose
// random source failed.
const msgPasswordlessBindingUnavailable = "httpsec: the passwordless ceremony binding could not be drawn" //nolint:gosec // G101: a fixed log message, not a credential

// cookie is the ceremony cookie carrying value for maxAge seconds; a
// negative maxAge clears it.
func (i *passwordlessInterceptor) cookie(value string, maxAge int) *Cookie {
	return &Cookie{
		Name:     i.cookieName,
		Value:    value,
		Path:     i.finishPath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

// finish clears the ceremony cookie, finishes the login bound to it, loads
// the user and completes the login.
//
// The cookie is cleared before anything else, so every response — the
// login, each refusal, and an error answered by the consumer's handler —
// carries the clearing header: a header set after a responder has written
// would never reach the client.
func (i *passwordlessInterceptor) finish(ex *Exchange) error {
	ex.Writer.SetCookie(i.cookie("", -1))

	body, err := postedJSON(ex.Request, passkey.AssertionBodyLimit)
	if err != nil {
		return err
	}

	// The first cookie of the name only: the library never tries each value a
	// request carries in turn, so a shadowing cookie cannot widen what binds.
	binding, _ := ex.Request.Cookie(i.cookieName)

	ctx := ex.Context()

	res, err := i.manager.Authenticate(ctx, body, binding)
	if errors.Is(err, passkey.ErrMalformedResponse) {
		return refusedAs(ErrCredentialsMissing, textCredentialsMissing, err)
	}

	if err != nil {
		return err
	}

	details, err := i.loadUser(ex, res.User)
	if err != nil {
		return err
	}

	principal := identity.PrincipalFromDetails(details)
	now := i.now()

	// No authentication record is published, as for a magic link and OIDC:
	// only form login, whose authenticator issues an event, has one.
	in := postAuthenticationInput(principal, factor.Passkey, details.Username, details.PasswordChangedAt, now)
	in.SecondFactorAtLogin = res.Proof

	tok, err := completeLogin(ex, loginTailDeps{
		engine:            i.engine,
		sessions:          i.sessions,
		tokens:            i.tokens,
		enrolmentLifetime: i.enrolmentLifetime,
		enforced:          i.enforced,
		challengeMethods:  i.challengeMethods,
		cancelHeld:        i.cancelHeld,
	}, in)
	if err != nil {
		return err
	}

	return i.respond(ex, LoginResult{Token: tok, Session: ex.Session})
}

// loadUser loads the credential's user, refusing an unknown, disabled or
// mismatched one with authenticate.ErrAuthenticationFailed. A loader that
// fails is an outage, answered behind fixed text.
func (i *passwordlessInterceptor) loadUser(ex *Exchange, user identity.UserID) (*identity.Details, error) {
	ctx := ex.Context()

	details, err := i.users.LoadByUserID(ctx, user)

	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		i.log.LogAttrs(ctx, slog.LevelDebug, "httpsec: a passwordless login's user no longer exists")

		return nil, authenticate.ErrAuthenticationFailed
	case err != nil:
		return nil, diag.Wrap(err, msgPasswordlessUserUnavailable)
	case details == nil || !details.Active:
		i.log.LogAttrs(ctx, slog.LevelDebug, "httpsec: a passwordless login's user is not active")

		return nil, authenticate.ErrAuthenticationFailed
	case details.ID != user:
		i.log.LogAttrs(ctx, slog.LevelError,
			"httpsec: the user loader returned a different user than the passkey records")

		return nil, authenticate.ErrAuthenticationFailed
	}

	return details, nil
}

// msgPasswordlessUserUnavailable is the fixed text of a passwordless login
// whose user could not be loaded.
const msgPasswordlessUserUnavailable = "httpsec: the passwordless login's user could not be loaded" //nolint:gosec // G101: a fixed log message, not a credential
