package httpsec

import (
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// FormLoginDeps are the collaborators form login is wired to.
//
// Every one is required, except Tokens in the session-reference mode
// (EnableSessionBearer), where it must be absent, and a missing or typed-nil
// field is refused when the chain is built. There is no useful default for any
// of them: scrty ships no
// user store to authenticate against, no durable session store, no signing key
// to issue a token with, and an attempt store of its own here would be one the
// lockout policy never reads, which is worse than none.
type FormLoginDeps struct {
	// Authenticator judges the submitted credentials. An authenticate.FirstOf
	// satisfies it, and so does a consumer's own provider.
	Authenticator authenticate.Authenticator

	// Sessions opens the session a successful login establishes.
	Sessions *session.Sessions

	// Tokens issues the access token the response carries. The session
	// identifier is the token's jti, which is how a later bearer request finds
	// the session the token was issued for.
	//
	// With EnableSessionBearer on, it must be left nil, and the response
	// carries the session's own identifier instead: a token would not be
	// accepted by that chain, so a generator here is a configuration error
	// from New.
	Tokens token.Generator

	// Attempts is where a failed login is recorded and a successful one clears
	// what came before. Supply the account-lockout policy's own view,
	// [github.com/kartaladev/scrty/policy/lockout.Policy.Attempts]: it records
	// into the store the policy reads, and it is what reports lockout transitions
	// to an observer the policy was given. A bare store the policy also reads
	// locks just the same, but nothing recorded through it is reported. A failure
	// recorded in one store and counted in another locks nothing.
	//
	// When the policy has a consecutive-failure cap (lockout.WithFailureStreakLimit),
	// its view is required: only the view advances the consecutive count, so
	// any other store here, the policy's own bare store included, fails New
	// with a configuration error naming this field. That check covers only
	// the policies registered in the engine before New runs: a capped policy
	// added later is not checked, and its view must still be what this login
	// records into.
	Attempts policy.AttemptStore
}

// LoginOption configures form login. Each replaces one of the defaults named
// on EnableFormLogin.
type LoginOption func(*formLogin) error

// EnableFormLogin answers logins at the form login slot.
//
// A chain has one form login. A second EnableFormLogin is refused with a
// configuration error naming the option, whatever path or limiter it carries:
// two guards over one slot would leave it unclear which one a request met.
//
// Default: POST on DefaultLoginPath, reading DefaultLoginUsernameParam and
// DefaultLoginPasswordParam from the form and then, when the form yields
// neither and the request declares a JSON content type, from the JSON body;
// at most DefaultLoginBodyLimit bytes of it; answering a success with a JSON
// document carrying the access token, an empty refresh token and the session's
// idle expiry. Every one of those is replaced by the option that names it.
//
// Every other request passes through untouched, so enabling form login costs
// the rest of the application nothing.
//
// # Order of steps
//
// A login is answered in this order, and each step refuses before the next
// runs:
//
//  1. Read the username and password (see below).
//  2. Check the source against the password-login guard. A throttled source
//     is refused with ratelimit.ErrThrottled, and one with no attributable
//     client address as a failed authentication, before any policy or
//     password work. The guard is shared with EnableBasicAuth and counts
//     failures per source, 50 per 15 minutes by default (WithLoginLimiter).
//  3. Run the pre-authentication policy phase. A deny refuses with its
//     reason, except a locked account, which by default is refused as a
//     wrong password after a decoy password verification (WithLockDisclosure)
//     and counts against the source.
//  4. Authenticate. A failure is recorded against the account (the attempt
//     store) and against the source; a success clears the account's failures
//     and spends nothing of the source's allowance.
//  5. Run the post-authentication phase, open the session, and issue the
//     access token, refusing with a ChallengeError when a challenge is
//     raised.
//
// # What the binding reads, and what it does not
//
// The credential is bound from the parsed POST body and from nothing else. A
// credential in the URL query never authenticates, because a query string is
// already written into every access log, proxy log and browser history that saw
// the URL, and into the Referer the next page sends. Request.FormValue looks in
// the posted form first and falls back to the URL query, on every adapter, for
// the consumer interceptors that legitimately read a query parameter; only this
// binding narrows.
//
// Two narrowings follow from that, and both are deliberate:
//
//   - A body is read as a form only when it declares
//     "application/x-www-form-urlencoded". A login sent as
//     "multipart/form-data" is therefore refused with ErrCredentialsMissing
//     rather than parsed: a body is what the request says it is, and a login
//     endpoint that guessed would accept a shape nobody wired it for.
//   - A urlencoded body that does not parse yields no credential at all, rather
//     than the pairs that did parse before the error. Half a body is not a
//     credential the client sent.
func EnableFormLogin(d FormLoginDeps, opts ...LoginOption) Option {
	const option = "EnableFormLogin"

	return func(c *config) error {
		l := &formLogin{
			authn:         d.Authenticator,
			sessions:      d.Sessions,
			tokens:        d.Tokens,
			attempts:      d.Attempts,
			now:           c.now,
			path:          DefaultLoginPath,
			usernameParam: DefaultLoginUsernameParam,
			passwordParam: DefaultLoginPasswordParam,
			bodyLimit:     DefaultLoginBodyLimit,
			respond:       writeLoginResult,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(l); err != nil {
				return err
			}
		}

		if err := eachInterceptor(c, func(*formLogin) error {
			return newConfigError("%s was given twice; one chain has one form login", option)
		}); err != nil {
			return err
		}

		c.enable(option, func() error {
			if err := requireDep(option, "authenticator", d.Authenticator); err != nil {
				return err
			}
			if err := requireDep(option, "session manager", d.Sessions); err != nil {
				return err
			}
			if err := checkTokenGenerator(c, option, "FormLoginDeps.Tokens", d.Tokens); err != nil {
				return err
			}

			return requireDep(option, "attempt store", d.Attempts)
		})

		c.useSessions(d.Sessions)
		c.wire(l.wire)
		// The bearer mode may be enabled after form login, so the issuer is
		// chosen once every option has been applied.
		c.wire(func(*Chain) { l.issue = c.credentialIssuer(l.tokens) })
		c.register(l, OrderFormLogin)

		return nil
	}
}

// WithLoginRequestPath answers logins on path instead.
//
// Default: DefaultLoginPath. An empty path is refused: it would match nothing,
// so the endpoint the consumer asked for would silently not exist.
func WithLoginRequestPath(path string) LoginOption {
	return func(l *formLogin) error {
		if path == "" {
			return newConfigError("WithLoginRequestPath was given no path, so form login " +
				"would answer nothing")
		}

		l.path = path
		return nil
	}
}

// WithLoginParams reads the identifier and the password from these names.
//
// Default: DefaultLoginUsernameParam and DefaultLoginPasswordParam. They name
// both the form fields and the JSON members, so one call settles both shapes.
// An empty name, or two identical names, is refused: neither could read a
// credential the consumer meant to send.
func WithLoginParams(username, password string) LoginOption {
	return func(l *formLogin) error {
		switch {
		case username == "" || password == "":
			return newConfigError("WithLoginParams needs both field names, and was given "+
				"%q and %q", username, password)
		case username == password:
			return newConfigError("WithLoginParams was given %q for both fields, which cannot "+
				"carry an identifier and a password separately", username)
		}

		l.usernameParam = username
		l.passwordParam = password
		return nil
	}
}

// WithLoginBodyLimit reads at most n bytes of a login body.
//
// Default: DefaultLoginBodyLimit. The bound applies before anything is parsed,
// because the login endpoint is unauthenticated and an unbounded read there
// costs an attacker no credential at all. A limit of zero or less is refused:
// it would reject every login, including the correct ones.
func WithLoginBodyLimit(n int64) LoginOption {
	return func(l *formLogin) error {
		if n <= 0 {
			return newConfigError("WithLoginBodyLimit takes a positive bound, and %d would "+
				"refuse every login", n)
		}

		l.bodyLimit = n
		return nil
	}
}

// WithLoginResponder writes the success response through fn.
//
// Default: a JSON document carrying the access token, an empty refresh token
// field and the session's idle expiry. fn is called instead of the downstream
// handler, because a login is this library's own endpoint.
//
// A nil responder is refused: a login that succeeded and wrote nothing answers
// the caller with an empty 200, which reads as a success carrying no
// credential.
func WithLoginResponder(fn LoginResponder) LoginOption {
	return func(l *formLogin) error {
		if fn == nil {
			return newConfigError("WithLoginResponder was given no responder; omit it to keep " +
				"the default JSON response")
		}

		l.respond = fn
		return nil
	}
}

// WithLoginLimiter counts form login's failures against l, by source, instead
// of the password-login limiter form login shares with Basic.
//
// Default: one limiter shared by form login and Basic, built from the chain's
// factory (WithRateLimiterFactory, or the in-memory default) under the
// namespace "password-login", allowing 50 failures per source in 15 minutes.
// Sharing it means a source spraying passwords across both endpoints spends
// one allowance. With this option form login counts against l alone, under
// the flow "password-login-form", and Basic keeps the shared default unless it
// is given its own (WithBasicAuthLimiter). The limit and window are l's own.
//
// The flow is the endpoint's own so that nothing is shared with Basic: its
// IPv6 aggregate (WithIPv6Aggregate) is built under the namespace
// "password-login-form-ipv6-aggregate", and a factory that refuses one
// namespace with two policies builds the chain all the same. That aggregate is
// sized from l's own
// policy, the multiplier times the limit and window l reports through
// ratelimit.PolicyReporter, as the memory limiter does. A limiter that reports
// none gets no default aggregate and one warning at construction naming
// EnableFormLogin; an explicit WithIPv6Aggregate refuses it with a
// configuration error, and WithoutIPv6Aggregate silences the warning.
//
// A nil limiter, or a typed nil, is refused: it would read as "no limit"
// while the consumer believed one was set.
func WithLoginLimiter(l ratelimit.Limiter) LoginOption {
	return func(f *formLogin) error {
		if err := requireDep("WithLoginLimiter", "limiter", l); err != nil {
			return err
		}

		f.limiter = l

		return nil
	}
}

// WithLoginLifetime lets fn choose the absolute lifetime of the session a
// login opens, from the fields the request carried (LoginFields), for example
// a longer one when the user ticked "remember me".
//
// Default: with no option, or when fn returns zero or less, the session lives
// for the manager's absolute timeout (session.WithAbsoluteTimeout). A positive
// d is given to the new session (session.WithAbsoluteLifetime). fn runs once
// the password is verified, before the policy phase and the session creation,
// so it does not run for a failed credential check, but it does run for a
// login the policy phase then refuses.
//
// fn never sees the password: the configured password parameter is not among
// the fields. The manager holds d to its lifetime maximum
// (session.WithMaxAbsoluteLifetime): a larger d is a wiring mistake, so the
// login is refused with session.ErrConfig, a 500, and no session is created,
// rather than silently shortened. Renewals of the session are held to the
// family maximum (session.WithMaxFamilyLifetime) as for any session. fn must
// not block. A nil fn is refused when the chain is built.
func WithLoginLifetime(fn func(*Exchange, LoginFields) time.Duration) LoginOption {
	return func(l *formLogin) error {
		if fn == nil {
			return newConfigError("WithLoginLifetime was given no function; omit the option " +
				"to keep the absolute timeout")
		}

		l.lifetime = fn

		return nil
	}
}
