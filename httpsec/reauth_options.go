package httpsec

import (
	"strings"
	"time"

	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/onetime"
)

// ReauthenticationOption configures re-authentication. Each replaces one of
// the defaults named on EnableReauthentication.
type ReauthenticationOption func(*reauthInterceptor) error

// EnableReauthentication turns on the re-authentication endpoints at
// OrderReauthentication, where a signed-in session proves its user again and
// so becomes fresh for a recency guard (Guards.RequireRecentAuthentication).
//
// Default: off. Without it a recency guard still refuses a stale session, and
// the user becomes fresh by signing in again.
//
// # Endpoints
//
// Under the prefix, DefaultReauthenticationPrefix unless
// WithReauthenticationPrefix names another:
//
//   - GET <prefix>/methods lists how the session's user may re-prove, as the
//     JSON document {"methods":[{"name":…,"channel":…,"begins":…}],
//     "password":…} marked Cache-Control: no-store, or through
//     WithReauthenticationMethodsResponder;
//   - POST <prefix>/begin/<method> begins a second-factor method that has a
//     begin step;
//   - POST <prefix>/verify/<method> re-proves with a second-factor method;
//   - POST <prefix>/password re-proves with the session's own user's
//     password.
//
// Every other request, including a GET to a verify path, passes on untouched.
//
// # Who may re-prove
//
// Only a full session: one with a resolved caller, whose second factor is
// satisfied or was never asked for, that owes no password change and is not
// confined to enrolment or recovery, on a request no consumer challenge was
// raised for (Exchange.RaisedChallenge). A session owing a challenge is refused
// by that challenge's gate, which runs first; any other request the endpoints
// cannot serve, a raised consumer challenge included, is refused with
// ErrAuthenticationRequired. A session that is
// still fresh is served.
//
// # With what: the factor policy
//
// By default a user re-proves with the strongest factor they hold. A user
// enrolled on any of the MFA slot's methods re-proves with one of those, and
// is refused the password with ErrReauthenticationMethodNotUsable; a user
// enrolled on none re-proves with the password, when form login is enabled. A
// method counts whatever its channel, so a session that signed in with a
// passkey may re-prove with the passkey method. An enrolment lookup that fails
// refuses the request and never falls back to the password.
// RequireSecondFactorForReauthentication strengthens the policy so that no
// user re-proves with the password. There is no option to weaken it: a
// password re-proof by a user who holds a second factor would make a session
// fresh at single-factor strength, fresh enough to bind a new authenticator.
//
// # Defaults
//
// The prefix is DefaultReauthenticationPrefix (WithReauthenticationPrefix). A
// successful re-proof answers with the document a login answers with
// (WithReauthenticationResponder), and a begin with the method's data as JSON
// (WithReauthenticationBeginResponder). A re-proof challenge lives 5 minutes
// (WithReauthenticationChallengeTTL), at most 10 are issued to one user for
// one method within the store's one-hour issuance window
// (WithReauthenticationChallengeLimit), and they are kept in an in-memory
// store serving one process (WithReauthenticationChallengeStore).
//
// # Dependencies
//
// It reuses what the chain already has, and has no factor of its own: the MFA
// slot (EnableMFA) for its methods and its per-user verification throttle,
// and form login (EnableFormLogin) for its password path and account lockout.
// At least one of them must be enabled. The session is rotated in the chain's
// session manager. The rotated session's credential is issued as the chain's
// bearer mode decides: through WithReauthenticationTokens in the signed-token
// mode, where it is required, and as the session's own identifier with
// EnableSessionBearer on, where a generator is refused.
//
// # Configuration errors
//
// New fails with ErrConfig, naming the cause, when re-authentication is
// enabled twice; when neither EnableMFA nor EnableFormLogin is enabled; when
// RequireSecondFactorForReauthentication is given without EnableMFA; when an
// endpoint's path equals or lies under the logout path, the form login path,
// or the MFA verify or begin prefix, or one of those lies under the begin or
// verify path, or the listing path equals the MFA listing path; when the
// token generator is missing or refused as above; and when an option is given
// an empty prefix, a lifetime or limit of zero or less, or an absent store,
// generator or responder.
func EnableReauthentication(opts ...ReauthenticationOption) Option {
	const option = "EnableReauthentication"

	return func(c *config) error {
		// One prefix, one listing and one factor policy per chain: a second
		// configuration would offer what the first refuses.
		if err := eachInterceptor(c, func(*reauthInterceptor) error {
			return newConfigError("%s was given twice; one chain has one set of "+
				"re-authentication endpoints", option)
		}); err != nil {
			return err
		}

		i := &reauthInterceptor{
			prefix:         DefaultReauthenticationPrefix,
			respond:        writeReauthResult,
			beginRespond:   writeMFABegin,
			methodsRespond: writeReauthMethods,
			challengeTTL:   defaultReauthChallengeTTL,
			challengeCap:   defaultReauthChallengeLimit,
			now:            c.now,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(i); err != nil {
				return err
			}
		}

		// The MFA slot, form login, logout and the bearer mode may each be
		// enabled after this option, so what depends on them is settled once
		// every option has been applied.
		c.enable(option, func() error { return i.settle(c, option) })

		c.register(i, OrderReauthentication)

		c.wire(func(ch *Chain) {
			i.sessions = c.sessions
			i.issue = c.credentialIssuer(i.tokens)
			i.log = ch.logger
			i.sampler = ch.sampler
		})

		return nil
	}
}

// settle finds the MFA slot and form login the endpoints reuse, and refuses a
// configuration they cannot serve.
func (i *reauthInterceptor) settle(c *config, option string) error {
	i.mfa = c.mfaOf()
	i.login = c.formLogin()

	if i.mfa == nil && i.login == nil {
		return newConfigError("%s found neither EnableMFA nor EnableFormLogin on the chain, so "+
			"there is nothing to re-prove with; enable at least one", option)
	}

	if i.secondFactorOnly && i.mfa == nil {
		return newConfigError("RequireSecondFactorForReauthentication needs EnableMFA: without "+
			"second-factor methods no user could re-prove at all, so give %s the MFA slot or drop "+
			"the requirement", option)
	}

	if err := i.checkPaths(c, option); err != nil {
		return err
	}

	if c.sessionBearer {
		return checkTokenGenerator(c, option, "WithReauthenticationTokens", i.tokens)
	}

	if i.tokens == nil {
		return newConfigError("%s needs a token generator (WithReauthenticationTokens): a "+
			"re-proof rotates the session, which ends the credential the caller arrived with, so "+
			"the response has to hand back one naming the rotated session", option)
	}

	return nil
}

// claimedPath is a path another endpoint of the chain answers. under reports
// that the endpoint claims every path beneath it too.
type claimedPath struct {
	name, path string
	under      bool
}

// checkPaths refuses an endpoint path another endpoint already answers. Each
// pair is checked both ways, so the order the options were given in does not
// matter: a re-proof path at or under a path another endpoint claims, and a
// path that lies under the begin or verify path, which claim every POST
// beneath them.
func (i *reauthInterceptor) checkPaths(c *config, option string) error {
	var taken []claimedPath

	if c.logoutPath != "" {
		taken = append(taken, claimedPath{"the logout path", c.logoutPath, true})
	}

	if i.login != nil {
		taken = append(taken, claimedPath{"the form login path", i.login.path, true})
	}

	if i.mfa != nil {
		taken = append(taken,
			claimedPath{"the MFA verify prefix", i.mfa.verifyPrefix, true},
			claimedPath{"the MFA begin prefix", i.mfa.beginPrefix, true})

		if i.mfa.listing != nil {
			taken = append(taken, claimedPath{"the MFA listing path", i.mfa.listing.path, false})
		}
	}

	p := i.paths()
	own := []claimedPath{
		{"listing", p.methods, false},
		{"begin", p.begin, true},
		{"verify", p.verify, true},
		{"password", p.password, false},
	}

	for _, mine := range own {
		for _, other := range taken {
			if collides(mine, other) {
				return newConfigError("%s's %s path %q collides with %s %q, so one endpoint "+
					"would answer the other's requests", option, mine.name, mine.path, other.name, other.path)
			}
		}
	}

	return nil
}

// collides reports whether a and b would both answer one request path.
func collides(a, b claimedPath) bool {
	switch {
	case a.path == b.path:
		return true
	case b.under && underPrefix(a.path, b.path):
		return true
	case a.under && underPrefix(b.path, a.path):
		return true
	default:
		return false
	}
}

// WithReauthenticationPrefix answers the endpoints under prefix instead.
//
// Default: DefaultReauthenticationPrefix. A trailing slash is dropped, so
// "/account/confirm" and "/account/confirm/" are the same prefix. An empty
// prefix is refused rather than read as the default, and so is one that does
// not start with "/", which matches no request path, and the root "/", which
// would claim "/methods", "/password" and everything under "/begin" and
// "/verify" across the application. New also refuses a prefix whose paths
// collide with another endpoint's (see EnableReauthentication).
func WithReauthenticationPrefix(prefix string) ReauthenticationOption {
	const option = "WithReauthenticationPrefix"

	return func(i *reauthInterceptor) error {
		switch {
		case prefix == "":
			return newConfigError("%s was given no prefix; omit the option to keep %q",
				option, DefaultReauthenticationPrefix)
		case !strings.HasPrefix(prefix, "/"):
			return newConfigError("%s was given %q, which does not start with \"/\" and so "+
				"matches no request path", option, prefix)
		}

		trimmed := strings.TrimRight(prefix, "/")
		if trimmed == "" {
			return newConfigError("%s was given the root path %q, which would claim paths "+
				"across the whole application", option, prefix)
		}

		i.prefix = trimmed

		return nil
	}
}

// WithReauthenticationTokens issues the rotated session's access token through
// gen.
//
// There is no default, and it is required in the signed-token mode: a re-proof
// rotates the session, which deletes the handle the caller arrived with, and a
// token names its session through its jti. With EnableSessionBearer on it must
// not be given: the endpoints hand back the rotated session's identifier
// instead, and a generator is a configuration error from New. Give the
// generator the first factors issue through, so the credentials are
// indistinguishable to whatever verifies them. An absent generator, including
// an interface holding a nil pointer, is refused.
func WithReauthenticationTokens(gen token.Generator) ReauthenticationOption {
	return func(i *reauthInterceptor) error {
		if err := requireDep("WithReauthenticationTokens", "token generator", gen); err != nil {
			return err
		}

		i.tokens = gen

		return nil
	}
}

// WithReauthenticationResponder replaces the response a successful re-proof
// answers with, at the verify and password endpoints.
//
// Default: 200 with the JSON document a successful login answers with,
// carrying the rotated session's credential and validity, marked
// Cache-Control: no-store. A consumer's responder owns its headers. An absent
// function is refused; omit the option to keep the default.
func WithReauthenticationResponder(fn ReauthenticationResponder) ReauthenticationOption {
	return func(i *reauthInterceptor) error {
		if fn == nil {
			return newConfigError("WithReauthenticationResponder was given no function; omit the " +
				"option to keep the default document")
		}

		i.respond = fn

		return nil
	}
}

// WithReauthenticationBeginResponder replaces the response a successful begin
// answers with.
//
// Default: 200 with the method's begin data as an "application/json" body,
// unchanged, marked Cache-Control: no-store because it carries a live
// challenge, as the MFA begin answers. A consumer's responder owns its
// headers. An absent function is refused; omit the option to keep the
// default.
func WithReauthenticationBeginResponder(fn MFABeginResponder) ReauthenticationOption {
	return func(i *reauthInterceptor) error {
		if fn == nil {
			return newConfigError("WithReauthenticationBeginResponder was given no function; omit " +
				"the option to keep the default document")
		}

		i.beginRespond = fn

		return nil
	}
}

// WithReauthenticationMethodsResponder replaces the response the method
// listing answers with. fn receives the same decision every re-proof endpoint
// applies, and may filter it: a deployment with federated users who have no
// password can drop the password for them.
//
// Default: 200 with the JSON document {"methods":[{"name":…,"channel":…,
// "begins":…}],"password":…}, an empty list as [], marked Cache-Control:
// no-store. A consumer's responder owns its headers. An absent function is
// refused; omit the option to keep the default.
func WithReauthenticationMethodsResponder(fn ReauthenticationMethodsResponder) ReauthenticationOption {
	return func(i *reauthInterceptor) error {
		if fn == nil {
			return newConfigError("WithReauthenticationMethodsResponder was given no function; " +
				"omit the option to keep the default document")
		}

		i.methodsRespond = fn

		return nil
	}
}

// WithReauthenticationChallengeTTL lets a re-proof challenge be answered for d
// after it is issued.
//
// Default: 5 minutes, the MFA challenge's default, kept separately: this
// option governs re-proof challenges alone, and WithMFAChallengeTTL login
// challenges alone. A lifetime of zero or less is refused, since no challenge
// could ever be answered.
func WithReauthenticationChallengeTTL(d time.Duration) ReauthenticationOption {
	return func(i *reauthInterceptor) error {
		if d <= 0 {
			return newConfigError("WithReauthenticationChallengeTTL was given %s; a challenge that "+
				"expires as it is issued can never be answered", d)
		}

		i.challengeTTL = d

		return nil
	}
}

// WithReauthenticationChallengeLimit lets begin issue n re-proof challenges to
// one user for one method within the challenge store's issuance window, one
// hour. A begin past the limit is refused as mfa.ErrVerifyThrottled and issues
// nothing.
//
// Default: 10, the MFA challenge's default, kept separately as
// WithReauthenticationChallengeTTL is. A limit of zero or less is refused,
// since it would refuse every begin.
func WithReauthenticationChallengeLimit(n int) ReauthenticationOption {
	return func(i *reauthInterceptor) error {
		if n <= 0 {
			return newConfigError("WithReauthenticationChallengeLimit was given %d; a limit that "+
				"refuses every begin leaves no challenge to answer", n)
		}

		i.challengeCap = n

		return nil
	}
}

// WithReauthenticationChallengeStore keeps re-proof challenges in s.
//
// Default: an in-memory store on the chain's clock, which serves one process:
// a challenge issued by one replica cannot be answered at another. A
// deployment running more than one replica gives a store its replicas share.
// Re-proof challenges are issued under their own purposes, so s may be the
// store the MFA challenges use without either honouring the other's. An absent
// store, including an interface holding a nil pointer, is refused.
func WithReauthenticationChallengeStore(s onetime.Store) ReauthenticationOption {
	return func(i *reauthInterceptor) error {
		if err := requireDep("WithReauthenticationChallengeStore", "one-time store", s); err != nil {
			return err
		}

		i.challengeStore = s

		return nil
	}
}

// RequireSecondFactorForReauthentication makes every re-proof a second
// factor: the password endpoint refuses every user with
// ErrReauthenticationMethodNotUsable, and a user with no second factor is
// offered nothing and becomes fresh only by signing in again.
//
// Default: off, under which a user who holds no second factor re-proves with
// the password. It needs EnableMFA, or New fails with ErrConfig. There is no
// opposite option: a user who holds a second factor never re-proves with the
// password (see EnableReauthentication).
func RequireSecondFactorForReauthentication() ReauthenticationOption {
	return func(i *reauthInterceptor) error {
		i.secondFactorOnly = true

		return nil
	}
}
