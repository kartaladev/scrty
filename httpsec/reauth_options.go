package httpsec

import (
	"slices"
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
//     begin step, answering the method's data as JSON marked Cache-Control:
//     no-store, or through WithReauthenticationBeginResponder, for the
//     session's own user only: a resolved caller naming another user is
//     refused with ErrAuthenticationRequired before the throttle is consulted
//     and before any challenge is issued;
//   - POST <prefix>/verify/<method> re-proves with a second-factor method,
//     under the MFA slot's per-user verification throttle, for the session's
//     own user only: a resolved caller naming another user is refused with
//     ErrAuthenticationRequired. The verified response then passes the
//     post-authentication policy phase with the input a login of the
//     session's user and first factor builds, marked as a re-authentication
//     and carrying what the login did: the library's proof of a second factor
//     met at the first when the session records one, and the evidence the
//     provider asserted when the session is federated. Every deny refuses
//     with the policy's reason, and any challenge other than a second
//     factor's refuses as at the password endpoint, leaving the session as it
//     was. A second-factor challenge (policy.ChallengeMFA) does not refuse,
//     since one was just verified, but what it hid is judged: the phase is
//     asked again with the second factor counted as met
//     (policy.Input.MFASatisfied, beside Reauthenticating), and a deny or any
//     other challenge that surfaces then refuses the same way, so a password
//     change registered after the second-factor policy still refuses;
//   - POST <prefix>/password re-proves with the session's own user's
//     password. It reads only the password, from the form field form login
//     reads it from or a JSON member of that name, under form login's body
//     limit, and checks it for the resolved caller's username: a username in
//     the request is ignored. The check is form login's own, under the
//     account lockout and the password-login source guard; a wrong password
//     is recorded against the user, a lock is refused as a login refuses one,
//     and a success clears the user's recorded failures. The proved password then
//     passes the post-authentication policy phase as a login's does: a deny
//     refuses with the policy's reason, and a challenge refuses with a
//     *ChallengeError carrying no session, leaving the session as it was.
//
// Every other request, including a GET to a verify path, passes on untouched.
//
// # What a second-factor challenge hides
//
// The engine answers with the first challenge in registration order, so a
// policy registered after one that challenges for a second factor is reached
// only on the re-judgement above. The library's policies answer it: policy.MFA
// allows once MFASatisfied is set, and policy.MFARequirement allows an unmet
// federated session once MFASatisfied and Reauthenticating are both set,
// while its refusals, refuse mode's included, stand. The line: a consumer
// policy that raises policy.ChallengeMFA without reading MFASatisfied raises
// it again on the re-judgement, and the challenge is then dropped as before,
// with whatever is registered after it. Such a policy reads MFASatisfied, or
// is registered after the policies it would hide.
//
// A successful re-proof sets the session's authentication time to now, read
// from the chain's clock (WithClock). A second-factor re-proof also records the
// second factor as satisfied then, but only when the method's channel differs
// from the channel of the session's first factor, the test /mfa/verify
// applies: a re-proof on the first factor's own channel (a passkey session
// re-proved with the passkey) refreshes freshness only and leaves the
// second-factor state and its time as they were, as does a password
// re-proof. The session is then rotated to a new handle, so
// the credential the caller arrived with stops working, and the response
// carries the rotated session's credential: by default the JSON document a
// login answers with, marked Cache-Control: no-store
// (WithReauthenticationResponder replaces it). The credential is issued
// inside the rotation, before anything is stored, so one that cannot be issued
// refuses the re-proof with the issuer's failure and stores nothing: the
// credential the caller arrived with keeps working. A rotation a concurrent
// renewal won, or that lost to a concurrent re-proof or second-factor
// verification of the same session through this server or any other manager
// sharing the session store, is refused with ErrSessionRenewalConflict (409)
// inside the winner's in-flight window, and a failed re-proof changes neither
// the session nor its handle.
//
// # Who may re-prove
//
// Only a full session: one with a resolved caller, whose second factor is
// satisfied or was never asked for, that owes no password change and is not
// confined to enrolment or recovery, on a request no consumer challenge was
// raised for (Exchange.RaisedChallenge). A session owing a challenge is refused
// by that challenge's gate, which runs first; any other request the endpoints
// cannot serve, a raised consumer challenge included, is refused with
// ErrAuthenticationRequired. A session that is still fresh is served.
//
// # With what: the factor policy
//
// By default a user re-proves with the strongest factor they hold. A user
// enrolled on any of the MFA slot's methods re-proves with one of those, and
// is refused the password with ErrReauthenticationMethodNotUsable; a user
// enrolled on none re-proves with the password, when form login is enabled. A
// method counts whatever its channel, so a session that signed in with a
// passkey may re-prove with the passkey method. An enrolment lookup that fails
// refuses the request and never falls back to the password. The password
// endpoint looks the methods up in configuration order and stops at the first
// one the user is enrolled on, which alone refuses the password; the listing
// asks every method, and both reach the same answer.
// RequireSecondFactorForReauthentication strengthens the policy so that no
// user re-proves with the password. There is no option to weaken it: a
// password re-proof by a user who holds a second factor would make a session
// fresh at single-factor strength, fresh enough to bind a new authenticator.
//
// Whether a user has a password at all is not known without loading them, so
// the policy offers the password to every user who holds no second factor. A
// user who signed in only through a provider then fails a password re-proof
// as a wrong password would. A deployment with such users filters the
// password out for them in WithReauthenticationMethodsResponder, which runs on
// the request carrying the session.
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
// endpoint's path collides with the path of another endpoint the chain
// enabled, judged by how each matches: the begin and verify paths are
// matched by prefix, the listing and password paths exactly. A path collides
// when it equals another's, or lies under another that is matched by prefix
// (the MFA verify, begin and enrolment prefixes, the passkey registration and
// credentials prefixes, the OIDC authorize, callback and back-channel logout
// prefixes), or has another under it when it is itself matched by prefix; the
// exact paths (logout, form login, the MFA listing, session renewal, password
// change, every account recovery path, the magic-link and passwordless passkey
// login paths, the OIDC handoff path and the key set endpoint) collide only on
// equality or under the begin or verify path, so "/login/reauth" is accepted
// beside form login at "/login"; when the MFA slot was given a challenge store
// (WithMFAChallengeStore), has a method with a begin step, and
// WithReauthenticationChallengeStore was not, because the re-proof challenges
// would sit in per-process memory while the login challenges are shared (a
// TOTP-only slot has no challenge to store and needs no re-proof store, though
// it accepts one); when WithReauthenticationChallengeStore is given on a chain
// without the MFA slot, where nothing issues re-proof challenges; when
// EnablePasskeys is on a chain with the MFA slot and re-authentication is not
// enabled; when the token generator is missing or refused as above; and when
// an option is given an empty prefix, a lifetime or limit of zero or less, or
// an absent store, generator or responder.
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

	if i.mfa == nil && i.challengeStore != nil {
		return newConfigError("WithReauthenticationChallengeStore was given on a chain without the "+
			"MFA slot, and with no second-factor methods nothing issues re-proof challenges, so "+
			"the store would never be used; enable EnableMFA with a challenge method or drop the "+
			"option from %s", option)
	}

	if i.mfa != nil && i.mfa.challengeStoreGiven && i.challengeStore == nil &&
		slices.ContainsFunc(i.mfa.methods, isChallengeMethod) {
		return newConfigError("WithMFAChallengeStore was given a challenge store but "+
			"WithReauthenticationChallengeStore was not: a store shared between replicas for "+
			"login challenges would leave the re-proof challenges of %s in per-process memory, "+
			"so a challenge begun on one replica could not be verified on another; give both "+
			"options the same store", option)
	}

	if err := i.checkPaths(c, option); err != nil {
		return err
	}

	if err := i.buildChallenges(c, option); err != nil {
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

	return checkIssuingGenerator(c, option, "WithReauthenticationTokens", i.tokens)
}

// buildChallenges builds one re-proof challenge manager per challenge method
// of the MFA slot, all over one store, told apart from each other and from the
// login challenges by their purposes. The default store is an in-memory one on
// the chain's clock, so expiry means the same on both sides; a store the
// consumer gave (WithReauthenticationChallengeStore) keeps its own clock.
func (i *reauthInterceptor) buildChallenges(c *config, option string) error {
	i.challenges = make(map[string]*onetime.Tokens)
	i.sweeps = make(map[string]*sweepClock)

	if i.mfa == nil {
		return nil
	}

	// The default store is built only when a challenge method needs one.
	store := i.challengeStore
	if store == nil && slices.ContainsFunc(i.mfa.methods, isChallengeMethod) {
		def, err := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(c.clock))
		if err != nil {
			return newConfigError("%s could not build the re-proof challenge store: %s", option, err)
		}

		store = def
	}

	challenges, sweeps, err := challengeManagers(c, i.mfa.methods, store, i.challengeTTL, reauthChallengePurpose,
		func(method string, err error) error {
			return newConfigError("%s could not build the re-proof challenges of %q: %s", option, method, err)
		})
	if err != nil {
		return err
	}

	i.challenges, i.sweeps = challenges, sweeps

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
	taken := claimedPaths(c, i.mfa, i.login)

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

// claimedPaths is every path the chain's other endpoints answer, each marked
// by how its interceptor matches it: a prefix claims every path beneath it,
// anything else only itself. Form login and logout compare their path exactly,
// so form login at "/login" does not stop the listing answering at
// "/login/reauth/methods".
//
// Recovery's endpoints are all listed whichever proofs are on, because which
// of them answer is decided after the options are applied, and a path the
// consumer configured is one the consumer meant.
func claimedPaths(c *config, m *mfaInterceptor, login *formLogin) []claimedPath {
	var taken []claimedPath

	add := func(name, path string, under bool) {
		taken = append(taken, claimedPath{name, path, under})
	}

	if c.logoutPath != "" {
		add("the logout path", c.logoutPath, false)
	}

	if login != nil {
		add("the form login path", login.path, false)
	}

	if m != nil {
		add("the MFA verify prefix", m.verifyPrefix, true)
		add("the MFA begin prefix", m.beginPrefix, true)

		if m.listing != nil {
			add("the MFA listing path", m.listing.path, false)
		}
	}

	_ = eachInterceptor(c, func(e *enrolmentInterceptor) error {
		add("the MFA enrolment begin prefix", e.beginPrefix, true)
		add("the MFA enrolment confirm prefix", e.confirmPrefix, true)

		if e.emailConfirmation {
			add("the MFA enrolment email-confirm prefix", e.emailPrefix, true)
		}

		return nil
	})

	_ = eachInterceptor(c, func(k *passkeyInterceptor) error {
		add("the passkey registration prefix", k.regPrefix, true)
		add("the passkey credentials prefix", k.credPrefix, true)

		return nil
	})

	_ = eachInterceptor(c, func(l *passwordlessInterceptor) error {
		add("the passwordless begin path", l.beginPath, false)
		add("the passwordless finish path", l.finishPath, false)

		return nil
	})

	_ = eachInterceptor(c, func(l *magicLinkInterceptor) error {
		add("the magic-link request path", l.requestPath, false)
		add("the magic-link consume path", l.consumePath, false)

		return nil
	})

	_ = eachInterceptor(c, func(o *oidcInterceptor) error {
		add("the OIDC authorize prefix", o.authorizePath, true)
		add("the OIDC callback prefix", o.callbackPath, true)
		add("the OIDC back-channel logout prefix", o.backchannelPath, true)

		if o.handoffs != nil || o.handoffRedeemerSet {
			add("the OIDC handoff path", o.handoffPath, false)
		}

		return nil
	})

	_ = eachInterceptor(c, func(j *jwksEndpoint) error {
		add("the key set endpoint", j.path, false)

		return nil
	})

	_ = eachInterceptor(c, func(r *sessionRenewal) error {
		add("the session renewal path", r.path, false)

		return nil
	})

	_ = eachInterceptor(c, func(g *passwordChangeGate) error {
		if g.change != nil {
			add("the password-change endpoint", g.path, false)
		}

		return nil
	})

	_ = eachInterceptor(c, func(r *recoveryInterceptor) error {
		for _, e := range r.endpointPaths() {
			add("the recovery "+e.name+" path", e.path, false)
		}

		return nil
	})

	return taken
}

// collides reports whether a and b would both answer one request path. A
// prefix written with a trailing slash claims what its slash-free form does.
func collides(a, b claimedPath) bool {
	switch {
	case a.path == b.path:
		return true
	case b.under && underPrefix(a.path, strings.TrimRight(b.path, "/")):
		return true
	case a.under && underPrefix(b.path, strings.TrimRight(a.path, "/")):
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
// rotates the session, which supersedes the handle the caller arrived with,
// marked, for its in-flight window, and a
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
// store the MFA challenges use without either honouring the other's.
//
// A chain that gave the MFA slot a store (WithMFAChallengeStore) and has a
// method with a begin step (a challenge method, such as passkeys) must give
// this option too, normally the same store: New fails with ErrConfig naming
// both options otherwise, so a shared login store never leaves re-proof
// challenges in per-process memory. A slot of TOTP alone issues no challenge,
// and builds without this option whether or not the MFA slot was given a
// store. An absent store, including an interface holding a nil pointer, is
// refused.
//
// A chain without the MFA slot (EnableMFA) refuses this option: New fails with
// ErrConfig naming it, because nothing issues re-proof challenges there. A
// slot of TOTP alone accepts it, so one store can be given to both options
// before a challenge method is added.
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

// WithReauthenticationRehash upgrades an outdated password hash when a password
// re-proof verifies the password.
//
// Default: none, and without a write nothing is encoded or stored; a form
// login's own write (WithLoginRehash) does not extend to re-proofs. With fn, a
// re-proof whose password verified and which was not refused afterwards, one
// challenged for a second factor included, asks the current encoder whether the
// stored hash needs upgrading (password.Upgrader). When it does, the password
// is encoded again with that encoder, at the cost of one more key derivation,
// and fn receives the user, the hash it replaces and the new hash. fn's error
// is logged and never changes the outcome; see [RehashFunc] for writing it
// safely. A nil fn is refused.
func WithReauthenticationRehash(fn RehashFunc) ReauthenticationOption {
	return func(i *reauthInterceptor) error {
		if fn == nil {
			return newConfigError("WithReauthenticationRehash was given no write; omit the option " +
				"to rehash nothing")
		}

		i.rehash = fn

		return nil
	}
}
