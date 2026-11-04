package httpsec

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

//go:generate mockgen -destination=passkeyverifier_mock_test.go -package=httpsec_test -typed -mock_names=Verifier=MockPasskeyVerifier,ParsedRegistration=MockParsedRegistration,ParsedAssertion=MockParsedAssertion github.com/kartaladev/scrty/authenticate/passkey Verifier,ParsedRegistration,ParsedAssertion

// The default paths of the passkey endpoints. Each group is replaced by its
// prefix option.
const (
	// DefaultPasskeyRegistrationPrefix is where registration answers: POST
	// "<prefix>/begin", "<prefix>/finish", "<prefix>/confirm" and
	// "<prefix>/confirm-email" (WithPasskeyRegistrationPrefix).
	DefaultPasskeyRegistrationPrefix = "/passkey/register" //nolint:gosec // G101: a route path, not a credential

	// DefaultPasskeyCredentialsPrefix is where a user's passkeys are listed
	// (GET "<prefix>"), renamed (POST "<prefix>/rename") and removed (POST
	// "<prefix>/remove") (WithPasskeyCredentialsPrefix).
	DefaultPasskeyCredentialsPrefix = "/passkey/credentials" //nolint:gosec // G101: a route path, not a credential

	// DefaultPasswordlessPrefix is where passwordless login answers, when it
	// is enabled: POST "<prefix>/begin" and "<prefix>/finish".
	DefaultPasswordlessPrefix = "/passkey/login"

	// DefaultPasswordlessCookieName is the passwordless ceremony cookie's name.
	DefaultPasswordlessCookieName = "passkey_ceremony"
)

// The last segments of the registration endpoints, under the registration
// prefix, and of the management endpoints, under the credentials prefix.
const (
	passkeyBeginSegment        = "/begin"
	passkeyFinishSegment       = "/finish"
	passkeyConfirmSegment      = "/confirm"
	passkeyConfirmEmailSegment = "/confirm-email"
	passkeyRenameSegment       = "/rename"
	passkeyRemoveSegment       = "/remove"
)

// PasskeyDeps are what EnablePasskeys works over.
type PasskeyDeps struct {
	// Passkeys runs the ceremonies. Required.
	Passkeys *passkey.Passkeys

	// Sessions is the session manager a confined session is saved through
	// when a passkey bound on it becomes active. Required, and it should be
	// the one the chain resolves sessions through.
	Sessions *session.Sessions

	// Users loads the user a passwordless login names. The registration and
	// management endpoints do not use it.
	Users identity.UserLoader
}

// PasskeyOption configures the passkey endpoints. Each replaces one of the
// defaults named on EnablePasskeys.
type PasskeyOption func(*passkeyInterceptor) error

// passkeyInterceptor is the passkey endpoints that need a session.
type passkeyInterceptor struct {
	deps PasskeyDeps

	regPrefix  string
	credPrefix string

	// loginPrefix is the passwordless prefix, and loginPrefixSet reports
	// that WithPasskeyPasswordlessPrefix moved it.
	loginPrefix    string
	loginPrefixSet bool

	// passwordless holds the passwordless settings when WithPasskeyPasswordlessLogin
	// was given, and login the passwordless endpoints built from them.
	passwordless *passwordlessConfig
	login        *passwordlessInterceptor

	respondBegin        PasskeyBeginResponder
	respondRegistration PasskeyRegistrationResponder
	respondList         PasskeyListResponder
	respondRename       PasskeyChangeResponder
	respondRemove       PasskeyChangeResponder

	// silentRemoval is WithoutPasskeyRemovalNotification: a removal queues
	// no notice.
	silentRemoval bool

	// method reports, from assembly on, that the passkey MFA method is on the
	// MFA slot, so a passkey bound on a recovery-pending session can be proven
	// there. Without it a recovery-pending session is refused registration:
	// the binding would leave it owing a second factor nothing could resolve.
	method bool

	// mfaMethods are the MFA slot's methods, the passkey method among them
	// when it is there, resolved at assembly and nil with no MFA slot. The
	// manager decides registration and removal admission over them.
	mfaMethods []policy.MFAMethodLookup

	// passwordlessLogin reports, from assembly on, that the chain serves
	// passwordless login, so the manager counts the user's own passkeys as a
	// second factor the account has when the login proves one.
	passwordlessLogin bool

	// resolving holds the consumer challenge kinds the registration endpoints
	// serve a request raising (WithPasskeyRegistrationResolving), nil by
	// default.
	resolving map[policy.ChallengeKind]bool

	// enrolment is the chain's enrolment path, handed over at assembly when
	// the path counts the passkey method among its enrolling methods, and nil
	// otherwise. Its email confirmation, contact resolver and confirmation
	// limiter apply to a registration on an enrolment-only session.
	enrolment *enrolmentInterceptor
}

// registrationPaths are the four registration endpoints' paths, which the
// recovery gate and the enrolment gate exempt.
func (p *passkeyInterceptor) registrationPaths() []string {
	return []string{
		p.regPrefix + passkeyBeginSegment,
		p.regPrefix + passkeyFinishSegment,
		p.regPrefix + passkeyConfirmSegment,
		p.regPrefix + passkeyConfirmEmailSegment,
	}
}

// paths are every path the passkey endpoints answer, named for a
// configuration error.
func (p *passkeyInterceptor) paths() []struct{ name, path string } {
	paths := []struct{ name, path string }{
		{"registration begin", p.regPrefix + passkeyBeginSegment},
		{"registration finish", p.regPrefix + passkeyFinishSegment},
		{"saved-code confirm", p.regPrefix + passkeyConfirmSegment},
		{"emailed-code confirm", p.regPrefix + passkeyConfirmEmailSegment},
		{"listing", p.credPrefix},
		{"rename", p.credPrefix + passkeyRenameSegment},
		{"remove", p.credPrefix + passkeyRemoveSegment},
	}

	if p.login != nil {
		paths = append(paths,
			struct{ name, path string }{"passwordless begin", p.login.beginPath},
			struct{ name, path string }{"passwordless finish", p.login.finishPath})
	}

	return paths
}

// EnablePasskeys serves passkey registration on the chain, at OrderPasskeys,
// inside bearer authentication and every gate.
//
// The registration endpoints answer POST only, each on its exact path under
// the registration prefix, DefaultPasskeyRegistrationPrefix by default
// (WithPasskeyRegistrationPrefix):
//
//   - "<prefix>/begin" admits the session (passkey.Passkeys.BeginRegistration),
//     deciding whether it owes a second factor over the MFA slot's methods,
//     the passkey method among them when it is there, and over the user's own
//     active passkeys when that method is there or
//     WithPasskeyPasswordlessLogin is given and its login proves the second
//     factor. A password session steps
//     up through the passkey MFA method (recognised by identity: a wrapped
//     method opens no route); a passkey-first session cannot meet the second
//     factor through it (a same-channel re-proof refreshes freshness only),
//     and signs in again with user verification, by password and then the
//     passkey step-up, or by a re-proof on another channel. It answers 200 with
//     {"publicKey":{…creation options…}} and Cache-Control: no-store
//     (WithPasskeyBeginResponder);
//   - "<prefix>/finish" reads the authenticator's response as a JSON body of
//     at most passkey.RegistrationBodyLimit (64 KiB), finishes the
//     registration, and answers 200 with
//     {"id","name","state","pending":[…],"recovery_codes":[…]|null,
//     "backup_eligible","no_synced_passkey","recovery_not_set_up"} and
//     Cache-Control: no-store (WithPasskeyRegistrationResponder). "state" is
//     "active" or "pending", and "pending" lists "saved_codes" and
//     "email_code" for the confirmations the passkey still awaits;
//   - "<prefix>/confirm" reads the "code" field of a URL-encoded body and
//     confirms the user kept the saved recovery codes their pending passkey
//     awaits, answering 204;
//   - "<prefix>/confirm-email" reads the "code" field likewise and redeems
//     the code emailed for a passkey registered from an enrolment-only
//     session, answering 204.
//
// The management endpoints answer under the credentials prefix,
// DefaultPasskeyCredentialsPrefix by default (WithPasskeyCredentialsPrefix):
//
//   - GET "<prefix>" lists the session user's passkeys in every state, with
//     no public key (passkey.Passkeys.List), answering 200 with
//     {"passkeys":[…]} and Cache-Control: no-store
//     (WithPasskeyListResponder);
//   - POST "<prefix>/rename" reads the "id" and "name" fields of a
//     URL-encoded body and names the passkey under the registration's name
//     rules (passkey.Passkeys.Rename), answering 204
//     (WithPasskeyRenameResponder);
//   - POST "<prefix>/remove" reads the "id" field likewise and removes the
//     passkey, in any state, under the registration's assurance and
//     freshness (passkey.Passkeys.Remove), answering 204
//     (WithPasskeyRemoveResponder). A stale or under-assured session is
//     refused with passkey.ErrReauthenticationRequired (403). Removing a
//     passwordless-only user's last active passkey leaves them only account
//     recovery to sign in with. The optional "other_sessions" field of the
//     same body chooses whether the user's other sessions end with it: "end"
//     or "keep". Absent, the manager's default applies, which is to end them
//     (passkey.WithoutSessionRevocationOnRemoval makes it keep them). Any
//     other value, an empty one, or the field given more than once is refused
//     with ErrMalformedRequest (400) before anything changes. Asking to end
//     sessions of a manager wired with no session revoker is a passkey.ErrConfig
//     refusal.
//
// They serve full sessions only: a confined session, or one owing an MFA or
// password-change challenge, is refused with the ChallengeError it owes. A
// session that owes no challenge but is not full (a confinement marker left
// without its state, or a second-factor state outside the named ones, which no
// library path produces) is refused as ErrAuthenticationRequired. An
// identifier that does not parse, names another user's passkey or names
// none is passkey.ErrNotFound (404), and nothing changes.
//
// On a chain with EnableOIDCProvider, the manager must say what a suspended clone
// does to the user's application grants, by passkey.WithGrantRevoker or
// passkey.WithoutCloneGrantRevocation; one with neither refuses the chain with a
// configuration error. A chain using only the manager's MFAMethod, without
// EnablePasskeys, is outside that check. With no provider nothing changes.
//
// Passwordless login is off by default and is enabled with
// WithPasskeyPasswordlessLogin, which serves its own two endpoints as a first
// factor at OrderPasskeyLogin.
//
// Every registration and management request on which the chain's per-request
// policy raised a challenge of the consumer's own (Exchange.RaisedChallenge,
// declared with WithChallengeEnforcer) is refused with a ChallengeError of
// that kind before anything is begun, stored or changed: the gate enforcing
// such a challenge is the consumer's and may sit after the passkey slot. On
// registration, a second factor or a password change the session owes is
// named in preference to it, and a recovery-pending or enrolment-only
// session is refused with the raised kind. On management, any challenge the
// session owes, recovery and enrolment included, is named in preference to
// it. WithPasskeyRegistrationResolving names the consumer kinds the four
// registration endpoints serve instead; management never does.
//
// Any other method on these paths passes through untouched, and so does
// every other path. A request without a session, or whose session carries no
// resolved caller (no Exchange.Authentication principal), is refused with
// ErrAuthenticationRequired.
//
// The response is read by the library and never from the URL query: a body
// that is not JSON, is empty, does not parse, or that the verifier cannot
// read (passkey.ErrMalformedResponse) is refused with ErrCredentialsMissing
// (400), and one over the limit with ErrRequestTooLarge (413), before any
// challenge is spent. These limits are not defaults; there is no option to
// relax them.
//
// Which sessions reach the endpoints is the gates' decision. A full session
// is admitted by the manager's own rule (assurance and freshness). A
// recovery-pending session reaches the four registration endpoints only when
// the passkey MFA method is on the MFA slot (EnableMFA), because the recovery
// gate then exempts them; without the method it is refused with a
// ChallengeError of kind policy.ChallengeAccountRecovery, since a passkey it
// bound could never be proven. An enrolment-only session reaches them only
// when the passkey MFA method is among the enrolment path's enrolling
// methods (EnableMFAEnrolment, WithEnrolmentMethods); its registration then
// follows the path's email confirmation (WithoutEnrolmentEmailConfirmation), contact
// resolver (WithEnrolmentContactResolver) and confirmation limiter
// (WithEnrolmentConfirmLimiter), so the user's budget is shared with the
// path. When a passkey becomes active for a recovery-pending or enrolment-only
// session — at finish, or at the confirmation that activates it — the session
// moves to the MFA-pending state, keeping its confinement marker and its
// recovery time, and is saved; the user then proves the new passkey at the
// MFA slot's begin and verify endpoints for the method "passkey", which
// restore the session's deadlines and rotate it. A registration on a full
// session leaves its second-factor state alone.
//
// Flushing the chain's refusal logs (Chain.FlushRefusalLogs) flushes the
// passkey manager's sampler too.
//
// New refuses the chain when the manager or the session manager is missing,
// when EnablePasskeys is given twice, when the chain has the MFA slot
// (EnableMFA) and does not enable EnableReauthentication (how a full session
// that has not met its second factor meets it before managing passkeys, since
// /mfa/verify serves only a pending session; a chain without the MFA slot is
// not bound by it, whatever the order of the options), and when any passkey
// path is empty, does not start with "/", equals another passkey path, the login path, the
// logout path, the password-change resolve path or an account-recovery
// endpoint path, or lies under the MFA verify or begin prefix or an enrolment
// prefix.
func EnablePasskeys(deps PasskeyDeps, opts ...PasskeyOption) Option {
	const option = "EnablePasskeys"

	return func(c *config) error {
		p := &passkeyInterceptor{
			deps:                deps,
			regPrefix:           DefaultPasskeyRegistrationPrefix,
			credPrefix:          DefaultPasskeyCredentialsPrefix,
			loginPrefix:         DefaultPasswordlessPrefix,
			respondBegin:        writePasskeyBegin,
			respondRegistration: writePasskeyRegistration,
			respondList:         writePasskeyList,
			respondRename:       writePasskeyChanged,
			respondRemove:       writePasskeyChanged,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(p); err != nil {
				return err
			}
		}

		if c.passkeysOf() != nil {
			return newConfigError("%s was given twice; one chain has one set of passkey endpoints", option)
		}

		c.enable(option, func() error {
			if err := requireDep(option, "passkey manager (PasskeyDeps.Passkeys)", deps.Passkeys); err != nil {
				return err
			}

			if err := requireDep(option, "session manager (PasskeyDeps.Sessions)", deps.Sessions); err != nil {
				return err
			}

			return p.checkPasswordless(option)
		})

		c.useSessions(deps.Sessions)
		c.register(p, OrderPasskeys)

		if p.passwordless != nil {
			p.login = p.newPasswordless(c.now)
			c.register(p.login, OrderPasskeyLogin)
			c.wire(p.login.wire)
		}

		return nil
	}
}

// flushRefusalLogs reports what the passkey manager's sampler is holding
// back.
func (p *passkeyInterceptor) flushRefusalLogs() error {
	if p.deps.Passkeys != nil {
		return p.deps.Passkeys.FlushRefusalLogs()
	}

	return nil
}

// passkeysOf returns the chain's passkey endpoints, or nil when passkeys are
// not enabled.
func (c *config) passkeysOf() *passkeyInterceptor {
	var found *passkeyInterceptor

	_ = eachInterceptor(c, func(p *passkeyInterceptor) error {
		if found == nil {
			found = p
		}

		return nil
	})

	return found
}

// servedByPasskeys reports whether m is the library's passkey MFA method,
// the one passkey registration enrols (passkey.Passkeys.MFAMethod). It is
// recognised by its type, never by its shape: a consumer's method that also
// declares it serves the enrolment path without being an mfa.Enroller is
// not enrolled by passkey registration, and is judged as any other method.
func servedByPasskeys(m mfa.Method) bool {
	_, ok := m.(*passkey.MFAMethod)

	return ok
}

// hasPasskeyMethod reports whether the chain's MFA slot serves a method
// passkey registration enrols.
func (c *config) hasPasskeyMethod() bool {
	m := c.mfaOf()
	if m == nil {
		return false
	}

	for _, method := range m.methods {
		if servedByPasskeys(method) {
			return true
		}
	}

	return false
}

// hasReauthentication reports whether EnableReauthentication was given,
// whatever the order of the options.
func (c *config) hasReauthentication() bool {
	found := false

	_ = eachInterceptor(c, func(*reauthInterceptor) error {
		found = true

		return nil
	})

	return found
}

// wirePasskeys checks the passkey paths against the rest of the chain, once
// every option has been applied, and hands the passkey endpoints the
// enrolment path when it counts the passkey method among its enrolling
// methods. It runs after wireMFAEnrolment, which settles that.
func (c *config) wirePasskeys() error {
	const option = "EnablePasskeys"

	p := c.passkeysOf()
	if p == nil {
		return nil
	}

	if c.mfaOf() != nil && !c.hasReauthentication() {
		return newConfigError("%s on a chain with the MFA slot needs EnableReauthentication: "+
			"re-authentication is how a full session that has not met its second factor meets it "+
			"before managing passkeys, since /mfa/verify serves only a pending session", option)
	}

	if p.loginPrefixSet && p.passwordless == nil {
		return newConfigError("%s was given WithPasskeyPasswordlessPrefix without WithPasskeyPasswordlessLogin, "+
			"so the prefix would move no endpoint", option)
	}

	c.checkAfterWiring(func() error { return p.checkCloneGrants(c) })

	if err := p.checkResolving(c); err != nil {
		return err
	}

	if err := p.checkPaths(option, c); err != nil {
		return err
	}

	if p.login != nil {
		if err := p.login.resolve(option, c); err != nil {
			return err
		}
	}

	p.method = c.hasPasskeyMethod()
	p.passwordlessLogin = p.passwordless != nil
	if m := c.mfaOf(); m != nil {
		p.mfaMethods = m.lookups
	}

	_ = eachInterceptor(c, func(i *enrolmentInterceptor) error {
		if i.passkeys {
			p.enrolment = i
			i.passkeyPaths = p.registrationPaths()
		}

		return nil
	})

	return nil
}

// checkCloneGrants refuses a manager on a chain with a provider that was told
// nothing about a suspended clone's grants. The package's own default revokes
// nothing, since it alone has no provider, and here that would leave a suspected
// clone's grants alive with nobody having chosen it.
func (p *passkeyInterceptor) checkCloneGrants(c *config) error {
	if c.oidcProvider == nil || p.deps.Passkeys == nil || p.deps.Passkeys.CloneGrantsDecided() {
		return nil
	}

	return newConfigError("EnablePasskeys on a chain with EnableOIDCProvider needs a manager that says what " +
		"a suspected clone does to the user's grants: build it with passkey.WithGrantRevoker(provider), or " +
		"with passkey.WithoutCloneGrantRevocation() to keep them")
}

// checkPaths refuses a passkey path that collides with another passkey path,
// the login path, the logout path, the password-change resolve path or an
// account-recovery endpoint path, or that lies under a prefix another
// endpoint answers every POST under: the MFA verify and begin prefixes, and
// the enrolment prefixes.
func (p *passkeyInterceptor) checkPaths(option string, c *config) error {
	taken := map[string]string{}
	if l := c.formLogin(); l != nil {
		taken[l.path] = "the login path"
	}
	if c.logoutPath != "" {
		taken[c.logoutPath] = "the logout path"
	}

	_ = eachInterceptor(c, func(g *passwordChangeGate) error {
		if g.change != nil {
			taken[g.path] = "the password-change resolve path"
		}

		return nil
	})

	_ = eachInterceptor(c, func(i *recoveryInterceptor) error {
		for _, r := range i.endpointPaths() {
			taken[r.path] = "the recovery " + r.name + " path"
		}

		return nil
	})

	var prefixes []struct{ name, prefix string }
	if m := c.mfaOf(); m != nil {
		prefixes = append(prefixes,
			struct{ name, prefix string }{"EnableMFA's verify prefix", m.verifyPrefix},
			struct{ name, prefix string }{"EnableMFA's begin prefix", m.beginPrefix})
	}

	_ = eachInterceptor(c, func(i *enrolmentInterceptor) error {
		for _, prefix := range i.prefixes() {
			prefixes = append(prefixes, struct{ name, prefix string }{"an enrolment prefix", prefix})
		}

		return nil
	})

	for _, e := range p.paths() {
		if other, ok := taken[e.path]; ok {
			return newConfigError("%s's %s path %q is already %s: whichever endpoint matched "+
				"first would swallow the other", option, e.name, e.path, other)
		}

		for _, o := range prefixes {
			if underPrefix(e.path, o.prefix) {
				return newConfigError("%s's %s path %q lies under %s %q, whose endpoint answers "+
					"every POST under it", option, e.name, e.path, o.name, o.prefix)
			}
		}

		taken[e.path] = "the passkey " + e.name + " path"
	}

	return nil
}

// passkeyPrefix validates a passkey endpoint prefix and returns it without a
// trailing slash.
func passkeyPrefix(option, prefix string) (string, error) {
	switch {
	case prefix == "":
		return "", newConfigError("%s was given no prefix, so the endpoints would not exist", option)
	case !strings.HasPrefix(prefix, "/"):
		return "", newConfigError("%s was given %q, which does not start with \"/\" and so "+
			"matches no request path", option, prefix)
	}

	trimmed := strings.TrimRight(prefix, "/")
	if trimmed == "" {
		return "", newConfigError("%s was given the root path %q; give the endpoints a prefix "+
			"of their own", option, prefix)
	}

	return trimmed, nil
}

// Intercept serves the passkey endpoints, and passes every other request on.
func (p *passkeyInterceptor) Intercept(ex *Exchange, next Next) error {
	if served, err := p.manage(ex); served {
		return err
	}

	r := ex.Request
	if r.Method() != http.MethodPost {
		return next(ex)
	}

	var serve func(*Exchange, *session.Session) error

	switch r.Path() {
	case p.regPrefix + passkeyBeginSegment:
		serve = p.begin
	case p.regPrefix + passkeyFinishSegment:
		serve = p.finish
	case p.regPrefix + passkeyConfirmSegment:
		serve = p.confirmSaved
	case p.regPrefix + passkeyConfirmEmailSegment:
		serve = p.confirmEmail
	default:
		return next(ex)
	}

	// There must be a session and a resolved caller for it: a session whose
	// first factor published no caller names nobody to register for.
	s := ex.Session
	if s == nil || ex.Authentication == nil || ex.Authentication.Principal == nil {
		return ErrAuthenticationRequired
	}

	// The enrolment gate lets an enrolment-only session through only when
	// passkey registration serves the path; this holds the line even for an
	// interceptor a consumer placed between the two.
	if s.MFA == session.MFAEnrolmentPending && p.enrolment == nil {
		return &ChallengeError{Kind: policy.ChallengeMFAEnrolment, Session: s}
	}

	// Likewise the recovery gate lets a recovery-pending session through only
	// when the passkey method is on the MFA slot to prove the new passkey at.
	if s.MFA == session.MFARecoveryPending && !p.method {
		return &ChallengeError{Kind: policy.ChallengeAccountRecovery, Session: s}
	}

	// A second factor or a password change the session owes is named in
	// preference to a challenge raised on the request, whether or not
	// registration resolves the raised kind.
	if err := owedBeforeRaised(ex, s); err != nil {
		return err
	}

	// A challenge the per-request policy raised on this request is enforced
	// by a gate of the consumer's. One registered after this slot cannot
	// refuse a registration that is already begun or finished, so every
	// registration request, whatever the session's state, is refused here.
	// The kinds WithPasskeyRegistrationResolving names are the exception: the
	// consumer's gate lets registration through to resolve them.
	if !p.resolvesRaised(ex.RaisedChallenge()) {
		if err := raisedChallengeRefusal(ex, s); err != nil {
			return err
		}
	}

	return serve(ex, s)
}

// owedBeforeRaised refuses a session that owes a second factor or a password
// change with that challenge, when a consumer kind was raised on the request,
// and reports nil otherwise. The gates ahead of the endpoints refuse such a
// session first on a chain that enables them; this holds the line past a
// reordered chain. It does nothing when no kind was raised, so the request is
// judged as it always was, by the manager.
func owedBeforeRaised(ex *Exchange, s *session.Session) error {
	if ex.RaisedChallenge() == policy.ChallengeNone {
		return nil
	}

	switch kind := owedChallenge(s); kind {
	case policy.ChallengeMFA, policy.ChallengePasswordChange:
		return &ChallengeError{Kind: kind, Session: s}
	default:
		return nil
	}
}

// registrationContext is what the manager is told about s's registration or
// removal: always the MFA slot's methods and whether the chain serves
// passwordless login, which admission decides over; and,
// for an enrolment-only session, the enrolment path's email confirmation,
// contact resolver and confirmation limiter, where any other session leaves
// the manager's own to apply.
func (p *passkeyInterceptor) registrationContext(s *session.Session) passkey.RegistrationContext {
	rc := passkey.RegistrationContext{MFAMethods: p.mfaMethods, PasswordlessLogin: p.passwordlessLogin}
	if s.MFA != session.MFAEnrolmentPending || p.enrolment == nil {
		return rc
	}

	rc.EmailConfirmation = p.enrolment.emailConfirmation
	rc.ContactResolver = p.enrolment.contact
	rc.ConfirmLimiter = p.enrolment.confirmLimiter

	return rc
}

// PasskeyBeginResponder writes a ceremony begin's answer: options are the
// creation or request options for the browser, as the verifier rendered them
// (the members of navigator.credentials' publicKey argument).
//
// It is called instead of the downstream handler. An error it returns leaves
// the chain as the request's refusal; the challenge in the options has
// already been issued and will expire unused.
type PasskeyBeginResponder func(ex *Exchange, options json.RawMessage) error

// PasskeyRegistrationResponder writes a finished registration. res carries
// the stored passkey, whether it is active, and the saved recovery codes when
// it awaits their confirmation, which is the only time they are readable: a
// responder that drops them leaves the user unable to confirm.
//
// It is called instead of the downstream handler, after the passkey is
// stored and, when it became active, after a confined session has been moved
// on to its second factor.
type PasskeyRegistrationResponder func(ex *Exchange, res *passkey.RegistrationResult) error

// WithPasskeyRegistrationPrefix answers the registration endpoints under
// prefix instead: POST "<prefix>/begin", "<prefix>/finish", "<prefix>/confirm"
// and "<prefix>/confirm-email".
//
// Default: DefaultPasskeyRegistrationPrefix. A trailing slash is dropped. An
// empty prefix, one that does not start with "/", and the root "/" are
// refused; New also refuses a prefix whose paths collide with another
// endpoint's (see EnablePasskeys). The recovery and enrolment gates exempt
// the moved paths, not the defaults.
func WithPasskeyRegistrationPrefix(prefix string) PasskeyOption {
	return func(p *passkeyInterceptor) error {
		trimmed, err := passkeyPrefix("WithPasskeyRegistrationPrefix", prefix)
		if err != nil {
			return err
		}

		p.regPrefix = trimmed

		return nil
	}
}

// WithPasskeyCredentialsPrefix answers the management endpoints under prefix
// instead: GET "<prefix>" lists, POST "<prefix>/rename" renames and POST
// "<prefix>/remove" removes.
//
// Default: DefaultPasskeyCredentialsPrefix. It is validated as
// WithPasskeyRegistrationPrefix's is.
func WithPasskeyCredentialsPrefix(prefix string) PasskeyOption {
	return func(p *passkeyInterceptor) error {
		trimmed, err := passkeyPrefix("WithPasskeyCredentialsPrefix", prefix)
		if err != nil {
			return err
		}

		p.credPrefix = trimmed

		return nil
	}
}

// WithPasskeyBeginResponder replaces how a registration begin is answered.
//
// Default: 200 with {"publicKey":<options>} as JSON, and Cache-Control:
// no-store. A nil function is refused; omit the option to keep the default.
func WithPasskeyBeginResponder(fn PasskeyBeginResponder) PasskeyOption {
	return func(p *passkeyInterceptor) error {
		if fn == nil {
			return newConfigError("WithPasskeyBeginResponder was given no function; omit the " +
				"option to keep the default document")
		}

		p.respondBegin = fn

		return nil
	}
}

// WithPasskeyRegistrationResponder replaces how a finished registration is
// answered.
//
// Default: 200 with {"id","name","state","pending","recovery_codes",
// "backup_eligible","no_synced_passkey","recovery_not_set_up"} as JSON, and
// Cache-Control: no-store (see EnablePasskeys). A nil function is refused;
// omit the option to keep the default.
func WithPasskeyRegistrationResponder(fn PasskeyRegistrationResponder) PasskeyOption {
	return func(p *passkeyInterceptor) error {
		if fn == nil {
			return newConfigError("WithPasskeyRegistrationResponder was given no function; omit " +
				"the option to keep the default document")
		}

		p.respondRegistration = fn

		return nil
	}
}

// WithPasskeyRegistrationResolving lets the registration endpoints serve a
// request on which the chain's per-request policy raised one of kinds, each a
// challenge kind of the consumer's own.
//
// Default: without it, a request on which a consumer kind was raised
// (Exchange.RaisedChallenge, declared with WithChallengeEnforcer) is refused
// with a ChallengeError of that kind on every passkey registration and
// management endpoint. That is the
// safe default, because the gate enforcing the kind is the consumer's and may
// sit after the passkey slot, which would otherwise serve the request first.
//
// With it, a request on which one of kinds was raised is served by the four
// registration endpoints (begin, finish, confirm and email confirm), under
// every other rule unchanged: assurance, freshness, confinement, and a
// second factor or password change the session owes, which is still named
// first. It is for a
// consumer whose gate lets registration through so that the binding resolves
// its kind, as the library's enrolment gate does for its own. The listing,
// the rename and the removal never serve it, since none of them binds an
// authenticator, and a raised kind not in kinds is refused on every one of them.
//
// The library marks nothing: whether the binding resolved the challenge is
// for the consumer's policy to judge on the request that follows. Naming a
// kind here only stops the passkey endpoints refusing it. The option may be
// given more than once; the kinds are joined.
//
// New refuses, with an error naming this option, a call with no kinds,
// ChallengeNone, a kind the library enforces through its own gate (the
// built-in kinds), and a kind the chain does not declare with
// WithChallengeEnforcer, whichever of the two options comes first.
func WithPasskeyRegistrationResolving(kinds ...policy.ChallengeKind) PasskeyOption {
	const option = "WithPasskeyRegistrationResolving"

	return func(p *passkeyInterceptor) error {
		if len(kinds) == 0 {
			return newConfigError("%s was given no kinds; omit the option to keep refusing every "+
				"raised challenge on the passkey endpoints", option)
		}

		for _, kind := range kinds {
			if kind == policy.ChallengeNone {
				return newConfigError("%s was given ChallengeNone, which is not a challenge", option)
			}

			if b, ok := builtInEnforcers[kind]; ok {
				return newConfigError("%s was given %s, which the library enforces through its own "+
					"gate (%s); only a consumer kind declared with WithChallengeEnforcer can be named",
					option, kind, b.option)
			}

			if p.resolving == nil {
				p.resolving = make(map[policy.ChallengeKind]bool, len(kinds))
			}

			p.resolving[kind] = true
		}

		return nil
	}
}

// resolvesRaised reports whether the registration endpoints serve a request
// on which kind was raised: nothing was raised, or WithPasskeyRegistrationResolving
// named it.
func (p *passkeyInterceptor) resolvesRaised(kind policy.ChallengeKind) bool {
	return kind == policy.ChallengeNone || p.resolving[kind]
}

// checkResolving refuses a kind WithPasskeyRegistrationResolving named that
// the chain does not declare with WithChallengeEnforcer. It runs once every
// option has been applied, so the order of the two options does not matter.
func (p *passkeyInterceptor) checkResolving(c *config) error {
	for kind := range p.resolving {
		if !c.consumerEnforced[kind] {
			return newConfigError("WithPasskeyRegistrationResolving was given %s, which the chain does "+
				"not declare: add WithChallengeEnforcer for it, or remove it from the option", kind)
		}
	}

	return nil
}
