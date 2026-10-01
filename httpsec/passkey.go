package httpsec

//go:generate mockgen -destination=passkeyverifier_mock_test.go -package=httpsec_test -typed -mock_names=Verifier=MockPasskeyVerifier,ParsedRegistration=MockParsedRegistration,ParsedAssertion=MockParsedAssertion github.com/kartaladev/scrty/passkey Verifier,ParsedRegistration,ParsedAssertion

import (
	"net/http"
	"strings"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// The default paths of the passkey endpoints. Each group is replaced by its
// prefix option.
const (
	// DefaultPasskeyRegistrationPrefix is where registration answers: POST
	// "<prefix>/begin", "<prefix>/finish", "<prefix>/confirm" and
	// "<prefix>/confirm-email" (WithPasskeyRegistrationPrefix).
	DefaultPasskeyRegistrationPrefix = "/passkey/register"

	// DefaultPasskeyCredentialsPrefix is where a user's passkeys are listed
	// (GET "<prefix>"), renamed (POST "<prefix>/rename") and removed (POST
	// "<prefix>/remove") (WithPasskeyCredentialsPrefix).
	DefaultPasskeyCredentialsPrefix = "/passkey/credentials"

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
	Passkeys *passkey.Manager

	// Sessions is the session manager a confined session is saved through
	// when a passkey bound on it becomes active. Required, and it should be
	// the one the chain resolves sessions through.
	Sessions *session.Manager

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

	respondBegin        PasskeyBeginResponder
	respondRegistration PasskeyRegistrationResponder

	// method reports, from assembly on, that the passkey MFA method is on the
	// MFA slot, so a passkey bound on a recovery-pending session can be proven
	// there. Without it a recovery-pending session is refused registration:
	// the binding would leave it owing a second factor nothing could resolve.
	method bool

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
	return []struct{ name, path string }{
		{"registration begin", p.regPrefix + passkeyBeginSegment},
		{"registration finish", p.regPrefix + passkeyFinishSegment},
		{"saved-code confirm", p.regPrefix + passkeyConfirmSegment},
		{"emailed-code confirm", p.regPrefix + passkeyConfirmEmailSegment},
		{"listing", p.credPrefix},
		{"rename", p.credPrefix + passkeyRenameSegment},
		{"remove", p.credPrefix + passkeyRemoveSegment},
	}
}

// EnablePasskeys serves passkey registration on the chain, at OrderPasskeys,
// inside bearer authentication and every gate.
//
// The registration endpoints answer POST only, each on its exact path under
// the registration prefix, DefaultPasskeyRegistrationPrefix by default
// (WithPasskeyRegistrationPrefix):
//
//   - "<prefix>/begin" admits the session (passkey.Manager.BeginRegistration)
//     and answers 200 with {"publicKey":{…creation options…}} and
//     Cache-Control: no-store (WithPasskeyBeginResponder);
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
// Any other method on these paths passes through untouched, and so does
// every other path. A request without a session is refused with
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
// follows the path's email confirmation (WithoutEmailConfirmation), contact
// resolver (WithContactResolver) and confirmation limiter
// (WithEnrolmentConfirmLimiter), so the user's budget is shared with the
// path. When a passkey becomes active for a recovery-pending or enrolment-only
// session — at finish, or at the confirmation that activates it — the session
// moves to the MFA-pending state, keeping its confinement marker and its
// recovery time, and is saved; the user then proves the new passkey at the
// MFA slot's begin and verify endpoints for the method "passkey", which
// restore the session's deadlines and rotate it. A registration on a full
// session leaves its second-factor state alone.
//
// New refuses the chain when the manager or the session manager is missing,
// when EnablePasskeys is given twice, and when any passkey path is empty,
// does not start with "/", equals another passkey path, the login path, the
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
			respondBegin:        writePasskeyBegin,
			respondRegistration: writePasskeyRegistration,
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

			return requireDep(option, "session manager (PasskeyDeps.Sessions)", deps.Sessions)
		})

		c.useSessions(deps.Sessions)
		c.register(p, OrderPasskeys)

		return nil
	}
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
// the one passkey registration enrols (passkey.Manager.MFAMethod). It is
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

	if err := p.checkPaths(option, c); err != nil {
		return err
	}

	p.method = c.hasPasskeyMethod()

	_ = eachInterceptor(c, func(i *enrolmentInterceptor) error {
		if i.passkeys {
			p.enrolment = i
			i.passkeyPaths = p.registrationPaths()
		}

		return nil
	})

	return nil
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

	s := ex.Session
	if s == nil {
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

	return serve(ex, s)
}

// registrationContext is what the manager is told about s's registration:
// for an enrolment-only session, the enrolment path's email confirmation,
// contact resolver and confirmation limiter; for any other, nothing, so the
// manager's own apply.
func (p *passkeyInterceptor) registrationContext(s *session.Session) passkey.RegistrationContext {
	if s.MFA != session.MFAEnrolmentPending || p.enrolment == nil {
		return passkey.RegistrationContext{}
	}

	return passkey.RegistrationContext{
		EmailConfirmation: p.enrolment.emailConfirmation,
		ContactResolver:   p.enrolment.contact,
		ConfirmLimiter:    p.enrolment.confirmLimiter,
	}
}
