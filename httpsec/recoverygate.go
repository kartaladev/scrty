package httpsec

import (
	"net/http"

	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// recoveryGate confines a session an account recovery created, until it binds
// a new authenticator or changes its password.
//
// Its exemptions are not configured: they are read at assembly from the
// built-ins that serve them, so a consumer who moves an endpoint moves the
// exemption with it, and nothing else can be added. There is deliberately no
// option to let further routes through. A capability that adds another way to
// bind an authenticator adds its endpoint here in its own change.
type recoveryGate struct {
	// enrolPrefixes are the enrolment path's endpoint prefixes, and empty when
	// the chain has no enrolment path.
	enrolPrefixes []string

	// resolvePath is the password-change gate's resolve endpoint, and empty
	// when the chain registered none.
	resolvePath string

	// logoutPath is the chain's logout endpoint, and empty when the chain has
	// no logout.
	logoutPath string

	// codes answers the saved-code endpoints, and is nil when the gate was
	// registered without account recovery's endpoints.
	codes *recoveryInterceptor
}

// Intercept refuses a recovery-pending session everything except the
// endpoints that can bind it and logout.
//
// A session in any other state passes untouched, and so does a request
// carrying no session: whether an anonymous request may go on is the
// authentication interceptors' business.
//
// For a recovery-pending session only these pass, each by POST alone, since
// every one of them changes something and a link another site could make the
// caller follow must not:
//
//   - a request under an enrolment prefix, when the enrolment path is on;
//   - the password-change resolve endpoint, when one is registered;
//   - the chain's logout, so the session can always be ended.
//
// Everything else, the saved-code endpoints included, is refused with a
// ChallengeError of kind policy.ChallengeAccountRecovery carrying the session
// and no token: the caller already holds the credential the session was
// reached with, and a gate issues nothing.
//
// The saved-code endpoints are answered here, once a recovery-pending session
// has been refused: a GET or a POST on the codes path, while the core enables
// saved codes, goes to them, and they answer only a full session (see
// recoveryInterceptor.codes). They sit at this slot rather than beside the
// other recovery endpoints because they need the session the authentication
// interceptors resolved, and must never be reached by a session a recovery
// has confined.
func (g *recoveryGate) Intercept(ex *Exchange, next Next) error {
	s := ex.Session
	if s != nil && s.MFA == session.MFARecoveryPending {
		if g.exempt(ex.Request) {
			return next(ex)
		}

		return &ChallengeError{Kind: policy.ChallengeAccountRecovery, Session: s}
	}

	if g.codes != nil && g.codes.answersCodes(ex.Request) {
		return g.codes.codes(ex, next)
	}

	return next(ex)
}

// exempt reports whether r is one of the requests a recovery-pending session
// may make.
func (g *recoveryGate) exempt(r Request) bool {
	if r.Method() != http.MethodPost {
		return false
	}

	for _, prefix := range g.enrolPrefixes {
		if underPrefix(r.Path(), prefix) {
			return true
		}
	}

	path := r.Path()

	return (g.resolvePath != "" && path == g.resolvePath) || (g.logoutPath != "" && path == g.logoutPath)
}

// enableRecoveryGate registers the recovery gate at OrderAccountRecovery.
// EnableAccountRecovery calls it, handing over the interceptor whose
// saved-code endpoints the gate serves; codes is nil only in a test that
// registers the gate alone.
//
// It does not count policy.ChallengeAccountRecovery as enforced. The gate
// raises that kind itself, as a ChallengeError, and acts only on a
// recovery-pending session; a policy raising it on any other session would be
// confined by nothing, so no policy may declare or raise it (see
// refuseGateOnly).
//
// The gate's exemptions are handed over once the chain exists, because the
// enrolment path, the password-change resolve endpoint and logout may each be
// enabled, or moved, by an option applied after this one.
func (c *config) enableRecoveryGate(codes *recoveryInterceptor) {
	g := &recoveryGate{codes: codes}

	c.register(g, OrderAccountRecovery)
	c.wire(func(*Chain) { c.wireRecoveryGate(g) })
}

// wireRecoveryGate hands g the exemptions the chain's other built-ins serve.
func (c *config) wireRecoveryGate(g *recoveryGate) {
	g.logoutPath = c.logoutPath

	_ = eachInterceptor(c, func(i *enrolmentInterceptor) error {
		g.enrolPrefixes = append(g.enrolPrefixes, i.prefixes()...)

		return nil
	})

	_ = eachInterceptor(c, func(p *passwordChangeGate) error {
		if p.change != nil {
			g.resolvePath = p.path
		}

		return nil
	})
}
