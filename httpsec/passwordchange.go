package httpsec

import (
	"net/http"

	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// ChangePasswordFunc changes the caller's own password.
//
// There is no default, because the library ships no user store to change a
// password in and no rules about what a new one must look like. With none
// supplied there is no resolve endpoint at all, and a session that owes a
// change is refused until a new login clears it — see
// WithChangePasswordEndpoint. It is called
// with the exchange, and it owns the response: the library writes nothing on
// this path, so whatever a consumer's clients expect to read is what they
// read. An error it returns is the request's refusal, unchanged.
type ChangePasswordFunc func(ex *Exchange) error

// passwordChangeGate holds every session that owes a password change, and lets
// the consumer's resolve endpoint through so the debt can be paid.
type passwordChangeGate struct {
	sessions *session.Manager

	// path and change are the consumer's resolve endpoint, and are empty when
	// they registered none. Without one, only a new login clears the challenge.
	path   string
	change ChangePasswordFunc
}

// Intercept refuses any session that owes a password change, and lets the
// consumer's resolve endpoint through so the debt can be paid.
//
// A request carrying no session passes: the gate guards sessions, and whether
// an anonymous request may go on is the business of the authentication
// interceptors outside it.
func (g *passwordChangeGate) Intercept(ex *Exchange, next Next) error {
	if g.isResolveRequest(ex.Request) {
		return g.resolve(ex)
	}

	if ex.Session != nil && ex.Session.PasswordChangePending {
		// No token: the caller already holds the credential this session was
		// reached with, and a gate issues nothing.
		return &ChallengeError{Kind: policy.ChallengePasswordChange, Session: ex.Session}
	}

	return next(ex)
}

// isResolveRequest reports whether r is the consumer's resolve endpoint.
//
// Only POST, and only on the exact path: a request that merely reads something
// under that path is not a password change, and letting it through would open
// a hole in the gate the size of one URL.
func (g *passwordChangeGate) isResolveRequest(r Request) bool {
	return g.change != nil && r.Method() == http.MethodPost && r.Path() == g.path
}

// resolve runs the consumer's change, and records the debt as paid only when
// it reports that it was.
func (g *passwordChangeGate) resolve(ex *Exchange) error {
	// The endpoint changes this caller's own password, so there has to be a
	// caller: without a session it would be an unauthenticated password change
	// on an account named by nothing but the request body.
	if ex.Session == nil {
		return ErrAuthenticationRequired
	}

	if err := g.change(ex); err != nil {
		// The consumer's error is the refusal, unchanged: they know why they
		// refused, and restating it here would lose that.
		return err
	}

	ex.Session.PasswordChangePending = false

	// Persisted before the response returns, because the marker is what every
	// later request is judged on: a change that cleared the flag in memory
	// alone would be owed again on the next request.
	return g.sessions.Save(ex.Context(), ex.Session)
}
