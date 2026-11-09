package session

import (
	"encoding/base64"
	"fmt"
	"io"
)

// KeyBinding binds a sign-in to a key its holder proves possession of:
// either a DPoP key thumbprint or a client certificate thumbprint, never both.
// The zero value is an unbound session.
//
// A session's binding is fixed when the sign-in is built (WithKeyBinding)
// and every successor in its family keeps it: rotation, renewal and
// re-authentication carry it from the stored record, Save never changes it,
// and Prepared.Commit refuses a built session whose binding was changed. The
// one exception is a re-authentication, which may bind a session that is
// unbound (WithReauthenticationBinding), and never rebinds or unbinds one.
type KeyBinding struct {
	// JKT is the SHA-256 JWK thumbprint of the DPoP key (RFC 9449, the
	// cnf "jkt" member), base64url-encoded without padding.
	JKT string

	// X5TS256 is the SHA-256 thumbprint of the client certificate (RFC 8705,
	// the cnf "x5t#S256" member), base64url-encoded without padding.
	X5TS256 string
}

// IsZero reports whether b binds nothing.
func (b KeyBinding) IsZero() bool { return b == KeyBinding{} }

// both reports whether b names both a DPoP key and a certificate, which no
// binding may.
func (b KeyBinding) both() bool { return b.JKT != "" && b.X5TS256 != "" }

// WithKeyBinding binds the session being created to binding, in the one write that
// creates it, so a credential issued for the built session (Prepare,
// CreateIssuing) carries the same binding. The default, with no option, is an
// unbound session.
//
// A binding naming both a DPoP key and a certificate is refused by Prepare, Create
// and CreateIssuing with ErrConfig, and nothing is stored. The zero binding binds
// nothing.
func WithKeyBinding(binding KeyBinding) CreateOption {
	return func(s *Session) { s.KeyBinding = binding }
}

// WithReauthenticationBinding binds the successor of a re-authentication,
// a strict rotation (Sessions.Rotate, Sessions.RotateIssuing) after the user
// proved a factor again, to binding. The default, with no option, carries the
// stored session's binding over unchanged, bound or not.
//
// A re-authentication may bind an unbound session, because it is a fresh
// proof of the user's factor. It never changes or removes an existing
// binding: a binding naming another key than the stored session's is refused with
// ErrConfig, and a binding equal to it keeps the session as it is. The zero binding binds
// nothing. A binding naming both a DPoP key and a certificate is refused with
// ErrConfig. Every refusal is made before the issuing step runs, and nothing
// is stored.
//
// A renewal never binds (Sessions.RotateWithGrace refuses this option with
// ErrConfig): otherwise whoever holds an unbound session could renew it under
// their own key and lock its owner out.
func WithReauthenticationBinding(binding KeyBinding) RotateOption {
	return func(r *rotation) {
		r.binding = binding
		r.bindingSet = true
	}
}

// csrfTokenBytes is how much entropy a CSRF token carries.
const csrfTokenBytes = 32

// WithCSRFToken gives the session being created a CSRF token: 32 bytes from
// the manager's random source (crypto/rand by default, see WithRandom),
// encoded URL-safe without padding, set on the built session so a page served
// with it can read it before the session is stored. Every successor in the
// family carries it, so it survives every renewal and re-authentication, and
// a new sign-in gets a new one. The default, with no option, is a session
// with no token.
//
// A random source that fails is an error from Prepare, Create and
// CreateIssuing, and nothing is stored: a token drawn from anything weaker
// would look exactly like a good one.
func WithCSRFToken() CreateOption {
	return func(s *Session) { s.csrfRequested = true }
}

// newCSRFToken reads csrfTokenBytes from the manager's random source and
// encodes them URL-safe without padding.
func (m *Sessions) newCSRFToken() (string, error) {
	raw := make([]byte, csrfTokenBytes)
	if _, err := io.ReadFull(m.random, raw); err != nil {
		return "", fmt.Errorf("session: reading %d random bytes for a CSRF token: %w", csrfTokenBytes, err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// checkReauthenticationBinding applies r's binding, if any, to rotated, the
// successor of stored, which already carries stored's binding: an unbound
// session takes it, and a bound one keeps its own, or is refused when r names
// another key.
func checkReauthenticationBinding(r rotation, stored, rotated *Session) error {
	if !r.bindingSet || r.binding.IsZero() {
		return nil
	}
	if stored.KeyBinding.IsZero() {
		rotated.KeyBinding = r.binding

		return nil
	}
	if stored.KeyBinding != r.binding {
		return fmt.Errorf("%w: a re-authentication cannot rebind a bound session", ErrConfig)
	}

	return nil
}
