package identity

import "errors"

// The errors the identity ports return, which callers identify with errors.Is.
//
// They are sentinels rather than types because callers branch on which one it
// is, never on data carried with it: a provisioner's collision error
// deliberately carries no username.
var (
	// ErrUserNotFound is returned by a user loader for an unknown username, and
	// by a provisioner's Update for a user that does not exist.
	ErrUserNotFound = errors.New("identity: user not found")

	// ErrUserExists is returned by Provision when the username is taken.
	ErrUserExists = errors.New("identity: user already exists")

	// ErrPrivilegesNotFound is returned by a role loader for a role that grants
	// no privileges.
	ErrPrivilegesNotFound = errors.New("identity: role privileges not found")

	// ErrNoPrincipal is the value MustPrincipalFromContext panics with when the
	// context carries no principal. A recovering caller identifies it with
	// errors.Is, so a recover that catches an unrelated panic can re-panic
	// instead of swallowing it.
	ErrNoPrincipal = errors.New("identity: no principal in context")

	// ErrMissingPort identifies the configuration error a component returns when
	// a port it cannot work without was not supplied. Every MissingPortError
	// matches it, so a caller recognises a wiring mistake without naming each
	// port in turn.
	ErrMissingPort = errors.New("identity: required port not configured")
)

// MissingPortError is the configuration error a component returns when a port it
// cannot work without was not supplied.
//
// It names the port, so the consumer learns which one to wire rather than being
// told only that something is missing.
//
// scrty never substitutes an in-memory or empty implementation for an unsupplied
// port. A component that cannot work without one fails at construction, where
// the mistake is cheap to find, rather than at the first request, where it would
// look like a runtime fault.
type MissingPortError struct {
	Port string
}

// MissingPort returns the configuration error for a port that was not supplied.
func MissingPort(port string) error { return &MissingPortError{Port: port} }

func (e *MissingPortError) Error() string {
	return "identity: no " + e.Port + " configured"
}

// Is reports that every MissingPortError matches ErrMissingPort.
func (e *MissingPortError) Is(target error) bool { return target == ErrMissingPort }
