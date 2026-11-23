package admin

import "errors"

// The reasons an administration call fails for, each identifiable with
// errors.Is. A storage failure matches none of them. Error text never contains
// a username, an email, an attribute value or a password hash.
var (
	// ErrConfig is wrapped by every error a constructor in this package
	// returns for a wiring mistake.
	ErrConfig = errors.New("admin: invalid configuration")

	// ErrNotFound reports that no live user, role or assignment has the given
	// identifier or name.
	ErrNotFound = errors.New("admin: not found")

	// ErrAlreadyExists reports a username, email or role name already taken.
	// The concrete error is an AlreadyExistsError naming the field.
	ErrAlreadyExists = errors.New("admin: already exists")

	// ErrStillAssigned reports a role that is assigned to a live user and was
	// deleted without force.
	ErrStillAssigned = errors.New("admin: still assigned")

	// ErrStaleUpdate reports that the stored version differs from the one the
	// caller read. Nothing was written.
	ErrStaleUpdate = errors.New("admin: stale update")

	// ErrUnknownPrivilege reports a grant that names a resource, privilege or
	// scope the catalogue does not list.
	ErrUnknownPrivilege = errors.New("admin: unknown privilege")

	// ErrInvalidInput reports input outside the documented bounds or shape,
	// including a cursor that does not decode.
	ErrInvalidInput = errors.New("admin: invalid input")

	// ErrNoActor reports a write whose context carries neither a principal nor
	// a system actor.
	ErrNoActor = errors.New("admin: no actor")
)

// The fields an AlreadyExistsError names.
const (
	// FieldUsername is a username another user holds, deleted or not, or one
	// equal to another live user's email.
	FieldUsername = "username"
	// FieldEmail is an email another live user holds, or one equal to another
	// user's username.
	FieldEmail = "email"
	// FieldRole is a role name another role holds.
	FieldRole = "role"
	// FieldID is a user identifier an import names that belongs to a
	// soft-deleted user: a deleted user is never undeleted, so its identifier
	// cannot be imported again.
	FieldID = "id"
)

// AlreadyExistsError is the concrete error behind ErrAlreadyExists. It names
// the field that collided and never the value.
type AlreadyExistsError struct {
	// Field is FieldUsername, FieldEmail, FieldRole or FieldID.
	Field string
}

// Error returns fixed text naming the field only.
func (e AlreadyExistsError) Error() string { return "admin: already exists: " + e.Field }

// Is reports whether target is ErrAlreadyExists.
func (e AlreadyExistsError) Is(target error) bool { return target == ErrAlreadyExists }
