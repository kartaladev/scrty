package admin

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/identity"
)

//go:generate mockgen -destination=userstore_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/admin UserStore

// UserStore is the storage the user administration service writes through.
//
// Every method that takes a version changes nothing and returns ErrStaleUpdate
// when the stored version differs, and ErrNotFound when no live user has the
// identifier. A store signals a taken username or email with an error matching
// ErrAlreadyExists (see AlreadyExistsError). The service validates input
// before calling; a store need not repeat those checks. Every write that
// changes something increases the version: UpdateUser, SetActive when it
// changes the flag, SetPassword and DeleteUser.
//
// A user identifier argument the store cannot represent (scrty's stores hold
// them as UUIDs) names no user: the store answers ErrNotFound, never a storage
// error. A cursor's AfterID or an Organization.ID it cannot represent is
// ErrInvalidInput instead (see ListUsers). Error text never carries a value: a store does not pass on a
// driver's detail, such as a unique violation's DETAIL line, which quotes the
// conflicting username or email.
type UserStore interface {
	// ListUsers returns up to query.Limit live users ordered by
	// (lower(username), id). When query.AfterUsername is not empty it returns
	// only users strictly after the pair (lower(AfterUsername), AfterID) in that
	// order. AfterUsername is the username as stored: the store lower-cases both
	// sides in its own query, so the order and the comparison agree.
	//
	// query.Search matches username, display name and email as a substring,
	// ignoring case, and is literal: a store that searches with LIKE escapes
	// its %, _ and \ characters. query.AfterID and an Organization.ID come
	// from caller input the service only bounds: a store that cannot represent
	// such a value (scrty's stores hold identifiers as UUIDs) answers an error
	// matching ErrInvalidInput, never a storage error.
	ListUsers(ctx context.Context, query UserQuery) ([]User, error)

	// GetUser returns the live user with the identifier.
	GetUser(ctx context.Context, id identity.UserID) (User, error)

	// CreateUser stores the user under the identifier the service set.
	//
	// It refuses, ignoring case and as an AlreadyExistsError naming the field:
	// a username any user has, deleted or not (FieldUsername); an email a live
	// user has (FieldEmail); a username equal to another live user's email
	// (FieldUsername); and an email equal to another user's username
	// (FieldEmail). The refusal is decided by the write, so concurrent
	// creations produce one user. An Organization.ID the store cannot
	// represent is ErrInvalidInput.
	CreateUser(ctx context.Context, user NewUser) (User, error)

	// UpdateUser applies the named fields and increases the version. A
	// non-nil change.EmailVerifiedAt holding the zero time clears the stored
	// verification time; the service sends it whenever the email changes
	// without a verification time, and a store must apply it. An email
	// that another live user has, or that equals another user's username,
	// ignoring case, is an AlreadyExistsError with FieldEmail, decided by the
	// write. An Organization.ID the store cannot represent is ErrInvalidInput.
	UpdateUser(ctx context.Context, id identity.UserID, version int64, change UserChange) (User, error)

	// SetActive sets the active flag and increases the version. The bool
	// reports whether anything changed; a flag already at the requested value
	// writes nothing and leaves the version alone.
	SetActive(ctx context.Context, id identity.UserID, version int64, active bool) (User, bool, error)

	// DeleteUser soft-deletes the user: it keeps the record and username,
	// clears the active flag and the email, removes the attributes and the
	// password history, and increases the version.
	DeleteUser(ctx context.Context, id identity.UserID, version int64) error

	// CurrentPasswordHash returns the user's stored password hash, empty when
	// the user has none, and ErrNotFound when no live user has the identifier.
	// The service feeds it to the password policy's reuse rule only. It is
	// credential material: never log it or put it in an error.
	CurrentPasswordHash(ctx context.Context, id identity.UserID) ([]byte, error)

	// SetPassword stores hash as the user's password, sets the
	// password-changed time to at and increases the version, in one write. It records no password
	// history: the password policy's reuse rule retires the replaced hash
	// through its own history port before this is called.
	SetPassword(ctx context.Context, id identity.UserID, version int64, hash []byte, at time.Time) (User, error)
}

//go:generate mockgen -destination=importstore_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/admin ImportStore
//go:generate mockgen -destination=rolestore_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/admin RoleStore
//go:generate mockgen -destination=grantstore_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/admin GrantStore
//go:generate mockgen -destination=assignmentstore_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/admin AssignmentStore
//go:generate mockgen -destination=recognizer_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/authenticate/password Recognizer

// ImportStore is the storage the import service writes through.
//
// The service refuses an identifier that is not a canonical UUID before the
// store is called. Error text never carries a value: a store does not pass on
// a driver's detail, such as a unique violation's DETAIL line, which quotes
// the conflicting username or email.
type ImportStore interface {
	// ImportUser creates the user under user.ID when no user has it, or
	// updates it when one does, in one transaction that locks the row, and
	// writes only when a given value differs from the stored one. It reports
	// which of the three happened. It stores PasswordHash as given, and
	// CreatedAt and UpdatedAt as given when they are not zero. A zero time
	// means "not given": on creation the store fills it with the current
	// time; on an existing user it neither compares nor writes it, so a
	// payload without times imported twice reports ImportUnchanged.
	//
	// Every other field is a value, its zero value included: an empty name
	// or email, no attributes and no roles are written as such, and a zero
	// EmailVerifiedAt clears the stored verification time, so an address
	// never stays verified on an import that does not say it is. An update
	// that writes increases the version.
	//
	// It matches by identifier only: a username, or an email, that belongs to
	// a different identifier fails with an error matching ErrAlreadyExists
	// (see AlreadyExistsError) and writes nothing, so an import never takes
	// over another account. An identifier that belongs to a soft-deleted
	// user fails the same way with AlreadyExistsError.Field FieldID, since a
	// deleted user is never undeleted. Two concurrent imports of one new
	// identifier create one user. A role the store does not hold is
	// ErrNotFound.
	ImportUser(ctx context.Context, user ImportedUser) (ImportOutcome, error)
}

// RoleStore is the storage the role administration service writes through.
//
// Every method that takes a version changes nothing and returns
// ErrStaleUpdate when the stored version differs, and ErrNotFound when no role
// has the name. Role names are matched exactly: the service refuses a name
// with surrounding white space, and a store neither trims nor folds case.
// Error text never carries a value.
type RoleStore interface {
	// ListRoles returns every role ordered by name, each with the number of
	// live users assigned to it; only roles carrying label when label is not
	// empty.
	ListRoles(ctx context.Context, label string) ([]Role, error)

	// GetRole returns the role with the name.
	GetRole(ctx context.Context, name string) (Role, error)

	// CreateRole stores the role at version one. A taken name is an error
	// matching ErrAlreadyExists, with AlreadyExistsError.Field FieldRole.
	CreateRole(ctx context.Context, role Role) (Role, error)

	// UpdateRole applies the named fields and increases the version. The name
	// never changes.
	UpdateRole(ctx context.Context, name string, version int64, change RoleChange) (Role, error)

	// DeleteRole removes the role. Without force, a role assigned to a live
	// user is ErrStillAssigned and nothing changes. With force, the role, its
	// grants and its assignments are removed in one transaction, and a user
	// whose primary grant was removed gets another remaining grant as primary.
	DeleteRole(ctx context.Context, name string, version int64, force bool) error
}

// GrantStore is the storage the grant administration service writes through.
// A role's grants share the role's version, and every replacement increases
// it. Group, resource and privilege names arrive as the catalogue declares
// them (an unlisted resource being cleared arrives trimmed). Role names are
// matched exactly. Error text never carries a value.
type GrantStore interface {
	// GetGrants returns every grant of the role and the role's version. An
	// unknown role is ErrNotFound.
	GetGrants(ctx context.Context, role string) ([]Grant, int64, error)

	// ReplaceGrants replaces exactly the named resources' grants of the role,
	// in one transaction, leaving every other resource unchanged, and returns
	// the role's new version. It matches the existing rows of a resource by
	// group and resource as the authorizer reads them, surrounding white space
	// trimmed and ASCII case ignored, so clearing a resource the catalogue no
	// longer lists removes every row the authorizer would still load. The rows
	// it inserts carry the names as given. A version that differs from the stored one is
	// ErrStaleUpdate and changes nothing; concurrent replacements for one role
	// are applied one after another.
	ReplaceGrants(ctx context.Context, role string, version int64, resources []ResourceGrants) (int64, error)
}

// AssignmentStore is the storage the assignment service writes through. A
// user's role grants share the user's version.
//
// Every method that takes a version changes nothing and returns
// ErrStaleUpdate when the stored version differs, and ErrNotFound when no live
// user has the identifier. Writes to one user's grants are applied one after
// another, and each increases the user's version. A user or grant
// identifier the store cannot represent (scrty's stores hold them as UUIDs)
// is ErrNotFound, never a storage error. Role names are matched exactly.
// Error text never carries a value.
type AssignmentStore interface {
	// ListAssignments returns the user's role grants and the user's version.
	ListAssignments(ctx context.Context, id identity.UserID) ([]*identity.AssignedRole, int64, error)

	// AddAssignment grants the role and returns the user's new version. A
	// role the store does not hold is ErrNotFound. A primary assignment
	// replaces the user's previous primary grant.
	AddAssignment(ctx context.Context, id identity.UserID, version int64, a Assignment) (int64, error)

	// RemoveAssignment removes the grant with the identifier and returns the
	// user's new version. When it was primary, another remaining grant
	// becomes primary. An unknown grant is ErrNotFound.
	RemoveAssignment(ctx context.Context, id identity.UserID, version int64, grantID string) (int64, error)

	// SetPrimary marks the grant primary, and every other grant of the user
	// not primary, and returns the user's new version. An unknown grant is
	// ErrNotFound.
	SetPrimary(ctx context.Context, id identity.UserID, version int64, grantID string) (int64, error)
}
