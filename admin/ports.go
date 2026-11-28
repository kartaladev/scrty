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
	// It refuses, as an AlreadyExistsError naming the field: a username any
	// user has, deleted or not, compared exactly, byte for byte
	// (FieldUsername); an email a live user has, ignoring case (FieldEmail);
	// a username equal to a live user's email, ignoring case (FieldUsername);
	// and an email equal to a live user's username, ignoring case
	// (FieldEmail). A deleted user's username stays taken, but no longer
	// blocks an email. The refusal is decided by the write, so concurrent
	// creations produce one user. An Organization.ID the store cannot
	// represent is ErrInvalidInput.
	CreateUser(ctx context.Context, user NewUser) (User, error)

	// UpdateUser applies the named fields and increases the version. It never
	// receives a username: Users.Update sends a change naming one to
	// UsernameUpdater.UpdateUserRenaming instead.
	//
	// The verification time follows these rules, each decided under the row
	// lock the version comparison takes, never from an earlier read:
	//   - change.EmailVerifiedAt non-nil is stored as given; the zero time
	//     clears the stored verification time.
	//   - change.Email named and change.EmailVerifiedAt nil: the store keeps
	//     the stored verification time when the named email equals the stored
	//     one ignoring case (the comparison of the email uniqueness rule,
	//     PostgreSQL's lower() in scrty's stores), and clears it otherwise, so
	//     a new or cleared address never inherits the old one's verification.
	//     The email is stored as named, so a change of case only is written.
	//   - A non-zero change.EmailVerifiedAt with no email left to verify (the
	//     stored email is empty and the change names none) is ErrInvalidInput
	//     and changes nothing.
	//
	// An email
	// that another live user has, or that equals another live user's
	// username, ignoring case, is an AlreadyExistsError with FieldEmail,
	// decided by the write. An Organization.ID the store cannot represent is ErrInvalidInput.
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

//go:generate mockgen -destination=usernameupdater_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/admin UsernameUpdater

// UsernameUpdater is the optional store capability that lets Users.Update
// change a username. NewUsers checks once whether the UserStore implements it.
// Update sends a change naming a username (UserChange.Username) to
// UpdateUserRenaming, and every other change to UserStore.UpdateUser, which
// therefore never receives a username: a store written before usernames could
// change needs no change, and cannot silently ignore one. Over a store without
// this method, an update naming a username is refused with an error matching
// ErrConfig before the store is called; callers on such a store leave Username
// nil unless it changed, since even re-sending the current username is refused.
//
// Every user store scrty ships implements it.
//
// A consumer store that embeds a scrty store and overrides UpdateUser, for
// example to add its own checks, inherits UpdateUserRenaming unchanged, so
// renames bypass that override. Override UpdateUserRenaming too.
//
// Default: none; a store opts in by implementing the method.
type UsernameUpdater interface {
	// UpdateUserRenaming applies change, which names a username, as
	// UserStore.UpdateUser applies the other fields, in one write under the
	// same version check, and also writes the username under the rules of
	// UserStore.CreateUser: a username another user holds, deleted or not,
	// compared exactly, or equal to another live user's email ignoring case,
	// is an AlreadyExistsError with FieldUsername. The user's own username and
	// email never clash. Either everything the change names is written, or
	// nothing is.
	//
	// renamed reports whether the stored username differed from the named one,
	// byte for byte, decided under the row lock; a change of case only is a
	// rename. Re-sending the current username is still a write (the version
	// increases) with renamed false. Users.Update revokes sessions
	// (WithSessionRevocation) only when renamed is true.
	UpdateUserRenaming(ctx context.Context, id identity.UserID, version int64, change UserChange) (updated User, renamed bool, err error)
}

//go:generate mockgen -destination=userpager_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/admin UserPager

// UserPager is the optional store capability behind offset listing
// (UserFilter.Offset) and Users.Count. NewUsers checks once whether the
// UserStore implements it. Over a store without it, a list that names a
// non-zero offset, and a count, are refused with an error matching ErrConfig
// before the store is called; cursor listing and offset zero need nothing
// more than UserStore.ListUsers. WithMaxListOffset over such a store fails
// NewUsers.
//
// Every user store scrty ships implements it.
//
// A consumer store that embeds a scrty store and overrides ListUsers, for
// example to hide users from a tenant, inherits ListUsersFrom and CountUsers
// unchanged, so offset pages and counts bypass that override. Override
// ListUsersFrom and CountUsers too.
//
// Default: none; a store opts in by implementing the methods.
type UserPager interface {
	// ListUsersFrom lists the users matching query's filters in the order of
	// UserStore.ListUsers, skipping the first offset of them. query.Limit is
	// the page size; query's After fields are empty, since an offset and a
	// cursor are alternatives. offset is at least one and at most the
	// service's maximum. The service truncates a longer result to the limit.
	ListUsersFrom(ctx context.Context, query UserQuery, offset int) ([]User, error)

	// CountUsers returns how many live users match query's Search, Active,
	// Role and Attribute. It ignores Limit and the After fields, which are
	// empty. A negative count is refused by the service. The count is a read
	// of its own: it is not taken in the same snapshot as a page.
	CountUsers(ctx context.Context, query UserQuery) (int64, error)
}

//go:generate mockgen -destination=sessionrevoker_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/admin SessionRevoker

// SessionRevoker ends every session of a user. WithSessionRevocation gives
// one to Users, which calls it after a committed rename. *session.Sessions
// satisfies it as it is, so this package needs no import of session and no
// adapter.
//
// Default: none; Users revokes no session unless WithSessionRevocation gives
// a revoker.
type SessionRevoker interface {
	// DeleteByUser removes every session of the user. It runs on the context
	// Users.Update was called with.
	DeleteByUser(ctx context.Context, user identity.UserID) error
}

//go:generate mockgen -destination=importstore_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/admin ImportStore
//go:generate mockgen -destination=rolestore_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/admin RoleStore
//go:generate mockgen -destination=grantstore_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/admin GrantStore
//go:generate mockgen -destination=assignmentstore_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/admin AssignmentStore
//go:generate mockgen -destination=recognizer_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/authenticate/password Recognizer

// ImportStore is the storage the import service writes through.
//
// The service does not interpret the identifier: its form is the store's to
// judge. A store that cannot represent one (scrty's stores require a canonical
// lower-case UUID) answers ErrInvalidInput. Error text never carries a value: a
// store does not pass on a driver's detail, such as a unique violation's DETAIL
// line, which quotes the conflicting username or email.
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
	// a different identifier, compared as UserStore.CreateUser compares them,
	// fails with an error matching ErrAlreadyExists
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
	AddAssignment(ctx context.Context, id identity.UserID, version int64, assignment Assignment) (int64, error)

	// RemoveAssignment removes the grant with the identifier and returns the
	// user's new version. When it was primary, another remaining grant
	// becomes primary. An unknown grant is ErrNotFound.
	RemoveAssignment(ctx context.Context, id identity.UserID, version int64, grantID string) (int64, error)

	// SetPrimary marks the grant primary, and every other grant of the user
	// not primary, and returns the user's new version. An unknown grant is
	// ErrNotFound.
	SetPrimary(ctx context.Context, id identity.UserID, version int64, grantID string) (int64, error)
}
