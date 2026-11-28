package admin

import (
	"time"

	"github.com/kartaladev/scrty/identity"
)

// User is a user as an administrator sees it. It has no password field: a
// password hash never leaves the store through this package.
type User struct {
	ID       identity.UserID
	Username string
	// Name is the display name.
	Name  string
	Email string
	// EmailVerifiedAt is zero when the email is unverified or absent.
	EmailVerifiedAt time.Time
	Active          bool
	// Attributes are the application's own profile attributes, stored and
	// returned unchanged.
	Attributes map[string]string
	// Roles are every role grant of the user, with dates and the primary mark.
	Roles        []*identity.AssignedRole
	Organization *identity.Organization
	// Version increases on every administrative write to the user. An update
	// names the version the caller read.
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewUser is the input of Users.Create. A user is created active, with no
// password and no roles; SetPassword and the assignment service add those.
type NewUser struct {
	// ID is set by the service from its generator; a value the caller sets
	// is replaced.
	ID       identity.UserID
	Username string
	Name     string
	// Email is optional. An empty email stores none.
	Email           string
	EmailVerifiedAt time.Time
	Attributes      map[string]string
	Organization    *identity.Organization
}

// AttributeMatch selects users by an exact attribute name and value.
type AttributeMatch struct {
	Name, Value string
}

// UserFilter is what List accepts.
type UserFilter struct {
	// Search matches username, display name and email, ignoring case. Its
	// wildcard characters are taken literally.
	Search string
	// Active, when set, keeps only users with that flag.
	Active *bool
	// Role, when set, keeps only users holding a grant of that role.
	Role string
	// Attribute, when set, keeps only users with that exact attribute.
	Attribute *AttributeMatch
	// PageSize is the number of users to return; zero means the default.
	PageSize int
	// Cursor continues a list from the Next of the previous page.
	Cursor string
	// Offset is the number of users to skip before the page; zero, the
	// default, is the first page. It is the alternative to Cursor, and naming
	// both is ErrInvalidInput, as is a negative offset or one above the
	// service's maximum (DefaultMaxListOffset, WithMaxListOffset). A non-zero
	// offset needs a store that implements UserPager; over one that does not,
	// List fails with an error matching ErrConfig.
	//
	// Offset paging lets a caller jump to page n, at a cost: the store reads
	// and discards the skipped users, and users created or deleted between two
	// requests make a later page skip or repeat a user. A Cursor continues
	// after the last user seen and is the consistent way to walk a whole list;
	// use Offset for a page picker, not for an export.
	Offset int
}

// UserPage is one page of a list.
type UserPage struct {
	Users []User
	// Next continues the list by cursor. It is empty when the page was not
	// full, and always for a page listed from a non-zero offset, which has no
	// cursor to continue: a caller that wants the next offset page adds the
	// page size to the offset. A page from offset zero is the first page of the
	// default listing and carries Next as usual.
	// It is opaque, not signed: a caller that edits one only moves where a list starts, in a list
	// it may already read in full, so it grants nothing and is not an access token.
	Next string
}

// UserChange names the fields an update changes; a nil field is unchanged.
type UserChange struct {
	// Username renames the user when non-nil. Nil, the default, leaves it
	// unchanged. It is validated as NewUser.Username is (not blank, no leading
	// or trailing white space, valid UTF-8 without control characters, at most
	// MaxTextBytes), and the store refuses one another user holds as
	// UserStore.CreateUser does. A change naming only a username is a change.
	//
	// Only a store implementing UsernameUpdater can rename: Update sends a
	// change naming a username there, and refuses it with an error matching
	// ErrConfig, before any store call, over a store that does not.
	// UserStore.UpdateUser never receives a username. On such a store, leave
	// Username nil unless it changed.
	//
	// What a rename leaves behind:
	//   - Sessions are keyed by the user identifier and survive a rename,
	//     unless WithSessionRevocation is given.
	//   - Lockout state (failure counts and holds) is keyed by the username
	//     and stays under the old one. The renamed account starts clean. The
	//     next holder of the old username inherits what it carries: counts
	//     age out of their window, but a hold never expires. An administrator
	//     who renames a user should call the lockout policy's Reset with the
	//     old username to release it.
	//   - The standalone JWTAuthenticator in username-subject mode keeps
	//     accepting tokens naming the old username until they expire, and once
	//     another user takes that username they name that user. Consumers of
	//     that mode keep token lifetimes short or do not reuse released
	//     usernames.
	Username *string
	Name     *string
	Email    *string
	// EmailVerifiedAt is set when non-nil; a pointer to the zero time clears it.
	// When Email is named and EmailVerifiedAt is nil, the store keeps the
	// stored verification time if Email equals the stored email ignoring case,
	// and clears it otherwise, so a new or cleared email is never verified by
	// the old address's verification (see UserStore.UpdateUser). A non-zero
	// time with no email to verify is ErrInvalidInput.
	EmailVerifiedAt *time.Time
	// Attributes replaces the whole set when non-nil; an empty non-nil map
	// removes every attribute.
	Attributes map[string]string
	// Organization is set when non-nil; a pointer to a nil organization
	// removes it.
	Organization **identity.Organization
}

// UserQuery is a UserFilter the service has validated: the page size is the
// bounded Limit and the cursor is decoded into the last pair of the previous
// page. A store lists users ordered by (lower(username), id), strictly after
// (AfterUsername, AfterID) when AfterUsername is not empty. UserPager's
// CountUsers receives a query holding the filters only: Limit and the After
// fields are zero, and a store ignores them.
type UserQuery struct {
	// Search is literal text matched as a substring of the username, the
	// display name and the email, ignoring case; a store escapes its own
	// wildcard characters (%, _ and \ for LIKE).
	Search    string
	Active    *bool
	Role      string
	Attribute *AttributeMatch
	// AfterUsername is the username of the last user of the previous page as
	// stored, not case-folded, and AfterID its identifier; both are empty on
	// the first page. They come from a cursor the caller may have changed: a
	// store that cannot represent AfterID answers ErrInvalidInput, not a
	// storage error.
	AfterUsername string
	AfterID       identity.UserID
	// Limit is between 1 and the service's maximum page size.
	Limit int
}

// ImportedUser is the input of Importer.Import: a user's values as another
// system holds them, written as given.
type ImportedUser struct {
	// ID is the user's identifier, a canonical lower-case UUID.
	ID       identity.UserID
	Username string
	Name     string
	Email    string
	// EmailVerifiedAt is written as given: a zero value clears the stored
	// verification time. Unlike CreatedAt and UpdatedAt, zero is a value, not
	// "not given", so an import never leaves an address verified that the
	// source does not say is.
	EmailVerifiedAt time.Time
	// PasswordHash is stored unchanged. It must be one the importer's
	// recogniser recognises; empty means the user has no password.
	PasswordHash []byte
	Active       bool
	// CreatedAt is the user's creation time. Zero means not given: the store
	// sets the time of the import when it creates the user, and neither
	// compares nor writes it for an existing user.
	CreatedAt time.Time
	// UpdatedAt is the last update time, not before CreatedAt when both are
	// given. Zero means not given, as for CreatedAt.
	UpdatedAt time.Time
	// Roles are the names of the roles the user holds.
	Roles      []string
	Attributes map[string]string
}

// ImportOutcome is what an import did.
type ImportOutcome uint8

// The outcomes of an import. The zero value is none of them.
const (
	// ImportCreated is a user created under the given identifier.
	ImportCreated ImportOutcome = iota + 1
	// ImportUpdated is an existing user whose values differed and were written.
	ImportUpdated
	// ImportUnchanged is an existing user whose values were all equal;
	// nothing was written.
	ImportUnchanged
)

// String returns the outcome's name.
func (o ImportOutcome) String() string {
	switch o {
	case ImportCreated:
		return "created"
	case ImportUpdated:
		return "updated"
	case ImportUnchanged:
		return "unchanged"
	default:
		return "unknown"
	}
}

// Role is a role as an administrator sees it. Its Name is the immutable key of
// its grants and assignments; DisplayName is what a "rename" changes.
type Role struct {
	Name        string
	DisplayName string
	Description string
	Labels      []string
	SuperRole   bool
	// Version increases on every write to the role and its grants.
	Version int64
	// Assigned is the number of live users holding the role; the store fills
	// it and Create ignores it.
	Assigned int
}

// RoleChange names the fields a role update changes; a nil field is unchanged.
// The name cannot change.
type RoleChange struct {
	DisplayName *string
	Description *string
	// Labels replaces the whole set when non-nil; a pointer to an empty slice
	// removes every label.
	Labels    *[]string
	SuperRole *bool
}

// Grant is one privilege a role holds on a resource.
type Grant struct {
	Group     string
	Resource  string
	Privilege string
	// Granted is false for a privilege the role explicitly does not hold.
	Granted bool
	// Scope is how far the privilege reaches; empty reads as identity.ScopeAll.
	Scope identity.Scope
}

// ResourceGrants is the complete privilege list of one resource, which
// Grants.Replace writes in place of the resource's current grants.
type ResourceGrants struct {
	Group    string
	Resource string
	// Grants is every grant the resource keeps; an empty list removes them
	// all. A grant's Group and Resource may be left empty, and then are the
	// ResourceGrants' own.
	Grants []Grant
}

// Assignment is a role grant to add to a user.
type Assignment struct {
	// Role is the role's name.
	Role string
	// Primary makes the grant the user's primary one.
	Primary bool
	// Start and End bound the grant; a zero time is unbounded. End must be
	// after Start when both are set.
	Start, End time.Time
}
