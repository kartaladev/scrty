package identity

import "context"

// Field names a user field an option can set.
//
// A provisioner writes exactly the fields whose option was applied, which
// NewUser.IsSet reports, so a field the caller never named is left as the store
// holds it rather than being overwritten with a zero value.
type Field uint8

// The user fields options can set.
const (
	FieldName Field = iota
	FieldEmail
	FieldRoles
	FieldOrganization
	FieldPassword

	fieldCount // not a field; keeps the set array in step with the list above
)

// NewUser carries the fields a Provision or Update call named, and which of them
// were named at all.
//
// Implementations decide what to write from IsSet, never from a value being
// empty: naming a field with an empty value is a request to clear it, while not
// naming it at all is a request to leave it alone, and the two are different.
type NewUser struct {
	Name         string
	Email        string
	Roles        []string
	Organization *Organization
	Password     []byte

	set [fieldCount]bool
}

// IsSet reports whether the caller named f.
func (u *NewUser) IsSet(f Field) bool {
	if f >= fieldCount {
		return false
	}

	return u.set[f]
}

func (u *NewUser) mark(f Field) {
	if f < fieldCount {
		u.set[f] = true
	}
}

// UserOption names one field of a Provision or Update call.
type UserOption func(*NewUser)

// WithUserName names the display name. Unnamed, it is left unchanged by Update
// and empty by Provision.
func WithUserName(name string) UserOption {
	return func(u *NewUser) { u.Name = name; u.mark(FieldName) }
}

// WithUserEmail names the email address.
//
// The email is passed through to the store and is never used to look up or match
// a user: matching on it would let a caller take over an existing account by
// claiming its address.
func WithUserEmail(email string) UserOption {
	return func(u *NewUser) { u.Email = email; u.mark(FieldEmail) }
}

// WithUserRoles names the role names, the first of which is the primary role.
//
// Naming no roles at all still counts as naming the field, which is what lets
// Update tell "leave the grants alone" apart from "these are the grants now".
func WithUserRoles(roles ...string) UserOption {
	return func(u *NewUser) { u.Roles = roles; u.mark(FieldRoles) }
}

// WithUserOrganization names the organization. A nil organization names the
// field, clearing it.
func WithUserOrganization(org *Organization) UserOption {
	return func(u *NewUser) { u.Organization = org; u.mark(FieldOrganization) }
}

// WithUserPassword names the already-hashed password.
//
// The hash is stored exactly as given and is never hashed again: this package
// does no hashing, and a store that re-hashed here would make every stored
// credential unverifiable.
func WithUserPassword(hash []byte) UserOption {
	return func(u *NewUser) { u.Password = hash; u.mark(FieldPassword) }
}

// ApplyUserOptions collects opts into a NewUser.
//
// Implementations of UserProvisioner call it to learn which fields the caller
// named. A nil option is skipped, so a caller building an option slice
// conditionally need not filter it first.
func ApplyUserOptions(opts ...UserOption) *NewUser {
	u := &NewUser{}

	for _, opt := range opts {
		if opt != nil {
			opt(u)
		}
	}

	return u
}

// UserLoader loads users from the consumer's own store.
//
// scrty ships no implementation: a component that needs a UserLoader and is
// given none fails at construction rather than falling back to an empty store.
type UserLoader interface {
	// LoadByUsername loads the user with this username, passed exactly as
	// presented and never trimmed or case-folded. A miss returns ErrUserNotFound;
	// any other failure returns an error that is not ErrUserNotFound, so a caller
	// can tell "no such user" from "the store is down".
	LoadByUsername(ctx context.Context, username string) (*Details, error)

	// LoadByUserID loads the user with this reference, matched byte-for-byte and
	// never parsed, trimmed or case-folded. The same miss-versus-outage contract
	// applies: a miss returns ErrUserNotFound, and any other failure returns an
	// error that is not.
	//
	// A flow that recorded a reference and later resolves it — redeeming a
	// sign-in link, for one — must load by that reference rather than by the
	// username it was requested with. A username is a reusable handle: reissued
	// to another person, it would let a credential minted for the first
	// authenticate the second.
	LoadByUserID(ctx context.Context, id UserID) (*Details, error)
}

// RoleLoader resolves a role name to the privileges it grants.
//
// scrty ships no implementation.
type RoleLoader interface {
	// LoadPrivileges returns the resource privileges effective for role. A role
	// that grants none returns ErrPrivilegesNotFound.
	LoadPrivileges(ctx context.Context, role string) ([]*ResourcePrivileges, error)
}

// UserProvisioner creates and amends users in the consumer's own store.
//
// Provision and Update are separate verbs rather than one upsert, because an
// upsert would let a caller overwrite an existing account on its first call —
// the same takeover path as matching identities by email.
//
// scrty ships no implementation.
type UserProvisioner interface {
	// Provision creates a user from a required username. A taken username returns
	// ErrUserExists and leaves the existing user untouched, and the collision is
	// decided by the write itself rather than by a preceding read, so concurrent
	// calls for one username create exactly one user. The first role name is
	// primary and each occurrence of a name creates its own grant. The password
	// hash is stored exactly as given. The created user is active. Errors never
	// quote the username, which is an email address on just-in-time provisioning.
	Provision(ctx context.Context, username string, opts ...UserOption) (*Details, error)

	// Update amends an existing user, writing only the fields whose option was
	// applied and leaving every other stored field as it was. An unknown username
	// returns ErrUserNotFound and creates nothing. It returns the complete stored
	// record, not only the amended columns, and never changes PasswordChangedAt,
	// including when the password is written. Concurrent updates of one user are
	// serialized.
	Update(ctx context.Context, username string, opts ...UserOption) (*Details, error)
}

// MFARequirementLookup reports whether a user must use a second factor.
//
// The requirement is recorded with the user rather than with any enrolment, so
// losing an enrolment row cannot silently clear it. Callers fail closed on an
// error rather than reading a failure as "not required".
//
// scrty ships no implementation.
type MFARequirementLookup interface {
	Required(ctx context.Context, userID UserID) (bool, error)
}
