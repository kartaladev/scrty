package identity

import (
	"context"
	"time"
)

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
	FieldPasswordChangedAt

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

	PasswordChangedAt time.Time

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
//
// Named alone, it leaves the stored password-changed time as it was. That is
// right for a password mirrored from an identity provider, and wrong for a local
// change: use WithUserPasswordChange there, or the user is never challenged by
// password-age policy.
func WithUserPassword(hash []byte) UserOption {
	return func(u *NewUser) { u.Password = hash; u.mark(FieldPassword) }
}

// WithUserPasswordChangedAt names when the password was last changed.
//
// Unnamed, the stored time is left as it was by Update, and is zero after
// Provision: no password write moves it on its own. Name it on a local password
// change, together with the new hash (WithUserPasswordChange does both), and the
// store records the rotation that password-age policy reads. Leave it unnamed
// when the password is mirrored from an identity provider, so a mirror written
// on every federated login cannot keep a user permanently fresh. Naming the zero
// time clears it.
func WithUserPasswordChangedAt(t time.Time) UserOption {
	return func(u *NewUser) { u.PasswordChangedAt = t; u.mark(FieldPasswordChangedAt) }
}

// WithUserPasswordChange names a local password change: the already-hashed
// password and when it changed, together.
//
// Use it wherever the user changed their own password or an administrator reset
// it, so the change records itself for password-age policy. A password mirrored
// from an identity provider is named with WithUserPassword alone, so it never
// moves the time.
func WithUserPasswordChange(hash []byte, at time.Time) UserOption {
	return func(u *NewUser) {
		WithUserPassword(hash)(u)
		WithUserPasswordChangedAt(at)(u)
	}
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
	// hash is stored exactly as given. The password-changed time is stored only
	// when the caller names it with WithUserPasswordChangedAt (or
	// WithUserPasswordChange), and is zero otherwise, including when a password
	// is named without it. The created user is active. Errors never
	// quote the username, which is an email address on just-in-time provisioning.
	Provision(ctx context.Context, username string, opts ...UserOption) (*Details, error)

	// Update amends an existing user, writing only the fields whose option was
	// applied and leaving every other stored field as it was. An unknown username
	// returns ErrUserNotFound and creates nothing. It returns the complete stored
	// record, not only the amended columns. Concurrent updates of one user are
	// serialized.
	//
	// PasswordChangedAt is a field like any other: it is written only when the
	// caller names it with WithUserPasswordChangedAt, and naming the zero time
	// clears it. A password named without it leaves the stored time as it was, so
	// a password mirrored from an identity provider on every login never moves
	// it, while a local change records itself by naming both:
	//
	//	// a local change records itself; a mirror names only the hash
	//	store.Update(ctx, username, identity.WithUserPasswordChange(hash, now))
	Update(ctx context.Context, username string, opts ...UserOption) (*Details, error)
}

// MFARequirementLookup reports whether a user must use a second factor.
//
// The requirement is recorded with the user rather than with any enrolment, so
// losing an enrolment row cannot silently clear it. Callers fail closed on an
// error rather than reading a failure as "not required".
//
// A reference that names no stored user, including one the implementation
// cannot parse, is answered with ErrUserNotFound, never with "not required":
// the reference comes from an authenticated principal, so an unknown user means
// something changed after the login, and answering false would fail open. A
// stored user with no requirement recorded is not required, with no error. Any
// other failure is an error that is not ErrUserNotFound.
//
// scrty ships no implementation.
type MFARequirementLookup interface {
	Required(ctx context.Context, userID UserID) (bool, error)
}
