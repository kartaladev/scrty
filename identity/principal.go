// Package identity defines who a caller is inside scrty: the principal exposed
// to application code, the details a user store returns, and the ports through
// which a consumer supplies users, role privileges and the multi-factor
// requirement from their own data.
//
// A user reference is opaque and consumer-owned. scrty stores, compares and
// returns it byte-for-byte, and never parses it, changes its case, trims it or
// derives meaning from its format. Role, organization and group identifiers
// follow the same rule.
package identity

import "time"

// UserID references a user in the consumer's own data.
//
// It is opaque: scrty never parses it, so any format a consumer's store uses
// travels through unchanged. Two references that differ only in case are two
// different users.
type UserID string

// AssignedRole is a role granted to a user.
//
// SuperRole, StartDate and ValidUntil are carried as data. What they mean for
// access is the authorization capability's decision, not this package's.
type AssignedRole struct {
	ID         string
	Name       string
	Primary    bool
	SuperRole  bool
	StartDate  time.Time
	ValidUntil time.Time
}

// Privilege is one named privilege and whether a role holds it.
//
// A privilege that is not granted is carried as refused rather than omitted, so
// a caller can tell "refused" apart from "not mentioned".
type Privilege struct {
	Name    string
	Granted bool
}

// ResourcePrivileges are the privileges a role holds on one resource.
//
// Like AssignedRole, this is data the identity model carries unchanged. Whether
// a privilege permits a particular request is the authorization capability's
// decision, not this package's.
type ResourcePrivileges struct {
	Group      string
	Resource   string
	Privileges []Privilege
}

// Group is a grouping an organization belongs to.
type Group struct {
	ID       string
	Name     string
	Internal bool
}

// Organization is the organization a user belongs to.
//
// scrty supplies no default: a user whose store reports no organization has
// none.
type Organization struct {
	ID    string
	Name  string
	Group *Group
}

// Kind distinguishes a human user from a machine caller.
//
// The zero value is KindUser, so a principal built without a kind is a human
// user rather than an unknown one. That is deliberate: a caller who forgets to
// set the kind gets the more restricted identity, since service principals are
// the ones that carry scopes and skip a second factor.
type Kind uint8

// The principal kinds.
const (
	KindUser Kind = iota
	KindService
)

// Principal is the identity scrty exposes outward, to interceptors and to
// application code.
//
// It never carries the password hash. Use PrincipalFromDetails to obtain one
// from a store's record.
type Principal struct {
	ID           UserID
	Name         string // the display name, not the username
	Username     string
	Roles        []*AssignedRole
	ActiveRole   *AssignedRole
	Organization *Organization
	Kind         Kind
	Scopes       []string // granted scopes; service principals only
}

// IsService reports whether p is a machine caller rather than a human user.
func (p Principal) IsService() bool { return p.Kind == KindService }

// Details is the record a user store returns.
//
// It carries the password hash, so it stays on the library's own call paths and
// is never handed outward.
type Details struct {
	ID           UserID
	Name         string // the display name, not the username
	Username     string
	Password     []byte
	Active       bool // false unless the store marks the user active
	Roles        []*AssignedRole
	Organization *Organization

	// PasswordChangedAt is when the password was last changed, as the store
	// records it. Neither Provision nor Update moves it: the store keeps the
	// hash, but when a password last changed is the consumer's to decide, and a
	// password-age policy reads this to refuse a stale credential.
	//
	// It stays on Details and never reaches Principal: it is record-keeping for
	// the library's own call paths, not part of the outward identity.
	PasswordChangedAt time.Time
}

// PrincipalFromDetails maps a store's record to the outward principal.
//
// It drops the password hash, and sets the active role to the primary role when
// the record has one. Where a record flags several roles primary, the first in
// the record wins; the library does not reject the record, because role data is
// carried rather than decided. Absent details yield no principal.
func PrincipalFromDetails(d *Details) *Principal {
	if d == nil {
		return nil
	}

	p := &Principal{
		ID:           d.ID,
		Name:         d.Name,
		Username:     d.Username,
		Roles:        d.Roles,
		Organization: d.Organization,
	}

	for _, r := range d.Roles {
		if r != nil && r.Primary {
			p.ActiveRole = r

			break
		}
	}

	return p
}
