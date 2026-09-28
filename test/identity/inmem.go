package identitytest

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"

	"github.com/kartaladev/scrty/identity"
)

// ErrEmptyUsername is returned by Provision when the username is empty. It is
// this store's own error: the identity package names no sentinel for it, because
// the rule is "the username is required", not a contract about which error says
// so.
var ErrEmptyUsername = errors.New("identitytest: username is required")

// InMemoryStore implements every identity port over process memory.
//
// It is safe for concurrent use, and deliberately so in the way the contracts
// require rather than merely in the way that avoids a race: Provision decides a
// username collision under the same lock that performs the insert, and Update
// holds that lock across its whole read-modify-write. A store that took the lock
// only around each map access would pass the race detector and still break both
// contracts.
//
// A user holds its organization by reference, as a store keeping organizations
// in their own table would: Provision and Update keep only the identifier they
// are given, and every record returned resolves it against the organizations
// seeded through SeedOrganization, or to none. Grants are returned primary
// first, then in stored order.
//
// The records live apart from the injected faults: Share hands out another store
// over the same records, whose faults are its own.
type InMemoryStore struct {
	*inMemoryRecords

	faultMu sync.Mutex
	loadErr error
	mfaErr  error
}

// inMemoryRecords is the state every store returned by Share has in common,
// guarded by one lock so the contracts' atomicity holds across them.
type inMemoryRecords struct {
	mu     sync.Mutex
	byName map[string]*identity.Details
	privs  map[string][]*identity.ResourcePrivileges
	mfa    map[identity.UserID]bool
	orgs   map[string]*identity.Organization
	nextID int
}

// NewInMemoryStore returns an empty store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{inMemoryRecords: &inMemoryRecords{
		byName: make(map[string]*identity.Details),
		privs:  make(map[string][]*identity.ResourcePrivileges),
		mfa:    make(map[identity.UserID]bool),
		orgs:   make(map[string]*identity.Organization),
	}}
}

// Share returns another store over the same records as s, with no faults
// injected and fault hooks of its own.
//
// It is how a single store hosts a whole conformance run, as one database
// would: the factory hands each case s.Share(), so every case writes to the same
// records while a fault one case injects through FailUserLoads or
// FailMFALookups fails that case's calls only.
func (s *InMemoryStore) Share() *InMemoryStore {
	return &InMemoryStore{inMemoryRecords: s.inMemoryRecords}
}

// SeedRole records the privileges a role grants.
//
// The rows are copied in for the same reason SeedRoleGrants copies grants:
// holding the caller's pointers would let seeded state alias the store's own.
func (s *InMemoryStore) SeedRole(
	_ context.Context, role string, p []*identity.ResourcePrivileges,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.privs[role] = clonePrivileges(p)

	return nil
}

// SeedMFARequired records whether a user must use a second factor. The
// requirement is held against the user reference, never against an enrolment.
func (s *InMemoryStore) SeedMFARequired(
	_ context.Context, id identity.UserID, required bool,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.mfa[id] = required

	return nil
}

// SeedRoleGrants replaces a user's role grants outright.
//
// The grants are copied in, not referenced: holding the caller's pointers would
// let a seeded slice alias the store's own state, so a rebuild could appear to
// preserve a grant's attributes when it had merely handed back the same pointer.
func (s *InMemoryStore) SeedRoleGrants(
	_ context.Context, username string, grants []*identity.AssignedRole,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.byName[username]
	if !ok {
		return identity.ErrUserNotFound
	}

	copied := make([]*identity.AssignedRole, 0, len(grants))

	for _, g := range grants {
		if g == nil {
			continue
		}

		gc := *g
		copied = append(copied, &gc)
	}

	d.Roles = copied

	return nil
}

// SeedOrganization records an organization and its group, replacing any
// organization seeded earlier under the same identifier.
//
// A user holds only the organization's identifier, as a store keeping
// organizations in their own table would, and each load resolves it here. The
// organization is copied in, so the caller's value stays the caller's.
func (s *InMemoryStore) SeedOrganization(_ context.Context, org *identity.Organization) error {
	if org == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.orgs[org.ID] = cloneOrg(org)

	return nil
}

// FailUserLoads makes every later user load through this store return err. A
// store obtained through Share is not affected, and a nil err clears the fault.
//
// It exists so the suite can check that a backend outage is distinguishable from
// an unknown user: a caller that cannot tell them apart counts an outage as a
// failed login attempt, and locks out a user who did nothing wrong.
func (s *InMemoryStore) FailUserLoads(err error) {
	s.faultMu.Lock()
	defer s.faultMu.Unlock()

	s.loadErr = err
}

// FailMFALookups makes every later MFA requirement lookup through this store
// return err, so a caller's fail-closed behaviour can be exercised. A store
// obtained through Share is not affected, and a nil err clears the fault.
func (s *InMemoryStore) FailMFALookups(err error) {
	s.faultMu.Lock()
	defer s.faultMu.Unlock()

	s.mfaErr = err
}

// fault reads one injected fault.
func (s *InMemoryStore) fault(which *error) error {
	s.faultMu.Lock()
	defer s.faultMu.Unlock()

	return *which
}

// LoadByUsername implements identity.UserLoader.
func (s *InMemoryStore) LoadByUsername(
	_ context.Context, username string,
) (*identity.Details, error) {
	if err := s.fault(&s.loadErr); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.byName[username]
	if !ok {
		return nil, identity.ErrUserNotFound
	}

	return s.recordLocked(d), nil
}

// LoadByUserID implements identity.UserLoader.
//
// The reference is matched byte-for-byte, exactly as LoadByUsername matches a
// username: the store keeps its records under the username it provisioned them
// with, so this walks them rather than keeping a second index that could fall
// out of step with the first.
func (s *InMemoryStore) LoadByUserID(
	_ context.Context, id identity.UserID,
) (*identity.Details, error) {
	if err := s.fault(&s.loadErr); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, d := range s.byName {
		if d.ID == id {
			return s.recordLocked(d), nil
		}
	}

	return nil, identity.ErrUserNotFound
}

// LoadPrivileges implements identity.RoleLoader.
func (s *InMemoryStore) LoadPrivileges(
	_ context.Context, role string,
) ([]*identity.ResourcePrivileges, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.privs[role]
	if !ok || len(p) == 0 {
		return nil, identity.ErrPrivilegesNotFound
	}

	return clonePrivileges(p), nil
}

// Required implements identity.MFARequirementLookup.
func (s *InMemoryStore) Required(_ context.Context, id identity.UserID) (bool, error) {
	if err := s.fault(&s.mfaErr); err != nil {
		return false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.mfa[id], nil
}

// Provision implements identity.UserProvisioner.
func (s *InMemoryStore) Provision(
	_ context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	if username == "" {
		return nil, ErrEmptyUsername
	}

	u := identity.ApplyUserOptions(opts...)

	s.mu.Lock()
	defer s.mu.Unlock()

	// The collision is decided here, under the same lock as the insert. A
	// pre-flight read released before this point would let two callers both pass
	// it and both create the user.
	if _, taken := s.byName[username]; taken {
		// The message never quotes the username: on just-in-time provisioning it
		// is the caller's email address.
		return nil, identity.ErrUserExists
	}

	s.nextID++
	id := strconv.Itoa(s.nextID)

	d := &identity.Details{
		ID:           identity.UserID("u-" + id),
		Name:         u.Name,
		Username:     username,
		Password:     bytes.Clone(u.Password),
		Active:       true,
		Organization: orgReference(u.Organization),
	}

	// The time is written only when named: a password named alone leaves it
	// zero, so a mirrored password never records a rotation.
	if u.IsSet(identity.FieldPasswordChangedAt) {
		d.PasswordChangedAt = u.PasswordChangedAt
	}

	// Each occurrence of a name creates its own grant, and the first is primary.
	for i, name := range u.Roles {
		d.Roles = append(d.Roles, &identity.AssignedRole{
			ID:      "r-" + id + "-" + strconv.Itoa(i),
			Name:    name,
			Primary: i == 0,
		})
	}

	s.byName[username] = d

	return s.recordLocked(d), nil
}

// Update implements identity.UserProvisioner.
func (s *InMemoryStore) Update(
	_ context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	u := identity.ApplyUserOptions(opts...)

	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.byName[username]
	if !ok {
		return nil, identity.ErrUserNotFound
	}

	// Every field is written from IsSet, never from the value being empty, so a
	// field the caller did not name keeps whatever the store holds.
	if u.IsSet(identity.FieldName) {
		d.Name = u.Name
	}

	if u.IsSet(identity.FieldPassword) {
		d.Password = bytes.Clone(u.Password)
	}

	// Writing the password never moves the time on its own; only naming the
	// time does, and naming the zero time clears it.
	if u.IsSet(identity.FieldPasswordChangedAt) {
		d.PasswordChangedAt = u.PasswordChangedAt
	}

	if u.IsSet(identity.FieldOrganization) {
		d.Organization = orgReference(u.Organization)
	}

	if u.IsSet(identity.FieldRoles) {
		d.Roles = rebuildRoles(d.Roles, u.Roles)
	}

	return s.recordLocked(d), nil
}

// recordLocked returns the complete record of d as a caller sees it: a copy,
// with the organization reference resolved against the seeded organizations
// and the primary grant listed first. The caller holds s.mu.
func (s *InMemoryStore) recordLocked(d *identity.Details) *identity.Details {
	out := cloneDetails(d)
	out.Organization = nil

	if d.Organization != nil {
		out.Organization = cloneOrg(s.orgs[d.Organization.ID])
	}

	// Primary first, then the stored order: a stable sort keeps every other
	// grant where it was.
	slices.SortStableFunc(out.Roles, func(a, b *identity.AssignedRole) int {
		switch {
		case a.Primary == b.Primary:
			return 0
		case a.Primary:
			return -1
		default:
			return 1
		}
	})

	return out
}

// orgReference keeps only the identifier of the organization a caller named: an
// organization is the consumer's own record, seeded through SeedOrganization,
// and a user merely refers to it. Naming no organization, or one with no
// identifier, refers to none.
func orgReference(o *identity.Organization) *identity.Organization {
	if o == nil || o.ID == "" {
		return nil
	}

	return &identity.Organization{ID: o.ID}
}

// rebuildRoles applies the role rules: empty names are skipped, a repeated name
// collapses to its first occurrence, and when no name survives the stored grants
// are left untouched, so nothing can strip every role through Update. A
// surviving name that matches an existing grant keeps that grant's identifier,
// super-role flag and validity window; where the stored grants repeat a name,
// the first stored grant is the one reused.
func rebuildRoles(stored []*identity.AssignedRole, names []string) []*identity.AssignedRole {
	survivors := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))

	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}

		seen[n] = true

		survivors = append(survivors, n)
	}

	if len(survivors) == 0 {
		return stored
	}

	existing := make(map[string]*identity.AssignedRole, len(stored))
	for _, r := range stored {
		if r != nil && existing[r.Name] == nil {
			existing[r.Name] = r
		}
	}

	rebuilt := make([]*identity.AssignedRole, 0, len(survivors))

	for i, n := range survivors {
		if prev := existing[n]; prev != nil {
			rebuilt = append(rebuilt, &identity.AssignedRole{
				ID:         prev.ID,
				Name:       prev.Name,
				Primary:    i == 0,
				SuperRole:  prev.SuperRole,
				StartDate:  prev.StartDate,
				ValidUntil: prev.ValidUntil,
			})

			continue
		}

		rebuilt = append(rebuilt, &identity.AssignedRole{Name: n, Primary: i == 0})
	}

	return rebuilt
}

// cloneDetails returns a deep enough copy that a caller cannot reach into the
// store through the record it was handed.
func cloneDetails(d *identity.Details) *identity.Details {
	out := *d
	out.Password = bytes.Clone(d.Password)
	out.Organization = cloneOrg(d.Organization)
	out.Roles = make([]*identity.AssignedRole, 0, len(d.Roles))

	for _, r := range d.Roles {
		rc := *r
		out.Roles = append(out.Roles, &rc)
	}

	return &out
}

// cloneOrg copies an organization and the group it points at.
//
// Both are pointers, so copying only the Details struct would leave the caller
// holding the store's own organization: writing through it would move the
// stored user into another organization, or mark its group internal.
func cloneOrg(o *identity.Organization) *identity.Organization {
	if o == nil {
		return nil
	}

	out := *o

	if o.Group != nil {
		g := *o.Group
		out.Group = &g
	}

	return &out
}

// clonePrivileges copies a role's privilege rows, each with its own privilege
// list, so a reader cannot grant itself a privilege the role is refused.
func clonePrivileges(p []*identity.ResourcePrivileges) []*identity.ResourcePrivileges {
	out := make([]*identity.ResourcePrivileges, 0, len(p))

	for _, e := range p {
		if e == nil {
			continue
		}

		ec := *e
		ec.Privileges = slices.Clone(e.Privileges)
		out = append(out, &ec)
	}

	return out
}

var (
	_ identity.UserLoader           = (*InMemoryStore)(nil)
	_ identity.RoleLoader           = (*InMemoryStore)(nil)
	_ identity.UserProvisioner      = (*InMemoryStore)(nil)
	_ identity.MFARequirementLookup = (*InMemoryStore)(nil)
)
