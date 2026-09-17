package identitytest

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

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
type InMemoryStore struct {
	mu     sync.Mutex
	byName map[string]*identity.Details
	privs  map[string][]*identity.ResourcePrivileges
	mfa    map[identity.UserID]bool
	nextID int

	loadErr  error
	privsErr error
	mfaErr   error
}

// NewInMemoryStore returns an empty store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		byName: make(map[string]*identity.Details),
		privs:  make(map[string][]*identity.ResourcePrivileges),
		mfa:    make(map[identity.UserID]bool),
	}
}

// SeedRole records the privileges a role grants.
func (s *InMemoryStore) SeedRole(
	_ context.Context, role string, p []*identity.ResourcePrivileges,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.privs[role] = p

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

// SeedPasswordChangedAt records when a user's password was last changed.
//
// It is seeding, not a port: nothing in the identity ports sets this time, which
// is exactly the contract the suite checks — neither Provision nor Update may
// move it.
func (s *InMemoryStore) SeedPasswordChangedAt(
	_ context.Context, username string, at time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.byName[username]
	if !ok {
		return identity.ErrUserNotFound
	}

	d.PasswordChangedAt = at

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

// FailUserLoads makes every user load return err.
//
// It exists so the suite can check that a backend outage is distinguishable from
// an unknown user: a caller that cannot tell them apart counts an outage as a
// failed login attempt, and locks out a user who did nothing wrong.
func (s *InMemoryStore) FailUserLoads(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.loadErr = err
}

// FailMFALookups makes every MFA requirement lookup return err, so a caller's
// fail-closed behaviour can be exercised.
func (s *InMemoryStore) FailMFALookups(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.mfaErr = err
}

// LoadByUsername implements identity.UserLoader.
func (s *InMemoryStore) LoadByUsername(
	_ context.Context, username string,
) (*identity.Details, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loadErr != nil {
		return nil, s.loadErr
	}

	d, ok := s.byName[username]
	if !ok {
		return nil, identity.ErrUserNotFound
	}

	return cloneDetails(d), nil
}

// LoadPrivileges implements identity.RoleLoader.
func (s *InMemoryStore) LoadPrivileges(
	_ context.Context, role string,
) ([]*identity.ResourcePrivileges, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.privsErr != nil {
		return nil, s.privsErr
	}

	p, ok := s.privs[role]
	if !ok || len(p) == 0 {
		return nil, identity.ErrPrivilegesNotFound
	}

	return p, nil
}

// Required implements identity.MFARequirementLookup.
func (s *InMemoryStore) Required(_ context.Context, id identity.UserID) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.mfaErr != nil {
		return false, s.mfaErr
	}

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
		Password:     u.Password,
		Active:       true,
		Organization: u.Organization,
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

	return cloneDetails(d), nil
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
		d.Password = u.Password
	}

	if u.IsSet(identity.FieldOrganization) {
		d.Organization = u.Organization
	}

	if u.IsSet(identity.FieldRoles) {
		d.Roles = rebuildRoles(d.Roles, u.Roles)
	}

	return cloneDetails(d), nil
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
	out.Password = append([]byte(nil), d.Password...)
	out.Roles = make([]*identity.AssignedRole, 0, len(d.Roles))

	for _, r := range d.Roles {
		rc := *r
		out.Roles = append(out.Roles, &rc)
	}

	return &out
}

var (
	_ identity.UserLoader           = (*InMemoryStore)(nil)
	_ identity.RoleLoader           = (*InMemoryStore)(nil)
	_ identity.UserProvisioner      = (*InMemoryStore)(nil)
	_ identity.MFARequirementLookup = (*InMemoryStore)(nil)
)
