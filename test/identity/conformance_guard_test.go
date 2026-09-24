package identitytest_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	identitytest "github.com/kartaladev/scrty/test/identity"
)

// defectVar names the environment variable that selects the single deliberate
// flaw the store under test carries. One defect per process, so the suite's
// verdict is attributable to it and to nothing else.
const defectVar = "SCRTY_IDENTITY_DEFECT"

// defect is one deliberate flaw a store can carry.
type defect string

const (
	defectNone defect = ""
	// The collision is decided by a read that is released before the insert.
	defectPreflightCollision defect = "preflight-collision"
	// LoadByUsername hands back the store's own record.
	defectAliasingLoad defect = "aliasing-load"
	// Provision and Update hand back the store's own record.
	defectAliasingWrite defect = "aliasing-write"
	// LoadPrivileges hands back the store's own privilege rows.
	defectAliasingPrivileges defect = "aliasing-privileges"
	// A write holds the caller's password buffer rather than copying it.
	defectAliasingPassword defect = "aliasing-password"
	// A write holds the caller's organization rather than copying it.
	defectAliasingOrganization defect = "aliasing-organization"
	// The collision check is case-insensitive, so two distinct users collide.
	defectCaseFoldingCollision defect = "case-folding-collision"
	// Provision stamps the password-changed time.
	defectProvisionStampsChangedAt defect = "provision-stamps-changed-at"
	// Update stamps the password-changed time when it writes a password.
	defectUpdateStampsChangedAt defect = "update-stamps-changed-at"
	// A backend failure is reported as "not required".
	defectMFAFailOpen defect = "mfa-fail-open"
	// A role rebuild with no surviving name strips every grant.
	defectRoleStrip defect = "role-strip"
	// A rebuilt grant is minted fresh, losing the stored attributes.
	defectRoleMint defect = "role-mint"
	// The loader trims and case-folds the username it is given.
	defectTrimmingLoader defect = "trimming-loader"
	// Update writes every field, ignoring which the caller named.
	defectIgnoresIsSet defect = "ignores-isset"
	// Update's read-modify-write is not serialized.
	defectUnserializedUpdate defect = "unserialized-update"
	// Fault injection does nothing.
	defectNoFaultInjection defect = "no-fault-injection"
	// A created user is not active.
	defectInactiveOnCreate defect = "inactive-on-create"
	// The collision error quotes the username.
	defectLeakyCollisionError defect = "leaky-collision-error"
	// Update is an upsert.
	defectUpsert defect = "upsert"
	// Two concurrent role rebuilds both decide from the pre-state: a lost
	// update, forced deterministically so the outcome does not depend on
	// scheduling.
	defectLostUpdate defect = "lost-update"
	// A refused privilege is filtered out instead of carried as refused.
	defectFiltersRefusedPrivileges defect = "filters-refused-privileges"
	// Provision refuses a username that is only whitespace, although the
	// contract says a username is opaque.
	defectRefusesOpaqueUsername defect = "refuses-opaque-username"
)

// everyDefect is every flaw the guard expects the conformance suite to catch.
// A defect that is not listed here is a defect no run exercises.
var everyDefect = []defect{
	defectPreflightCollision,
	defectAliasingLoad,
	defectAliasingWrite,
	defectAliasingPrivileges,
	defectAliasingPassword,
	defectAliasingOrganization,
	defectCaseFoldingCollision,
	defectProvisionStampsChangedAt,
	defectUpdateStampsChangedAt,
	defectMFAFailOpen,
	defectRoleStrip,
	defectRoleMint,
	defectTrimmingLoader,
	defectIgnoresIsSet,
	defectUnserializedUpdate,
	defectNoFaultInjection,
	defectInactiveOnCreate,
	defectLeakyCollisionError,
	defectUpsert,
	defectLostUpdate,
	defectFiltersRefusedPrivileges,
	defectRefusesOpaqueUsername,
}

// brokenStore implements every identity port over process memory, carrying
// exactly one deliberate defect. It is written on its own rather than wrapped
// around the shipped double, so that the suite — not an inherited correctness —
// is what decides the verdict.
type brokenStore struct {
	d defect

	mu     sync.Mutex
	byName map[string]*identity.Details
	privs  map[string][]*identity.ResourcePrivileges
	mfa    map[identity.UserID]bool
	nextID int

	loadErr error
	mfaErr  error

	// arrived counts the callers that have reached a meeting point, so that a
	// defect which needs two callers inside the same window shows itself on
	// every run rather than only when the scheduler allows. Under -race the
	// scheduler is the least likely to allow it.
	arrived atomic.Int64
}

var errUsernameRequired = errors.New("identitytest: username is required")

func newBrokenStore(d defect) *brokenStore {
	return &brokenStore{
		d:      d,
		byName: make(map[string]*identity.Details),
		privs:  make(map[string][]*identity.ResourcePrivileges),
		mfa:    make(map[identity.UserID]bool),
	}
}

// meet blocks until want callers have reached it, or until a short deadline
// passes so that a case with only one caller is not held up.
func (s *brokenStore) meet(want int64) {
	if s.arrived.Add(1) >= want {
		return
	}

	deadline := time.Now().Add(100 * time.Millisecond)
	for s.arrived.Load() < want && time.Now().Before(deadline) {
		runtime.Gosched()
	}
}

func (s *brokenStore) key(username string) string {
	if s.d == defectCaseFoldingCollision {
		return strings.ToLower(username)
	}

	return username
}

func (s *brokenStore) SeedRole(
	_ context.Context, role string, p []*identity.ResourcePrivileges,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.privs[role] = p

	return nil
}

func (s *brokenStore) SeedMFARequired(_ context.Context, id identity.UserID, required bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.mfa[id] = required

	return nil
}

func (s *brokenStore) SeedPasswordChangedAt(
	_ context.Context, username string, at time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.byName[s.key(username)]
	if !ok {
		return identity.ErrUserNotFound
	}

	d.PasswordChangedAt = at

	return nil
}

func (s *brokenStore) SeedRoleGrants(
	_ context.Context, username string, grants []*identity.AssignedRole,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.byName[s.key(username)]
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

func (s *brokenStore) FailUserLoads(err error) {
	if s.d == defectNoFaultInjection {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.loadErr = err
}

func (s *brokenStore) FailMFALookups(err error) {
	if s.d == defectNoFaultInjection {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.mfaErr = err
}

func (s *brokenStore) LoadByUsername(
	_ context.Context, username string,
) (*identity.Details, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loadErr != nil {
		return nil, s.loadErr
	}

	if s.d == defectTrimmingLoader {
		username = strings.ToLower(strings.TrimSpace(username))
	}

	d, ok := s.byName[s.key(username)]
	if !ok {
		return nil, identity.ErrUserNotFound
	}

	if s.d == defectAliasingLoad {
		return d, nil
	}

	return clonedDetails(d), nil
}

func (s *brokenStore) LoadByUserID(
	_ context.Context, id identity.UserID,
) (*identity.Details, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loadErr != nil {
		return nil, s.loadErr
	}

	for _, d := range s.byName {
		if d.ID != id {
			continue
		}

		if s.d == defectAliasingLoad {
			return d, nil
		}

		return clonedDetails(d), nil
	}

	return nil, identity.ErrUserNotFound
}

func (s *brokenStore) LoadPrivileges(
	_ context.Context, role string,
) ([]*identity.ResourcePrivileges, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.privs[role]
	if !ok || len(p) == 0 {
		return nil, identity.ErrPrivilegesNotFound
	}

	if s.d == defectAliasingPrivileges {
		return p, nil
	}

	out := make([]*identity.ResourcePrivileges, 0, len(p))

	for _, e := range p {
		ec := *e
		ec.Privileges = append([]identity.Privilege(nil), e.Privileges...)

		if s.d == defectFiltersRefusedPrivileges {
			kept := make([]identity.Privilege, 0, len(ec.Privileges))

			for _, pr := range ec.Privileges {
				if pr.Granted {
					kept = append(kept, pr)
				}
			}

			ec.Privileges = kept
		}

		out = append(out, &ec)
	}

	return out, nil
}

func (s *brokenStore) Required(_ context.Context, id identity.UserID) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.mfaErr != nil {
		if s.d == defectMFAFailOpen {
			return false, nil
		}

		return false, s.mfaErr
	}

	return s.mfa[id], nil
}

func (s *brokenStore) Provision(
	_ context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	if username == "" {
		return nil, errUsernameRequired
	}

	if s.d == defectRefusesOpaqueUsername && strings.TrimSpace(username) == "" {
		return nil, errUsernameRequired
	}

	u := identity.ApplyUserOptions(opts...)

	if s.d == defectPreflightCollision {
		// The question is asked, and the lock released, before the insert.
		s.mu.Lock()
		_, taken := s.byName[s.key(username)]
		s.mu.Unlock()

		if taken {
			return nil, identity.ErrUserExists
		}

		// Hold here until a second caller has also passed the read, so both
		// insert on a question neither asked again.
		s.meet(2)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.d != defectPreflightCollision {
		if _, taken := s.byName[s.key(username)]; taken {
			if s.d == defectLeakyCollisionError {
				return nil, errors.New("identitytest: user " + username + " already exists: " +
					identity.ErrUserExists.Error())
			}

			return nil, identity.ErrUserExists
		}
	}

	return s.insertLocked(username, u), nil
}

func (s *brokenStore) insertLocked(username string, u *identity.NewUser) *identity.Details {
	s.nextID++
	id := strconv.Itoa(s.nextID)

	d := &identity.Details{
		ID:       identity.UserID("u-" + id),
		Name:     u.Name,
		Username: username,
		Active:   s.d != defectInactiveOnCreate,
	}

	s.adopt(d, u)

	if s.d == defectProvisionStampsChangedAt {
		d.PasswordChangedAt = time.Now()
	}

	for i, name := range u.Roles {
		d.Roles = append(d.Roles, &identity.AssignedRole{
			ID:      "r-" + id + "-" + strconv.Itoa(i),
			Name:    name,
			Primary: i == 0,
		})
	}

	s.byName[s.key(username)] = d

	if s.d == defectAliasingWrite {
		return d
	}

	return clonedDetails(d)
}

// adopt takes the caller's password buffer and organization into d, copying
// them unless the store's defect is to hold the caller's own memory.
func (s *brokenStore) adopt(d *identity.Details, u *identity.NewUser) {
	if s.d == defectAliasingPassword {
		d.Password = u.Password
	} else {
		d.Password = append([]byte(nil), u.Password...)
	}

	if s.d == defectAliasingOrganization {
		d.Organization = u.Organization
	} else {
		d.Organization = clonedOrg(u.Organization)
	}
}

func (s *brokenStore) Update(
	_ context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	u := identity.ApplyUserOptions(opts...)

	if s.d == defectUnserializedUpdate {
		return s.unserializedUpdate(username, u)
	}

	if s.d == defectLostUpdate {
		return s.lostUpdate(username, u)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.byName[s.key(username)]
	if !ok {
		if s.d == defectUpsert {
			return s.insertLocked(username, u), nil
		}

		return nil, identity.ErrUserNotFound
	}

	s.write(d, u)

	if s.d == defectAliasingWrite {
		return d, nil
	}

	return clonedDetails(d), nil
}

// unserializedUpdate reads, decides and writes without holding the lock across
// the three, which is what lets two role rebuilds interleave.
func (s *brokenStore) unserializedUpdate(
	username string, u *identity.NewUser,
) (*identity.Details, error) {
	s.mu.Lock()
	d, ok := s.byName[s.key(username)]
	s.mu.Unlock()

	if !ok {
		return nil, identity.ErrUserNotFound
	}

	snapshot := clonedDetails(d)

	// Both callers decide from the state they read, which the other is about to
	// replace.
	s.meet(2)

	s.write(snapshot, u)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.byName[s.key(username)] = snapshot

	return clonedDetails(snapshot), nil
}

// lostUpdate reads the pre-state, waits until the other caller has read it too,
// and only then writes. Both callers therefore decide from grants the other is
// about to replace — the interleaving the suite's concurrent-roles case says it
// detects, made deterministic so no run can miss it.
func (s *brokenStore) lostUpdate(
	username string, u *identity.NewUser,
) (*identity.Details, error) {
	s.mu.Lock()
	d, ok := s.byName[s.key(username)]

	var snapshot *identity.Details
	if ok {
		snapshot = clonedDetails(d)
	}

	s.mu.Unlock()

	if !ok {
		return nil, identity.ErrUserNotFound
	}

	// Both callers have now read; release them together.
	s.meet(2)

	s.write(snapshot, u)

	// Make the winner deterministic rather than scheduler-dependent: the caller
	// re-asserting admin writes second.
	if len(u.Roles) > 0 && u.Roles[0] == "admin" {
		time.Sleep(20 * time.Millisecond)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.byName[s.key(username)] = snapshot

	return clonedDetails(snapshot), nil
}

func (s *brokenStore) write(d *identity.Details, u *identity.NewUser) {
	ignore := s.d == defectIgnoresIsSet

	if ignore || u.IsSet(identity.FieldName) {
		d.Name = u.Name
	}

	if ignore || u.IsSet(identity.FieldPassword) {
		if s.d == defectAliasingPassword {
			d.Password = u.Password
		} else {
			d.Password = append([]byte(nil), u.Password...)
		}

		if s.d == defectUpdateStampsChangedAt {
			d.PasswordChangedAt = time.Now()
		}
	}

	if ignore || u.IsSet(identity.FieldOrganization) {
		if s.d == defectAliasingOrganization {
			d.Organization = u.Organization
		} else {
			d.Organization = clonedOrg(u.Organization)
		}
	}

	if ignore || u.IsSet(identity.FieldRoles) {
		d.Roles = s.rebuild(d.Roles, u.Roles)
	}
}

func (s *brokenStore) rebuild(
	stored []*identity.AssignedRole, names []string,
) []*identity.AssignedRole {
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
		if s.d == defectRoleStrip {
			return nil
		}

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
		if prev := existing[n]; prev != nil && s.d != defectRoleMint {
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

func clonedDetails(d *identity.Details) *identity.Details {
	out := *d
	out.Password = append([]byte(nil), d.Password...)
	out.Organization = clonedOrg(d.Organization)
	out.Roles = make([]*identity.AssignedRole, 0, len(d.Roles))

	for _, r := range d.Roles {
		rc := *r
		out.Roles = append(out.Roles, &rc)
	}

	return &out
}

func clonedOrg(o *identity.Organization) *identity.Organization {
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

var (
	_ identity.UserLoader           = (*brokenStore)(nil)
	_ identity.RoleLoader           = (*brokenStore)(nil)
	_ identity.UserProvisioner      = (*brokenStore)(nil)
	_ identity.MFARequirementLookup = (*brokenStore)(nil)
)

// TestBrokenStoreConformance runs the conformance suite against a store
// carrying the defect named by the environment, and is the child half of
// TestConformanceSuiteIsLoadBearing. Without a defect named it skips: a plain
// run of this package has nothing to prove here.
func TestBrokenStoreConformance(t *testing.T) {
	d, named := os.LookupEnv(defectVar)
	if !named {
		t.Skipf("no defect named in %s; run through TestConformanceSuiteIsLoadBearing", defectVar)
	}

	t.Logf("defect under test: %q", d)

	identitytest.RunConformanceSuite(t, func(t *testing.T) identitytest.Fixture {
		t.Helper()

		return newBrokenStore(defect(d))
	})
}

// TestConformanceSuiteIsLoadBearing checks the suite itself: for every defect
// above, a store carrying it must fail the suite, and a store carrying none
// must pass.
//
// It is the only thing that keeps the suite honest. A case whose assertion
// cannot fail — one that reads a value back rather than a stored one, or that
// accepts any interleaving — leaves a contract unchecked for every consumer
// implementation, and nothing else notices. Each defect runs in its own process
// because a failing suite reports through its own *testing.T, which cannot be
// substituted.
func TestConformanceSuiteIsLoadBearing(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		defect defect
		assert func(t *testing.T, err error, output string)
	}

	cases := make([]testCase, 0, len(everyDefect)+1)

	cases = append(cases, testCase{
		name:   "a store with no defect passes",
		defect: defectNone,
		assert: func(t *testing.T, err error, output string) {
			require.NoError(t, err,
				"the suite rejected a conforming store, so every defect below fails for the "+
					"wrong reason:\n%s", output)
		},
	})

	for _, d := range everyDefect {
		cases = append(cases, testCase{
			name:   string(d) + " is caught",
			defect: d,
			assert: func(t *testing.T, err error, output string) {
				require.Error(t, err,
					"the suite passed a store whose %s defect breaks a contract the library "+
						"relies on, so no consumer implementation is checked against it either:\n%s",
					d, output)
			},
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			output, err := runSuiteInProcess(t, tc.defect)
			tc.assert(t, err, output)
		})
	}
}

// runSuiteInProcess re-executes this test binary, running only the child test
// against a store carrying d, and returns its combined output.
func runSuiteInProcess(t *testing.T, d defect) (string, error) {
	t.Helper()

	//nolint:gosec // G204: this test binary re-executed with fixed arguments
	cmd := exec.CommandContext(t.Context(), os.Args[0],
		"-test.run=^TestBrokenStoreConformance$", "-test.count=1", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), defectVar+"="+string(d))

	out, err := cmd.CombinedOutput()

	// A skip means the child never ran the suite, so the verdict below would be
	// about nothing at all.
	assert.NotContains(t, string(out), "SKIP",
		"the child skipped rather than running the suite, so nothing was checked")

	return string(out), err
}
