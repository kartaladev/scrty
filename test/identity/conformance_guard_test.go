package identitytest_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"slices"
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
	// Provision stamps the password-changed time when a password is named and
	// the time is not.
	defectProvisionStampsChangedAt defect = "provision-stamps-changed-at"
	// Update stamps the password-changed time when a password is named and the
	// time is not, as a mirrored password would on every login.
	defectUpdateStampsChangedAt defect = "update-stamps-changed-at"
	// Neither verb writes a password-changed time the caller named, so a local
	// change is never recorded.
	defectIgnoresNamedChangedAt defect = "ignores-named-changed-at"
	// A named zero password-changed time is skipped rather than clearing the
	// stored one, as a store deciding from the value instead of IsSet would.
	defectKeepsChangedAtOnNamedZero defect = "keeps-changed-at-on-named-zero"
	// Update stamps the password-changed time whenever it is unset, rather than
	// only when the caller names it — the same failure a SQL default of
	// COALESCE(password_changed_at, now()) would produce.
	defectStampsWhenUnset defect = "stamps-when-unset"
	// Update writes a named password-changed time but drops the password change
	// that named it, when both are named together.
	defectDropsPasswordWithTime defect = "drops-password-with-time"
	// A backend failure is reported as "not required".
	defectMFAFailOpen defect = "mfa-fail-open"
	// An MFA lookup of a reference that names no stored user answers "not
	// required" rather than user-not-found, failing open for a deleted user.
	defectMFAUnknownNotRequired defect = "mfa-unknown-not-required"
	// An MFA lookup of a stored user with no requirement recorded answers
	// user-not-found, as a sparse lookup that stores flags only for users who
	// need MFA would if it skipped the existence check.
	defectMFAUnflaggedNotFound defect = "mfa-unflagged-not-found"
	// A role rebuild with no surviving name strips every grant.
	defectRoleStrip defect = "role-strip"
	// A rebuilt grant is minted fresh, losing the stored attributes.
	defectRoleMint defect = "role-mint"
	// The loader trims and case-folds the username it is given.
	defectTrimmingLoader defect = "trimming-loader"
	// LoadByUserID matches a reference case-insensitively instead of byte for byte.
	defectCaseFoldsUserID defect = "case-folds user references"
	// LoadByUserID trims whitespace from a reference before comparing, although a
	// reference is opaque and must match byte for byte.
	defectTrimsUserID defect = "trims user references"
	// Update writes every field, ignoring which the caller named.
	defectIgnoresIsSet defect = "ignores-isset"
	// Update's read-modify-write is not serialized.
	defectUnserializedUpdate defect = "unserialized-update"
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
	// A loaded organization is returned without the group it belongs to.
	defectDropsOrganizationGroup defect = "drops-organization-group"
	// Update returns a record carrying only the fields the caller named.
	defectAmendedFieldsOnly defect = "amended-fields-only"
	// A role rebuild keeps the last of the stored grants that repeat a name.
	defectKeepsLastDuplicate defect = "keeps-last-duplicate"
	// Provision on a taken username replaces the existing user and succeeds.
	defectOverwritesOnCollision defect = "overwrites-on-collision"
	// Update of the empty username answers user-not-found rather than
	// refusing the username.
	defectUpdateEmptyUsernameNotFound defect = "update-empty-username-not-found"
	// Provision of the empty username answers user-already-exists rather than
	// refusing the username.
	defectProvisionEmptyUsernameExists defect = "provision-empty-username-exists"
	// LoadPrivileges returns entries in stored order, not grouped by resource
	// group and then resource.
	defectUnorderedPrivileges defect = "unordered-privileges"
	// An update that does not name roles re-mints every grant, keeping only
	// its name and primary flag.
	defectRemintsUnnamedGrants defect = "remints-unnamed-grants"
	// Provision on a taken username refuses, but first appends the requested
	// grants to the existing user.
	defectCollisionAppendsGrants defect = "collision-appends-grants"
	// Provision derives a grant identifier from the role name, so a repeated
	// name shares one identifier.
	defectDuplicateRoleSharesID defect = "duplicate-role-shares-id"
	// An update that names no field clears the stored name.
	defectNothingClearsName defect = "nothing-clears-name"
	// A newly named role inherits the super-role flag and validity window of
	// the user's first stored grant.
	defectNewRoleInherits defect = "new-role-inherits"
	// Where the stored grants repeat a name, the rebuild keeps the first
	// grant's identifier but takes the attributes of the later duplicate.
	defectDuplicatePromotesLater defect = "duplicate-promotes-later-attributes"
	// A role rebuild skips an empty name only when no non-empty name survives,
	// so a list mixing empty and real names creates a grant named "".
	defectKeepsEmptyRoleNames defect = "keeps-empty-role-names"
	// Provision stores the user but returns a record with no display name and
	// no organization.
	defectProvisionReturnsPartial defect = "provision-returns-partial-record"
	// A failed MFA lookup is reported as user-not-found, so an outage reads as
	// a deleted user.
	defectMFAFaultReadsNotFound defect = "mfa-fault-reads-not-found"
	// An update naming an empty role list re-mints every grant with a fresh
	// identifier and no validity window, keeping its name, primary and
	// super-role flags.
	defectRemintsOnEmptyRoleList defect = "remints-on-empty-role-list"
	// Provision given no password stores a placeholder hash rather than an
	// empty one.
	defectPlaceholderPassword defect = "placeholder-password"
	// Provision mints its first grant with a validity window.
	defectProvisionGrantsWindow defect = "provision-grants-window"
)

// variantOtherLocation is not a defect: a store that returns every stored
// time as the same instant in another location, as a database session in
// another time zone does. The suite must pass it, because an instant is what
// the contracts store.
const variantOtherLocation defect = "returns-times-in-another-location"

// otherLocation is the location variantOtherLocation reports times in.
var otherLocation = time.FixedZone("x", 7*3600)

// missingHook names the defect of a store that lacks the named hook: a seeding
// hook answers ErrHookUnsupported, a fault hook does nothing.
func missingHook(hook string) defect { return defect("missing-hook-" + hook) }

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
	defectIgnoresNamedChangedAt,
	defectKeepsChangedAtOnNamedZero,
	defectStampsWhenUnset,
	defectDropsPasswordWithTime,
	defectMFAFailOpen,
	defectMFAUnknownNotRequired,
	defectMFAUnflaggedNotFound,
	defectRoleStrip,
	defectRoleMint,
	defectTrimmingLoader,
	defectCaseFoldsUserID,
	defectTrimsUserID,
	defectIgnoresIsSet,
	defectUnserializedUpdate,
	defectInactiveOnCreate,
	defectLeakyCollisionError,
	defectUpsert,
	defectLostUpdate,
	defectFiltersRefusedPrivileges,
	defectRefusesOpaqueUsername,
	defectDropsOrganizationGroup,
	defectAmendedFieldsOnly,
	defectKeepsLastDuplicate,
	defectOverwritesOnCollision,
	defectUpdateEmptyUsernameNotFound,
	defectUnorderedPrivileges,
	defectRemintsUnnamedGrants,
	defectCollisionAppendsGrants,
	defectDuplicateRoleSharesID,
	defectNothingClearsName,
	defectNewRoleInherits,
	defectDuplicatePromotesLater,
	defectProvisionEmptyUsernameExists,
	defectKeepsEmptyRoleNames,
	defectProvisionReturnsPartial,
	defectMFAFaultReadsNotFound,
	defectRemintsOnEmptyRoleList,
	defectPlaceholderPassword,
	defectProvisionGrantsWindow,
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
	orgs   map[string]*identity.Organization
	nextID int

	loadErr error
	mfaErr  error

	// arrived counts the callers that have reached a meeting point, so that a
	// defect which needs two callers inside the same window shows itself on
	// every run rather than only when the scheduler allows. Under -race the
	// scheduler is the least likely to allow it.
	arrived atomic.Int64

	// grantSeq numbers the grants a rebuild mints; it is atomic because the
	// unserialized defects rebuild outside the lock.
	grantSeq atomic.Int64
}

var errUsernameRequired = errors.New("identitytest: username is required")

func newBrokenStore(d defect) *brokenStore {
	return &brokenStore{
		d:      d,
		byName: make(map[string]*identity.Details),
		privs:  make(map[string][]*identity.ResourcePrivileges),
		mfa:    make(map[identity.UserID]bool),
		orgs:   make(map[string]*identity.Organization),
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
	if s.d == missingHook("SeedRole") {
		return identitytest.ErrHookUnsupported
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.privs[role] = p

	return nil
}

func (s *brokenStore) SeedMFARequired(_ context.Context, id identity.UserID, required bool) error {
	if s.d == missingHook("SeedMFARequired") {
		return identitytest.ErrHookUnsupported
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.mfa[id] = required

	return nil
}

func (s *brokenStore) SeedRoleGrants(
	_ context.Context, username string, grants []*identity.AssignedRole,
) error {
	if s.d == missingHook("SeedRoleGrants") {
		return identitytest.ErrHookUnsupported
	}

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

func (s *brokenStore) SeedOrganization(_ context.Context, org *identity.Organization) error {
	if s.d == missingHook("SeedOrganization") {
		return identitytest.ErrHookUnsupported
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.orgs[org.ID] = clonedOrg(org)

	return nil
}

func (s *brokenStore) FailUserLoads(err error) {
	if s.d == missingHook("FailUserLoads") {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.loadErr = err
}

func (s *brokenStore) FailMFALookups(err error) {
	if s.d == missingHook("FailMFALookups") {
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
		return s.resolveInPlaceLocked(d), nil
	}

	return s.recordLocked(d), nil
}

func (s *brokenStore) LoadByUserID(
	_ context.Context, id identity.UserID,
) (*identity.Details, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loadErr != nil {
		return nil, s.loadErr
	}

	lookup := id
	if s.d == defectTrimsUserID {
		lookup = identity.UserID(strings.TrimSpace(string(id)))
	}

	for _, d := range s.byName {
		matches := d.ID == lookup
		if s.d == defectCaseFoldsUserID {
			matches = strings.EqualFold(string(d.ID), string(id))
		}

		if !matches {
			continue
		}

		if s.d == defectAliasingLoad {
			return s.resolveInPlaceLocked(d), nil
		}

		return s.recordLocked(d), nil
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

	if s.d != defectUnorderedPrivileges {
		slices.SortStableFunc(out, func(a, b *identity.ResourcePrivileges) int {
			if c := strings.Compare(a.Group, b.Group); c != 0 {
				return c
			}

			return strings.Compare(a.Resource, b.Resource)
		})
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

		if s.d == defectMFAFaultReadsNotFound {
			return false, identity.ErrUserNotFound
		}

		return false, s.mfaErr
	}

	if s.d == defectMFAUnknownNotRequired {
		return s.mfa[id], nil
	}

	if s.d == defectMFAUnflaggedNotFound {
		required, ok := s.mfa[id]
		if !ok {
			return false, identity.ErrUserNotFound
		}

		return required, nil
	}

	for _, d := range s.byName {
		if d.ID == id {
			return s.mfa[id], nil
		}
	}

	return false, identity.ErrUserNotFound
}

func (s *brokenStore) Provision(
	_ context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	if username == "" {
		if s.d == defectProvisionEmptyUsernameExists {
			return nil, identity.ErrUserExists
		}

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

	if s.d != defectPreflightCollision && s.d != defectOverwritesOnCollision {
		if _, taken := s.byName[s.key(username)]; taken {
			if s.d == defectCollisionAppendsGrants {
				existing := s.byName[s.key(username)]
				for _, n := range u.Roles {
					existing.Roles = append(existing.Roles, &identity.AssignedRole{ID: "appended", Name: n})
				}
			}

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

	switch {
	case u.IsSet(identity.FieldPasswordChangedAt):
		s.writeChangedAt(d, u)
	case s.d == defectProvisionStampsChangedAt && u.IsSet(identity.FieldPassword):
		d.PasswordChangedAt = time.Now()
	}

	for i, name := range u.Roles {
		grantID := "r-" + id + "-" + strconv.Itoa(i)
		if s.d == defectDuplicateRoleSharesID {
			grantID = "r-" + id + "-" + name
		}

		grant := &identity.AssignedRole{
			ID:      grantID,
			Name:    name,
			Primary: i == 0,
		}

		if s.d == defectProvisionGrantsWindow && i == 0 {
			grant.StartDate = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
			grant.ValidUntil = time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
		}

		d.Roles = append(d.Roles, grant)
	}

	s.byName[s.key(username)] = d

	if s.d == defectAliasingWrite {
		return d
	}

	out := s.recordLocked(d)

	if s.d == defectProvisionReturnsPartial {
		out.Name = ""
		out.Organization = nil
	}

	return out
}

// adopt takes the caller's password buffer and organization into d, copying
// them unless the store's defect is to hold the caller's own memory.
func (s *brokenStore) adopt(d *identity.Details, u *identity.NewUser) {
	switch {
	case s.d == defectDropsPasswordWithTime && u.IsSet(identity.FieldPasswordChangedAt):
		// the local change's time is recorded, its password is not
	case s.d == defectAliasingPassword:
		d.Password = u.Password
	case s.d == defectPlaceholderPassword && !u.IsSet(identity.FieldPassword):
		d.Password = []byte("!")
	default:
		d.Password = append([]byte(nil), u.Password...)
	}

	d.Organization = s.orgRef(u.Organization)
}

func (s *brokenStore) Update(
	_ context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	if username == "" && s.d != defectUpdateEmptyUsernameNotFound {
		return nil, errUsernameRequired
	}

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

	if s.d == defectAmendedFieldsOnly {
		return s.amendedOnlyLocked(d, u), nil
	}

	return s.recordLocked(d), nil
}

// amendedOnlyLocked returns the user's identity and the fields u named, and
// nothing the update did not touch: a store answering from its UPDATE statement
// rather than reading the record back.
func (s *brokenStore) amendedOnlyLocked(d *identity.Details, u *identity.NewUser) *identity.Details {
	full := s.recordLocked(d)
	out := &identity.Details{ID: full.ID, Username: full.Username}

	if u.IsSet(identity.FieldName) {
		out.Name = full.Name
	}

	if u.IsSet(identity.FieldPassword) {
		out.Password = full.Password
	}

	if u.IsSet(identity.FieldPasswordChangedAt) {
		out.PasswordChangedAt = full.PasswordChangedAt
	}

	if u.IsSet(identity.FieldOrganization) {
		out.Organization = full.Organization
	}

	if u.IsSet(identity.FieldRoles) {
		out.Roles = full.Roles
	}

	return out
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

	return s.recordLocked(snapshot), nil
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

	return s.recordLocked(snapshot), nil
}

func (s *brokenStore) write(d *identity.Details, u *identity.NewUser) {
	ignore := s.d == defectIgnoresIsSet

	if ignore || u.IsSet(identity.FieldName) {
		d.Name = u.Name
	}

	if ignore || u.IsSet(identity.FieldPassword) {
		dropPassword := s.d == defectDropsPasswordWithTime && u.IsSet(identity.FieldPasswordChangedAt)

		if !dropPassword {
			if s.d == defectAliasingPassword {
				d.Password = u.Password
			} else {
				d.Password = append([]byte(nil), u.Password...)
			}
		}

		if s.d == defectUpdateStampsChangedAt && !u.IsSet(identity.FieldPasswordChangedAt) {
			d.PasswordChangedAt = time.Now()
		}

		if s.d == defectStampsWhenUnset && !u.IsSet(identity.FieldPasswordChangedAt) &&
			d.PasswordChangedAt.IsZero() {
			d.PasswordChangedAt = time.Now()
		}
	}

	if ignore || u.IsSet(identity.FieldPasswordChangedAt) {
		s.writeChangedAt(d, u)
	}

	if ignore || u.IsSet(identity.FieldOrganization) {
		d.Organization = s.orgRef(u.Organization)
	}

	switch {
	case ignore || u.IsSet(identity.FieldRoles):
		d.Roles = s.rebuild(d.Roles, u.Roles)
	case s.d == defectRemintsUnnamedGrants:
		reminted := make([]*identity.AssignedRole, 0, len(d.Roles))
		for _, r := range d.Roles {
			reminted = append(reminted, &identity.AssignedRole{ID: s.mintGrantID(), Name: r.Name, Primary: r.Primary})
		}

		d.Roles = reminted
	}

	if s.d == defectNothingClearsName && namesNothing(u) {
		d.Name = ""
	}
}

// namesNothing reports whether u names no field at all.
func namesNothing(u *identity.NewUser) bool {
	for _, f := range []identity.Field{
		identity.FieldName, identity.FieldEmail, identity.FieldPassword, identity.FieldPasswordChangedAt,
		identity.FieldOrganization, identity.FieldRoles,
	} {
		if u.IsSet(f) {
			return false
		}
	}

	return true
}

// mintGrantID returns an identifier no other grant of this store holds.
func (s *brokenStore) mintGrantID() string {
	return "g-" + strconv.FormatInt(s.grantSeq.Add(1), 10)
}

// writeChangedAt writes the named password-changed time into d, unless the
// store's defect is to drop it.
func (s *brokenStore) writeChangedAt(d *identity.Details, u *identity.NewUser) {
	switch {
	case s.d == defectIgnoresNamedChangedAt:
	case s.d == defectKeepsChangedAtOnNamedZero && u.PasswordChangedAt.IsZero():
	default:
		d.PasswordChangedAt = u.PasswordChangedAt
	}
}

func (s *brokenStore) rebuild(
	stored []*identity.AssignedRole, names []string,
) []*identity.AssignedRole {
	survivors := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))

	for _, n := range names {
		if seen[n] || (n == "" && s.d != defectKeepsEmptyRoleNames) {
			continue
		}

		seen[n] = true
		survivors = append(survivors, n)
	}

	if !slices.ContainsFunc(survivors, func(n string) bool { return n != "" }) {
		switch s.d {
		case defectRoleStrip:
			return nil
		case defectRemintsOnEmptyRoleList:
			reminted := make([]*identity.AssignedRole, 0, len(stored))
			for _, r := range stored {
				reminted = append(reminted, &identity.AssignedRole{
					ID: s.mintGrantID(), Name: r.Name, Primary: r.Primary, SuperRole: r.SuperRole,
				})
			}

			return reminted
		}

		return stored
	}

	existing := make(map[string]*identity.AssignedRole, len(stored))
	for _, r := range stored {
		switch first := existing[r.Name]; {
		case r == nil:
		case first == nil || s.d == defectKeepsLastDuplicate:
			existing[r.Name] = r
		case s.d == defectDuplicatePromotesLater:
			promoted := *r
			promoted.ID = first.ID
			existing[r.Name] = &promoted
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

		fresh := &identity.AssignedRole{ID: s.mintGrantID(), Name: n, Primary: i == 0}
		if s.d == defectNewRoleInherits && len(stored) > 0 {
			fresh.SuperRole = stored[0].SuperRole
			fresh.StartDate = stored[0].StartDate
			fresh.ValidUntil = stored[0].ValidUntil
		}

		rebuilt = append(rebuilt, fresh)
	}

	return rebuilt
}

// orgRef keeps the reference to the organization a caller named, copied unless
// the store's defect is to hold the caller's own value, which it then resolves
// by whatever identifier that value carries at load time.
func (s *brokenStore) orgRef(o *identity.Organization) *identity.Organization {
	switch {
	case o == nil || o.ID == "":
		return nil
	case s.d == defectAliasingOrganization:
		return o
	default:
		return &identity.Organization{ID: o.ID}
	}
}

// recordLocked returns a copy of d as a caller sees it: the organization
// resolved from its reference, and the primary grant first.
func (s *brokenStore) recordLocked(d *identity.Details) *identity.Details {
	out := clonedDetails(d)
	out.Organization = nil

	if d.Organization != nil {
		out.Organization = clonedOrg(s.orgs[d.Organization.ID])
	}

	if s.d == defectDropsOrganizationGroup && out.Organization != nil {
		out.Organization.Group = nil
	}

	primaryFirst(out.Roles)

	if s.d == variantOtherLocation {
		inOtherLocation(out)
	}

	return out
}

// inOtherLocation moves every non-zero time of d to otherLocation, keeping the
// instant.
func inOtherLocation(d *identity.Details) {
	move := func(tm *time.Time) {
		if !tm.IsZero() {
			*tm = tm.In(otherLocation)
		}
	}

	move(&d.PasswordChangedAt)

	for _, r := range d.Roles {
		move(&r.StartDate)
		move(&r.ValidUntil)
	}
}

// resolveInPlaceLocked resolves d's organization onto the store's own seeded
// record and hands d back, as a store aliasing its state would.
func (s *brokenStore) resolveInPlaceLocked(d *identity.Details) *identity.Details {
	if d.Organization != nil {
		if org, ok := s.orgs[d.Organization.ID]; ok {
			d.Organization = org
		} else {
			d.Organization = nil
		}
	}

	primaryFirst(d.Roles)

	return d
}

func primaryFirst(roles []*identity.AssignedRole) {
	slices.SortStableFunc(roles, func(a, b *identity.AssignedRole) int {
		switch {
		case a.Primary == b.Primary:
			return 0
		case a.Primary:
			return -1
		default:
			return 1
		}
	})
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

	cases := make([]testCase, 0, len(everyDefect)+2)

	cases = append(cases, testCase{
		name:   "a store with no defect passes",
		defect: defectNone,
		assert: func(t *testing.T, err error, output string) {
			require.NoError(t, err,
				"the suite rejected a conforming store, so every defect below fails for the "+
					"wrong reason:\n%s", output)
		},
	}, testCase{
		name:   "a store returning its times in another location passes",
		defect: variantOtherLocation,
		assert: func(t *testing.T, err error, output string) {
			require.NoError(t, err,
				"the suite compared a time's location rather than its instant, so it rejects a "+
					"conforming store whose database session is in another time zone:\n%s", output)
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
				// A failed run is not enough: a defect the preflight trips over is
				// reported as a missing hook, and the case written for it never runs.
				// It is caught only when a named case fails by assertion.
				assert.NotContains(t, output, "identitytest: required hook",
					"the %s defect stopped the run at the preflight, so no case was shown to "+
						"catch it:\n%s", d, output)
				assert.Contains(t, output, "--- FAIL: TestBrokenStoreConformance/",
					"no case of the suite failed by assertion for the %s defect:\n%s", d, output)
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

// TestConformanceSuiteRequiresEveryHook checks that a fixture lacking any one
// hook fails the run before a single case runs, with a message naming the hook.
//
// A skipped case is green in CI, and the implementations most likely to get a
// rule wrong are the ones most likely to leave out the hook that checks it; so
// a missing hook must stop the run, not thin it out.
func TestConformanceSuiteRequiresEveryHook(t *testing.T) {
	t.Parallel()

	hooks := []string{
		"SeedRole",
		"SeedMFARequired",
		"SeedRoleGrants",
		"SeedOrganization",
		"FailUserLoads",
		"FailMFALookups",
	}

	for _, hook := range hooks {
		t.Run(hook, func(t *testing.T) {
			t.Parallel()

			output, err := runSuiteInProcess(t, missingHook(hook), "-test.v")

			require.Error(t, err, "a fixture without %s passed the suite", hook)
			assert.True(t, strings.Contains(output, "identitytest: required hook "+hook+" is missing"),
				"the failure must name the missing hook %s, or the implementer is left to guess", hook)
			assert.Zero(t, strings.Count(output, "=== RUN   TestBrokenStoreConformance/"),
				"cases ran although the required hook %s was missing", hook)
		})
	}
}

// runSuiteInProcess re-executes this test binary, running only the child test
// against a store carrying d, and returns its combined output. Extra test
// flags, such as -test.v, are passed to the child.
func runSuiteInProcess(t *testing.T, d defect, flags ...string) (string, error) {
	t.Helper()

	args := append([]string{
		"-test.run=^TestBrokenStoreConformance$", "-test.count=1", "-test.timeout=5m",
	}, flags...)

	//nolint:gosec // G204: this test binary re-executed with fixed arguments
	cmd := exec.CommandContext(t.Context(), os.Args[0], args...)
	cmd.Env = append(os.Environ(), defectVar+"="+string(d))

	out, err := cmd.CombinedOutput()

	// A skip means the child never ran the suite, so the verdict below would be
	// about nothing at all.
	assert.NotContains(t, string(out), "SKIP",
		"the child skipped rather than running the suite, so nothing was checked")

	return string(out), err
}
