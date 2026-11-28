//go:build admin_stub

package admintest_test

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ascii"
	admintest "github.com/kartaladev/scrty/test/admin"
)

// defect is one deliberate flaw the toy store carries, so a guard test can
// show that the case written for it fails. One defect per store.
type defect string

const (
	defectNone defect = ""

	// The user part runs with no role, grant or assignment port and no
	// importer: its preflight must not require them.
	variantUserPortsOnly defect = "user-ports-only"
	// The import part runs with no role, grant or assignment port and no
	// provisioner.
	variantImportPortsOnly defect = "import-ports-only"

	// Each of these decides a collision or a version by a check released
	// before the write, then writes without checking again.
	defectUnlockedCreate       defect = "unlocked-create"
	defectUnlockedGrantReplace defect = "unlocked-grant-replace"
	defectUnlockedAssignment   defect = "unlocked-assignment"
	defectUnlockedImport       defect = "unlocked-import"

	// An import compares only the display name with the stored user.
	defectImportComparesNameOnly defect = "import-compares-name-only"
	// An import compares the number of roles, not their names.
	defectImportComparesRoleCount defect = "import-compares-role-count"
	// A concurrent import that finds the user just created reports it
	// updated, although the payload was identical.
	defectImportRaceReportsUpdated defect = "import-race-reports-updated"
	// An import of a deleted user's identifier restores the user.
	defectImportRestoresDeleted defect = "import-restores-deleted"
	// An import stores the identifier lower-cased, not as given.
	defectImportFoldsIdentifier defect = "import-folds-identifier"
	// An update applies whatever version the caller names.
	defectIgnoresVersionOnUpdate defect = "ignores-version-on-update"
	// An update naming the email keeps the stored verification whatever the
	// address, so a new address inherits the old one's verification.
	defectKeepsVerificationOnNewEmail defect = "keeps-verification-on-new-email"
	// An update naming the email clears the stored verification even when the
	// address is the stored one.
	defectClearsVerificationOnSameEmail defect = "clears-verification-on-same-email"
	// An update stores a verification time for a user with no email.
	defectVerifiesNoEmail defect = "verifies-no-email"

	// Removing a primary grant, or force-deleting its role, hands the mark
	// to the last remaining grant rather than the first.
	defectHandsPrimaryToLast defect = "hands-primary-to-last"
	// A forced role delete leaves the versions of the users it changed.
	defectForcedDeleteKeepsVersions defect = "forced-delete-keeps-versions"
	// A role delete without force counts deleted users as holders.
	defectCountsDeletedHolders defect = "counts-deleted-holders"

	// A no-op SetActive answers before the version is compared.
	defectNoopSetActiveSkipsVersion defect = "noop-set-active-skips-version"

	// The organization is dropped on create, kept when an update clears it.
	defectDropsOrganizationOnCreate defect = "drops-organization-on-create"
	defectKeepsOrganizationOnClear  defect = "keeps-organization-on-clear"
	// An assignment's start date is dropped.
	defectDropsStartDate defect = "drops-start-date"
	// GetUser returns grants without their dates.
	defectUndatedUserRoles defect = "undated-user-roles"

	// A cursor whose identifier is not a canonical UUID is ignored and the
	// listing restarts; a forged organization identifier is stored as none.
	defectIgnoresForgedCursor       defect = "ignores-forged-cursor"
	defectIgnoresForgedOrganization defect = "ignores-forged-organization"
	// Users are ordered and paged by the username's bytes, not lower-cased.
	defectPagesByBytes defect = "pages-by-bytes"

	// SetPassword records the replaced hash in the history itself.
	defectSetPasswordRecordsHistory defect = "set-password-records-history"
	// Deletion keeps the password history.
	defectDeleteKeepsHistory defect = "delete-keeps-history"
	// The email loader finds no one, live or deleted.
	defectBlindEmailLoader defect = "blind-email-loader"
	// A grant replacement matches existing rows of a resource by the exact
	// spelling instead of the authorizer's trimmed, case-folded one.
	defectExactResourceOnReplace defect = "exact-resource-on-replace"
	// A role update changing the super-role flag changes the catalogue only,
	// leaving the copy on every holder's grant as it was.
	defectSuperRoleStaysOnGrants defect = "super-role-stays-on-grants"
	// A role update changing the super-role flag copies it onto the holders'
	// grants without increasing their versions.
	defectSuperRoleKeepsVersions defect = "super-role-keeps-versions"
	// UpdateUser applies every other field but leaves the username as it
	// was, while still reporting the rename.
	defectRenameIgnored defect = "rename-ignored"
	// UpdateUser skips the username clash checks.
	defectRenameUnchecked defect = "rename-unchecked"
	// UpdateUser always reports renamed as false.
	defectRenamedFalse defect = "renamed-false"
	// UpdateUser always reports renamed as true, even for a change naming no
	// username or re-sending the current one.
	defectRenamedTrue defect = "renamed-true"
	// The user port does not implement admin.UserPager: a consumer store
	// that never pages by offset or counts, which must still pass the suite
	// with the offset and count cases skipped (D14).
	variantNoUserPager defect = "no-user-pager"
	// ListUsersFrom skips twice the offset it is given.
	defectOffsetTwice defect = "offset-twice"
	// CountUsers counts soft-deleted users too.
	defectCountDeleted defect = "count-deleted"
	// ListUsersFrom orders by identifier only, not by the cursor listing's
	// (lower(username), id).
	defectOffsetOrder defect = "offset-order"
)

// defectDeletedWritable is the defect under which one operation, named after
// the prefix, skips the soft-deletion filter.
const defectDeletedWritable = "deleted-writable:"

// raceWindow is how long a defective check-then-write store waits between its
// check and its write, standing in for a database round trip.
const raceWindow = 2 * time.Millisecond

// toyFixture is an in-memory implementation of every administration port,
// written for the guard tests only: one mutex serialises every call, which is
// what makes it correct, and a defect undoes exactly one rule.
type toyFixture struct{ s *toyStore }

func newToyFixture(d defect) toyFixture {
	return toyFixture{s: &toyStore{
		d:     d,
		users: map[identity.UserID]*toyUser{},
		roles: map[string]*toyRole{},
		orgs:  map[string]identity.Organization{},
		fails: map[string]string{},
		stall: map[string]toyStall{},
	}}
}

var _ admintest.Fixture = toyFixture{}

func (f toyFixture) Users() admin.UserStore {
	if f.s.d == variantNoUserPager {
		return toyUsersWithoutPager{UserStore: f.s, History: f.s}
	}

	return f.s
}

// toyUsersWithoutPager is the toy store's user port and password history
// without ListUsersFrom and CountUsers: a consumer store that never pages by
// offset or counts.
type toyUsersWithoutPager struct {
	admin.UserStore
	password.History
}

func (f toyFixture) Importer() admin.ImportStore {
	if f.s.d == variantUserPortsOnly {
		return nil
	}

	return f.s
}

func (f toyFixture) Roles() admin.RoleStore {
	if f.s.d == variantUserPortsOnly || f.s.d == variantImportPortsOnly {
		return nil
	}

	return f.s
}

func (f toyFixture) Grants() admin.GrantStore {
	if f.s.d == variantUserPortsOnly || f.s.d == variantImportPortsOnly {
		return nil
	}

	return f.s
}

func (f toyFixture) Assignments() admin.AssignmentStore {
	if f.s.d == variantUserPortsOnly || f.s.d == variantImportPortsOnly {
		return nil
	}

	return f.s
}

func (f toyFixture) Loader() identity.UserLoader { return f.s }

func (f toyFixture) Provisioner() identity.UserProvisioner {
	if f.s.d == variantImportPortsOnly {
		return nil
	}

	return f.s
}

func (f toyFixture) UserResidue(_ context.Context, id identity.UserID) (admintest.Residue, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	u, ok := f.s.users[id]
	if !ok {
		return admintest.Residue{}, nil
	}

	hist := make([][]byte, 0, len(u.history))
	for _, h := range u.history {
		hist = append(hist, bytes.Clone(h))
	}

	return admintest.Residue{
		Exists: true, Deleted: u.deleted, Active: u.active, Username: u.username, Email: u.email,
		Attributes: len(u.attrs), PasswordHistory: hist,
	}, nil
}

func (f toyFixture) SeedOrganization(_ context.Context, org *identity.Organization) error {
	if org == nil {
		return nil
	}

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	f.s.orgs[org.ID] = identity.Organization{ID: org.ID, Name: org.Name}

	return nil
}

func (f toyFixture) FailGrantWrite(_ context.Context, role, group, resource string) error {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	f.s.fails[role] = group + "/" + resource

	return nil
}

func (f toyFixture) StallGrantWrite(_ context.Context, role, group, resource string) (<-chan struct{}, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	ch := make(chan struct{})
	f.s.stall[role] = toyStall{at: group + "/" + resource, reached: ch}

	return ch, nil
}

type toyStall struct {
	at      string
	reached chan struct{}
}

type toyUser struct {
	id         identity.UserID
	username   string
	name       string
	email      string
	verifiedAt time.Time
	active     bool
	deleted    bool
	attrs      map[string]string
	org        string
	version    int64
	created    time.Time
	updated    time.Time
	hash       []byte
	changedAt  time.Time
	history    [][]byte
	grants     []*identity.AssignedRole // in position order
}

type toyRole struct {
	role   admin.Role
	grants []admin.Grant
}

type toyStore struct {
	d  defect
	mu sync.Mutex

	users map[identity.UserID]*toyUser
	roles map[string]*toyRole
	orgs  map[string]identity.Organization
	fails map[string]string
	stall map[string]toyStall
}

var (
	_ admin.UserStore          = (*toyStore)(nil)
	_ admin.ImportStore        = (*toyStore)(nil)
	_ admin.RoleStore          = (*toyStore)(nil)
	_ admin.GrantStore         = (*toyStore)(nil)
	_ admin.AssignmentStore    = (*toyStore)(nil)
	_ identity.UserLoader      = (*toyStore)(nil)
	_ identity.EmailLoader     = (*toyStore)(nil)
	_ identity.UserProvisioner = (*toyStore)(nil)
	_ password.History         = (*toyStore)(nil)
	_ admin.UserPager          = (*toyStore)(nil)
)

var errInjected = errors.New("toy store: injected storage failure")

func now() time.Time { return time.Now().UTC() }

func fold(s string) string { return strings.ToLower(s) }

// isCanonicalUUID reports whether s is a UUID in canonical lower-case text.
func isCanonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}

	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}

	return true
}

// live returns the live user with the identifier for operation op.
func (s *toyStore) live(op string, id identity.UserID) (*toyUser, error) {
	u, ok := s.users[id]
	if !ok || (u.deleted && s.d != defect(defectDeletedWritable+op)) {
		return nil, admin.ErrNotFound
	}

	return u, nil
}

func (s *toyStore) liveVersioned(op string, id identity.UserID, version int64) (*toyUser, error) {
	u, err := s.live(op, id)
	if err != nil {
		return nil, err
	}

	if u.version != version {
		return nil, admin.ErrStaleUpdate
	}

	return u, nil
}

// unlockedWindow, under the named defect, releases the lock for a moment
// between a check and the write that follows it.
func (s *toyStore) unlockedWindow(d defect) {
	if s.d != d {
		return
	}

	s.mu.Unlock()
	time.Sleep(raceWindow)
	s.mu.Lock()
}

// usernameTaken reports a username any other user has, deleted or not, or
// another live user's email, ignoring case.
func (s *toyStore) usernameTaken(name string, self identity.UserID) bool {
	for _, u := range s.users {
		if u.id == self {
			continue
		}

		if u.username == name || (!u.deleted && u.email != "" && fold(u.email) == fold(name)) {
			return true
		}
	}

	return false
}

// emailTaken reports an email another live user has, or another user's
// username, ignoring case.
func (s *toyStore) emailTaken(addr string, self identity.UserID) bool {
	if addr == "" {
		return false
	}

	for _, u := range s.users {
		if u.id == self {
			continue
		}

		if fold(u.username) == fold(addr) || (!u.deleted && u.email != "" && fold(u.email) == fold(addr)) {
			return true
		}
	}

	return false
}

func (s *toyStore) org(id string) *identity.Organization {
	if id == "" {
		return nil
	}

	o, ok := s.orgs[id]
	if !ok {
		return nil
	}

	return &o
}

// sortedGrants returns copies of the user's grants, the primary one first and
// the rest in position order.
func sortedGrants(u *toyUser, dated bool) []*identity.AssignedRole {
	out := make([]*identity.AssignedRole, 0, len(u.grants))

	for _, g := range u.grants {
		if g.Primary {
			c := *g
			out = append(out, &c)
		}
	}

	for _, g := range u.grants {
		if !g.Primary {
			c := *g
			out = append(out, &c)
		}
	}

	if !dated {
		for _, g := range out {
			g.StartDate, g.ValidUntil = time.Time{}, time.Time{}
		}
	}

	return out
}

func (s *toyStore) record(u *toyUser) admin.User {
	attrs := maps.Clone(u.attrs)
	if attrs == nil {
		attrs = map[string]string{}
	}

	return admin.User{
		ID: u.id, Username: u.username, Name: u.name, Email: u.email, EmailVerifiedAt: u.verifiedAt,
		Active: u.active, Attributes: attrs, Roles: sortedGrants(u, s.d != defectUndatedUserRoles),
		Organization: s.org(u.org), Version: u.version, CreatedAt: u.created, UpdatedAt: u.updated,
	}
}

func (s *toyStore) details(u *toyUser) *identity.Details {
	return &identity.Details{
		ID: u.id, Name: u.name, Username: u.username, Password: bytes.Clone(u.hash), Active: u.active,
		Roles: sortedGrants(u, true), Organization: s.org(u.org), PasswordChangedAt: u.changedAt,
		Email: u.email, EmailVerifiedAt: u.verifiedAt,
	}
}

func listKey(u *toyUser, d defect) string {
	if d == defectPagesByBytes {
		return u.username
	}

	return fold(u.username)
}

// matching returns the users q's filters match, live ones only unless
// deletedToo, in list order.
func (s *toyStore) matching(q admin.UserQuery, deletedToo bool) []*toyUser {
	var picked []*toyUser

	for _, u := range s.users {
		if u.deleted && !deletedToo {
			continue
		}

		if q.Search != "" {
			needle := fold(q.Search)
			if !strings.Contains(fold(u.username), needle) && !strings.Contains(fold(u.name), needle) &&
				!strings.Contains(fold(u.email), needle) {
				continue
			}
		}

		if q.Active != nil && u.active != *q.Active {
			continue
		}

		if q.Role != "" && !slices.ContainsFunc(u.grants, func(g *identity.AssignedRole) bool { return g.Name == q.Role }) {
			continue
		}

		if q.Attribute != nil {
			if v, ok := u.attrs[q.Attribute.Name]; !ok || v != q.Attribute.Value {
				continue
			}
		}

		picked = append(picked, u)
	}

	slices.SortFunc(picked, func(a, b *toyUser) int {
		return cmp.Or(strings.Compare(listKey(a, s.d), listKey(b, s.d)), strings.Compare(string(a.id), string(b.id)))
	})

	return picked
}

func (s *toyStore) ListUsers(_ context.Context, q admin.UserQuery) ([]admin.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if q.Limit < 1 {
		return nil, admin.ErrInvalidInput
	}

	picked := s.matching(q, false)

	honourCursor := q.AfterUsername != "" &&
		!(s.d == defectIgnoresForgedCursor && !isCanonicalUUID(string(q.AfterID)))

	afterKey := fold(q.AfterUsername)
	if s.d == defectPagesByBytes {
		afterKey = q.AfterUsername
	}

	out := make([]admin.User, 0, q.Limit)

	for _, u := range picked {
		if honourCursor {
			c := cmp.Or(strings.Compare(listKey(u, s.d), afterKey), strings.Compare(string(u.id), string(q.AfterID)))
			if c <= 0 {
				continue
			}
		}

		out = append(out, s.record(u))
		if len(out) == q.Limit {
			break
		}
	}

	return out, nil
}

// ListUsersFrom implements admin.UserPager.
func (s *toyStore) ListUsersFrom(_ context.Context, q admin.UserQuery, offset int) ([]admin.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if q.Limit < 1 || offset < 0 || q.AfterUsername != "" || q.AfterID != "" {
		return nil, admin.ErrInvalidInput
	}

	picked := s.matching(q, false)

	if s.d == defectOffsetOrder {
		slices.SortFunc(picked, func(a, b *toyUser) int { return strings.Compare(string(a.id), string(b.id)) })
	}

	if s.d == defectOffsetTwice {
		offset *= 2
	}

	if offset >= len(picked) {
		return []admin.User{}, nil
	}

	picked = picked[offset:]
	out := make([]admin.User, 0, min(q.Limit, len(picked)))

	for _, u := range picked[:min(q.Limit, len(picked))] {
		out = append(out, s.record(u))
	}

	return out, nil
}

// CountUsers implements admin.UserPager.
func (s *toyStore) CountUsers(_ context.Context, q admin.UserQuery) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return int64(len(s.matching(q, s.d == defectCountDeleted))), nil
}

func (s *toyStore) GetUser(_ context.Context, id identity.UserID) (admin.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, err := s.live("GetUser", id)
	if err != nil {
		return admin.User{}, err
	}

	return s.record(u), nil
}

func (s *toyStore) CreateUser(_ context.Context, in admin.NewUser) (admin.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[in.ID]; ok {
		return admin.User{}, admin.AlreadyExistsError{Field: "id"}
	}

	if s.usernameTaken(in.Username, in.ID) {
		return admin.User{}, admin.AlreadyExistsError{Field: admin.FieldUsername}
	}

	if s.emailTaken(in.Email, in.ID) {
		return admin.User{}, admin.AlreadyExistsError{Field: admin.FieldEmail}
	}

	s.unlockedWindow(defectUnlockedCreate)

	var org string
	if in.Organization != nil && !(s.d == defectDropsOrganizationOnCreate ||
		(s.d == defectIgnoresForgedOrganization && !isCanonicalUUID(in.Organization.ID))) {
		org = in.Organization.ID
	}

	t := now()
	u := &toyUser{
		id: in.ID, username: in.Username, name: in.Name, email: in.Email, verifiedAt: in.EmailVerifiedAt,
		active: true, attrs: maps.Clone(in.Attributes), org: org, version: 1, created: t, updated: t,
	}
	s.users[in.ID] = u

	return s.record(u), nil
}

// applyChange applies every field of c but the username to u, the locked live
// user, and increases the version. It refuses before writing anything.
func (s *toyStore) applyChange(u *toyUser, c admin.UserChange) error {
	if c.Email != nil && s.emailTaken(*c.Email, u.id) {
		return admin.AlreadyExistsError{Field: admin.FieldEmail}
	}

	emailLeft := u.email
	if c.Email != nil {
		emailLeft = *c.Email
	}

	if c.EmailVerifiedAt != nil && !c.EmailVerifiedAt.IsZero() && emailLeft == "" && s.d != defectVerifiesNoEmail {
		return admin.ErrInvalidInput
	}

	if c.Name != nil {
		u.name = *c.Name
	}

	if c.Email != nil {
		sameAddress := strings.EqualFold(*c.Email, u.email) && u.email != ""
		switch {
		case c.EmailVerifiedAt != nil, s.d == defectKeepsVerificationOnNewEmail:
		case s.d == defectClearsVerificationOnSameEmail, !sameAddress:
			u.verifiedAt = time.Time{}
		}

		u.email = *c.Email
	}

	if c.EmailVerifiedAt != nil {
		u.verifiedAt = *c.EmailVerifiedAt
	}

	if c.Attributes != nil {
		u.attrs = maps.Clone(c.Attributes)
	}

	if c.Organization != nil {
		switch org := *c.Organization; {
		case org == nil:
			if s.d != defectKeepsOrganizationOnClear {
				u.org = ""
			}
		case s.d == defectIgnoresForgedOrganization && !isCanonicalUUID(org.ID):
			u.org = ""
		default:
			u.org = org.ID
		}
	}

	u.version++
	u.updated = now()

	return nil
}

// UpdateUser implements admin.UserStore. Under the one lock, it checks the
// version and, when the change names one, the username, applies the other
// fields, and writes the username last, so a refusal writes nothing. A change
// naming no username reports no rename.
func (s *toyStore) UpdateUser(
	_ context.Context, id identity.UserID, version int64, c admin.UserChange,
) (admin.User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, err := s.liveVersioned("UpdateUser", id, version)
	if s.d == defectIgnoresVersionOnUpdate {
		u, err = s.live("UpdateUser", id)
	}
	if err != nil {
		return admin.User{}, false, err
	}

	if c.Username != nil && s.d != defectRenameUnchecked && s.renameTaken(*c.Username, id) {
		return admin.User{}, false, admin.AlreadyExistsError{Field: admin.FieldUsername}
	}

	if err := s.applyChange(u, c); err != nil {
		return admin.User{}, false, err
	}

	renamed := false
	if c.Username != nil {
		renamed = u.username != *c.Username
		if s.d != defectRenameIgnored {
			u.username = *c.Username
		}
	}

	if s.d == defectRenamedFalse {
		renamed = false
	}

	if s.d == defectRenamedTrue {
		renamed = true
	}

	return s.record(u), renamed, nil
}

// renameTaken reports a username another user holds, deleted or not,
// compared exactly, or another live user's email, ignoring case: the rule of
// a rename (D4).
func (s *toyStore) renameTaken(name string, self identity.UserID) bool {
	for _, u := range s.users {
		if u.id == self {
			continue
		}

		if u.username == name || (!u.deleted && u.email != "" && fold(u.email) == fold(name)) {
			return true
		}
	}

	return false
}

func (s *toyStore) SetActive(_ context.Context, id identity.UserID, version int64, active bool) (admin.User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.d == defectNoopSetActiveSkipsVersion {
		if u, err := s.live("SetActive", id); err == nil && u.active == active {
			return s.record(u), false, nil
		}
	}

	u, err := s.liveVersioned("SetActive", id, version)
	if err != nil {
		return admin.User{}, false, err
	}

	if u.active == active {
		return s.record(u), false, nil
	}

	u.active = active
	u.version++
	u.updated = now()

	return s.record(u), true, nil
}

func (s *toyStore) DeleteUser(_ context.Context, id identity.UserID, version int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, err := s.liveVersioned("DeleteUser", id, version)
	if err != nil {
		return err
	}

	u.deleted, u.active, u.email, u.attrs = true, false, "", nil
	if s.d != defectDeleteKeepsHistory {
		u.history = nil
	}

	u.version++
	u.updated = now()

	return nil
}

func (s *toyStore) CurrentPasswordHash(_ context.Context, id identity.UserID) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, err := s.live("CurrentPasswordHash", id)
	if err != nil {
		return nil, err
	}

	return bytes.Clone(u.hash), nil
}

func (s *toyStore) SetPassword(_ context.Context, id identity.UserID, version int64, hash []byte, at time.Time) (admin.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, err := s.liveVersioned("SetPassword", id, version)
	if err != nil {
		return admin.User{}, err
	}

	if s.d == defectSetPasswordRecordsHistory && len(u.hash) > 0 {
		u.history = append(u.history, u.hash)
	}

	u.hash = bytes.Clone(hash)
	u.changedAt = at
	u.version++
	u.updated = now()

	return s.record(u), nil
}

// RecentPasswords, RetirePassword and ForgetPasswords make the toy store a
// password.History, through which the suite seeds history.
func (s *toyStore) RecentPasswords(_ context.Context, id identity.UserID, limit int) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[id]
	if !ok {
		return [][]byte{}, nil
	}

	out := make([][]byte, 0, min(limit, len(u.history)))
	for i := len(u.history) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, bytes.Clone(u.history[i]))
	}

	return out, nil
}

func (s *toyStore) RetirePassword(_ context.Context, id identity.UserID, hash []byte, keep int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, err := s.live("RetirePassword", id)
	if err != nil {
		return err
	}

	if n := len(u.history); n == 0 || !bytes.Equal(u.history[n-1], hash) {
		u.history = append(u.history, bytes.Clone(hash))
	}

	if len(u.history) > keep {
		u.history = u.history[len(u.history)-keep:]
	}

	return nil
}

func (s *toyStore) ForgetPasswords(_ context.Context, id identity.UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if u, ok := s.users[id]; ok {
		u.history = nil
	}

	return nil
}

func (s *toyStore) newGrant(role string, primary bool, start, end time.Time) (*identity.AssignedRole, error) {
	r, ok := s.roles[role]
	if !ok {
		return nil, admin.ErrNotFound
	}

	return &identity.AssignedRole{
		ID: rand.Text(), Name: role, Primary: primary, SuperRole: r.role.SuperRole, StartDate: start, ValidUntil: end,
	}, nil
}

func roleNames(u *toyUser) []string {
	out := make([]string, 0, len(u.grants))
	for _, g := range u.grants {
		out = append(out, g.Name)
	}

	slices.Sort(out)

	return out
}

// importDiffers reports whether the payload differs from the stored user in
// any field the import writes.
func (s *toyStore) importDiffers(u *toyUser, in admin.ImportedUser) bool {
	if s.d == defectImportComparesNameOnly {
		return u.name != in.Name
	}

	want := slices.Sorted(slices.Values(in.Roles))
	rolesDiffer := !slices.Equal(roleNames(u), want)

	if s.d == defectImportComparesRoleCount {
		rolesDiffer = len(u.grants) != len(in.Roles)
	}

	return u.username != in.Username || u.name != in.Name || u.email != in.Email ||
		!u.verifiedAt.Equal(in.EmailVerifiedAt) || !bytes.Equal(u.hash, in.PasswordHash) ||
		u.active != in.Active || !u.created.Equal(in.CreatedAt) || !u.updated.Equal(in.UpdatedAt) ||
		rolesDiffer || !maps.Equal(u.attrs, in.Attributes)
}

func (s *toyStore) ImportUser(_ context.Context, in admin.ImportedUser) (admin.ImportOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.d == defectImportFoldsIdentifier {
		in.ID = identity.UserID(strings.ToLower(string(in.ID)))
	}

	for _, r := range in.Roles {
		if _, ok := s.roles[r]; !ok {
			return 0, admin.ErrNotFound
		}
	}

	if s.usernameTaken(in.Username, in.ID) {
		return 0, admin.AlreadyExistsError{Field: admin.FieldUsername}
	}

	if s.emailTaken(in.Email, in.ID) {
		return 0, admin.AlreadyExistsError{Field: admin.FieldEmail}
	}

	u, exists := s.users[in.ID]
	if exists && u.deleted && s.d != defectImportRestoresDeleted {
		return 0, admin.AlreadyExistsError{Field: "id"}
	}

	if !exists {
		s.unlockedWindow(defectUnlockedImport)
	}

	outcome := admin.ImportCreated

	switch {
	case !exists:
		u = &toyUser{id: in.ID}
	case s.d == defectImportRaceReportsUpdated && u.version == 1:
		return admin.ImportUpdated, nil
	case !s.importDiffers(u, in) && !u.deleted:
		return admin.ImportUnchanged, nil
	default:
		outcome = admin.ImportUpdated
	}

	grants := make([]*identity.AssignedRole, 0, len(in.Roles))
	for i, r := range in.Roles {
		g, err := s.newGrant(r, i == 0, time.Time{}, time.Time{})
		if err != nil {
			return 0, err
		}

		grants = append(grants, g)
	}

	u.username, u.name, u.email, u.verifiedAt = in.Username, in.Name, in.Email, in.EmailVerifiedAt
	u.hash, u.active, u.created, u.updated = bytes.Clone(in.PasswordHash), in.Active, in.CreatedAt, in.UpdatedAt
	u.attrs, u.grants, u.deleted = maps.Clone(in.Attributes), grants, false
	u.version++
	s.users[in.ID] = u

	return outcome, nil
}

func (s *toyStore) assigned(role string, deletedToo bool) int {
	n := 0

	for _, u := range s.users {
		if u.deleted && !deletedToo {
			continue
		}

		if slices.ContainsFunc(u.grants, func(g *identity.AssignedRole) bool { return g.Name == role }) {
			n++
		}
	}

	return n
}

func (s *toyStore) roleRecord(r *toyRole) admin.Role {
	out := r.role
	out.Labels = slices.Clone(r.role.Labels)
	out.Assigned = s.assigned(r.role.Name, false)

	return out
}

func (s *toyStore) ListRoles(_ context.Context, label string) ([]admin.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []admin.Role

	for _, r := range s.roles {
		if label != "" && !slices.Contains(r.role.Labels, label) {
			continue
		}

		out = append(out, s.roleRecord(r))
	}

	slices.SortFunc(out, func(a, b admin.Role) int { return strings.Compare(a.Name, b.Name) })

	return out, nil
}

func (s *toyStore) GetRole(_ context.Context, name string) (admin.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.roles[name]
	if !ok {
		return admin.Role{}, admin.ErrNotFound
	}

	return s.roleRecord(r), nil
}

func (s *toyStore) CreateRole(_ context.Context, role admin.Role) (admin.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.roles[role.Name]; ok {
		return admin.Role{}, admin.AlreadyExistsError{Field: admin.FieldRole}
	}

	role.Version, role.Assigned, role.Labels = 1, 0, slices.Clone(role.Labels)
	r := &toyRole{role: role}
	s.roles[role.Name] = r

	return s.roleRecord(r), nil
}

func (s *toyStore) UpdateRole(_ context.Context, name string, version int64, c admin.RoleChange) (admin.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.roles[name]
	if !ok {
		return admin.Role{}, admin.ErrNotFound
	}

	if r.role.Version != version {
		return admin.Role{}, admin.ErrStaleUpdate
	}

	if c.DisplayName != nil {
		r.role.DisplayName = *c.DisplayName
	}

	if c.Description != nil {
		r.role.Description = *c.Description
	}

	if c.Labels != nil {
		r.role.Labels = slices.Clone(*c.Labels)
	}

	if c.SuperRole != nil && *c.SuperRole != r.role.SuperRole {
		r.role.SuperRole = *c.SuperRole
		s.copySuperRole(name, r.role.SuperRole)
	}

	r.role.Version++

	return s.roleRecord(r), nil
}

// copySuperRole sets the flag on every grant of role, and increases the
// version of each user holding one, deleted or not, as the SQL stores do.
func (s *toyStore) copySuperRole(role string, flag bool) {
	if s.d == defectSuperRoleStaysOnGrants {
		return
	}

	for _, u := range s.users {
		held := false
		for _, g := range u.grants {
			if g.Name == role {
				g.SuperRole, held = flag, true
			}
		}

		if held && s.d != defectSuperRoleKeepsVersions {
			u.version++
			u.updated = now()
		}
	}
}

// handOver makes a remaining grant primary when none is: the one with the
// lowest position, or the last one under defectHandsPrimaryToLast.
func (s *toyStore) handOver(u *toyUser) {
	if len(u.grants) == 0 || slices.ContainsFunc(u.grants, func(g *identity.AssignedRole) bool { return g.Primary }) {
		return
	}

	heir := u.grants[0]
	if s.d == defectHandsPrimaryToLast {
		heir = u.grants[len(u.grants)-1]
	}

	heir.Primary = true
}

func (s *toyStore) DeleteRole(_ context.Context, name string, version int64, force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.roles[name]
	if !ok {
		return admin.ErrNotFound
	}

	if r.role.Version != version {
		return admin.ErrStaleUpdate
	}

	if !force && s.assigned(name, s.d == defectCountsDeletedHolders) > 0 {
		return admin.ErrStillAssigned
	}

	for _, u := range s.users {
		kept := slices.DeleteFunc(slices.Clone(u.grants), func(g *identity.AssignedRole) bool { return g.Name == name })
		if len(kept) == len(u.grants) {
			continue
		}

		u.grants = kept
		s.handOver(u)

		if !u.deleted && s.d != defectForcedDeleteKeepsVersions {
			u.version++
			u.updated = now()
		}
	}

	delete(s.roles, name)

	return nil
}

func (s *toyStore) GetGrants(_ context.Context, role string) ([]admin.Grant, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.roles[role]
	if !ok {
		return nil, 0, admin.ErrNotFound
	}

	return slices.Clone(r.grants), r.role.Version, nil
}

// grantKey is a group and resource as the authorizer reads them: surrounding
// ASCII space trimmed, ASCII case ignored.
func grantKey(group, resource string) string {
	return ascii.ToLower(ascii.TrimSpace(group)) + "/" + ascii.ToLower(ascii.TrimSpace(resource))
}

func (s *toyStore) ReplaceGrants(ctx context.Context, role string, version int64, resources []admin.ResourceGrants) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.roles[role]
	if !ok {
		return 0, admin.ErrNotFound
	}

	if r.role.Version != version {
		return 0, admin.ErrStaleUpdate
	}

	seen := make(map[string]struct{}, len(resources))

	for _, rg := range resources {
		if rg.Resource == "" {
			return 0, admin.ErrInvalidInput
		}

		for _, g := range rg.Grants {
			if g.Privilege == "" {
				return 0, admin.ErrInvalidInput
			}
		}

		key := grantKey(rg.Group, rg.Resource)
		if _, dup := seen[key]; dup {
			return 0, admin.ErrInvalidInput
		}

		seen[key] = struct{}{}
	}

	s.unlockedWindow(defectUnlockedGrantReplace)

	grants := slices.Clone(r.grants)

	for _, rg := range resources {
		at := rg.Group + "/" + rg.Resource
		grants = slices.DeleteFunc(grants, func(g admin.Grant) bool {
			if s.d == defectExactResourceOnReplace {
				return g.Group == rg.Group && g.Resource == rg.Resource
			}

			return grantKey(g.Group, g.Resource) == grantKey(rg.Group, rg.Resource)
		})

		if s.fails[role] == at {
			return 0, errInjected
		}

		if st, ok := s.stall[role]; ok && st.at == at {
			delete(s.stall, role)
			close(st.reached)
			<-ctx.Done()

			return 0, ctx.Err()
		}

		for _, g := range rg.Grants {
			g.Group, g.Resource = rg.Group, rg.Resource
			grants = append(grants, g)
		}
	}

	r.grants = grants
	r.role.Version++

	return r.role.Version, nil
}

func (s *toyStore) ListAssignments(_ context.Context, id identity.UserID) ([]*identity.AssignedRole, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, err := s.live("ListAssignments", id)
	if err != nil {
		return nil, 0, err
	}

	return sortedGrants(u, true), u.version, nil
}

func (s *toyStore) AddAssignment(_ context.Context, id identity.UserID, version int64, a admin.Assignment) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, err := s.liveVersioned("AddAssignment", id, version)
	if err != nil {
		return 0, err
	}

	s.unlockedWindow(defectUnlockedAssignment)

	start := a.Start
	if s.d == defectDropsStartDate {
		start = time.Time{}
	}

	g, err := s.newGrant(a.Role, a.Primary, start, a.End)
	if err != nil {
		return 0, err
	}

	if a.Primary {
		for _, other := range u.grants {
			other.Primary = false
		}
	}

	u.grants = append(u.grants, g)
	u.version++
	u.updated = now()

	return u.version, nil
}

func (s *toyStore) RemoveAssignment(_ context.Context, id identity.UserID, version int64, grantID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, err := s.liveVersioned("RemoveAssignment", id, version)
	if err != nil {
		return 0, err
	}

	i := slices.IndexFunc(u.grants, func(g *identity.AssignedRole) bool { return g.ID == grantID })
	if i < 0 {
		return 0, admin.ErrNotFound
	}

	u.grants = slices.Delete(slices.Clone(u.grants), i, i+1)
	s.handOver(u)
	u.version++
	u.updated = now()

	return u.version, nil
}

func (s *toyStore) SetPrimary(_ context.Context, id identity.UserID, version int64, grantID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, err := s.liveVersioned("SetPrimary", id, version)
	if err != nil {
		return 0, err
	}

	if !slices.ContainsFunc(u.grants, func(g *identity.AssignedRole) bool { return g.ID == grantID }) {
		return 0, admin.ErrNotFound
	}

	for _, g := range u.grants {
		g.Primary = g.ID == grantID
	}

	u.version++
	u.updated = now()

	return u.version, nil
}

func (s *toyStore) LoadByUsername(_ context.Context, username string) (*identity.Details, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if !u.deleted && u.username == username {
			return s.details(u), nil
		}
	}

	return nil, identity.ErrUserNotFound
}

func (s *toyStore) LoadByUserID(_ context.Context, id identity.UserID) (*identity.Details, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[id]
	if !ok || u.deleted {
		return nil, identity.ErrUserNotFound
	}

	return s.details(u), nil
}

func (s *toyStore) LoadByEmail(_ context.Context, addr string) (*identity.Details, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.d == defectBlindEmailLoader {
		return nil, identity.ErrUserNotFound
	}

	for _, u := range s.users {
		if !u.deleted && u.email != "" && !u.verifiedAt.IsZero() && fold(u.email) == fold(addr) {
			return s.details(u), nil
		}
	}

	return nil, identity.ErrUserNotFound
}

func (s *toyStore) Provision(_ context.Context, username string, opts ...identity.UserOption) (*identity.Details, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.usernameTaken(username, "") {
		return nil, identity.ErrUserExists
	}

	c := identity.ApplyUserOptions(opts...)
	t := now()
	u := &toyUser{
		id: identity.UserID(rand.Text()), username: username, name: c.Name, active: true, version: 1,
		created: t, updated: t, hash: bytes.Clone(c.Password), changedAt: c.PasswordChangedAt,
	}
	s.users[u.id] = u

	return s.details(u), nil
}

func (s *toyStore) Update(_ context.Context, username string, opts ...identity.UserOption) (*identity.Details, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var u *toyUser

	for _, cand := range s.users {
		if !cand.deleted && cand.username == username {
			u = cand
		}
	}

	if u == nil {
		return nil, identity.ErrUserNotFound
	}

	c := identity.ApplyUserOptions(opts...)
	if c.IsSet(identity.FieldName) {
		u.name = c.Name
	}

	if c.IsSet(identity.FieldPassword) {
		u.hash = bytes.Clone(c.Password)
	}

	if c.IsSet(identity.FieldPasswordChangedAt) {
		u.changedAt = c.PasswordChangedAt
	}

	u.version++
	u.updated = now()

	return s.details(u), nil
}
