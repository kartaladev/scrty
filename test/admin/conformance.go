package admintest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
)

// RunConformanceSuite checks an implementation of scrty's administration ports
// against every contract the administration services rely on: it runs the
// user, import and role parts, after a preflight that requires every port and
// hook any of them uses.
//
// A consumer implementing the ports over their own tables calls it from their
// own test:
//
//	func TestMyAdminStoreConformance(t *testing.T) {
//	    admintest.RunConformanceSuite(t, func(t *testing.T) admintest.Fixture {
//	        return newMyAdminFixture(t)
//	    })
//	}
func RunConformanceSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	requireUsableFixture(t, newFixture, partUsers|partImport|partRoles)

	t.Run("Users", func(t *testing.T) { runUserSuite(t, newFixture) })
	t.Run("Import", func(t *testing.T) { runImportSuite(t, newFixture) })
	t.Run("Roles", func(t *testing.T) { runRoleSuite(t, newFixture) })
}

// RunUserSuite checks the user administration port alone. Its preflight
// requires the Users, Loader and Provisioner ports and the UserResidue and
// SeedOrganization hooks, and a way to seed password history (see
// HistorySeeder). Roles, Grants, Assignments and Importer may be nil, and the
// grant hooks unsupported: every case that needs a role runs in RunRoleSuite.
func RunUserSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	requireUsableFixture(t, newFixture, partUsers)
	runUserSuite(t, newFixture)
}

// RunImportSuite checks the import port alone. Its preflight requires the
// Importer, Users and Loader ports and the UserResidue hook. Roles, Grants,
// Assignments and Provisioner may be nil, and the other hooks unsupported:
// the import cases that name roles run in RunRoleSuite.
func RunImportSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	requireUsableFixture(t, newFixture, partImport)
	runImportSuite(t, newFixture)
}

// RunRoleSuite checks the role, grant and assignment ports, and the parts of
// the user and import ports that concern role grants. Its preflight requires
// the Roles, Grants, Assignments, Users, Importer and Loader ports and the
// FailGrantWrite and StallGrantWrite hooks. Provisioner may be nil, and the
// other hooks unsupported.
func RunRoleSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	requireUsableFixture(t, newFixture, partRoles)
	runRoleSuite(t, newFixture)
}

// part is a set of the suite's parts, naming what a preflight requires.
type part uint8

const (
	partUsers part = 1 << iota
	partImport
	partRoles
)

// requireUsableFixture fails the whole run, before any case, when the factory
// cannot produce a fixture, or a port or hook one of the parts uses is
// missing, so the reason is reported once rather than as a scatter of case
// failures. A port or hook no part in parts uses is not checked.
func requireUsableFixture(t *testing.T, newFixture Factory, parts part) {
	t.Helper()

	require.NotNil(t, newFixture, "the suite needs a factory to build the implementation under test")

	f := newFixture(t)
	require.NotNil(t, f, "the factory returned no fixture, so no contract can be checked")

	all := partUsers | partImport | partRoles
	ports := []struct {
		name  string
		need  part
		isNil func() bool
	}{
		{"Users", all, func() bool { return f.Users() == nil }},
		{"Importer", partImport | partRoles, func() bool { return f.Importer() == nil }},
		{"Roles", partRoles, func() bool { return f.Roles() == nil }},
		{"Grants", partRoles, func() bool { return f.Grants() == nil }},
		{"Assignments", partRoles, func() bool { return f.Assignments() == nil }},
		{"Loader", all, func() bool { return f.Loader() == nil }},
		{"Provisioner", partUsers, func() bool { return f.Provisioner() == nil }},
	}
	for _, p := range ports {
		if p.need&parts != 0 && p.isNil() {
			t.Errorf("admintest: the fixture returned no %s port", p.name)
		}
	}

	if t.Failed() {
		t.FailNow()
	}

	ctx := t.Context()
	probe := "probe-" + tag(t) + "-" + rand.Text()[:8]

	hooks := []struct {
		name string
		need part
		call func() error
	}{
		{"UserResidue", partUsers | partImport, func() error {
			r, err := f.UserResidue(ctx, newUserID(t))
			if err == nil && r.Exists {
				return errors.New("an identifier no record has was reported as existing")
			}

			return err
		}},
		{"SeedOrganization", partUsers, func() error {
			return f.SeedOrganization(ctx, &identity.Organization{ID: string(newUserID(t)), Name: "probe"})
		}},
		{"SeedPasswordHistory", partUsers, func() error {
			if historySeeder(f) == nil {
				return ErrHookUnsupported
			}

			return nil
		}},
		{"FailGrantWrite", partRoles, func() error { return f.FailGrantWrite(ctx, probe, "probe", "probe") }},
		{"StallGrantWrite", partRoles, func() error {
			_, err := f.StallGrantWrite(ctx, probe, "probe", "probe")

			return err
		}},
	}

	for _, h := range hooks {
		if h.need&parts == 0 {
			continue
		}

		switch err := h.call(); {
		case errors.Is(err, ErrHookUnsupported):
			t.Errorf("admintest: required hook %s is missing", h.name)
		case err != nil:
			t.Errorf("admintest: required hook %s failed on the preflight probe: %v", h.name, err)
		}
	}

	if t.Failed() {
		t.FailNow()
	}
}

// historyKeep is how many retired hashes the suite keeps when it seeds
// password history through a store's password.History.
const historyKeep = 5

// historySeeder returns how the suite seeds one retired password hash for a
// user: the fixture's own HistorySeeder when it is one, otherwise the user
// store's RetirePassword when the store implements password.History, and nil
// when neither is offered.
func historySeeder(f Fixture) func(ctx context.Context, id identity.UserID, hash []byte) error {
	if s, ok := f.(HistorySeeder); ok {
		return s.SeedPasswordHistory
	}

	if h, ok := f.Users().(password.History); ok {
		return func(ctx context.Context, id identity.UserID, hash []byte) error {
			return h.RetirePassword(ctx, id, hash, historyKeep)
		}
	}

	return nil
}

// The times the suite stores. They are whole seconds in UTC, because a store
// may keep less than nanosecond precision; the suite compares with Equal.
var (
	importCreatedAt = time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	importUpdatedAt = time.Date(2022, 8, 9, 10, 11, 12, 0, time.UTC)
	passwordSetAt   = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	verifiedAt      = time.Date(2029, 5, 6, 7, 8, 9, 0, time.UTC)
)

// adminReasons are the administration sentinels. A storage failure matches
// none of them.
var adminReasons = []error{
	admin.ErrNotFound, admin.ErrAlreadyExists, admin.ErrStillAssigned, admin.ErrStaleUpdate,
	admin.ErrUnknownPrivilege, admin.ErrInvalidInput, admin.ErrNoActor, admin.ErrConfig,
}

// reasonOf names the administration sentinel err matches, or "none".
func reasonOf(err error) string {
	for _, r := range adminReasons {
		if errors.Is(err, r) {
			return r.Error()
		}
	}

	return "none"
}

// fieldID is the field an AlreadyExistsError names when an import names the
// identifier of a soft-deleted user (design, "Store rules fixed while writing
// the administration conformance suite"). The admin package declares no
// constant for it.
const fieldID = "id"

// requireAlreadyExists requires err to be an AlreadyExistsError naming field.
func requireAlreadyExists(t *testing.T, err error, field, msg string) {
	t.Helper()

	require.ErrorIs(t, err, admin.ErrAlreadyExists, msg)

	var ae admin.AlreadyExistsError
	require.ErrorAs(t, err, &ae, "%s: the error must be an admin.AlreadyExistsError naming the field", msg)
	assert.Equal(t, field, ae.Field, "%s: the error names the wrong field", msg)
}

// tag returns 12 hex characters unique to the case and to this run of it, so
// cases sharing one database, or a database that outlives the run, never meet
// each other's rows.
func tag(t *testing.T) string {
	t.Helper()

	sum := sha256.Sum256([]byte(runNonce(t) + "\x00" + t.Name()))

	return hex.EncodeToString(sum[:])[:12]
}

// username returns a username unique to the case and run, short enough for a
// varchar(64) column.
func username(t *testing.T, i int) string {
	t.Helper()

	return "u-" + tag(t) + "-" + strconv.Itoa(i)
}

// email returns an email address unique to the case and run.
func email(t *testing.T, i int) string {
	t.Helper()

	return "m-" + tag(t) + "-" + strconv.Itoa(i) + "@example.com"
}

// roleName returns a role name unique to the case and run.
func roleName(t *testing.T, label string) string {
	t.Helper()

	return "r-" + tag(t) + "-" + label
}

// letterTag returns tag(t) spelled in the letters a to p only, so a name
// built from it sorts the same under every collation: a database collation
// may weigh digits and punctuation differently from a byte comparison.
func letterTag(t *testing.T) string {
	t.Helper()

	b := []byte(tag(t))
	for i, c := range b {
		if c >= '0' && c <= '9' {
			b[i] = 'g' + (c - '0')
		}
	}

	return string(b)
}

// newUserID returns a fresh canonical lower-case UUID (version 4).
func newUserID(t *testing.T) identity.UserID {
	t.Helper()

	var b [16]byte

	_, err := rand.Read(b[:])
	require.NoError(t, err)

	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])

	return identity.UserID(h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32])
}

// runNonces holds the nonce of each running test, keyed by its *testing.T.
var runNonces sync.Map

// runNonce returns the nonce of this run of t, drawn from crypto/rand on
// first use: the test name alone repeats under go test -count=2.
func runNonce(t *testing.T) string {
	t.Helper()

	if n, ok := runNonces.Load(t); ok {
		return n.(string)
	}

	n, loaded := runNonces.LoadOrStore(t, rand.Text())
	if !loaded {
		t.Cleanup(func() { runNonces.Delete(t) })
	}

	return n.(string)
}

// raceRounds is how many times a race case repeats its race, each round over
// fresh records. One round can pass by luck of scheduling against a store
// that decides a collision or a version by a read it releases before the
// write; eight rounds make that luck unlikely.
const raceRounds = 8

// raceBound is how long together waits for every call of one round. A store
// that deadlocks two writers fails the case at this bound instead of hanging
// the run until go test's own timeout.
const raceBound = 30 * time.Second

// together runs fn n times concurrently, releasing every goroutine at once by
// closing one channel, and returns each call's error by index. It fails the
// case when the calls have not all returned within raceBound; the calls still
// blocked then are left behind, since a store that never returns cannot be
// stopped from here.
func together(t *testing.T, n int, fn func(i int) error) []error {
	t.Helper()

	errs := make([]error, n)
	start := make(chan struct{})
	done := make(chan struct{})

	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start

			errs[i] = fn(i)
		})
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	close(start)

	timer := time.NewTimer(raceBound)
	defer timer.Stop()

	select {
	case <-done:
	case <-timer.C:
		require.FailNowf(t, "concurrent writes did not return",
			"%d concurrent calls had not all returned after %v: the store deadlocks or never "+
				"releases a lock", n, raceBound)
	}

	return errs
}

// mustCreateUser creates a user with a fresh identifier and the given
// username, through the port under test.
func mustCreateUser(ctx context.Context, t *testing.T, f Fixture, nu admin.NewUser) admin.User {
	t.Helper()

	if nu.ID == "" {
		nu.ID = newUserID(t)
	}

	u, err := f.Users().CreateUser(ctx, nu)
	require.NoError(t, err, "the case could not create the user it needs")
	require.Equal(t, nu.ID, u.ID, "CreateUser must store the user under the identifier it was given")

	return u
}

// mustGetUser reads a live user through the port under test.
func mustGetUser(ctx context.Context, t *testing.T, f Fixture, id identity.UserID) admin.User {
	t.Helper()

	u, err := f.Users().GetUser(ctx, id)
	require.NoError(t, err, "the case could not read back a user it created")

	return u
}

// mustCreateRole creates a role named name through the port under test.
func mustCreateRole(ctx context.Context, t *testing.T, f Fixture, name string, labels ...string) admin.Role {
	t.Helper()

	r, err := f.Roles().CreateRole(ctx, admin.Role{Name: name, DisplayName: "Role " + name, Labels: labels})
	require.NoError(t, err, "the case could not create the role it needs")

	return r
}

// mustAssign grants role to the user and returns the user's new version.
func mustAssign(ctx context.Context, t *testing.T, f Fixture, id identity.UserID, version int64,
	a admin.Assignment,
) int64 {
	t.Helper()

	v, err := f.Assignments().AddAssignment(ctx, id, version, a)
	require.NoError(t, err, "the case could not assign the role it needs")
	require.Greater(t, v, version, "AddAssignment must increase the user's version")

	return v
}

// grantOf returns the user's grant of role, failing the case when there is
// none.
func grantOf(t *testing.T, roles []*identity.AssignedRole, role string) *identity.AssignedRole {
	t.Helper()

	for _, r := range roles {
		if r != nil && r.Name == role {
			return r
		}
	}

	require.Failf(t, "grant missing", "the user holds no grant of the role %s", role)

	return nil
}

// primaries returns the names of the user's primary grants.
func primaries(roles []*identity.AssignedRole) []string {
	var out []string

	for _, r := range roles {
		if r != nil && r.Primary {
			out = append(out, r.Name)
		}
	}

	return out
}

// waitFor waits for ch to close, failing the case after a bound so a hook
// that never fires cannot hang the run.
func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		require.FailNow(t, fmt.Sprintf("timed out waiting for %s", what))
	}
}
