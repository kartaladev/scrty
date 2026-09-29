package gormstore_test

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/migrate"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test"
)

// migratedIdentityDB starts PostgreSQL with both migration sets applied, the
// security-state set first and the identity set second, as a consumer wiring
// the default identity store deploys them, and opens a *gorm.DB on it. Both
// sets are rolled back at cleanup.
func migratedIdentityDB(t *testing.T) database {
	t.Helper()

	ss := migrate.SecurityState()
	is := migrate.Identity()
	conn := test.RunTestPostgres(t,
		test.WithTestPostgresMigrations(ss.FS(), ss.Dir, ss.VersionTable),
		test.WithTestPostgresMigrations(is.FS(), is.Dir, is.VersionTable),
	)
	conn.DB.SetMaxOpenConns(poolSize)

	return database{conn: conn, db: openGorm(t, conn.DSN)}
}

// newIdentityStore builds an identity store on db, failing t when the
// constructor refuses.
func newIdentityStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.IdentityStore {
	t.Helper()

	s, err := gormstore.NewIdentityStore(db, opts...)
	require.NoError(t, err)
	require.NotNil(t, s)

	return s
}

// seedTxKey is the context key under which a test's own transaction is
// attached for the fixture's seeding hooks, which write through it directly.
type seedTxKey struct{}

// withSeedTx returns ctx carrying tx for the seeding hooks.
func withSeedTx(ctx context.Context, tx *gormdb.DB) context.Context {
	return context.WithValue(ctx, seedTxKey{}, tx)
}

// identityFixture is the conformance suite's Fixture over the gorm identity
// store. The seeding hooks write the identity tables with raw SQL, through the
// transaction the context carries when there is one; the fault hooks are the
// fixture's own and never reach the store, so a fault one case injects fails
// that case's calls only.
type identityFixture struct {
	*gormstore.IdentityStore

	db *gormdb.DB

	mu      sync.Mutex
	loadErr error
	mfaErr  error
}

func newIdentityFixture(s *gormstore.IdentityStore, db *gormdb.DB) *identityFixture {
	return &identityFixture{IdentityStore: s, db: db}
}

// q is the handle a seeding hook writes through: the test's transaction when
// ctx carries one, otherwise the database.
func (f *identityFixture) q(ctx context.Context) *gormdb.DB {
	if tx, ok := ctx.Value(seedTxKey{}).(*gormdb.DB); ok {
		return tx.WithContext(ctx)
	}

	return f.db.WithContext(ctx)
}

func (f *identityFixture) fault(which *error) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	return *which
}

func (f *identityFixture) FailUserLoads(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.loadErr = err
}

func (f *identityFixture) FailMFALookups(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.mfaErr = err
}

func (f *identityFixture) LoadByUsername(ctx context.Context, username string) (*identity.Details, error) {
	if err := f.fault(&f.loadErr); err != nil {
		return nil, err
	}

	return f.IdentityStore.LoadByUsername(ctx, username)
}

func (f *identityFixture) LoadByUserID(ctx context.Context, ref identity.UserID) (*identity.Details, error) {
	if err := f.fault(&f.loadErr); err != nil {
		return nil, err
	}

	return f.IdentityStore.LoadByUserID(ctx, ref)
}

func (f *identityFixture) Required(ctx context.Context, ref identity.UserID) (bool, error) {
	if err := f.fault(&f.mfaErr); err != nil {
		return false, err
	}

	return f.IdentityStore.Required(ctx, ref)
}

// seedNow is the time every seeded row records as created and updated. The
// suite never reads it back.
var seedNow = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

// seedIDs mints the identifiers of the rows a seeding hook writes that carry
// none of their own.
var seedIDs = id.NewV7Generator()

func (f *identityFixture) SeedRole(ctx context.Context, role string, p []*identity.ResourcePrivileges) error {
	q := f.q(ctx)
	if err := q.Exec(`DELETE FROM resource_privileges WHERE role_name = ?`, role).Error; err != nil {
		return err
	}

	for _, rp := range p {
		if rp == nil {
			continue
		}
		for _, priv := range rp.Privileges {
			rowID, err := seedIDs.NewID()
			if err != nil {
				return err
			}
			if err := q.Exec(`INSERT INTO resource_privileges
  (id, role_name, resource_group, resource, privilege, granted, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				rowID, role, rp.Group, rp.Resource, priv.Name, priv.Granted, seedNow, seedNow).Error; err != nil {
				return err
			}
		}
	}

	return nil
}

func (f *identityFixture) SeedMFARequired(ctx context.Context, ref identity.UserID, required bool) error {
	res := f.q(ctx).Exec(`UPDATE users SET mfa_required = ? WHERE id = ?`, required, string(ref))
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return identity.ErrUserNotFound
	}

	return nil
}

func (f *identityFixture) SeedRoleGrants(ctx context.Context, username string, grants []*identity.AssignedRole) error {
	q := f.q(ctx)

	var userIDs []string
	if err := q.Raw(`SELECT id::text FROM users WHERE username = ?`, username).Scan(&userIDs).Error; err != nil {
		return err
	}
	if len(userIDs) == 0 {
		return identity.ErrUserNotFound
	}
	userID := userIDs[0]

	if err := q.Exec(`DELETE FROM assigned_roles WHERE user_id = ?`, userID).Error; err != nil {
		return err
	}

	primary := ""
	position := 0
	for _, g := range grants {
		if g == nil {
			continue
		}

		grantID := g.ID
		if grantID == "" {
			minted, err := seedIDs.NewID()
			if err != nil {
				return err
			}
			grantID = minted.String()
		}
		if g.Primary && primary == "" {
			primary = g.Name
		}

		if err := q.Exec(`INSERT INTO assigned_roles
  (id, user_id, role_name, position, is_primary, super_role, start_date, valid_until, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			grantID, userID, g.Name, position, g.Primary, g.SuperRole,
			nullTime(g.StartDate), nullTime(g.ValidUntil), seedNow, seedNow).Error; err != nil {
			return err
		}
		position++
	}

	return q.Exec(`UPDATE users SET role = ? WHERE id = ?`, primary, userID).Error
}

func (f *identityFixture) SeedOrganization(ctx context.Context, org *identity.Organization) error {
	if org == nil {
		return nil
	}
	q := f.q(ctx)

	var groupID sql.NullString
	if g := org.Group; g != nil {
		groupID = sql.NullString{String: g.ID, Valid: true}
		if err := q.Exec(`INSERT INTO groups (id, name, internal, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, internal = EXCLUDED.internal`,
			g.ID, g.Name, g.Internal, seedNow, seedNow).Error; err != nil {
			return err
		}
	}

	return q.Exec(`INSERT INTO organizations (id, name, group_id, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, group_id = EXCLUDED.group_id`,
		org.ID, org.Name, groupID, seedNow, seedNow).Error
}

// nullTime is t for a nullable column: NULL for the zero time.
func nullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: !t.IsZero()}
}

// descendingIDs is a consumer generator whose identifiers sort backwards: it
// starts at first followed by fifteen ff bytes (ffffffff-ffff-ffff-ffff-ffffffffffff
// for first 0xff) and decreases by one per call. A store ordering grants by
// identifier returns them reversed under it. Cases sharing a database each
// take their own first byte, so their identifiers never meet.
type descendingIDs struct {
	mu   sync.Mutex
	next id.ID
}

func newDescendingIDs(first byte) *descendingIDs {
	g := &descendingIDs{}
	for i := range g.next {
		g.next[i] = 0xff
	}
	g.next[0] = first

	return g
}

func (g *descendingIDs) NewID() (id.ID, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	out := g.next
	for i := len(g.next) - 1; i >= 0; i-- {
		g.next[i]--
		if g.next[i] != 0xff {
			break
		}
	}

	return out, nil
}

// failingIDs mints from the default generator and fails the failOn-th call
// (1-based) with err.
type failingIDs struct {
	mu     sync.Mutex
	calls  int
	failOn int
	err    error
}

func (g *failingIDs) NewID() (id.ID, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.calls++
	if g.calls == g.failOn {
		return id.Nil, g.err
	}

	return seedIDs.NewID()
}

// fixedIDs is a consumer generator that mints the same identifier every time.
type fixedIDs struct{ id id.ID }

func (g fixedIDs) NewID() (id.ID, error) { return g.id, nil }

// userRowCount is the number of stored users named username, read outside
// every transaction.
func userRowCount(ctx context.Context, t *testing.T, db *sql.DB, username string) int {
	t.Helper()

	var n int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE username = $1`, username).Scan(&n))

	return n
}
