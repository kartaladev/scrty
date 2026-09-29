package pgxstore_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/migrate"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test"
)

// migratedIdentity starts PostgreSQL with both migration sets applied, the
// security-state set first and the identity set second, as a consumer wiring
// the default identity store deploys them, and opens a pool on it. Both sets
// are rolled back at cleanup.
func migratedIdentity(t *testing.T) database {
	t.Helper()

	ss := migrate.SecurityState()
	is := migrate.Identity()
	conn := test.RunTestPostgres(t,
		test.WithTestPostgresMigrations(ss.FS(), ss.Dir, ss.VersionTable),
		test.WithTestPostgresMigrations(is.FS(), is.Dir, is.VersionTable),
	)
	conn.DB.SetMaxOpenConns(poolSize)

	return database{PostgresConn: conn, Pool: openPool(t, conn.DSN)}
}

// newIdentityStore builds an identity store on pool, failing t when the
// constructor refuses.
func newIdentityStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) *pgxstore.IdentityStore {
	t.Helper()

	s, err := pgxstore.NewIdentityStore(pool, opts...)
	require.NoError(t, err)
	require.NotNil(t, s)

	return s
}

// seedTxKey is the context key under which a test's own transaction is
// attached for the fixture's seeding hooks. The seeding hooks write raw SQL, so
// they need the transaction itself; pgxstore's own attachment is unexported.
type seedTxKey struct{}

// withSeedTx returns ctx carrying tx for the seeding hooks.
func withSeedTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, seedTxKey{}, tx)
}

// identityFixture is the conformance suite's Fixture over the pgx identity
// store. The seeding hooks write the identity tables with raw SQL, through the
// transaction the context carries when there is one; the fault hooks are the
// fixture's own and never reach the store, so a fault one case injects fails
// that case's calls only.
type identityFixture struct {
	*pgxstore.IdentityStore

	pool *pgxpool.Pool

	mu      sync.Mutex
	loadErr error
	mfaErr  error
}

func newIdentityFixture(s *pgxstore.IdentityStore, pool *pgxpool.Pool) *identityFixture {
	return &identityFixture{IdentityStore: s, pool: pool}
}

// q is the handle a seeding hook writes through: the test's transaction when
// ctx carries one, otherwise the pool.
func (f *identityFixture) q(ctx context.Context) pgxstore.DBTX {
	if tx, ok := ctx.Value(seedTxKey{}).(pgx.Tx); ok {
		return tx
	}

	return f.pool
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
	if _, err := q.Exec(ctx, `DELETE FROM resource_privileges WHERE role_name = $1`, role); err != nil {
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
			if _, err := q.Exec(ctx, `INSERT INTO resource_privileges
  (id, role_name, resource_group, resource, privilege, granted, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
				rowID.String(), role, rp.Group, rp.Resource, priv.Name, priv.Granted, seedNow); err != nil {
				return err
			}
		}
	}

	return nil
}

func (f *identityFixture) SeedMFARequired(ctx context.Context, ref identity.UserID, required bool) error {
	tag, err := f.q(ctx).Exec(ctx, `UPDATE users SET mfa_required = $2 WHERE id::text = $1`, string(ref), required)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrUserNotFound
	}

	return nil
}

func (f *identityFixture) SeedRoleGrants(ctx context.Context, username string, grants []*identity.AssignedRole) error {
	q := f.q(ctx)

	var userID string
	if err := q.QueryRow(ctx, `SELECT id::text FROM users WHERE username = $1`, username).Scan(&userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return identity.ErrUserNotFound
		}
		return err
	}

	if _, err := q.Exec(ctx, `DELETE FROM assigned_roles WHERE user_id = $1`, userID); err != nil {
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

		if _, err := q.Exec(ctx, `INSERT INTO assigned_roles
  (id, user_id, role_name, position, is_primary, super_role, start_date, valid_until, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)`,
			grantID, userID, g.Name, position, g.Primary, g.SuperRole,
			nullTime(g.StartDate), nullTime(g.ValidUntil), seedNow); err != nil {
			return err
		}
		position++
	}

	_, err := q.Exec(ctx, `UPDATE users SET role = $2 WHERE id = $1`, userID, primary)

	return err
}

func (f *identityFixture) SeedOrganization(ctx context.Context, org *identity.Organization) error {
	if org == nil {
		return nil
	}
	q := f.q(ctx)

	var groupID any
	if g := org.Group; g != nil {
		groupID = g.ID
		if _, err := q.Exec(ctx, `INSERT INTO groups (id, name, internal, created_at, updated_at)
VALUES ($1, $2, $3, $4, $4)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, internal = EXCLUDED.internal`,
			g.ID, g.Name, g.Internal, seedNow); err != nil {
			return err
		}
	}

	_, err := q.Exec(ctx, `INSERT INTO organizations (id, name, group_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $4)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, group_id = EXCLUDED.group_id`,
		org.ID, org.Name, groupID, seedNow)

	return err
}

// nullTime is t for a nullable column: NULL for the zero time.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}

	return t
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
func userRowCount(ctx context.Context, t *testing.T, pool *pgxpool.Pool, username string) int {
	t.Helper()

	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE username = $1`, username).Scan(&n))

	return n
}
