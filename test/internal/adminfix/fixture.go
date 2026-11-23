package adminfix

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
	admintest "github.com/kartaladev/scrty/test/admin"
)

// Store is what one SQL adapter's identity store offers the administration
// conformance suite: the user and import ports and the identity ports over the
// same tables. The role, grant and assignment ports are taken from the same
// value when it implements them (see Fixture.Roles).
type Store interface {
	admin.UserStore
	admin.ImportStore
	identity.UserLoader
	identity.UserProvisioner
}

// Fixture is the conformance suite's admintest.Fixture over an SQL identity
// store and the database it writes. Its hooks work through DB alone, so any
// adapter over PostgreSQL can use it: gorm through its *sql.DB.
//
// T is the test the fixture serves. The fault hooks (FailGrantWrite,
// StallGrantWrite) install database triggers and remove them in T's cleanup,
// so they refuse to run without it; build the fixture in the suite's factory
// with the *testing.T it is given.
type Fixture struct {
	Store Store
	DB    *sql.DB
	T     *testing.T
}

var _ admintest.Fixture = Fixture{}

// Users returns the store as the user port.
func (f Fixture) Users() admin.UserStore { return f.Store }

// Importer returns the store as the import port.
func (f Fixture) Importer() admin.ImportStore { return f.Store }

// Loader returns the store as the identity user loader.
func (f Fixture) Loader() identity.UserLoader { return f.Store }

// Provisioner returns the store as the identity user provisioner.
func (f Fixture) Provisioner() identity.UserProvisioner { return f.Store }

// Roles returns the store when it implements admin.RoleStore, otherwise nil,
// which the suite's preflight reports as a missing port for the role part.
func (f Fixture) Roles() admin.RoleStore {
	if r, ok := f.Store.(admin.RoleStore); ok {
		return r
	}

	return nil
}

// Grants is as Roles, for admin.GrantStore.
func (f Fixture) Grants() admin.GrantStore {
	if g, ok := f.Store.(admin.GrantStore); ok {
		return g
	}

	return nil
}

// Assignments is as Roles, for admin.AssignmentStore.
func (f Fixture) Assignments() admin.AssignmentStore {
	if a, ok := f.Store.(admin.AssignmentStore); ok {
		return a
	}

	return nil
}

// UserResidue reads the user row, live or deleted, its attribute count and
// its password history, straight from the tables.
func (f Fixture) UserResidue(ctx context.Context, ref identity.UserID) (admintest.Residue, error) {
	var (
		r       admintest.Residue
		email   sql.NullString
		deleted sql.NullTime
	)
	err := f.DB.QueryRowContext(ctx, `SELECT username, active, email, deleted_at FROM scrty_users
WHERE id::text = $1`, string(ref)).Scan(&r.Username, &r.Active, &email, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return admintest.Residue{}, nil
	}
	if err != nil {
		return admintest.Residue{}, fmt.Errorf("read user residue: %w", err)
	}
	r.Exists, r.Deleted, r.Email = true, deleted.Valid, email.String

	if err := f.DB.QueryRowContext(ctx, `SELECT count(*) FROM scrty_user_attributes WHERE user_id::text = $1`,
		string(ref)).Scan(&r.Attributes); err != nil {
		return admintest.Residue{}, fmt.Errorf("count attributes: %w", err)
	}

	rows, err := f.DB.QueryContext(ctx, `SELECT password FROM scrty_password_history WHERE user_id::text = $1`,
		string(ref))
	if err != nil {
		return admintest.Residue{}, fmt.Errorf("read password history: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return admintest.Residue{}, fmt.Errorf("scan password history: %w", err)
		}
		r.PasswordHistory = append(r.PasswordHistory, h)
	}
	if err := rows.Err(); err != nil {
		return admintest.Residue{}, fmt.Errorf("read password history: %w", err)
	}

	return r, nil
}

// SeedOrganization records the organization, and its group when it has one,
// straight into scrty_organizations and scrty_groups, replacing a record with
// the same identifier. An identifier that is not a UUID fails the insert, so
// the hook returns an error for it, as the suite expects of a store that holds
// identifiers as UUIDs.
func (f Fixture) SeedOrganization(ctx context.Context, org *identity.Organization) error {
	if org == nil {
		return errors.New("adminfix: seed organization: no organization")
	}
	now := time.Now().UTC()

	var groupID sql.NullString
	if g := org.Group; g != nil {
		groupID = sql.NullString{String: g.ID, Valid: true}
		if _, err := f.DB.ExecContext(ctx, `INSERT INTO scrty_groups (id, name, internal, created_at, updated_at)
VALUES ($1, $2, $3, $4, $4)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, internal = EXCLUDED.internal`,
			g.ID, g.Name, g.Internal, now); err != nil {
			return fmt.Errorf("adminfix: seed group: %w", err)
		}
	}

	if _, err := f.DB.ExecContext(ctx, `INSERT INTO scrty_organizations (id, name, group_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $4)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, group_id = EXCLUDED.group_id`,
		org.ID, org.Name, groupID, now); err != nil {
		return fmt.Errorf("adminfix: seed organization: %w", err)
	}

	return nil
}
