package gorm

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	gormdb "gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/password"
	"github.com/kartaladev/scrty/pkg/id"
)

// IdentityStore keeps users, their role grants, organizations, groups and role
// privileges in the tables migrate.Identity creates, over gorm. It implements
// identity.UserLoader, identity.RoleLoader, identity.UserProvisioner and
// identity.MFARequirementLookup, and is safe for concurrent use. It also
// implements password.History over the password_history table, for a
// password.ReuseGuard; no identity port call reads or writes that table. It
// keeps the same records as package sqlstore's and the pgx adapter's identity
// stores, so the three are interchangeable over one database.
//
// # Loading
//
// A user load reads the user row, its grants, its organization and that
// organization's group through one resolved handle, and returns the complete
// record or an error, never part of one. Usernames match exactly as given, with
// no case folding, trimming or normalisation. Grants are returned primary
// first, then in the order they were given, and are never filtered by their
// validity window; the active flag is returned as stored. An organization
// reference that names no stored organization loads as none, and a group
// reference that names no stored group loads as an organization without one.
//
// A user reference is the user's identifier as the canonical lowercase UUID
// string this store returns. Any other string, including the same UUID in
// upper case, names no user: LoadByUserID and Required report it as
// identity.ErrUserNotFound, never as a driver error and never, for Required,
// as "not required". A stored user's MFA flag is read fresh on every Required
// call; no port call writes it.
//
// # Writing
//
// Provision decides a username collision by its insert (gorm's on-conflict
// clause, ON CONFLICT (username) DO NOTHING, and the affected-row count), with
// no read before it, so of concurrent provisions of one new username exactly
// one creates the user and every other returns identity.ErrUserExists. Update
// locks the user's row (SELECT … FOR UPDATE) before it reads or writes
// anything else, so concurrent updates of one user apply one after another.
// Both write only the fields the caller named, through a column map rather
// than a struct, so gorm's skipping of zero values never decides what is
// written: a named empty name is written as the empty string, and a named zero
// password-changed-at time as NULL. That time in particular is written only
// when named, never because a password was. An email address is accepted and
// discarded; this store has no column for it and never matches on it. Neither
// verb reads or writes the MFA flag. Organizations, groups, the role
// catalogue (roles) and resource privileges have no write path through this
// store either: the consumer's own user management owns them, and Provision
// and Update store only an organization's reference and the role names a
// caller gives, as the user's own grants.
//
// Provision and Update are atomic. Outside a caller's transaction each runs in
// a transaction of its own; inside one it runs under a savepoint, so a failure
// undoes only the store's own writes and leaves the caller's transaction
// usable. A panic out of a consumer's generator or handle, and a context
// cancelled between two statements, leave nothing of the call behind either:
// its transaction is rolled back, or its savepoint rolled back and released.
// The savepoint names come from a counter of the store's own, never from
// input.
//
// # Defaults and options
//
// It honours WithTxResolver, WithIDGenerator (default id.NewV7Generator; the
// identifiers of the users, grants and history entries it creates) and
// WithClock (default clock.System(); every created_at, updated_at and
// retired_at it writes: gorm fills none of them itself), and refuses any other
// option.
//
// Every statement runs with gorm's logger discarded, like every store in this
// package, since its bound values are usernames, password hashes and user
// references. The stated limit of the package holds here too: callbacks and
// plugins registered on the consumer's *gorm.DB still see every statement.
//
// # Migrations
//
// Apply migrate.Identity() before deploying a release that wires this store,
// and keep it applied while that release runs: this store creates none of its
// own tables. With a table missing, every operation fails with a database
// error rather than succeeding partially, and Required is one of them: the
// MFA requirement policy that calls it already denies on any lookup error, so
// a missing identity set denies non-exempt logins rather than admitting them.
//
// # Errors
//
// Error text never carries a username, a password hash or a user reference. A
// database failure is returned wrapped with the operation's name, and is never
// reported as not-found. It is cut from the driver's error: its text is the
// library's own, "database failure" followed by the SQLSTATE when the
// driver's error reports one through a SQLState method, and keeps nothing of
// the driver's or gorm's text, since a PostgreSQL primary message can quote a
// value. It still matches context.Canceled, context.DeadlineExceeded,
// sql.ErrTxDone and sql.ErrConnDone when the driver's error did, but the
// driver's error value is not in its chain, because that value's detail fields
// can carry a failing row, username and password hash included. The identity
// sentinels, and a generator's own error, stay in the chain.
//
// Limits, stated: PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A
// username, display name or role name holding either is refused by a write
// with an error naming the field, and names no stored record on a read. An
// organization reference must be a UUID in canonical lowercase text, since
// organizations are keyed by one and references match byte for byte; any
// other, an upper-case spelling included, is refused by a write with text that
// does not carry it. Stored times are UTC, truncated to the microsecond.
// Because the identity tables declare no foreign keys, a consumer deleting a
// user is responsible for deleting that user's grants (assigned_roles) and
// calling ForgetPasswords for that user's password history in the same
// transaction; nothing cascades.
type IdentityStore struct {
	c *config

	// savepoints numbers the savepoints this store opens inside a caller's
	// transaction.
	savepoints atomic.Uint64
}

// NewIdentityStore returns a PostgreSQL identity store on db.
//
// It honours WithTxResolver, WithIDGenerator and WithClock, and refuses any
// other option, a nil db, a nil option and a nil option value with an error
// wrapping ErrConfig. It never touches the database.
func NewIdentityStore(db *gormdb.DB, opts ...Option) (*IdentityStore, error) {
	c, err := newConfig(db, opts, optIDGenerator, optClock)
	if err != nil {
		return nil, err
	}

	return &IdentityStore{c: c}, nil
}

var (
	errEmptyUsername = errors.New("the username is empty")
	errOrgReference  = errors.New("the organization reference is not a UUID in canonical lowercase text")
)

// LoadByUsername loads the user with this exact username, or returns
// identity.ErrUserNotFound.
func (s *IdentityStore) LoadByUsername(ctx context.Context, username string) (*identity.Details, error) {
	const op = "load user"

	if !storekit.Storable(username) {
		return nil, failed(op, identity.ErrUserNotFound)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	return load(q, op, pgschema.UserByUsername, username)
}

// LoadByUserID loads the user with this reference, or returns
// identity.ErrUserNotFound, including for a reference that is not a canonical
// lowercase UUID string.
func (s *IdentityStore) LoadByUserID(ctx context.Context, ref identity.UserID) (*identity.Details, error) {
	const op = "load user by reference"

	uid, ok := parseUserID(ref)
	if !ok {
		return nil, failed(op, identity.ErrUserNotFound)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	return load(q, op, pgschema.UserByID, uid)
}

// LoadPrivileges returns the privileges role grants, grouped by resource
// group and resource in that order, denied entries included, or
// identity.ErrPrivilegesNotFound when it has none.
func (s *IdentityStore) LoadPrivileges(ctx context.Context, role string) ([]*identity.ResourcePrivileges, error) {
	const op = "load role privileges"

	if !storekit.Storable(role) {
		return nil, failed(op, identity.ErrPrivilegesNotFound)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	rows, err := q.Raw(pgschema.PrivilegesByRole, role).Rows()
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	var out []*identity.ResourcePrivileges
	for rows.Next() {
		var (
			rowID, created, updated any
			roleName, group, res    string
			p                       identity.Privilege
		)
		if err := rows.Scan(&rowID, &roleName, &group, &res, &p.Name, &p.Granted, &created, &updated); err != nil {
			return nil, scanFailed(op, err)
		}

		if n := len(out); n > 0 && out[n-1].Group == group && out[n-1].Resource == res {
			out[n-1].Privileges = append(out[n-1].Privileges, p)
			continue
		}
		out = append(out, &identity.ResourcePrivileges{Group: group, Resource: res, Privileges: []identity.Privilege{p}})
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}

	if len(out) == 0 {
		return nil, failed(op, identity.ErrPrivilegesNotFound)
	}

	return out, nil
}

// Required reports the stored MFA-required flag of the user with this
// reference. An unknown user, and a reference that is not a canonical
// lowercase UUID string, is identity.ErrUserNotFound, never "not required".
func (s *IdentityStore) Required(ctx context.Context, ref identity.UserID) (bool, error) {
	const op = "look up MFA requirement"

	uid, ok := parseUserID(ref)
	if !ok {
		return false, failed(op, identity.ErrUserNotFound)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return false, failed(op, err)
	}

	var required bool
	found, err := queryRow(q, op, pgschema.MFARequiredByID, []any{uid}, &required)
	if err != nil {
		return false, err
	}
	if !found {
		return false, failed(op, identity.ErrUserNotFound)
	}

	return required, nil
}

// Provision creates a user from username and the fields opts name, or returns
// identity.ErrUserExists when the username is taken.
func (s *IdentityStore) Provision(
	ctx context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	const op = "provision user"

	if username == "" {
		return nil, failed(op, errEmptyUsername)
	}

	u := identity.ApplyUserOptions(opts...)
	if err := checkUser(username, u); err != nil {
		return nil, failed(op, err)
	}
	org, err := orgReference(u)
	if err != nil {
		return nil, failed(op, err)
	}

	// Every identifier is minted before the first write, so a generator
	// failure writes nothing.
	userID, err := s.c.ids.NewID()
	if err != nil {
		return nil, failed(op, err)
	}
	grantIDs := make([]id.ID, len(u.Roles))
	for i := range grantIDs {
		if grantIDs[i], err = s.c.ids.NewID(); err != nil {
			return nil, failed(op, err)
		}
	}

	now := storekit.Time(s.c.clock.Now())
	user := userRow{
		ID:          userID,
		Name:        u.Name,
		Username:    username,
		Password:    storekit.OrEmpty(u.Password),
		Active:      true,
		Role:        "",
		MFARequired: false,
		CreatedAt:   now,
		UpdatedAt:   now,
		// Written only when the caller named it; NULL otherwise.
		OrganizationID: org,
	}
	if u.IsSet(identity.FieldPasswordChangedAt) {
		user.PasswordChangedAt = nullTs(u.PasswordChangedAt)
	}
	grants := make([]assignedRoleRow, len(u.Roles))
	for i, name := range u.Roles {
		if i == 0 {
			user.Role = name
		}
		grants[i] = assignedRoleRow{
			ID: grantIDs[i], UserID: userID, RoleName: name, Position: int64(i), IsPrimary: i == 0,
			CreatedAt: now, UpdatedAt: now,
		}
	}

	var out *identity.Details
	err = s.atomically(ctx, op, func(q *gormdb.DB) error {
		res := q.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "username"}}, DoNothing: true}).
			Create(&user)
		if res.Error != nil {
			return dbFailed(op, res.Error)
		}
		if res.RowsAffected == 0 {
			return failed(op, identity.ErrUserExists)
		}

		if len(grants) > 0 {
			if err := q.Create(&grants).Error; err != nil {
				return dbFailed(op, err)
			}
		}

		var err error
		out, err = load(q, op, pgschema.UserByID, userID)

		return err
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// Update amends the fields opts name on the user with this username, or
// returns identity.ErrUserNotFound, and returns the complete stored record.
func (s *IdentityStore) Update(
	ctx context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	const op = "update user"

	if username == "" {
		return nil, failed(op, errEmptyUsername)
	}
	if !storekit.Storable(username) {
		return nil, failed(op, identity.ErrUserNotFound)
	}

	u := identity.ApplyUserOptions(opts...)
	if err := checkUser(username, u); err != nil {
		return nil, failed(op, err)
	}
	org, err := orgReference(u)
	if err != nil {
		return nil, failed(op, err)
	}

	var roles []string
	if u.IsSet(identity.FieldRoles) {
		roles = survivingRoles(u.Roles)
	}

	var out *identity.Details
	err = s.atomically(ctx, op, func(q *gormdb.DB) error {
		var locked userRow
		err := q.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
			Select("id").Where("username = ?", username).Take(&locked).Error
		if errors.Is(err, gormdb.ErrRecordNotFound) {
			return failed(op, identity.ErrUserNotFound)
		}
		if err != nil {
			return scanFailed(op, err)
		}
		userID := locked.ID

		now := storekit.Time(s.c.clock.Now())

		// The rebuilt grants, with every new identifier, are settled before
		// the first write, so a generator that fails or panics finds nothing
		// written.
		var rebuilt []assignedRoleRow
		if len(roles) > 0 {
			if rebuilt, err = s.planGrants(q, op, userID, roles, now); err != nil {
				return err
			}
		}

		set := userColumns(u, org)
		if len(roles) > 0 {
			set["role"] = roles[0]
		}
		if len(set) > 0 {
			set["updated_at"] = now
			if err := q.Model(&userRow{}).Where("id = ?", userID).Updates(set).Error; err != nil {
				return dbFailed(op, err)
			}
		}

		if len(rebuilt) > 0 {
			if err := q.Exec(pgschema.DeleteGrantsByUser, userID).Error; err != nil {
				return dbFailed(op, err)
			}
			if err := q.Create(&rebuilt).Error; err != nil {
				return dbFailed(op, err)
			}
		}

		out, err = load(q, op, pgschema.UserByID, userID)

		return err
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// userColumns is the users columns an update writes for the fields u names,
// keyed by column. Column names come only from this allow-list, never from
// input. A field is written when it was named, whatever its value (a map, not
// a struct, so gorm never drops a zero value), and left alone otherwise. The
// email has no column and writes nothing; the roles are written by the grant
// rebuild. The password-changed-at time is its own field: naming the password
// alone never writes it.
func userColumns(u *identity.NewUser, org *id.ID) map[string]any {
	set := map[string]any{}
	if u.IsSet(identity.FieldName) {
		set["name"] = u.Name
	}
	if u.IsSet(identity.FieldPassword) {
		set["password"] = storekit.OrEmpty(u.Password)
	}
	if u.IsSet(identity.FieldOrganization) {
		set["organization_id"] = org
	}
	if u.IsSet(identity.FieldPasswordChangedAt) {
		set["password_changed_at"] = nullTs(u.PasswordChangedAt)
	}

	return set
}

// planGrants is the grants that replace those of userID for roles, in that
// order, the first primary. A name the user already holds keeps its stored
// grant's identifier, super-role flag, validity window and creation time;
// where the user holds a name more than once, the grant first in stored
// position is kept, whatever the identifiers. A name the user does not hold
// gets a new grant, its identifier minted here, with no super role and no
// window. It only reads; the caller holds the user's row lock.
func (s *IdentityStore) planGrants(
	q *gormdb.DB, op string, userID id.ID, roles []string, now time.Time,
) ([]assignedRoleRow, error) {
	existing, err := grantsInPosition(q, op, userID)
	if err != nil {
		return nil, err
	}

	rebuilt := make([]assignedRoleRow, len(roles))
	for i, name := range roles {
		g, ok := existing[name]
		if !ok {
			fresh, err := s.c.ids.NewID()
			if err != nil {
				return nil, failed(op, err)
			}
			g = assignedRoleRow{ID: fresh, UserID: userID, RoleName: name, CreatedAt: now}
		}
		g.Position = int64(i)
		g.IsPrimary = i == 0
		g.UpdatedAt = now
		rebuilt[i] = g
	}

	return rebuilt, nil
}

// grantsInPosition returns the user's stored grants by name, keeping for each
// name the grant first in stored position.
func grantsInPosition(q *gormdb.DB, op string, userID id.ID) (map[string]assignedRoleRow, error) {
	rows, err := q.Raw(pgschema.GrantsByUserInPosition, userID).Rows()
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]assignedRoleRow)
	for rows.Next() {
		var (
			g         assignedRoleRow
			updatedAt time.Time
		)
		if err := rows.Scan(&g.ID, &g.RoleName, &g.Position, &g.IsPrimary, &g.SuperRole, &g.StartDate,
			&g.ValidUntil, &g.CreatedAt, &updatedAt); err != nil {
			return nil, scanFailed(op, err)
		}
		if _, seen := out[g.RoleName]; !seen {
			g.UserID = userID
			g.StartDate = tsPtr(g.StartDate)
			g.ValidUntil = tsPtr(g.ValidUntil)
			g.CreatedAt = storekit.Time(g.CreatedAt)
			out[g.RoleName] = g
		}
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
}

// queryRow runs query with args on q and scans its first row into dest,
// reporting false, with no error, when there is none. The rows are closed
// before it returns, so the connection is free for the next statement.
func queryRow(q *gormdb.DB, op, query string, args []any, dest ...any) (bool, error) {
	rows, err := q.Raw(query, args...).Rows()
	if err != nil {
		return false, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return false, dbFailed(op, err)
		}
		return false, nil
	}
	if err := rows.Scan(dest...); err != nil {
		return false, scanFailed(op, err)
	}
	if err := rows.Close(); err != nil {
		return false, dbFailed(op, err)
	}

	return true, nil
}

// load reads the complete record of the user query selects with arg, through
// q: the user row, then its grants, organization and group.
func load(q *gormdb.DB, op, query string, arg any) (*identity.Details, error) {
	var (
		d                    identity.Details
		userID               id.ID
		role                 string
		orgID                *id.ID
		changedAt            *time.Time
		mfa                  bool
		createdAt, updatedAt time.Time
	)
	found, err := queryRow(q, op, query, []any{arg}, &userID, &d.Name, &d.Username, &d.Password, &d.Active,
		&role, &orgID, &changedAt, &mfa, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, failed(op, identity.ErrUserNotFound)
	}
	d.ID = identity.UserID(userID.String())
	d.PasswordChangedAt = fromNull(changedAt)
	if d.Password == nil {
		d.Password = []byte{}
	}

	if d.Roles, err = grants(q, op, userID); err != nil {
		return nil, err
	}

	if orgID != nil {
		if d.Organization, err = organization(q, op, *orgID); err != nil {
			return nil, err
		}
	}

	return &d, nil
}

// grants reads the user's grants, primary first, then in stored position.
func grants(q *gormdb.DB, op string, userID id.ID) ([]*identity.AssignedRole, error) {
	rows, err := q.Raw(pgschema.GrantsByUser, userID).Rows()
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	var out []*identity.AssignedRole
	for rows.Next() {
		var (
			g                    identity.AssignedRole
			grantID              id.ID
			position             int
			start, until         *time.Time
			createdAt, updatedAt time.Time
		)
		if err := rows.Scan(&grantID, &g.Name, &position, &g.Primary, &g.SuperRole, &start, &until,
			&createdAt, &updatedAt); err != nil {
			return nil, scanFailed(op, err)
		}
		g.ID = grantID.String()
		g.StartDate = fromNull(start)
		g.ValidUntil = fromNull(until)
		out = append(out, &g)
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
}

// organization reads the organization orgID names and its group. A reference
// naming no organization is none, and a group reference naming no group is an
// organization without one; neither is an error.
func organization(q *gormdb.DB, op string, orgID id.ID) (*identity.Organization, error) {
	var (
		org                  identity.Organization
		rowID                id.ID
		groupID              *id.ID
		createdAt, updatedAt time.Time
	)
	found, err := queryRow(q, op, pgschema.OrganizationByID, []any{orgID},
		&rowID, &org.Name, &groupID, &createdAt, &updatedAt)
	if err != nil || !found {
		return nil, err
	}
	org.ID = rowID.String()

	if groupID == nil {
		return &org, nil
	}

	var (
		g   identity.Group
		gID id.ID
	)
	found, err = queryRow(q, op, pgschema.GroupByID, []any{*groupID}, &gID, &g.Name, &g.Internal, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	if !found {
		return &org, nil
	}
	g.ID = gID.String()
	org.Group = &g

	return &org, nil
}

// parseUserID is ref as the identifier it names, or false when ref is not the
// canonical lowercase UUID string this store hands out. pkg/id accepts either
// letter case; a reference is opaque and matched byte for byte, so another
// spelling of the same UUID names no user.
func parseUserID(ref identity.UserID) (id.ID, bool) {
	uid, err := id.Parse(string(ref))
	if err != nil || uid.String() != string(ref) {
		return id.Nil, false
	}

	return uid, true
}

// checkUser refuses text PostgreSQL cannot store, naming the field and never
// its value.
func checkUser(username string, u *identity.NewUser) error {
	fields := []storekit.Field{storekit.Text("username", username), storekit.Text("name", u.Name)}
	for _, r := range u.Roles {
		fields = append(fields, storekit.Text("role", r))
	}

	return storekit.CheckStorable(fields...)
}

// orgReference is the organization reference to store when the caller named
// one: nil (NULL) for none or one with no identifier, otherwise the parsed
// UUID. A reference that is not a UUID in canonical lowercase text, an
// upper-case spelling of one included, is refused before anything is written,
// with text that does not carry it. It matches byte for byte, as user
// references do, so every adapter stores the same references.
func orgReference(u *identity.NewUser) (*id.ID, error) {
	if !u.IsSet(identity.FieldOrganization) || u.Organization == nil || u.Organization.ID == "" {
		return nil, nil
	}

	org, err := id.Parse(u.Organization.ID)
	if err != nil || org.String() != u.Organization.ID {
		return nil, errOrgReference
	}

	return &org, nil
}

// survivingRoles applies the update's role rules: empty names are skipped and
// a repeated name collapses to its first occurrence. No survivor means the
// grants are left as stored.
func survivingRoles(names []string) []string {
	out := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}

	return out
}

var (
	_ identity.UserLoader           = (*IdentityStore)(nil)
	_ identity.RoleLoader           = (*IdentityStore)(nil)
	_ identity.UserProvisioner      = (*IdentityStore)(nil)
	_ identity.MFARequirementLookup = (*IdentityStore)(nil)
	_ password.History              = (*IdentityStore)(nil)
)
