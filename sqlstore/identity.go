package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
)

// IdentityStore keeps users, their role grants, organizations, groups and role
// privileges in the tables migrate.Identity creates. It implements
// identity.UserLoader, identity.RoleLoader, identity.UserProvisioner and
// identity.MFARequirementLookup, and is safe for concurrent use.
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
// Provision decides a username collision by its insert, with no read before
// it, so of concurrent provisions of one new username exactly one creates the
// user and every other returns identity.ErrUserExists. Update locks the user's
// row before it reads or writes anything else, so concurrent updates of one
// user apply one after another. Both write only the fields the caller named:
// the password-changed-at time in particular is written only when named,
// never because a password was. An email address is accepted and discarded;
// this store has no column for it and never matches on it. Neither verb reads
// or writes the MFA flag.
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
// identifiers of the users and grants it creates) and WithClock (default
// time.Now; every created_at and updated_at it writes), and refuses any other
// option.
//
// # Errors
//
// Error text never carries a username, a password hash or a user reference. A
// database failure is returned wrapped with the operation's name, and is never
// reported as not-found. It is cut from the driver's error: its text keeps the
// driver's own text (for PostgreSQL drivers, the primary message and the
// SQLSTATE), and it still matches context.Canceled, context.DeadlineExceeded,
// sql.ErrTxDone and sql.ErrConnDone when the driver's error did, but the
// driver's error value is not in its chain, because that value's detail fields
// can carry a failing row, username and password hash included. The
// identity sentinels, and a generator's own error, stay in the chain.
//
// Limits, stated: PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A
// username, display name or role name holding either is refused by a write
// with an error naming the field, and names no stored record on a read. An
// organization reference must be a UUID in canonical lowercase text, since
// organizations are keyed by one and references match byte for byte; any
// other, an upper-case spelling included, is refused by a write with text that
// does not carry it. Stored times are UTC, truncated to
// the microsecond. Because the identity tables declare no foreign keys, a
// consumer deleting a user is responsible for deleting that user's grants
// (assigned_roles) in the same transaction; nothing cascades.
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
func NewIdentityStore(db *sql.DB, opts ...Option) (*IdentityStore, error) {
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

	q, _, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	return s.load(ctx, q, op, pgschema.UserByUsername, username)
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

	q, _, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	return s.load(ctx, q, op, pgschema.UserByID, uid)
}

// LoadPrivileges returns the privileges role grants, grouped by resource
// group and resource in that order, denied entries included, or
// identity.ErrPrivilegesNotFound when it has none.
func (s *IdentityStore) LoadPrivileges(ctx context.Context, role string) ([]*identity.ResourcePrivileges, error) {
	const op = "load role privileges"

	if !storekit.Storable(role) {
		return nil, failed(op, identity.ErrPrivilegesNotFound)
	}

	q, _, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	rows, err := q.QueryContext(ctx, pgschema.PrivilegesByRole, role)
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

	q, _, _, err := s.c.conn(ctx)
	if err != nil {
		return false, failed(op, err)
	}

	var required bool
	err = q.QueryRowContext(ctx, pgschema.MFARequiredByID, uid).Scan(&required)
	if errors.Is(err, sql.ErrNoRows) {
		return false, failed(op, identity.ErrUserNotFound)
	}
	if err != nil {
		return false, scanFailed(op, err)
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

	var changedAt any
	if u.IsSet(identity.FieldPasswordChangedAt) {
		changedAt = nullTs(u.PasswordChangedAt)
	}
	primary := ""
	if len(u.Roles) > 0 {
		primary = u.Roles[0]
	}
	now := storekit.Time(s.c.now())

	var out *identity.Details
	err = s.atomically(ctx, op, func(q DBTX) error {
		res, err := q.ExecContext(ctx, pgschema.InsertUser, userID, u.Name, username,
			storekit.OrEmpty(u.Password), true, primary, org, changedAt, false, now, now)
		if err != nil {
			return dbFailed(op, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return dbFailed(op, err)
		}
		if n == 0 {
			return failed(op, identity.ErrUserExists)
		}

		for i, name := range u.Roles {
			if _, err := q.ExecContext(ctx, pgschema.InsertGrant, grantIDs[i], userID, name, i, i == 0,
				false, nil, nil, now, now); err != nil {
				return dbFailed(op, err)
			}
		}

		out, err = s.load(ctx, q, op, pgschema.UserByID, userID)

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
	err = s.atomically(ctx, op, func(q DBTX) error {
		var userID id.ID
		err := q.QueryRowContext(ctx, pgschema.LockUserByUsername, username).Scan(&userID)
		if errors.Is(err, sql.ErrNoRows) {
			return failed(op, identity.ErrUserNotFound)
		}
		if err != nil {
			return scanFailed(op, err)
		}

		now := storekit.Time(s.c.now())

		// The rebuilt grants, with every new identifier, are settled before
		// the first write, so a generator that fails or panics finds nothing
		// written.
		var rebuilt []storedGrant
		if len(roles) > 0 {
			if rebuilt, err = s.planGrants(ctx, q, op, userID, roles, now); err != nil {
				return err
			}
		}

		set := userColumns(u, org)
		if len(roles) > 0 {
			set = append(set, column{"role", roles[0]})
		}
		if len(set) > 0 {
			query, args := updateUserQuery(set, now, userID)
			if _, err := q.ExecContext(ctx, query, args...); err != nil {
				return dbFailed(op, err)
			}
		}

		if len(roles) > 0 {
			if err := writeGrants(ctx, q, op, userID, rebuilt, now); err != nil {
				return err
			}
		}

		out, err = s.load(ctx, q, op, pgschema.UserByID, userID)

		return err
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// storedGrant is one row of assigned_roles as a rebuild reads it.
type storedGrant struct {
	id                    id.ID
	name                  string
	superRole             bool
	startDate, validUntil sql.NullTime
	createdAt             time.Time
}

// planGrants is the grants that replace those of userID for roles, in that
// order, the first primary. A name the user already holds keeps its stored
// grant's identifier, super-role flag, validity window and creation time;
// where the user holds a name more than once, the grant first in stored
// position is kept, whatever the identifiers. A name the user does not hold
// gets a new grant, its identifier minted here, with no super role and no
// window. It only reads; the caller holds the user's row lock.
func (s *IdentityStore) planGrants(
	ctx context.Context, q DBTX, op string, userID id.ID, roles []string, now time.Time,
) ([]storedGrant, error) {
	existing, err := s.grantsInPosition(ctx, q, op, userID)
	if err != nil {
		return nil, err
	}

	rebuilt := make([]storedGrant, len(roles))
	for i, name := range roles {
		if g, ok := existing[name]; ok {
			rebuilt[i] = g
			continue
		}

		fresh, err := s.c.ids.NewID()
		if err != nil {
			return nil, failed(op, err)
		}
		rebuilt[i] = storedGrant{id: fresh, name: name, createdAt: now}
	}

	return rebuilt, nil
}

// writeGrants replaces the grants of userID with rebuilt, planned by
// planGrants, in that order, the first primary.
func writeGrants(ctx context.Context, q DBTX, op string, userID id.ID, rebuilt []storedGrant, now time.Time) error {
	if _, err := q.ExecContext(ctx, pgschema.DeleteGrantsByUser, userID); err != nil {
		return dbFailed(op, err)
	}

	for i, g := range rebuilt {
		if _, err := q.ExecContext(ctx, pgschema.InsertGrant, g.id, userID, g.name, i, i == 0,
			g.superRole, nullTimeArg(g.startDate), nullTimeArg(g.validUntil), g.createdAt, now); err != nil {
			return dbFailed(op, err)
		}
	}

	return nil
}

// grantsInPosition returns the user's stored grants by name, keeping for each
// name the grant first in stored position.
func (s *IdentityStore) grantsInPosition(
	ctx context.Context, q DBTX, op string, userID id.ID,
) (map[string]storedGrant, error) {
	rows, err := q.QueryContext(ctx, pgschema.GrantsByUserInPosition, userID)
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]storedGrant)
	for rows.Next() {
		var (
			g         storedGrant
			position  int
			primary   bool
			updatedAt time.Time
		)
		if err := rows.Scan(&g.id, &g.name, &position, &primary, &g.superRole, &g.startDate, &g.validUntil,
			&g.createdAt, &updatedAt); err != nil {
			return nil, scanFailed(op, err)
		}
		if _, seen := out[g.name]; !seen {
			out[g.name] = g
		}
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
}

// atomically runs fn as one unit on the handle ctx resolves to: under a
// savepoint inside a caller's transaction, otherwise in a transaction of the
// store's own on its *sql.DB.
func (s *IdentityStore) atomically(ctx context.Context, op string, fn func(q DBTX) error) error {
	q, _, ambient, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}

	if ambient {
		return s.underSavepoint(ctx, q, op, fn)
	}

	tx, err := s.c.base.BeginTx(ctx, nil)
	if err != nil {
		return dbFailed(op, err)
	}
	// Rolled back on every way out but a commit, a panic in fn included, so
	// the transaction and the row locks it holds never outlive the call.
	// After a commit the rollback does nothing.
	defer func() { _ = tx.Rollback() }()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return dbFailed(op, err)
	}

	return nil
}

// load reads the complete record of the user query selects with arg, through
// q: the user row, then its grants, organization and group.
func (s *IdentityStore) load(ctx context.Context, q DBTX, op, query string, arg any) (*identity.Details, error) {
	var (
		d                    identity.Details
		userID               id.ID
		role                 string
		orgID                sql.Null[id.ID]
		changedAt            sql.NullTime
		mfa                  bool
		createdAt, updatedAt time.Time
	)
	err := q.QueryRowContext(ctx, query, arg).Scan(&userID, &d.Name, &d.Username, &d.Password, &d.Active,
		&role, &orgID, &changedAt, &mfa, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, failed(op, identity.ErrUserNotFound)
	}
	if err != nil {
		return nil, scanFailed(op, err)
	}
	d.ID = identity.UserID(userID.String())
	d.PasswordChangedAt = fromNull(changedAt)
	if d.Password == nil {
		d.Password = []byte{}
	}

	if d.Roles, err = s.grants(ctx, q, op, userID); err != nil {
		return nil, err
	}

	if orgID.Valid {
		if d.Organization, err = s.organization(ctx, q, op, orgID.V); err != nil {
			return nil, err
		}
	}

	return &d, nil
}

// grants reads the user's grants, primary first, then in stored position.
func (s *IdentityStore) grants(ctx context.Context, q DBTX, op string, userID id.ID) ([]*identity.AssignedRole, error) {
	rows, err := q.QueryContext(ctx, pgschema.GrantsByUser, userID)
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
			start, until         sql.NullTime
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
func (s *IdentityStore) organization(ctx context.Context, q DBTX, op string, orgID id.ID) (*identity.Organization, error) {
	var (
		org                  identity.Organization
		rowID                id.ID
		groupID              sql.Null[id.ID]
		createdAt, updatedAt time.Time
	)
	err := q.QueryRowContext(ctx, pgschema.OrganizationByID, orgID).Scan(&rowID, &org.Name, &groupID, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, scanFailed(op, err)
	}
	org.ID = rowID.String()

	if !groupID.Valid {
		return &org, nil
	}

	var (
		g   identity.Group
		gID id.ID
	)
	err = q.QueryRowContext(ctx, pgschema.GroupByID, groupID.V).Scan(&gID, &g.Name, &g.Internal, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return &org, nil
	}
	if err != nil {
		return nil, scanFailed(op, err)
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
func orgReference(u *identity.NewUser) (any, error) {
	if !u.IsSet(identity.FieldOrganization) || u.Organization == nil || u.Organization.ID == "" {
		return nil, nil
	}

	org, err := id.Parse(u.Organization.ID)
	if err != nil || org.String() != u.Organization.ID {
		return nil, errOrgReference
	}

	return org, nil
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

// nullTimeArg is a scanned nullable time as a statement argument.
func nullTimeArg(t sql.NullTime) any {
	if !t.Valid {
		return nil
	}

	return t.Time
}

var (
	_ identity.UserLoader           = (*IdentityStore)(nil)
	_ identity.RoleLoader           = (*IdentityStore)(nil)
	_ identity.UserProvisioner      = (*IdentityStore)(nil)
	_ identity.MFARequirementLookup = (*IdentityStore)(nil)
)

// underSavepoint runs fn on q, a caller's transaction, under a savepoint of
// its own. When fn fails, the savepoint is rolled back, which undoes fn's
// writes and clears the aborted state a failed statement leaves, so the
// caller's transaction stays usable with its earlier writes intact; the
// savepoint is then released either way.
//
// When fn panics, or a panic interrupts one of the statements that closes
// the savepoint, the savepoint is rolled back and released before the panic
// goes on, so a caller that recovers it and commits commits none of fn's
// writes.
//
// The name comes from the store's own counter, never from input. The
// statements that close the savepoint run even when ctx is done, since
// leaving it open would leave the caller's transaction aborted, or would
// commit fn's writes with the caller's.
func (s *IdentityStore) underSavepoint(ctx context.Context, q DBTX, op string, fn func(q DBTX) error) error {
	name := "scrty_identity_" + strconv.FormatUint(s.savepoints.Add(1), 10)

	if _, err := q.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
		return dbFailed(op, err)
	}

	closeCtx := context.WithoutCancel(ctx)

	// open tracks whether the savepoint is still open, not whether fn has
	// returned: fn returning is not the same as the savepoint being closed,
	// since the statements that close it can themselves panic. The defer
	// below runs its best-effort cleanup whenever a panic leaves the
	// savepoint open, whether the panic came from fn or from a statement
	// that was closing it; every normal return, success or failure, clears
	// the flag first, since by then this call already made its own attempt
	// at closing the savepoint and the defer must not repeat it.
	open := true
	defer func() {
		if !open {
			return
		}
		// The savepoint is still open: a panic interrupted fn, or a
		// statement that was closing it. Leave nothing of the call's writes
		// behind. A panic is already unwinding, so each cleanup statement
		// recovers its own: a handle that panics here too must not replace
		// the panic the caller will recover.
		bestEffort(func() { _, _ = q.ExecContext(closeCtx, "ROLLBACK TO SAVEPOINT "+name) })
		bestEffort(func() { _, _ = q.ExecContext(closeCtx, "RELEASE SAVEPOINT "+name) })
	}()

	err := fn(q)

	if err != nil {
		if _, rbErr := q.ExecContext(closeCtx, "ROLLBACK TO SAVEPOINT "+name); rbErr != nil {
			open = false
			return errors.Join(err, dbFailed(op, rbErr))
		}
		if _, relErr := q.ExecContext(closeCtx, "RELEASE SAVEPOINT "+name); relErr != nil {
			open = false
			return errors.Join(err, dbFailed(op, relErr))
		}
		open = false

		return err
	}

	if _, err := q.ExecContext(closeCtx, "RELEASE SAVEPOINT "+name); err != nil {
		open = false
		return dbFailed(op, err)
	}
	open = false

	return nil
}

// bestEffort runs f, recovering any panic it raises. It is only for cleanup
// that runs while another panic is already unwinding, where f's own panic
// would otherwise replace that one.
func bestEffort(f func()) {
	defer func() { _ = recover() }()
	f()
}
