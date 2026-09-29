package pgx

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/password"
	"github.com/kartaladev/scrty/pkg/id"
)

// IdentityStore keeps users, their role grants, organizations, groups and role
// privileges in the tables migrate.Identity creates. It implements
// identity.UserLoader, identity.RoleLoader, identity.UserProvisioner and
// identity.MFARequirementLookup, and is safe for concurrent use. It also
// implements password.History over the password_history table, for a
// password.ReuseGuard; no identity port call reads or writes that table.
//
// It stores the same records in the same tables as the core's
// sqlstore.IdentityStore, with the same guarantees.
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
// or writes the MFA flag. Organizations, groups, the role catalogue (roles)
// and resource privileges have no write path through this store either: the
// consumer's own user management owns them, and Provision and Update store
// only an organization's reference and the role names a caller gives, as the
// user's own grants.
//
// Provision and Update are atomic. Outside a caller's transaction each runs in
// a transaction of its own, begun on the pool; inside one it runs in a
// savepoint of its own, so a failure undoes only the store's own writes and
// leaves the caller's transaction usable. A panic out of a consumer's
// generator or transaction wrapper, and a context cancelled between two
// statements, leave nothing of the call behind either: its transaction, or
// its savepoint, is rolled back. The savepoint is rolled back and then
// released when the call fails, and released when it succeeds, so no call,
// a refusal such as identity.ErrUserExists included, leaves one open in the
// caller's transaction. The SAVEPOINT, ROLLBACK TO SAVEPOINT and RELEASE
// SAVEPOINT statements are issued through Exec on the resolved handle, the
// transaction WithTx attached or a consumer's resolver returned, so a
// consumer's transaction wrapper sees them like every other statement. The
// savepoint is named from a counter of the store's own, never from input.
//
// # Defaults and options
//
// It honours WithTxResolver, WithIDGenerator (default id.NewV7Generator; the
// identifiers of the users, grants and history entries it creates) and
// WithClock (default clock.System(); every created_at, updated_at and
// retired_at it writes), and refuses any other option.
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
// reported as not-found. It is cut from the driver's error: its text is fixed
// library text naming the operation, plus the SQLSTATE when the driver's error
// reports one through a SQLState method (*pgconn.PgError does), and never the
// driver's own text, since a PostgreSQL primary message can quote a value. It
// still matches context.Canceled, context.DeadlineExceeded, pgx.ErrTxClosed
// and pgx.ErrTxCommitRollback when the driver's error did, but the driver's
// error value (a *pgconn.PgError among them) is not in its chain, because that
// value's detail fields can carry a failing row, username and password hash
// included. A column that cannot be scanned is named by index and name, never
// by the value. The identity sentinels, and a generator's own error, stay in
// the chain.
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

	// savepoints numbers the savepoints the store opens, for their names.
	savepoints atomic.Uint64
}

// NewIdentityStore returns a PostgreSQL identity store on pool.
//
// It honours WithTxResolver, WithIDGenerator and WithClock, and refuses any
// other option, a nil pool, a nil option and a nil option value with an error
// wrapping ErrConfig. It never touches the database.
func NewIdentityStore(pool *pgxpool.Pool, opts ...Option) (*IdentityStore, error) {
	c, err := newConfig(pool, opts, optIDGenerator, optClock)
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

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	return s.load(ctx, q, op, pgschema.UserByID, uuidArg(uid))
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

	rows, err := q.Query(ctx, pgschema.PrivilegesByRole, role)
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer rows.Close()

	var out []*identity.ResourcePrivileges
	for rows.Next() {
		var (
			group, res string
			p          identity.Privilege
		)
		// The identifier, role name and times are selected but not returned.
		if err := rows.Scan(nil, nil, &group, &res, &p.Name, &p.Granted, nil, nil); err != nil {
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
	err = q.QueryRow(ctx, pgschema.MFARequiredByID, uuidArg(uid)).Scan(&required)
	if errors.Is(err, pgxv5.ErrNoRows) {
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

	var changedAt pgtype.Timestamptz
	if u.IsSet(identity.FieldPasswordChangedAt) {
		changedAt = nullTs(u.PasswordChangedAt)
	}
	primary := ""
	if len(u.Roles) > 0 {
		primary = u.Roles[0]
	}
	now := storekit.Time(s.c.clock.Now())

	var out *identity.Details
	err = s.atomically(ctx, op, func(q DBTX) error {
		tag, err := q.Exec(ctx, pgschema.InsertUser, uuidArg(userID), u.Name, username,
			storekit.OrEmpty(u.Password), true, primary, org, changedAt, false, now, now)
		if err != nil {
			return dbFailed(op, err)
		}
		if tag.RowsAffected() == 0 {
			return failed(op, identity.ErrUserExists)
		}

		for i, name := range u.Roles {
			if _, err := q.Exec(ctx, pgschema.InsertGrant, uuidArg(grantIDs[i]), uuidArg(userID), name, i, i == 0,
				false, nil, nil, now, now); err != nil {
				return dbFailed(op, err)
			}
		}

		out, err = s.load(ctx, q, op, pgschema.UserByID, uuidArg(userID))

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
		var raw pgtype.UUID
		err := q.QueryRow(ctx, pgschema.LockUserByUsername, username).Scan(&raw)
		if errors.Is(err, pgxv5.ErrNoRows) {
			return failed(op, identity.ErrUserNotFound)
		}
		if err != nil {
			return scanFailed(op, err)
		}
		userID, err := scanID(raw)
		if err != nil {
			return failed(op, err)
		}

		now := storekit.Time(s.c.clock.Now())

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
			if _, err := q.Exec(ctx, query, args...); err != nil {
				return dbFailed(op, err)
			}
		}

		if len(roles) > 0 {
			if err := writeGrants(ctx, q, op, userID, rebuilt, now); err != nil {
				return err
			}
		}

		out, err = s.load(ctx, q, op, pgschema.UserByID, uuidArg(userID))

		return err
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// storedGrant is one row of assigned_roles as a rebuild reads it. The times
// are kept as scanned, so a kept grant is written back exactly as stored.
type storedGrant struct {
	id                    id.ID
	name                  string
	superRole             bool
	startDate, validUntil pgtype.Timestamptz
	createdAt             pgtype.Timestamptz
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
	existing, err := grantsInPosition(ctx, q, op, userID)
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
		rebuilt[i] = storedGrant{id: fresh, name: name, createdAt: pgtype.Timestamptz{Time: now, Valid: true}}
	}

	return rebuilt, nil
}

// writeGrants replaces the grants of userID with rebuilt, planned by
// planGrants, in that order, the first primary.
func writeGrants(ctx context.Context, q DBTX, op string, userID id.ID, rebuilt []storedGrant, now time.Time) error {
	if _, err := q.Exec(ctx, pgschema.DeleteGrantsByUser, uuidArg(userID)); err != nil {
		return dbFailed(op, err)
	}

	for i, g := range rebuilt {
		if _, err := q.Exec(ctx, pgschema.InsertGrant, uuidArg(g.id), uuidArg(userID), g.name, i, i == 0,
			g.superRole, g.startDate, g.validUntil, g.createdAt, now); err != nil {
			return dbFailed(op, err)
		}
	}

	return nil
}

// grantsInPosition returns the user's stored grants by name, keeping for each
// name the grant first in stored position.
func grantsInPosition(ctx context.Context, q DBTX, op string, userID id.ID) (map[string]storedGrant, error) {
	rows, err := q.Query(ctx, pgschema.GrantsByUserInPosition, uuidArg(userID))
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer rows.Close()

	out := make(map[string]storedGrant)
	for rows.Next() {
		var (
			g   storedGrant
			raw pgtype.UUID
		)
		// The position, primary flag and update time are selected but not
		// kept: a rebuild sets all three afresh.
		if err := rows.Scan(&raw, &g.name, nil, nil, &g.superRole, &g.startDate, &g.validUntil,
			&g.createdAt, nil); err != nil {
			return nil, scanFailed(op, err)
		}
		if g.id, err = scanID(raw); err != nil {
			return nil, failed(op, err)
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

// atomically runs fn as one unit on the handle ctx resolves to: in a
// savepoint inside a caller's transaction, otherwise in a transaction of the
// store's own on its pool.
func (s *IdentityStore) atomically(ctx context.Context, op string, fn func(q DBTX) error) error {
	q, ambient, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}

	if ambient {
		return s.underSavepoint(ctx, q, op, fn)
	}

	tx, err := s.c.base.Begin(ctx)
	if err != nil {
		return dbFailed(op, err)
	}
	// Rolled back on every way out but a commit, a panic in fn included, so
	// the transaction and the row locks it holds never outlive the call, even
	// when ctx is done. After a commit the rollback does nothing.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbFailed(op, err)
	}

	return nil
}

// underSavepoint runs fn on q, a caller's transaction, under a savepoint of
// its own. When fn fails, the savepoint is rolled back, which undoes fn's
// writes and clears the aborted state a failed statement leaves, so the
// caller's transaction stays usable with its earlier writes intact; the
// savepoint is then released either way. pgx's own nesting (Tx.Begin) is not
// used: its Rollback rolls back to the savepoint without releasing it, which
// leaves one open per failed call.
//
// When fn panics, or a panic interrupts one of the statements that closes
// the savepoint, the savepoint is rolled back and released before the panic
// goes on, so a caller that recovers it and commits commits none of fn's
// writes.
//
// The statements are issued through q's Exec, so a consumer's transaction
// wrapper sees them. The name comes from the store's own counter, never from
// input. The statements that close the savepoint run even when ctx is done,
// since leaving it open would leave the caller's transaction aborted, or
// would commit fn's writes with the caller's.
func (s *IdentityStore) underSavepoint(ctx context.Context, q DBTX, op string, fn func(q DBTX) error) error {
	name := "scrty_identity_" + strconv.FormatUint(s.savepoints.Add(1), 10)

	if _, err := q.Exec(ctx, "SAVEPOINT "+name); err != nil {
		return dbFailed(op, err)
	}

	closeCtx := context.WithoutCancel(ctx)
	exec := func(stmt string) error {
		_, err := q.Exec(closeCtx, stmt+name)
		return err
	}

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
		// recovers its own: a transaction wrapper that panics here too must
		// not replace the panic the caller will recover.
		bestEffort(func() { _ = exec("ROLLBACK TO SAVEPOINT ") })
		bestEffort(func() { _ = exec("RELEASE SAVEPOINT ") })
	}()

	err := fn(q)

	if err != nil {
		if rbErr := exec("ROLLBACK TO SAVEPOINT "); rbErr != nil {
			open = false
			return errors.Join(err, dbFailed(op, rbErr))
		}
		if relErr := exec("RELEASE SAVEPOINT "); relErr != nil {
			open = false
			return errors.Join(err, dbFailed(op, relErr))
		}
		open = false

		return err
	}

	if err := exec("RELEASE SAVEPOINT "); err != nil {
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

// load reads the complete record of the user query selects with arg, through
// q: the user row, then its grants, organization and group.
func (s *IdentityStore) load(ctx context.Context, q DBTX, op, query string, arg any) (*identity.Details, error) {
	var (
		d             identity.Details
		rawID, rawOrg pgtype.UUID
		changedAt     pgtype.Timestamptz
	)
	// The primary role, the MFA flag and the row's times are selected but
	// not returned: the grants carry the roles, Required reads the flag.
	err := q.QueryRow(ctx, query, arg).Scan(&rawID, &d.Name, &d.Username, &d.Password, &d.Active,
		nil, &rawOrg, &changedAt, nil, nil, nil)
	if errors.Is(err, pgxv5.ErrNoRows) {
		return nil, failed(op, identity.ErrUserNotFound)
	}
	if err != nil {
		return nil, scanFailed(op, err)
	}
	userID, err := scanID(rawID)
	if err != nil {
		return nil, failed(op, err)
	}
	d.ID = identity.UserID(userID.String())
	if d.PasswordChangedAt, err = fromNull(changedAt); err != nil {
		return nil, failed(op, err)
	}
	if d.Password == nil {
		d.Password = []byte{}
	}

	if d.Roles, err = grants(ctx, q, op, userID); err != nil {
		return nil, err
	}

	if rawOrg.Valid {
		if d.Organization, err = organization(ctx, q, op, nullableID(rawOrg)); err != nil {
			return nil, err
		}
	}

	return &d, nil
}

// grants reads the user's grants, primary first, then in stored position.
func grants(ctx context.Context, q DBTX, op string, userID id.ID) ([]*identity.AssignedRole, error) {
	rows, err := q.Query(ctx, pgschema.GrantsByUser, uuidArg(userID))
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer rows.Close()

	var out []*identity.AssignedRole
	for rows.Next() {
		var (
			g            identity.AssignedRole
			raw          pgtype.UUID
			position     int32
			start, until pgtype.Timestamptz
		)
		// The position is scanned to check the row, and not returned: the
		// query already orders by it. The row's times are not returned.
		if err := rows.Scan(&raw, &g.Name, &position, &g.Primary, &g.SuperRole, &start, &until,
			nil, nil); err != nil {
			return nil, scanFailed(op, err)
		}
		grantID, err := scanID(raw)
		if err != nil {
			return nil, failed(op, err)
		}
		g.ID = grantID.String()
		if g.StartDate, err = fromNull(start); err != nil {
			return nil, failed(op, err)
		}
		if g.ValidUntil, err = fromNull(until); err != nil {
			return nil, failed(op, err)
		}
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
func organization(ctx context.Context, q DBTX, op string, orgID id.ID) (*identity.Organization, error) {
	var (
		org          identity.Organization
		rawID, rawGr pgtype.UUID
	)
	err := q.QueryRow(ctx, pgschema.OrganizationByID, uuidArg(orgID)).Scan(&rawID, &org.Name, &rawGr, nil, nil)
	if errors.Is(err, pgxv5.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, scanFailed(op, err)
	}
	rowID, err := scanID(rawID)
	if err != nil {
		return nil, failed(op, err)
	}
	org.ID = rowID.String()

	if !rawGr.Valid {
		return &org, nil
	}

	var (
		g   identity.Group
		gID pgtype.UUID
	)
	err = q.QueryRow(ctx, pgschema.GroupByID, uuidArg(nullableID(rawGr))).Scan(&gID, &g.Name, &g.Internal, nil, nil)
	if errors.Is(err, pgxv5.ErrNoRows) {
		return &org, nil
	}
	if err != nil {
		return nil, scanFailed(op, err)
	}
	groupID, err := scanID(gID)
	if err != nil {
		return nil, failed(op, err)
	}
	g.ID = groupID.String()
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
// one: nil (NULL) for none or one with no identifier, otherwise its canonical
// text. A reference that is not a UUID in canonical lowercase text, an
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

	return uuidArg(org), nil
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
