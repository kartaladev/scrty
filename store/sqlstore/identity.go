package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
)

// IdentityStore keeps users, their role grants, organizations, groups and role
// privileges in the tables migrate.Identity creates. It implements
// identity.UserLoader, identity.RoleLoader, identity.UserProvisioner,
// identity.MFARequirementLookup and identity.EmailLoader, and is safe for
// concurrent use. It also implements password.History over the
// scrty_password_history table, for a password.NoReuse rule; no identity port
// call reads or writes that table.
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
// The record carries the user's email and its verification time as stored,
// each empty when none is, and each privilege carries its scope as stored; a
// privilege written before scopes existed reads "all".
//
// A soft-deleted user (one whose deleted_at is set by the administration
// services) is unknown to every port: LoadByUsername, LoadByUserID,
// LoadByEmail and Update report identity.ErrUserNotFound for it, and so does
// Required. Its row and username stay, so Provision of that username is still
// identity.ErrUserExists.
//
// LoadByEmail matches the address ignoring case (PostgreSQL's lower()), only
// among live users whose email is verified. An address PostgreSQL text cannot
// hold, or one the database's encoding cannot represent, is
// identity.ErrUserNotFound, since no user can hold it; any other failure is
// not.
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
// never because a password was. An email address passed to either verb is
// accepted and discarded, as an OIDC broker's just-in-time login passes one:
// only the administration services set a user's email. Neither verb reads or
// writes the MFA flag.
//
// Provision refuses, with identity.ErrUserExists and nothing written, a
// username that is the email of another live user, ignoring case. It first
// takes PostgreSQL's transaction-scoped advisory lock on the lower-cased
// username, the lock every write setting an email takes on the address, so the
// two cannot race to coincide. The lock is held until the transaction ends:
// inside a caller's transaction, until the caller commits or rolls back. Under
// a caller's REPEATABLE READ or SERIALIZABLE transaction, the check reads the
// caller's snapshot, so it cannot see an email committed after that snapshot
// was taken; the stores' own transactions are READ COMMITTED. Update increases
// the user's version whenever it writes to the user, so an administrator's
// earlier read of the user becomes stale; it never compares the version.
//
// Organizations, groups, the role catalogue (roles) and resource privileges
// have no write path through this store either: the consumer's own user
// management owns them, and Provision and Update store only an organization's
// reference and the role names a caller gives, as the user's own grants.
//
// Provision, Update and RetirePassword are atomic. Outside a caller's
// transaction each runs in a transaction of its own; inside one it runs under
// a savepoint, so a failure undoes only the store's own writes and leaves the
// caller's transaction usable. A panic out of a consumer's generator or handle, and a context
// cancelled between two statements, leave nothing of the call behind either:
// its transaction is rolled back, or its savepoint rolled back and released.
// The savepoint names come from a counter of the store's own, never from
// input.
//
// # Defaults and options
//
// It honours WithTxResolver, WithIDGenerator (default id.NewV7Generator; the
// identifiers of the users, grants and password-history entries it creates) and
// WithClock (default clock.System(); every created_at and updated_at it writes,
// and every password-history entry's retired_at), and refuses any other option.
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
// library's own, the operation's name and "database failure", followed by the
// SQLSTATE when the driver's error reports one through a SQLState method (as
// pgconn.PgError and lib/pq's Error do). The driver's message is never kept,
// since a PostgreSQL primary message can quote a value; a column-conversion
// failure of a Scan call names the column's index and name instead. It still
// matches context.Canceled, context.DeadlineExceeded,
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
// (scrty_assigned_roles) and calling ForgetPasswords for that user's password
// history in the same transaction; nothing cascades.
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

	errConditionOnProvision     = errors.New("a password condition cannot apply to a new user")
	errConditionWithoutPassword = errors.New("a password condition needs a new password named")
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

	return s.load(ctx, q, op, pgschema.UserRecordByUsername, username, username)
}

// LoadByUserID loads the user with this reference, or returns
// identity.ErrUserNotFound, including for a reference that is not a canonical
// lowercase UUID string.
func (s *IdentityStore) LoadByUserID(ctx context.Context, ref identity.UserID) (*identity.Details, error) {
	const op = "load user by reference"

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return nil, failed(op, identity.ErrUserNotFound)
	}

	q, _, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	return s.load(ctx, q, op, pgschema.UserRecordByID, uid, "")
}

// LoadByEmail loads the live user whose verified email is email, ignoring
// case, or returns identity.ErrUserNotFound. An empty email is not found
// before any query runs.
//
// Case folding is PostgreSQL's lower(): ASCII-only under a C or POSIX ctype,
// and no Unicode normalisation is applied, so canonically equivalent spellings
// of one address are different addresses. A consumer that wants stricter
// matching normalises the address before calling.
func (s *IdentityStore) LoadByEmail(ctx context.Context, email string) (*identity.Details, error) {
	const op = "load user by email"

	if email == "" || !storekit.Storable(email) {
		return nil, failed(op, identity.ErrUserNotFound)
	}

	q, _, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	return s.load(ctx, q, op, pgschema.UserRecordByVerifiedEmail, email, email)
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

	rows, err := q.QueryContext(ctx, pgschema.ScopedPrivilegesByRole, role)
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
			scope                   string
		)
		if err := rows.Scan(&rowID, &roleName, &group, &res, &p.Name, &p.Granted, &created, &updated, &scope); err != nil {
			return nil, scanFailed(op, err)
		}
		p.Scope = identity.Scope(scope)

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

	uid, ok := storekit.ParseUserID(ref)
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
//
// Provision's case-insensitive comparisons between a username and an email
// use PostgreSQL's lower(): ASCII-only under a C or POSIX ctype, and no
// Unicode normalisation is applied. A consumer that wants stricter matching
// normalises the username and email before calling.
func (s *IdentityStore) Provision(
	ctx context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	const op = "provision user"

	if username == "" {
		return nil, failed(op, errEmptyUsername)
	}

	u := identity.ApplyUserOptions(opts...)
	if _, conditional := u.ExpectedPassword(); conditional {
		return nil, failed(op, errConditionOnProvision)
	}
	if err := storekit.CheckUser(username, u); err != nil {
		return nil, failed(op, err)
	}
	org, err := orgReference(u)
	if err != nil {
		return nil, failed(op, err)
	}

	// Every identifier is minted before the first write, so a generator
	// failure writes nothing.
	userID, err := idgen.New(s.c.ids)
	if err != nil {
		return nil, failed(op, err)
	}
	grantIDs := make([]id.ID, len(u.Roles))
	for i := range grantIDs {
		if grantIDs[i], err = idgen.New(s.c.ids); err != nil {
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
	now := storekit.Time(s.c.clock.Now())

	var out *identity.Details
	err = s.atomically(ctx, op, func(q DBTX) error {
		if err := refuseAnotherUsersEmail(ctx, q, op, username); err != nil {
			return err
		}

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

		out, err = s.load(ctx, q, op, pgschema.UserRecordByID, userID, "")

		return err
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// Update amends the fields opts name on the user with this username, or
// returns identity.ErrUserNotFound, and returns the complete stored record.
//
// An update conditional on the stored hash (identity.WithUserPasswordIf) is
// decided by the UPDATE's own WHERE, on the user's row locked for this
// update: when the stored hash differs, nothing is written, the transaction
// (or savepoint) is rolled back, and the update returns
// identity.ErrNotUpdated. The condition needs a new password named, and is
// refused on Provision.
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
	expected, conditional := u.ExpectedPassword()
	if conditional && !u.IsSet(identity.FieldPassword) {
		return nil, failed(op, errConditionWithoutPassword)
	}
	if err := storekit.CheckUser(username, u); err != nil {
		return nil, failed(op, err)
	}
	org, err := orgReference(u)
	if err != nil {
		return nil, failed(op, err)
	}

	var roles []string
	if u.IsSet(identity.FieldRoles) {
		roles = storekit.SurvivingRoles(u.Roles)
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

		set := storekit.UserColumns(u, org, nullTs)
		if len(roles) > 0 {
			set = append(set, storekit.RoleColumn(roles[0]))
		}
		if len(set) > 0 {
			query, args := storekit.UpdateUserQuery(set, now, userID)
			if conditional {
				query, args = passwordCondition(query, args, expected)
			}
			res, err := q.ExecContext(ctx, query, args...)
			if err != nil {
				return dbFailed(op, err)
			}
			if conditional {
				n, err := res.RowsAffected()
				if err != nil {
					return dbFailed(op, err)
				}
				if n == 0 {
					return failed(op, identity.ErrNotUpdated)
				}
			}
			if _, err := q.ExecContext(ctx, pgschema.BumpUserVersion, userID); err != nil {
				return dbFailed(op, err)
			}
		}

		if len(roles) > 0 {
			if err := writeGrants(ctx, q, op, userID, rebuilt, now); err != nil {
				return err
			}
		}

		out, err = s.load(ctx, q, op, pgschema.UserRecordByID, userID, "")

		return err
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// refuseAnotherUsersEmail takes the advisory lock of username, inside the
// transaction q is, and refuses it with identity.ErrUserExists when it is the
// email of a live user, ignoring case. Every write that sets an email takes the
// same lock before checking the other way, so a username and another user's
// email cannot be written to coincide by two writers racing. The lock is held
// until the transaction ends.
func refuseAnotherUsersEmail(ctx context.Context, q DBTX, op, username string) error {
	if err := lockIdentifiers(ctx, q, op, username); err != nil {
		return err
	}

	var held bool
	if err := q.QueryRowContext(ctx, pgschema.EmailHeldByLiveUser, username, nil).Scan(&held); err != nil {
		return scanFailed(op, err)
	}
	if held {
		return failed(op, identity.ErrUserExists)
	}

	return nil
}

// lockIdentifiers takes, inside the transaction q is, the advisory lock of
// every one of values (usernames or emails) in the order the server gives
// their keys (see pgschema.IdentifierLockKeys), so two writers locking
// overlapping values cannot deadlock. The keys are read in full before the
// first lock is taken: a handle cannot run a statement while rows are open.
func lockIdentifiers(ctx context.Context, q DBTX, op string, values ...string) error {
	rows, err := q.QueryContext(ctx, pgschema.IdentifierLockKeys, pgschema.TextArray(values))
	if err != nil {
		return dbFailed(op, err)
	}
	var keys []int64
	for rows.Next() {
		var k int64
		if err := rows.Scan(&k); err != nil {
			_ = rows.Close()
			return scanFailed(op, err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return dbFailed(op, err)
	}
	if err := rows.Close(); err != nil {
		return dbFailed(op, err)
	}

	for _, k := range keys {
		if _, err := q.ExecContext(ctx, pgschema.LockIdentifierKey, k); err != nil {
			return dbFailed(op, err)
		}
	}

	return nil
}

// passwordCondition narrows the UPDATE query to a stored password equal to
// expected, so the condition is decided by the write itself.
func passwordCondition(query string, args []any, expected []byte) (string, []any) {
	args = append(args, storekit.OrEmpty(expected))

	return query + " AND password = $" + strconv.Itoa(len(args)), args
}

// storedGrant is one row of scrty_assigned_roles as a rebuild reads it.
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

		fresh, err := idgen.New(s.c.ids)
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

	tx, err := s.c.beginReadCommitted(ctx)
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
//
// typed is the text the caller supplied as arg, or "" when arg is not text a
// caller supplied. A typed value the database cannot hold matches no user: the
// load reports identity.ErrUserNotFound for it, as it does for a user that is
// not there (see storekit.LookupMiss).
func (s *IdentityStore) load(ctx context.Context, q DBTX, op, query string, arg any, typed string) (*identity.Details, error) {
	var (
		d                    identity.Details
		userID               id.ID
		role                 string
		orgID                sql.Null[id.ID]
		changedAt            sql.NullTime
		mfa                  bool
		createdAt, updatedAt time.Time
		email                sql.NullString
		verifiedAt           sql.NullTime
	)
	err := q.QueryRowContext(ctx, query, arg).Scan(&userID, &d.Name, &d.Username, &d.Password, &d.Active,
		&role, &orgID, &changedAt, &mfa, &createdAt, &updatedAt, &email, &verifiedAt)
	// A value the database cannot hold matches no user.
	if errors.Is(err, sql.ErrNoRows) || storekit.LookupMiss(typed, err) {
		return nil, failed(op, identity.ErrUserNotFound)
	}
	if err != nil {
		return nil, scanFailed(op, err)
	}
	d.ID = identity.UserID(userID.String())
	d.PasswordChangedAt = fromNull(changedAt)
	d.Email = email.String
	d.EmailVerifiedAt = fromNull(verifiedAt)
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

// orgReference is the organization reference to store when the caller named
// one: nil (NULL) for none or one with no identifier, otherwise the parsed
// UUID. A reference that is not a UUID in canonical lowercase text, an
// upper-case spelling of one included, is refused before anything is written,
// with text that does not carry it. It matches byte for byte, as user
// references do, so every adapter stores the same references.
func orgReference(u *identity.UserChange) (any, error) {
	if !u.IsSet(identity.FieldOrganization) || u.Organization == nil || u.Organization.ID == "" {
		return nil, nil
	}

	org, err := id.Parse(u.Organization.ID)
	if err != nil || org.String() != u.Organization.ID {
		return nil, errOrgReference
	}

	return org, nil
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
	_ identity.EmailLoader          = (*IdentityStore)(nil)
	_ password.History              = (*IdentityStore)(nil)
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
		storekit.BestEffort(func() { _, _ = q.ExecContext(closeCtx, "ROLLBACK TO SAVEPOINT "+name) })
		storekit.BestEffort(func() { _, _ = q.ExecContext(closeCtx, "RELEASE SAVEPOINT "+name) })
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
