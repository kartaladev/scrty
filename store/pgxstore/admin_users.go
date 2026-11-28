package pgxstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
)

// The administration ports. IdentityStore implements admin.UserStore and
// admin.ImportStore over the identity tables, with the statements of
// internal/pgschema it shares with pgxstore.
//
// Every versioned write runs in one transaction (or, inside a caller's, under
// a savepoint): it locks the live user's row (SELECT ... FOR UPDATE), compares
// the version the caller read, writes, and increases the version. A write
// that sets a username or an email takes the transaction-scoped advisory lock
// of each lower-cased value first, the lock Provision takes, then refuses a
// username taken by any user, deleted or not, a username that is another live
// user's email, and an email that is another live user's email or username,
// ignoring case, each with an admin.AlreadyExistsError naming the field. The
// insert itself still decides a collision the locks could not see (a writer
// that takes no lock): it inserts nothing, and the store reads which value
// collided. Case folding is PostgreSQL's lower(), as for Provision.
//
// A user reference that is not canonical lowercase UUID text names no user
// (admin.ErrNotFound). Text PostgreSQL cannot store, an organization reference
// or list cursor identifier that is not canonical lowercase UUID text, and a
// limit below one are admin.ErrInvalidInput. Error text never carries a
// username, an email, an attribute value or a password hash.
var (
	_ admin.UserStore   = (*IdentityStore)(nil)
	_ admin.ImportStore = (*IdentityStore)(nil)
)

// errImportConflict is an insert that collided with a row the store could
// not find afterwards: a concurrent writer removed it in between.
var errImportConflict = errors.New("the user collided with a row that is gone; retry")

// invalidInput is an admin.ErrInvalidInput naming what was wrong, never the
// value.
func invalidInput(op, what string) error {
	return failed(op, fmt.Errorf("%w: %s", admin.ErrInvalidInput, what))
}

// alreadyExists is the admin.AlreadyExistsError for field.
func alreadyExists(op, field string) error {
	return failed(op, admin.AlreadyExistsError{Field: field})
}

func notFound(op string) error { return failed(op, admin.ErrNotFound) }

// isUniqueViolation reports whether err is PostgreSQL's unique_violation.
func isUniqueViolation(err error) bool {
	var st storekit.SQLStater

	return errors.As(err, &st) && st.SQLState() == "23505"
}

// adminOrgReference is the stored reference of org: nil (NULL) for none,
// otherwise its canonical UUID.
func adminOrgReference(op string, org *identity.Organization) (any, error) {
	if org == nil || org.ID == "" {
		return nil, nil
	}

	v, err := id.Parse(org.ID)
	if err != nil || v.String() != org.ID {
		return nil, invalidInput(op, "the organization reference is not a UUID in canonical lowercase text")
	}

	return v, nil
}

// checkOrganization refuses, as admin.ErrInvalidInput, a reference (from
// adminOrgReference) that names no stored organization, and locks the one it
// names until the transaction ends. A nil reference is no organization.
func checkOrganization(ctx context.Context, q DBTX, op string, org any) error {
	if org == nil {
		return nil
	}

	var one int
	err := q.QueryRow(ctx, pgschema.ShareOrganization, org).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return invalidInput(op, "the organization reference names no organization")
	}
	if err != nil {
		return scanFailed(op, err)
	}

	return nil
}

// checkAttributes refuses attributes PostgreSQL text cannot store.
func checkAttributes(op string, attrs map[string]string) error {
	for k, v := range attrs {
		if !storekit.Storable(k, v) {
			return invalidInput(op, "an attribute holds text that cannot be stored")
		}
	}

	return nil
}

// emptyNull is s, or NULL when s is empty.
func emptyNull(s string) any {
	if s == "" {
		return nil
	}

	return s
}

var _ admin.UserPager = (*IdentityStore)(nil)

// ListUsers implements admin.UserStore.
func (s *IdentityStore) ListUsers(ctx context.Context, query admin.UserQuery) ([]admin.User, error) {
	const op = "list users"

	if query.Limit < 1 {
		return nil, invalidInput(op, "the limit is below one")
	}
	if !storekit.Storable(query.AfterUsername) {
		return nil, invalidInput(op, "a filter holds text that cannot be stored")
	}

	var after any
	if query.AfterUsername != "" || query.AfterID != "" {
		uid, ok := storekit.ParseUserID(query.AfterID)
		if !ok || query.AfterUsername == "" {
			return nil, invalidInput(op, "the cursor does not name a user")
		}
		after = uid
	}

	args, err := userFilterArgs(op, query)
	if err != nil {
		return nil, err
	}

	return s.listAdminUsers(ctx, op, pgschema.ListAdminUsers,
		append(args, query.AfterUsername, after, query.Limit)...)
}

// ListUsersFrom implements admin.UserPager: the users ListUsers lists for
// query's filters, in its order, after skipping offset of them. A limit below
// one, a negative offset and a cursor are refused, since an offset and a
// cursor are alternatives.
func (s *IdentityStore) ListUsersFrom(ctx context.Context, query admin.UserQuery, offset int) ([]admin.User, error) {
	const op = "list users from an offset"

	if query.Limit < 1 {
		return nil, invalidInput(op, "the limit is below one")
	}
	if offset < 0 {
		return nil, invalidInput(op, "the offset is below zero")
	}
	if query.AfterUsername != "" || query.AfterID != "" {
		return nil, invalidInput(op, "an offset listing names no cursor")
	}

	args, err := userFilterArgs(op, query)
	if err != nil {
		return nil, err
	}

	return s.listAdminUsers(ctx, op, pgschema.ListAdminUsersFrom, append(args, query.Limit, offset)...)
}

// CountUsers implements admin.UserPager: the number of live users matching
// query's filters, the users ListUsers lists. Limit and the cursor are
// ignored.
func (s *IdentityStore) CountUsers(ctx context.Context, query admin.UserQuery) (int64, error) {
	const op = "count users"

	args, err := userFilterArgs(op, query)
	if err != nil {
		return 0, err
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}

	var n int64
	if err := q.QueryRow(ctx, pgschema.CountAdminUsers, args...).Scan(&n); err != nil {
		return 0, dbFailed(op, err)
	}

	return n, nil
}

// userFilterArgs binds query's filters to the parameters $1 to $5 of
// pgschema's user listings and count, refusing text a column cannot store.
func userFilterArgs(op string, query admin.UserQuery) ([]any, error) {
	if !storekit.Storable(query.Search, query.Role) {
		return nil, invalidInput(op, "a filter holds text that cannot be stored")
	}

	var active, attrName, attrValue any
	if query.Active != nil {
		active = *query.Active
	}
	if a := query.Attribute; a != nil {
		if !storekit.Storable(a.Name, a.Value) {
			return nil, invalidInput(op, "a filter holds text that cannot be stored")
		}
		attrName, attrValue = a.Name, a.Value
	}

	return []any{pgschema.LikePattern(query.Search), active, query.Role, attrName, attrValue}, nil
}

// listAdminUsers runs a user listing statement with args and reads its users,
// with their grants, attributes and organizations.
func (s *IdentityStore) listAdminUsers(ctx context.Context, op, stmt string, args ...any) ([]admin.User, error) {
	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	rows, err := q.Query(ctx, stmt, args...)
	if err != nil {
		return nil, dbFailed(op, err)
	}
	var (
		users []admin.User
		orgs  []pgtype.UUID
	)
	for rows.Next() {
		u, org, err := scanAdminUser(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, scanFailed(op, err)
		}
		users = append(users, u)
		orgs = append(orgs, org)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}

	if err := s.completeUsers(ctx, q, op, users, orgs); err != nil {
		return nil, err
	}

	return users, nil
}

// GetUser implements admin.UserStore.
func (s *IdentityStore) GetUser(ctx context.Context, ref identity.UserID) (admin.User, error) {
	const op = "get user"

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return admin.User{}, notFound(op)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return admin.User{}, failed(op, err)
	}

	return s.readAdminUser(ctx, q, op, uid)
}

// CreateUser implements admin.UserStore. The user is created active, at
// version one, with no password and no roles.
func (s *IdentityStore) CreateUser(ctx context.Context, in admin.NewUser) (admin.User, error) {
	const op = "create user"

	uid, ok := storekit.ParseUserID(in.ID)
	if !ok {
		return admin.User{}, invalidInput(op, "the identifier is not a UUID in canonical lowercase text")
	}
	if in.Username == "" {
		return admin.User{}, invalidInput(op, "the username is empty")
	}
	if !storekit.Storable(in.Username, in.Name, in.Email) {
		return admin.User{}, invalidInput(op, "a field holds text that cannot be stored")
	}
	if err := checkAttributes(op, in.Attributes); err != nil {
		return admin.User{}, err
	}
	org, err := adminOrgReference(op, in.Organization)
	if err != nil {
		return admin.User{}, err
	}

	now := storekit.Time(s.c.clock.Now())

	var out admin.User
	err = s.atomically(ctx, op, func(q DBTX) error {
		if err := checkOrganization(ctx, q, op, org); err != nil {
			return err
		}
		if err := checkIdentifiers(ctx, q, op, uid, in.Username, in.Email); err != nil {
			return err
		}

		tag, err := q.Exec(ctx, pgschema.InsertAdminUser, uid, in.Username, in.Name, emptyNull(in.Email),
			nullTs(in.EmailVerifiedAt), []byte{}, true, "", org, now, now)
		if err != nil {
			return dbFailed(op, err)
		}
		if tag.RowsAffected() == 0 {
			return diagnoseCollision(ctx, q, op, uid, in.Username, in.Email, true)
		}

		if err := writeAttributes(ctx, q, op, uid, in.Attributes); err != nil {
			return err
		}

		out, err = s.readAdminUser(ctx, q, op, uid)

		return err
	})
	if err != nil {
		return admin.User{}, err
	}

	return out, nil
}

// UpdateUser implements admin.UserStore.
func (s *IdentityStore) UpdateUser(
	ctx context.Context, ref identity.UserID, version int64, change admin.UserChange,
) (admin.User, error) {
	const op = "update user"

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return admin.User{}, notFound(op)
	}

	upd, err := prepareAdminUpdate(op, change)
	if err != nil {
		return admin.User{}, err
	}

	var out admin.User
	err = s.atomically(ctx, op, func(q DBTX) error {
		cur, err := lockAdminUser(ctx, q, op, uid, version)
		if err != nil {
			return err
		}
		if err := upd.check(ctx, q, op, cur); err != nil {
			return err
		}

		if email := upd.changedEmail(cur); email != "" {
			if err := checkIdentifiers(ctx, q, op, uid, "", email); err != nil {
				return err
			}
		}

		out, err = s.writeAdminUpdate(ctx, q, op, uid, upd)

		return err
	})
	if err != nil {
		return admin.User{}, err
	}

	return out, nil
}

// UpdateUserRenaming implements admin.UsernameUpdater. It runs as UpdateUser
// does, in one transaction under the user's row lock, and also writes the
// username: both named identifiers are locked and checked together under the
// rules of CreateUser, the username is written alone first
// (pgschema.RenameAdminUser), so a unique violation there is the username's,
// and the other fields follow with the version. renamed is whether the stored
// username differed, byte for byte.
func (s *IdentityStore) UpdateUserRenaming(
	ctx context.Context, ref identity.UserID, version int64, change admin.UserChange,
) (admin.User, bool, error) {
	const op = "update user"

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return admin.User{}, false, notFound(op)
	}
	if change.Username == nil || *change.Username == "" {
		return admin.User{}, false, invalidInput(op, "the change names no username")
	}
	if !storekit.Storable(*change.Username) {
		return admin.User{}, false, invalidInput(op, "the username holds text that cannot be stored")
	}

	upd, err := prepareAdminUpdate(op, change)
	if err != nil {
		return admin.User{}, false, err
	}

	var (
		out     admin.User
		renamed bool
	)
	err = s.atomically(ctx, op, func(q DBTX) error {
		cur, err := lockAdminUser(ctx, q, op, uid, version)
		if err != nil {
			return err
		}
		if err := upd.check(ctx, q, op, cur); err != nil {
			return err
		}

		// One call, so the username and the email are locked in key order
		// before either is checked.
		if err := checkIdentifiers(ctx, q, op, uid, *change.Username, upd.changedEmail(cur)); err != nil {
			return err
		}

		tag, err := q.Exec(ctx, pgschema.RenameAdminUser, uid, *change.Username)
		if err != nil {
			if isUniqueViolation(err) {
				return alreadyExists(op, admin.FieldUsername)
			}
			return dbFailed(op, err)
		}
		n := tag.RowsAffected()
		if n > 1 {
			return failed(op, errRenameRows)
		}
		renamed = n == 1

		out, err = s.writeAdminUpdate(ctx, q, op, uid, upd)

		return err
	})
	if err != nil {
		return admin.User{}, false, err
	}

	return out, renamed, nil
}

// errRenameRows reports a rename that affected more than the one row its
// primary key names: the schema is not the one this store was written for.
var errRenameRows = errors.New("the rename affected more than one row")

// adminUpdate is an administrative update's fields other than the username,
// validated and laid out for pgschema.UpdateAdminUserQuery before the
// transaction starts.
type adminUpdate struct {
	change  admin.UserChange
	columns []string
	values  []any
	newOrg  any
}

// prepareAdminUpdate validates change's fields other than the username and
// lays them out as the columns of pgschema.UpdateAdminUserQuery.
func prepareAdminUpdate(op string, change admin.UserChange) (adminUpdate, error) {
	u := adminUpdate{change: change}
	if change.Name != nil {
		if !storekit.Storable(*change.Name) {
			return adminUpdate{}, invalidInput(op, "the name holds text that cannot be stored")
		}
		u.columns, u.values = append(u.columns, pgschema.ColumnName), append(u.values, *change.Name)
	}
	if change.Email != nil {
		if !storekit.Storable(*change.Email) {
			return adminUpdate{}, invalidInput(op, "the email holds text that cannot be stored")
		}
		u.columns, u.values = append(u.columns, pgschema.ColumnEmail), append(u.values, emptyNull(*change.Email))
		if change.EmailVerifiedAt == nil {
			// The statement keeps the verification only for the stored
			// address, compared under the row lock it runs in.
			u.columns = append(u.columns, pgschema.ColumnEmailVerifiedAtIfSameEmail)
			u.values = append(u.values, emptyNull(*change.Email))
		}
	}
	if change.EmailVerifiedAt != nil {
		u.columns = append(u.columns, pgschema.ColumnEmailVerifiedAt)
		u.values = append(u.values, nullTs(*change.EmailVerifiedAt))
	}
	if change.Organization != nil {
		org, err := adminOrgReference(op, *change.Organization)
		if err != nil {
			return adminUpdate{}, err
		}
		u.columns, u.values = append(u.columns, pgschema.ColumnOrganization), append(u.values, org)
		u.newOrg = org
	}
	if err := checkAttributes(op, change.Attributes); err != nil {
		return adminUpdate{}, err
	}

	return u, nil
}

// check refuses the update against cur, the locked row: a verification time
// with no email left to verify, and an organisation that does not exist.
func (u adminUpdate) check(ctx context.Context, q DBTX, op string, cur lockedUser) error {
	if verifiesNoEmail(u.change, cur) {
		return invalidInput(op, "an email verification time is set with no email to verify")
	}

	return checkOrganization(ctx, q, op, u.newOrg)
}

// changedEmail is the email the update sets when it names a non-empty one
// that differs from cur's, the locked row's, and "" otherwise: only a changed
// address needs the identifier checks.
func (u adminUpdate) changedEmail(cur lockedUser) string {
	if u.change.Email == nil || *u.change.Email == "" || *u.change.Email == cur.email.String {
		return ""
	}

	return *u.change.Email
}

// writeAdminUpdate writes the update's columns, updated_at and the next
// version, then its attributes, and reads the user back. A unique violation is
// the email's: the username, when it changes, is written before, alone.
func (s *IdentityStore) writeAdminUpdate(
	ctx context.Context, q DBTX, op string, uid id.ID, u adminUpdate,
) (admin.User, error) {
	now := storekit.Time(s.c.clock.Now())

	query, args := pgschema.UpdateAdminUserQuery(u.columns, u.values, now, uid)
	if _, err := q.Exec(ctx, query, args...); err != nil {
		if isUniqueViolation(err) {
			return admin.User{}, alreadyExists(op, admin.FieldEmail)
		}
		return admin.User{}, dbFailed(op, err)
	}

	if u.change.Attributes != nil {
		if err := replaceAttributes(ctx, q, op, uid, u.change.Attributes); err != nil {
			return admin.User{}, err
		}
	}

	return s.readAdminUser(ctx, q, op, uid)
}

// SetActive implements admin.UserStore.
func (s *IdentityStore) SetActive(
	ctx context.Context, ref identity.UserID, version int64, active bool,
) (admin.User, bool, error) {
	const op = "set user active"

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return admin.User{}, false, notFound(op)
	}

	var (
		out     admin.User
		changed bool
	)
	err := s.atomically(ctx, op, func(q DBTX) error {
		cur, err := lockAdminUser(ctx, q, op, uid, version)
		if err != nil {
			return err
		}

		if cur.active != active {
			now := storekit.Time(s.c.clock.Now())
			if _, err := q.Exec(ctx, pgschema.SetUserActive, uid, active, now); err != nil {
				return dbFailed(op, err)
			}
			changed = true
		}

		out, err = s.readAdminUser(ctx, q, op, uid)

		return err
	})
	if err != nil {
		return admin.User{}, false, err
	}

	return out, changed, nil
}

// DeleteUser implements admin.UserStore: it marks the user deleted and
// inactive, clears the email and its verification time, keeps the row, the
// username and the role grants, and removes the profile attributes and the
// password history, in one transaction.
func (s *IdentityStore) DeleteUser(ctx context.Context, ref identity.UserID, version int64) error {
	const op = "delete user"

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return notFound(op)
	}

	return s.atomically(ctx, op, func(q DBTX) error {
		if _, err := lockAdminUser(ctx, q, op, uid, version); err != nil {
			return err
		}

		now := storekit.Time(s.c.clock.Now())
		for _, stmt := range []struct {
			query string
			args  []any
		}{
			{pgschema.SoftDeleteUser, []any{uid, now}},
			{pgschema.DeleteAttributesByUser, []any{uid}},
			{pgschema.ForgetHistory, []any{uid}},
		} {
			if _, err := q.Exec(ctx, stmt.query, stmt.args...); err != nil {
				return dbFailed(op, err)
			}
		}

		return nil
	})
}

// CurrentPasswordHash implements admin.UserStore.
func (s *IdentityStore) CurrentPasswordHash(ctx context.Context, ref identity.UserID) ([]byte, error) {
	const op = "read current password"

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return nil, notFound(op)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	var hash []byte
	err = q.QueryRow(ctx, pgschema.CurrentPassword, uid).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound(op)
	}
	if err != nil {
		return nil, scanFailed(op, err)
	}
	if hash == nil {
		hash = []byte{}
	}

	return hash, nil
}

// SetPassword implements admin.UserStore. It writes only the new hash and the
// password-changed time, and increases the version: it records no password
// history, which the password policy's reuse rule keeps through
// password.History (RetirePassword) before this is called. An empty hash is
// admin.ErrInvalidInput.
func (s *IdentityStore) SetPassword(
	ctx context.Context, ref identity.UserID, version int64, hash []byte, at time.Time,
) (admin.User, error) {
	const op = "set password"

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return admin.User{}, notFound(op)
	}
	if len(hash) == 0 {
		return admin.User{}, invalidInput(op, "the password hash is empty")
	}

	var out admin.User
	err := s.atomically(ctx, op, func(q DBTX) error {
		if _, err := lockAdminUser(ctx, q, op, uid, version); err != nil {
			return err
		}

		now := storekit.Time(s.c.clock.Now())
		if _, err := q.Exec(ctx, pgschema.SetUserPassword, uid, hash, storekit.Time(at), now); err != nil {
			return dbFailed(op, err)
		}

		var err error
		out, err = s.readAdminUser(ctx, q, op, uid)

		return err
	})
	if err != nil {
		return admin.User{}, err
	}

	return out, nil
}

// ImportUser implements admin.ImportStore.
//
// It first takes the transaction-scoped advisory lock of the identifier
// (pgschema.LockImportIdentifier, a two-key lock that no username or email
// lock can equal), before any role, row or identifier lock,
// so imports of one identifier run one after another and never wait on each
// other in opposite orders. Inside a caller's transaction the lock is held
// until that transaction ends. Then it locks the row with the user's identifier, deleted or not. With none, it
// inserts the user, and when a concurrent import of the same identifier won
// the insert, it reads and locks that row and goes on as for an existing
// user, so the race reports ImportUnchanged or ImportUpdated, never a
// constraint error. An existing user's values are compared field by field
// (roles as the primary role and the set of names; attributes as a set) and
// written only when one differs. The identifier of a deleted user is
// admin.ErrAlreadyExists: an import never undeletes a user.
//
// Roles are granted in the order given, the first primary; repeated and
// empty names are skipped. A role the catalogue (scrty_roles) does not hold
// is admin.ErrNotFound. A new grant takes its super-role flag from the
// catalogue; an existing grant of a kept role keeps its own identifier,
// flags and window.
func (s *IdentityStore) ImportUser(ctx context.Context, in admin.ImportedUser) (admin.ImportOutcome, error) {
	const op = "import user"

	// The identifier is returned as given, so only the one spelling the
	// users table hands back is accepted: a canonical lower-case UUID, never
	// the nil UUID (design D14).
	uid, ok := storekit.ParseUserID(in.ID)
	if !ok || uid.IsZero() {
		return 0, invalidInput(op, "the identifier is not a non-nil UUID in canonical lowercase text")
	}
	if in.Username == "" {
		return 0, invalidInput(op, "the username is empty")
	}
	if !storekit.Storable(in.Username, in.Name, in.Email) || !storekit.Storable(in.Roles...) {
		return 0, invalidInput(op, "a field holds text that cannot be stored")
	}
	if err := checkAttributes(op, in.Attributes); err != nil {
		return 0, err
	}

	roles := storekit.SurvivingRoles(in.Roles)
	want := importValues{
		username: in.Username, name: in.Name, email: in.Email,
		verifiedAt: zeroOr(in.EmailVerifiedAt), password: storekit.OrEmpty(in.PasswordHash), active: in.Active,
		createdAt: zeroOr(in.CreatedAt), updatedAt: zeroOr(in.UpdatedAt),
	}
	primary := ""
	if len(roles) > 0 {
		primary = roles[0]
	}

	var outcome admin.ImportOutcome
	err := s.atomically(ctx, op, func(q DBTX) error {
		// Queue behind any other import of this identifier before taking
		// any other lock (see pgschema.LockImportIdentifier).
		if _, err := q.Exec(ctx, pgschema.LockImportIdentifier, uid.String()); err != nil {
			return dbFailed(op, err)
		}

		catalogue, err := knownRoles(ctx, q, op, roles)
		if err != nil {
			return err
		}

		now := storekit.Time(s.c.clock.Now())

		cur, found, err := lockImportUser(ctx, q, op, uid)
		if err != nil {
			return err
		}

		if !found {
			if err := checkIdentifiers(ctx, q, op, uid, in.Username, in.Email); err != nil {
				return err
			}

			tag, err := q.Exec(ctx, pgschema.InsertAdminUser, uid, want.username, want.name,
				emptyNull(want.email), nullTs(want.verifiedAt), want.password, want.active, primary, nil,
				givenOr(want.createdAt, now), givenOr(want.updatedAt, now))
			if err != nil {
				return dbFailed(op, err)
			}
			if tag.RowsAffected() == 1 {
				for i, name := range roles {
					gid, err := idgen.New(s.c.ids)
					if err != nil {
						return failed(op, err)
					}
					if _, err := q.Exec(ctx, pgschema.InsertGrant, gid, uid, name, i, i == 0,
						catalogue[name], nil, nil, now, now); err != nil {
						return dbFailed(op, err)
					}
				}
				if err := writeAttributes(ctx, q, op, uid, in.Attributes); err != nil {
					return err
				}
				outcome = admin.ImportCreated

				return nil
			}

			// The insert collided. A concurrent import of this identifier
			// that committed first is now visible: carry on as an update.
			if cur, found, err = lockImportUser(ctx, q, op, uid); err != nil {
				return err
			}
			if !found {
				return diagnoseCollision(ctx, q, op, uid, in.Username, in.Email, false)
			}
		}

		if cur.deleted {
			// The identifier belongs to a deleted user, whom an import never
			// undeletes.
			return alreadyExists(op, admin.FieldID)
		}

		stored, err := grantNames(ctx, q, op, uid)
		if err != nil {
			return err
		}
		attrs, err := attributesOf(ctx, q, op, uid)
		if err != nil {
			return err
		}

		rolesDiffer := !sameRoles(stored, roles)
		attrsDiffer := !sameAttributes(attrs, in.Attributes)
		if cur.values.equal(want) && !rolesDiffer && !attrsDiffer {
			outcome = admin.ImportUnchanged
			return nil
		}

		var setUsername, setEmail string
		if want.username != cur.values.username {
			setUsername = want.username
		}
		if want.email != "" && want.email != cur.values.email {
			setEmail = want.email
		}
		if setUsername != "" || setEmail != "" {
			if err := checkIdentifiers(ctx, q, op, uid, setUsername, setEmail); err != nil {
				return err
			}
		}

		storedPrimary := ""
		if len(stored) > 0 {
			storedPrimary = stored[0]
		}
		role := storedPrimary
		if rolesDiffer {
			role = primary
		}

		// A changed username is written alone first, so a unique violation
		// names the value that collided (pgschema.SetImportedUsername).
		if setUsername != "" {
			if _, err := q.Exec(ctx, pgschema.SetImportedUsername, uid, setUsername); err != nil {
				if isUniqueViolation(err) {
					return alreadyExists(op, admin.FieldUsername)
				}
				return dbFailed(op, err)
			}
		}

		if _, err := q.Exec(ctx, pgschema.UpdateImportedUser, uid, want.username, want.name,
			emptyNull(want.email), nullTs(want.verifiedAt), want.password, want.active, role,
			nullTs(want.createdAt), nullTs(want.updatedAt)); err != nil {
			if isUniqueViolation(err) {
				// The username was written alone just before, so only
				// the email can collide here.
				return alreadyExists(op, admin.FieldEmail)
			}
			return dbFailed(op, err)
		}

		if rolesDiffer {
			if err := s.regrant(ctx, q, op, uid, roles, catalogue, now); err != nil {
				return err
			}
		}
		if attrsDiffer {
			if err := replaceAttributes(ctx, q, op, uid, in.Attributes); err != nil {
				return err
			}
		}
		outcome = admin.ImportUpdated

		return nil
	})
	if err != nil {
		return 0, err
	}

	return outcome, nil
}

// regrant replaces the user's grants with roles, in that order, the first
// primary, keeping each kept role's stored grant, and taking a new grant's
// super-role flag from catalogue.
func (s *IdentityStore) regrant(
	ctx context.Context, q DBTX, op string, uid id.ID, roles []string, catalogue map[string]bool, now time.Time,
) error {
	existing, err := grantsInPosition(ctx, q, op, uid)
	if err != nil {
		return err
	}
	rebuilt, err := s.planGrants(ctx, q, op, uid, roles, now)
	if err != nil {
		return err
	}
	for i := range rebuilt {
		if _, kept := existing[rebuilt[i].name]; !kept {
			rebuilt[i].superRole = catalogue[rebuilt[i].name]
		}
	}

	return writeGrants(ctx, q, op, uid, rebuilt, now)
}

// importValues is the users columns an import compares and writes.
type importValues struct {
	username, name, email string
	verifiedAt            time.Time
	password              []byte
	active                bool
	createdAt, updatedAt  time.Time
}

// equal reports whether v, as stored, holds the values o gives. A zero
// creation or update time in o was not given, and is not compared.
func (v importValues) equal(o importValues) bool {
	return v.username == o.username && v.name == o.name && v.email == o.email &&
		v.verifiedAt.Equal(o.verifiedAt) && bytes.Equal(v.password, o.password) && v.active == o.active &&
		(o.createdAt.IsZero() || v.createdAt.Equal(o.createdAt)) &&
		(o.updatedAt.IsZero() || v.updatedAt.Equal(o.updatedAt))
}

// givenOr is t, or fallback when t is zero: a time an import did not give.
func givenOr(t, fallback time.Time) time.Time {
	if t.IsZero() {
		return fallback
	}

	return t
}

// zeroOr is t as stored: zero stays zero, any other is UTC to the microsecond.
func zeroOr(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}

	return storekit.Time(t)
}

// sameRoles reports whether the stored grant names, primary first, hold the
// same primary and the same set of names as roles.
func sameRoles(stored, roles []string) bool {
	if len(stored) == 0 || len(roles) == 0 {
		return len(stored) == len(roles)
	}
	if stored[0] != roles[0] {
		return false
	}
	set := make(map[string]bool, len(stored))
	for _, n := range stored {
		set[n] = true
	}
	if len(set) != len(stored) || len(set) != len(roles) {
		return false
	}
	for _, n := range roles {
		if !set[n] {
			return false
		}
	}

	return true
}

// sameAttributes reports whether a and b hold the same pairs; nil and empty
// are equal.
func sameAttributes(a, b map[string]string) bool {
	return len(a) == len(b) && maps.Equal(a, b)
}

// importRow is a user row an import locked.
type importRow struct {
	values  importValues
	deleted bool
}

// lockImportUser locks and reads the user with uid, deleted or not.
func lockImportUser(ctx context.Context, q DBTX, op string, uid id.ID) (importRow, bool, error) {
	var (
		r                    importRow
		email                pgtype.Text
		verified, deleted    pgtype.Timestamptz
		createdAt, updatedAt time.Time
	)
	err := q.QueryRow(ctx, pgschema.LockImportUser, uid).Scan(&r.values.username, &r.values.name, &email,
		&verified, &r.values.password, &r.values.active, &createdAt, &updatedAt, &deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return importRow{}, false, nil
	}
	if err != nil {
		return importRow{}, false, scanFailed(op, err)
	}
	r.values.email = email.String
	if r.values.verifiedAt, err = fromNull(verified); err != nil {
		return importRow{}, false, failed(op, err)
	}
	r.values.createdAt = createdAt.UTC()
	r.values.updatedAt = updatedAt.UTC()
	r.values.password = storekit.OrEmpty(r.values.password)
	r.deleted = deleted.Valid

	return r, true, nil
}

// knownRoles reads the catalogue's super-role flag of each of roles, and
// refuses with admin.ErrNotFound when the catalogue lacks one.
func knownRoles(ctx context.Context, q DBTX, op string, roles []string) (map[string]bool, error) {
	out := make(map[string]bool, len(roles))
	if len(roles) == 0 {
		return out, nil
	}

	rows, err := q.Query(ctx, pgschema.KnownRoles, roles)
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			name  string
			super bool
		)
		if err := rows.Scan(&name, &super); err != nil {
			return nil, scanFailed(op, err)
		}
		out[name] = super
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}
	if len(out) != len(roles) {
		return nil, failed(op, fmt.Errorf("%w: a role is not in the catalogue", admin.ErrNotFound))
	}

	return out, nil
}

// grantNames is the names of the user's grants, primary first, then in
// stored position.
func grantNames(ctx context.Context, q DBTX, op string, uid id.ID) ([]string, error) {
	rows, err := q.Query(ctx, pgschema.GrantsByUser, uid)
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var (
			gid, start, until, created, updated any
			name                                string
			position                            int
			primary, super                      bool
		)
		if err := rows.Scan(&gid, &name, &position, &primary, &super, &start, &until, &created, &updated); err != nil {
			return nil, scanFailed(op, err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
}

// attributesOf reads the user's profile attributes.
func attributesOf(ctx context.Context, q DBTX, op string, uid id.ID) (map[string]string, error) {
	all, err := attributesByUsers(ctx, q, op, []id.ID{uid})
	if err != nil {
		return nil, err
	}

	return all[uid], nil
}

// lockedUser is the part of a locked user row a versioned write reads.
type lockedUser struct {
	email    pgtype.Text
	password []byte
	active   bool
}

// verifiesNoEmail reports whether change sets a verification time while the
// user is left with no email to verify: the change names an empty email, or
// names none and u, the locked row, holds none.
func verifiesNoEmail(change admin.UserChange, u lockedUser) bool {
	if change.EmailVerifiedAt == nil || change.EmailVerifiedAt.IsZero() {
		return false
	}
	if change.Email != nil {
		return *change.Email == ""
	}

	return !u.email.Valid || u.email.String == ""
}

// lockAdminUser locks the live user uid and checks that its version is
// version: admin.ErrNotFound with no live row, admin.ErrStaleUpdate when the
// versions differ.
func lockAdminUser(ctx context.Context, q DBTX, op string, uid id.ID, version int64) (lockedUser, error) {
	var (
		u      lockedUser
		stored int64
	)
	err := q.QueryRow(ctx, pgschema.LockAdminUser, uid).Scan(&stored, &u.email, &u.password, &u.active)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedUser{}, notFound(op)
	}
	if err != nil {
		return lockedUser{}, scanFailed(op, err)
	}
	if stored != version {
		return lockedUser{}, failed(op, admin.ErrStaleUpdate)
	}

	return u, nil
}

// checkIdentifiers takes the advisory locks of username and email (each
// skipped when empty), then refuses a username another user holds, deleted
// or not, or that is another live user's email, and an email that is another
// live user's email or username, ignoring case. self is the writing user,
// whom no check counts.
func checkIdentifiers(ctx context.Context, q DBTX, op string, self id.ID, username, email string) error {
	if err := lockIdentifiers(ctx, q, op, username, email); err != nil {
		return err
	}

	checks := []struct {
		value, query, field string
	}{
		{username, pgschema.UsernameTaken, admin.FieldUsername},
		{username, pgschema.EmailHeldByLiveUser, admin.FieldUsername},
		{email, pgschema.EmailHeldByLiveUser, admin.FieldEmail},
		{email, pgschema.UsernameHeldByLiveUser, admin.FieldEmail},
	}
	for _, c := range checks {
		if c.value == "" {
			continue
		}
		var held bool
		if err := q.QueryRow(ctx, c.query, c.value, self).Scan(&held); err != nil {
			return scanFailed(op, err)
		}
		if held {
			return alreadyExists(op, c.field)
		}
	}

	return nil
}

// diagnoseCollision reads why an insert of uid with username and email
// inserted nothing: the username, then the email, then (when idTaken counts)
// the identifier.
func diagnoseCollision(ctx context.Context, q DBTX, op string, uid id.ID, username, email string, idTaken bool) error {
	checks := []struct {
		value, query, field string
	}{
		{username, pgschema.UsernameTaken, admin.FieldUsername},
		{email, pgschema.EmailHeldByLiveUser, admin.FieldEmail},
	}
	for _, c := range checks {
		if c.value == "" {
			continue
		}
		var held bool
		if err := q.QueryRow(ctx, c.query, c.value, uid).Scan(&held); err != nil {
			return scanFailed(op, err)
		}
		if held {
			return alreadyExists(op, c.field)
		}
	}

	if idTaken {
		var held bool
		if err := q.QueryRow(ctx, pgschema.UserIDTaken, uid).Scan(&held); err != nil {
			return scanFailed(op, err)
		}
		if held {
			return failed(op, storekit.ErrIdentifierInUse)
		}
	}

	return failed(op, errImportConflict)
}

// writeAttributes stores attrs for user uid.
func writeAttributes(ctx context.Context, q DBTX, op string, uid id.ID, attrs map[string]string) error {
	for name, value := range attrs {
		if _, err := q.Exec(ctx, pgschema.InsertAttribute, uid, name, value); err != nil {
			return dbFailed(op, err)
		}
	}

	return nil
}

// replaceAttributes replaces every attribute of user uid with attrs.
func replaceAttributes(ctx context.Context, q DBTX, op string, uid id.ID, attrs map[string]string) error {
	if _, err := q.Exec(ctx, pgschema.DeleteAttributesByUser, uid); err != nil {
		return dbFailed(op, err)
	}

	return writeAttributes(ctx, q, op, uid, attrs)
}

// scanAdminUser scans one row of the administration user columns.
func scanAdminUser(scan func(dest ...any) error) (admin.User, pgtype.UUID, error) {
	var (
		u                    admin.User
		rawID                pgtype.UUID
		email                pgtype.Text
		verified             pgtype.Timestamptz
		org                  pgtype.UUID
		createdAt, updatedAt time.Time
	)
	if err := scan(&rawID, &u.Username, &u.Name, &email, &verified, &u.Active, &org, &u.Version,
		&createdAt, &updatedAt); err != nil {
		return admin.User{}, org, err
	}
	uid, err := scanID(rawID)
	if err != nil {
		return admin.User{}, org, err
	}
	u.ID = identity.UserID(uid.String())
	u.Email = email.String
	if u.EmailVerifiedAt, err = fromNull(verified); err != nil {
		return admin.User{}, org, err
	}
	u.CreatedAt = createdAt.UTC()
	u.UpdatedAt = updatedAt.UTC()

	return u, org, nil
}

// readAdminUser reads the live user uid with its grants, attributes and
// organization, or admin.ErrNotFound.
func (s *IdentityStore) readAdminUser(ctx context.Context, q DBTX, op string, uid id.ID) (admin.User, error) {
	u, org, err := scanAdminUser(q.QueryRow(ctx, pgschema.AdminUserByID, uid).Scan)
	if errors.Is(err, pgx.ErrNoRows) {
		return admin.User{}, notFound(op)
	}
	if err != nil {
		return admin.User{}, scanFailed(op, err)
	}

	users := []admin.User{u}
	if err := s.completeUsers(ctx, q, op, users, []pgtype.UUID{org}); err != nil {
		return admin.User{}, err
	}

	return users[0], nil
}

// completeUsers fills each user's grants, attributes and organization
// (orgs[i] is users[i]'s reference), with one query for every user's grants,
// one for their attributes, and one per distinct organization.
func (s *IdentityStore) completeUsers(
	ctx context.Context, q DBTX, op string, users []admin.User, orgs []pgtype.UUID,
) error {
	if len(users) == 0 {
		return nil
	}

	ids := make([]id.ID, len(users))
	for i, u := range users {
		ids[i], _ = storekit.ParseUserID(u.ID)
	}

	roles, err := grantsByUsers(ctx, q, op, ids)
	if err != nil {
		return err
	}
	attrs, err := attributesByUsers(ctx, q, op, ids)
	if err != nil {
		return err
	}

	resolved := make(map[id.ID]*identity.Organization)
	for i := range users {
		users[i].Roles = roles[ids[i]]
		users[i].Attributes = attrs[ids[i]]
		if users[i].Attributes == nil {
			users[i].Attributes = map[string]string{}
		}

		if !orgs[i].Valid {
			continue
		}
		ref := nullableID(orgs[i])
		org, seen := resolved[ref]
		if !seen {
			if org, err = organization(ctx, q, op, ref); err != nil {
				return err
			}
			resolved[ref] = org
		}
		if org != nil {
			cp := *org
			if org.Group != nil {
				g := *org.Group
				cp.Group = &g
			}
			users[i].Organization = &cp
		}
	}

	return nil
}

// uuidArray is ids as their canonical text, which pgx encodes for a uuid[]
// parameter.
func uuidArray(ids []id.ID) []string {
	text := make([]string, len(ids))
	for i, v := range ids {
		text[i] = v.String()
	}

	return text
}

// grantsByUsers reads the grants of every one of ids, each user's primary
// first, then in stored position.
func grantsByUsers(ctx context.Context, q DBTX, op string, ids []id.ID) (map[id.ID][]*identity.AssignedRole, error) {
	rows, err := q.Query(ctx, pgschema.GrantsByUsers, uuidArray(ids))
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer rows.Close()

	out := make(map[id.ID][]*identity.AssignedRole, len(ids))
	for rows.Next() {
		var (
			g                    identity.AssignedRole
			rawUser, rawGrant    pgtype.UUID
			position             int32
			start, until         pgtype.Timestamptz
			createdAt, updatedAt time.Time
		)
		if err := rows.Scan(&rawUser, &rawGrant, &g.Name, &position, &g.Primary, &g.SuperRole, &start, &until,
			&createdAt, &updatedAt); err != nil {
			return nil, scanFailed(op, err)
		}
		uid, err := scanID(rawUser)
		if err != nil {
			return nil, failed(op, err)
		}
		grantID, err := scanID(rawGrant)
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
		out[uid] = append(out[uid], &g)
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
}

// attributesByUsers reads the attributes of every one of ids.
func attributesByUsers(ctx context.Context, q DBTX, op string, ids []id.ID) (map[id.ID]map[string]string, error) {
	rows, err := q.Query(ctx, pgschema.AttributesByUsers, uuidArray(ids))
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer rows.Close()

	out := make(map[id.ID]map[string]string, len(ids))
	for rows.Next() {
		var (
			raw         pgtype.UUID
			name, value string
		)
		if err := rows.Scan(&raw, &name, &value); err != nil {
			return nil, scanFailed(op, err)
		}
		uid, err := scanID(raw)
		if err != nil {
			return nil, failed(op, err)
		}
		if out[uid] == nil {
			out[uid] = make(map[string]string)
		}
		out[uid][name] = value
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
}
