package gormstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"gorm.io/gorm"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
)

// The administration ports. IdentityStore implements admin.UserStore and
// admin.ImportStore over the identity tables, with the statements of
// internal/pgschema it shares with the other adapters, run through gorm's Raw
// and Exec so the SQL is the same text on every adapter.
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
// (admin.ErrNotFound). Text PostgreSQL cannot store, an organization
// reference or list cursor identifier that is not canonical lowercase UUID
// text, and a limit below one are admin.ErrInvalidInput. Error text never
// carries a username, an email, an attribute value or a password hash.
var (
	_ admin.UserStore   = (*IdentityStore)(nil)
	_ admin.ImportStore = (*IdentityStore)(nil)
)

// errImportConflict is an insert that collided with a row the store could not
// find afterwards: a concurrent writer removed it in between.
var errImportConflict = errors.New("the user collided with a row that is gone; retry")

// invalidInput is an admin.ErrInvalidInput naming what was wrong, never the
// value.
func invalidInput(op, what string) error {
	return failed(op, fmt.Errorf("%w: %s", admin.ErrInvalidInput, what))
}

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
func checkOrganization(q *gorm.DB, op string, org any) error {
	if org == nil {
		return nil
	}

	var one int
	found, err := queryRow(q, op, pgschema.ShareOrganization, []any{org}, &one)
	if err != nil {
		return err
	}
	if !found {
		return invalidInput(op, "the organization reference names no organization")
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

// ListUsers implements admin.UserStore.
func (s *IdentityStore) ListUsers(ctx context.Context, query admin.UserQuery) ([]admin.User, error) {
	const op = "list users"

	if query.Limit < 1 {
		return nil, invalidInput(op, "the limit is below one")
	}
	if !storekit.Storable(query.Search, query.Role, query.AfterUsername) {
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

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	rows, err := q.Raw(pgschema.ListAdminUsers, pgschema.LikePattern(query.Search), active, query.Role,
		attrName, attrValue, query.AfterUsername, after, query.Limit).Rows()
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	var (
		users []admin.User
		orgs  []*id.ID
	)
	for rows.Next() {
		var row adminUserRow
		if err := rows.Scan(row.dest()...); err != nil {
			return nil, scanFailed(op, err)
		}
		users = append(users, row.user())
		orgs = append(orgs, row.org)
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}
	// The rows are closed before the next statement runs on the connection.
	if err := rows.Close(); err != nil {
		return nil, dbFailed(op, err)
	}

	if err := completeUsers(q, op, users, orgs); err != nil {
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

	return readAdminUser(q, op, uid)
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
	err = s.atomically(ctx, op, func(q *gorm.DB) error {
		if err := checkOrganization(q, op, org); err != nil {
			return err
		}
		if err := checkIdentifiers(q, op, uid, in.Username, in.Email); err != nil {
			return err
		}

		res := q.Exec(pgschema.InsertAdminUser, uid, in.Username, in.Name, emptyNull(in.Email),
			nullTs(in.EmailVerifiedAt), []byte{}, true, "", org, now, now)
		if res.Error != nil {
			return dbFailed(op, res.Error)
		}
		if res.RowsAffected == 0 {
			return diagnoseCollision(q, op, uid, in.Username, in.Email, true)
		}

		if err := writeAttributes(q, op, uid, in.Attributes); err != nil {
			return err
		}

		out, err = readAdminUser(q, op, uid)

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

	var (
		columns []string
		values  []any
		newOrg  any
	)
	if change.Name != nil {
		if !storekit.Storable(*change.Name) {
			return admin.User{}, invalidInput(op, "the name holds text that cannot be stored")
		}
		columns, values = append(columns, pgschema.ColumnName), append(values, *change.Name)
	}
	if change.Email != nil {
		if !storekit.Storable(*change.Email) {
			return admin.User{}, invalidInput(op, "the email holds text that cannot be stored")
		}
		columns, values = append(columns, pgschema.ColumnEmail), append(values, emptyNull(*change.Email))
		if change.EmailVerifiedAt == nil {
			// The statement keeps the verification only for the stored
			// address, compared under the row lock it runs in.
			columns = append(columns, pgschema.ColumnEmailVerifiedAtIfSameEmail)
			values = append(values, emptyNull(*change.Email))
		}
	}
	if change.EmailVerifiedAt != nil {
		columns, values = append(columns, pgschema.ColumnEmailVerifiedAt), append(values, nullTs(*change.EmailVerifiedAt))
	}
	if change.Organization != nil {
		org, err := adminOrgReference(op, *change.Organization)
		if err != nil {
			return admin.User{}, err
		}
		columns, values = append(columns, pgschema.ColumnOrganization), append(values, org)
		newOrg = org
	}
	if err := checkAttributes(op, change.Attributes); err != nil {
		return admin.User{}, err
	}

	var out admin.User
	err := s.atomically(ctx, op, func(q *gorm.DB) error {
		cur, err := lockAdminUser(q, op, uid, version)
		if err != nil {
			return err
		}
		if verifiesNoEmail(change, cur) {
			return invalidInput(op, "an email verification time is set with no email to verify")
		}
		if err := checkOrganization(q, op, newOrg); err != nil {
			return err
		}

		now := storekit.Time(s.c.clock.Now())

		if change.Email != nil && *change.Email != "" && (cur.email == nil || *change.Email != *cur.email) {
			if err := checkIdentifiers(q, op, uid, "", *change.Email); err != nil {
				return err
			}
		}

		query, args := pgschema.UpdateAdminUserQuery(columns, values, now, uid)
		if err := q.Exec(query, args...).Error; err != nil {
			if isUniqueViolation(err) {
				// The email is the only unique value this update can set.
				return alreadyExists(op, admin.FieldEmail)
			}

			return dbFailed(op, err)
		}

		if change.Attributes != nil {
			if err := replaceAttributes(q, op, uid, change.Attributes); err != nil {
				return err
			}
		}

		out, err = readAdminUser(q, op, uid)

		return err
	})
	if err != nil {
		return admin.User{}, err
	}

	return out, nil
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
	err := s.atomically(ctx, op, func(q *gorm.DB) error {
		cur, err := lockAdminUser(q, op, uid, version)
		if err != nil {
			return err
		}

		if cur.active != active {
			now := storekit.Time(s.c.clock.Now())
			if err := q.Exec(pgschema.SetUserActive, uid, active, now).Error; err != nil {
				return dbFailed(op, err)
			}
			changed = true
		}

		out, err = readAdminUser(q, op, uid)

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

	return s.atomically(ctx, op, func(q *gorm.DB) error {
		if _, err := lockAdminUser(q, op, uid, version); err != nil {
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
			if err := q.Exec(stmt.query, stmt.args...).Error; err != nil {
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
	found, err := queryRow(q, op, pgschema.CurrentPassword, []any{uid}, &hash)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, notFound(op)
	}

	return storekit.OrEmpty(hash), nil
}

// SetPassword implements admin.UserStore. It writes the hash, the
// password-changed time and the version, and nothing else: the password
// policy's reuse rule records the replaced hash in the history through the
// consumer's password.History. An empty hash is admin.ErrInvalidInput.
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
	err := s.atomically(ctx, op, func(q *gorm.DB) error {
		if _, err := lockAdminUser(q, op, uid, version); err != nil {
			return err
		}

		now := storekit.Time(s.c.clock.Now())
		if err := q.Exec(pgschema.SetUserPassword, uid, hash, storekit.Time(at), now).Error; err != nil {
			return dbFailed(op, err)
		}

		var err error
		out, err = readAdminUser(q, op, uid)

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
// Roles are granted in the order given, the first primary; repeated and empty
// names are skipped. A role the catalogue (scrty_roles) does not hold is
// admin.ErrNotFound. A new grant takes its super-role flag from the
// catalogue; an existing grant of a kept role keeps its own identifier, flags
// and window.
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
	err := s.atomically(ctx, op, func(q *gorm.DB) error {
		// Queue behind any other import of this identifier before taking
		// any other lock (see pgschema.LockImportIdentifier).
		if err := q.Exec(pgschema.LockImportIdentifier, uid.String()).Error; err != nil {
			return dbFailed(op, err)
		}

		catalogue, err := knownRoles(q, op, roles)
		if err != nil {
			return err
		}

		now := storekit.Time(s.c.clock.Now())

		cur, found, err := lockImportUser(q, op, uid)
		if err != nil {
			return err
		}

		if !found {
			if err := checkIdentifiers(q, op, uid, in.Username, in.Email); err != nil {
				return err
			}

			// A time the import did not give is the time of this creation.
			created, updated := want.createdAt, want.updatedAt
			if created.IsZero() {
				created = now
			}
			if updated.IsZero() {
				updated = now
			}
			res := q.Exec(pgschema.InsertAdminUser, uid, want.username, want.name, emptyNull(want.email),
				nullTs(want.verifiedAt), want.password, want.active, primary, nil, created, updated)
			if res.Error != nil {
				return dbFailed(op, res.Error)
			}
			if res.RowsAffected == 1 {
				grants := make([]assignedRoleRow, len(roles))
				for i, name := range roles {
					gid, err := idgen.New(s.c.ids)
					if err != nil {
						return failed(op, err)
					}
					grants[i] = assignedRoleRow{
						ID: gid, UserID: uid, RoleName: name, Position: int64(i), IsPrimary: i == 0,
						SuperRole: catalogue[name], CreatedAt: now, UpdatedAt: now,
					}
				}
				if len(grants) > 0 {
					if err := q.Create(&grants).Error; err != nil {
						return dbFailed(op, err)
					}
				}
				if err := writeAttributes(q, op, uid, in.Attributes); err != nil {
					return err
				}
				outcome = admin.ImportCreated

				return nil
			}

			// The insert collided. A concurrent import of this identifier
			// that committed first is now visible: carry on as an update.
			if cur, found, err = lockImportUser(q, op, uid); err != nil {
				return err
			}
			if !found {
				return diagnoseCollision(q, op, uid, in.Username, in.Email, false)
			}
		}

		if cur.deleted {
			// The identifier belongs to a deleted user, whom an import never
			// undeletes.
			return alreadyExists(op, admin.FieldID)
		}

		stored, err := grantNames(q, op, uid)
		if err != nil {
			return err
		}
		attrs, err := attributesOf(q, op, uid)
		if err != nil {
			return err
		}

		rolesDiffer := !sameRoles(stored, roles)
		attrsDiffer := !maps.Equal(attrs, in.Attributes) && (len(attrs) > 0 || len(in.Attributes) > 0)
		// A time the import did not give is not compared and not overwritten.
		if want.createdAt.IsZero() {
			want.createdAt = cur.values.createdAt
		}
		if want.updatedAt.IsZero() {
			want.updatedAt = cur.values.updatedAt
		}
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
			if err := checkIdentifiers(q, op, uid, setUsername, setEmail); err != nil {
				return err
			}
		}

		role := ""
		if len(stored) > 0 {
			role = stored[0]
		}
		if rolesDiffer {
			role = primary
		}

		// A changed username is written alone first, so a unique violation
		// names the value that collided (pgschema.SetImportedUsername).
		if setUsername != "" {
			if err := q.Exec(pgschema.SetImportedUsername, uid, setUsername).Error; err != nil {
				if isUniqueViolation(err) {
					return alreadyExists(op, admin.FieldUsername)
				}

				return dbFailed(op, err)
			}
		}

		if err := q.Exec(pgschema.UpdateImportedUser, uid, want.username, want.name, emptyNull(want.email),
			nullTs(want.verifiedAt), want.password, want.active, role, want.createdAt, want.updatedAt).Error; err != nil {
			if isUniqueViolation(err) {
				// The username was written alone just before, so only
				// the email can collide here.
				return alreadyExists(op, admin.FieldEmail)
			}

			return dbFailed(op, err)
		}

		if rolesDiffer {
			if err := s.regrant(q, op, uid, roles, catalogue, now); err != nil {
				return err
			}
		}
		if attrsDiffer {
			if err := replaceAttributes(q, op, uid, in.Attributes); err != nil {
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
	q *gorm.DB, op string, uid id.ID, roles []string, catalogue map[string]bool, now time.Time,
) error {
	existing, err := grantsInPosition(q, op, uid)
	if err != nil {
		return err
	}
	rebuilt, err := s.planGrants(q, op, uid, roles, now)
	if err != nil {
		return err
	}
	for i := range rebuilt {
		if _, kept := existing[rebuilt[i].RoleName]; !kept {
			rebuilt[i].SuperRole = catalogue[rebuilt[i].RoleName]
		}
	}

	if err := q.Exec(pgschema.DeleteGrantsByUser, uid).Error; err != nil {
		return dbFailed(op, err)
	}
	if len(rebuilt) > 0 {
		if err := q.Create(&rebuilt).Error; err != nil {
			return dbFailed(op, err)
		}
	}

	return nil
}

// importValues is the users columns an import compares and writes.
type importValues struct {
	username, name, email string
	verifiedAt            time.Time
	password              []byte
	active                bool
	createdAt, updatedAt  time.Time
}

func (v importValues) equal(o importValues) bool {
	return v.username == o.username && v.name == o.name && v.email == o.email &&
		v.verifiedAt.Equal(o.verifiedAt) && bytes.Equal(v.password, o.password) && v.active == o.active &&
		v.createdAt.Equal(o.createdAt) && v.updatedAt.Equal(o.updatedAt)
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

// importRow is a user row an import locked.
type importRow struct {
	values  importValues
	deleted bool
}

// lockImportUser locks and reads the user with uid, deleted or not.
func lockImportUser(q *gorm.DB, op string, uid id.ID) (importRow, bool, error) {
	var (
		r                    importRow
		email                *string
		verified, deleted    *time.Time
		createdAt, updatedAt time.Time
	)
	found, err := queryRow(q, op, pgschema.LockImportUser, []any{uid}, &r.values.username, &r.values.name, &email,
		&verified, &r.values.password, &r.values.active, &createdAt, &updatedAt, &deleted)
	if err != nil || !found {
		return importRow{}, false, err
	}
	if email != nil {
		r.values.email = *email
	}
	r.values.verifiedAt = fromNull(verified)
	r.values.createdAt = createdAt.UTC()
	r.values.updatedAt = updatedAt.UTC()
	r.values.password = storekit.OrEmpty(r.values.password)
	r.deleted = deleted != nil

	return r, true, nil
}

// knownRoles reads the catalogue's super-role flag of each of roles, and
// refuses with admin.ErrNotFound when the catalogue lacks one.
func knownRoles(q *gorm.DB, op string, roles []string) (map[string]bool, error) {
	out := make(map[string]bool, len(roles))
	if len(roles) == 0 {
		return out, nil
	}

	rows, err := q.Raw(pgschema.KnownRoles, pgschema.TextArray(roles)).Rows()
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()
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
	if err := rows.Close(); err != nil {
		return nil, dbFailed(op, err)
	}
	if len(out) != len(roles) {
		return nil, failed(op, fmt.Errorf("%w: a role is not in the catalogue", admin.ErrNotFound))
	}

	return out, nil
}

// grantNames is the names of the user's grants, primary first, then in stored
// position.
func grantNames(q *gorm.DB, op string, uid id.ID) ([]string, error) {
	rows, err := q.Raw(pgschema.GrantsByUser, uid).Rows()
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

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
	if err := rows.Close(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
}

// attributesOf reads the user's profile attributes.
func attributesOf(q *gorm.DB, op string, uid id.ID) (map[string]string, error) {
	all, err := attributesByUsers(q, op, []id.ID{uid})
	if err != nil {
		return nil, err
	}

	return all[uid], nil
}

// lockedUser is the part of a locked user row a versioned write reads.
type lockedUser struct {
	email    *string
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

	return u.email == nil || *u.email == ""
}

// lockAdminUser locks the live user uid and checks that its version is
// version: admin.ErrNotFound with no live row, admin.ErrStaleUpdate when the
// versions differ.
func lockAdminUser(q *gorm.DB, op string, uid id.ID, version int64) (lockedUser, error) {
	var (
		u      lockedUser
		stored int64
	)
	found, err := queryRow(q, op, pgschema.LockAdminUser, []any{uid}, &stored, &u.email, &u.password, &u.active)
	if err != nil {
		return lockedUser{}, err
	}
	if !found {
		return lockedUser{}, notFound(op)
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
func checkIdentifiers(q *gorm.DB, op string, self id.ID, username, email string) error {
	if err := lockIdentifiers(q, op, username, email); err != nil {
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

	return refuseHeld(q, op, self, checks)
}

// refuseHeld runs each check, a boolean query over (value, self), and
// refuses with the AlreadyExistsError of the first whose answer is true.
func refuseHeld(q *gorm.DB, op string, self id.ID, checks []struct{ value, query, field string }) error {
	for _, c := range checks {
		if c.value == "" {
			continue
		}
		var held bool
		if _, err := queryRow(q, op, c.query, []any{c.value, self}, &held); err != nil {
			return err
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
func diagnoseCollision(q *gorm.DB, op string, uid id.ID, username, email string, idTaken bool) error {
	err := refuseHeld(q, op, uid, []struct{ value, query, field string }{
		{username, pgschema.UsernameTaken, admin.FieldUsername},
		{email, pgschema.EmailHeldByLiveUser, admin.FieldEmail},
	})
	if err != nil {
		return err
	}

	if idTaken {
		var held bool
		if _, err := queryRow(q, op, pgschema.UserIDTaken, []any{uid}, &held); err != nil {
			return err
		}
		if held {
			return failed(op, storekit.ErrIdentifierInUse)
		}
	}

	return failed(op, errImportConflict)
}

// writeAttributes stores attrs for user uid.
func writeAttributes(q *gorm.DB, op string, uid id.ID, attrs map[string]string) error {
	for name, value := range attrs {
		if err := q.Exec(pgschema.InsertAttribute, uid, name, value).Error; err != nil {
			return dbFailed(op, err)
		}
	}

	return nil
}

// replaceAttributes replaces every attribute of user uid with attrs.
func replaceAttributes(q *gorm.DB, op string, uid id.ID, attrs map[string]string) error {
	if err := q.Exec(pgschema.DeleteAttributesByUser, uid).Error; err != nil {
		return dbFailed(op, err)
	}

	return writeAttributes(q, op, uid, attrs)
}

// adminUserRow is one row of the administration user columns.
type adminUserRow struct {
	uid                  id.ID
	username, name       string
	email                *string
	verified             *time.Time
	active               bool
	org                  *id.ID
	version              int64
	createdAt, updatedAt time.Time
}

// dest is the scan destinations of the columns, in order.
func (r *adminUserRow) dest() []any {
	return []any{&r.uid, &r.username, &r.name, &r.email, &r.verified, &r.active, &r.org, &r.version,
		&r.createdAt, &r.updatedAt}
}

// user is the row as an admin.User, without grants, attributes or
// organization; r.org is the organization's reference.
func (r *adminUserRow) user() admin.User {
	u := admin.User{
		ID: identity.UserID(r.uid.String()), Username: r.username, Name: r.name,
		EmailVerifiedAt: fromNull(r.verified), Active: r.active, Version: r.version,
		CreatedAt: r.createdAt.UTC(), UpdatedAt: r.updatedAt.UTC(),
	}
	if r.email != nil {
		u.Email = *r.email
	}

	return u
}

// readAdminUser reads the live user uid with its grants, attributes and
// organization, or admin.ErrNotFound.
func readAdminUser(q *gorm.DB, op string, uid id.ID) (admin.User, error) {
	var row adminUserRow
	found, err := queryRow(q, op, pgschema.AdminUserByID, []any{uid}, row.dest()...)
	if err != nil {
		return admin.User{}, err
	}
	if !found {
		return admin.User{}, notFound(op)
	}

	users := []admin.User{row.user()}
	if err := completeUsers(q, op, users, []*id.ID{row.org}); err != nil {
		return admin.User{}, err
	}

	return users[0], nil
}

// completeUsers fills each user's grants, attributes and organization
// (orgs[i] is users[i]'s reference), with one query for every user's grants,
// one for their attributes, and one per distinct organization.
func completeUsers(q *gorm.DB, op string, users []admin.User, orgs []*id.ID) error {
	if len(users) == 0 {
		return nil
	}

	ids := make([]id.ID, len(users))
	for i, u := range users {
		ids[i], _ = storekit.ParseUserID(u.ID)
	}

	roles, err := grantsByUsers(q, op, ids)
	if err != nil {
		return err
	}
	attrs, err := attributesByUsers(q, op, ids)
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

		if orgs[i] == nil {
			continue
		}
		org, seen := resolved[*orgs[i]]
		if !seen {
			if org, err = organization(q, op, *orgs[i]); err != nil {
				return err
			}
			resolved[*orgs[i]] = org
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

// uuidArray is ids as a PostgreSQL uuid[] literal.
func uuidArray(ids []id.ID) string {
	text := make([]string, len(ids))
	for i, v := range ids {
		text[i] = v.String()
	}

	return pgschema.TextArray(text)
}

// grantsByUsers reads the grants of every one of ids, each user's primary
// first, then in stored position.
func grantsByUsers(q *gorm.DB, op string, ids []id.ID) (map[id.ID][]*identity.AssignedRole, error) {
	rows, err := q.Raw(pgschema.GrantsByUsers, uuidArray(ids)).Rows()
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[id.ID][]*identity.AssignedRole, len(ids))
	for rows.Next() {
		var (
			g                    identity.AssignedRole
			uid, grantID         id.ID
			position             int
			start, until         *time.Time
			createdAt, updatedAt time.Time
		)
		if err := rows.Scan(&uid, &grantID, &g.Name, &position, &g.Primary, &g.SuperRole, &start, &until,
			&createdAt, &updatedAt); err != nil {
			return nil, scanFailed(op, err)
		}
		g.ID = grantID.String()
		g.StartDate = fromNull(start)
		g.ValidUntil = fromNull(until)
		out[uid] = append(out[uid], &g)
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}
	if err := rows.Close(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
}

// attributesByUsers reads the attributes of every one of ids.
func attributesByUsers(q *gorm.DB, op string, ids []id.ID) (map[id.ID]map[string]string, error) {
	rows, err := q.Raw(pgschema.AttributesByUsers, uuidArray(ids)).Rows()
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[id.ID]map[string]string, len(ids))
	for rows.Next() {
		var (
			uid         id.ID
			name, value string
		)
		if err := rows.Scan(&uid, &name, &value); err != nil {
			return nil, scanFailed(op, err)
		}
		if out[uid] == nil {
			out[uid] = make(map[string]string)
		}
		out[uid][name] = value
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}
	if err := rows.Close(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
}
