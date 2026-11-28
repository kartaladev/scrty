package pgschema_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pgschema"
)

func TestLikePattern(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		search string
		assert func(t *testing.T, got string)
	}

	cases := []testCase{
		{name: "empty is no search", search: "", assert: func(t *testing.T, got string) { assert.Empty(t, got) }},
		{name: "plain text is wrapped", search: "ada", assert: func(t *testing.T, got string) { assert.Equal(t, "%ada%", got) }},
		{
			name: "wildcards and the escape are literal", search: `a_b%c\d`,
			assert: func(t *testing.T, got string) { assert.Equal(t, `%a\_b\%c\\d%`, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, pgschema.LikePattern(tc.search))
		})
	}
}

func TestUpdateAdminUserQuery(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		columns []string
		values  []any
		assert  func(t *testing.T, query string, args []any, panicked bool)
	}

	cases := []testCase{
		{
			name: "no column writes the time and the version only",
			assert: func(t *testing.T, query string, args []any, panicked bool) {
				require.False(t, panicked)
				assert.Equal(t, "UPDATE scrty_users SET updated_at = $1, version = version + 1 WHERE id = $2", query)
				assert.Equal(t, []any{"now", "uid"}, args)
			},
		},
		{
			name:    "named columns bind in order",
			columns: []string{pgschema.ColumnName, pgschema.ColumnEmail},
			values:  []any{"n", "e"},
			assert: func(t *testing.T, query string, args []any, panicked bool) {
				require.False(t, panicked)
				assert.Equal(t, "UPDATE scrty_users SET name = $1, email = $2, updated_at = $3, "+
					"version = version + 1 WHERE id = $4", query)
				assert.Equal(t, []any{"n", "e", "now", "uid"}, args)
			},
		},
		{
			name:    "the verification kept for the same email compares the stored email ignoring case",
			columns: []string{pgschema.ColumnEmail, pgschema.ColumnEmailVerifiedAtIfSameEmail},
			values:  []any{"E", "E"},
			assert: func(t *testing.T, query string, args []any, panicked bool) {
				require.False(t, panicked)
				assert.Equal(t, "UPDATE scrty_users SET email = $1, "+
					"email_verified_at = CASE WHEN lower(email) = lower($2::text) THEN email_verified_at END, "+
					"updated_at = $3, version = version + 1 WHERE id = $4", query)
				assert.Equal(t, []any{"E", "E", "now", "uid"}, args)
			},
		},
		{
			name:    "an unknown column panics",
			columns: []string{"password"},
			values:  []any{"x"},
			assert: func(t *testing.T, _ string, _ []any, panicked bool) {
				assert.True(t, panicked)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				query    string
				args     []any
				panicked = true
			)
			func() {
				defer func() { _ = recover() }()
				query, args = pgschema.UpdateAdminUserQuery(tc.columns, tc.values, "now", "uid")
				panicked = false
			}()
			tc.assert(t, query, args, panicked)
		})
	}
}

func TestLockImportIdentifierUsesTwoKeyForm(t *testing.T) {
	t.Parallel()

	want := fmt.Sprintf("pg_advisory_xact_lock(%d::int4, hashtext($1::text))", pgschema.ImportLockClass)
	assert.Contains(t, pgschema.LockImportIdentifier, want)
}

// TestListAdminUsersUnchanged pins the cursor listing to the text it had
// before its filters moved into a fragment shared with the offset listing and
// the count: the same parameters $1 to $8, the same cursor comparison, order
// and limit, so the refactor cannot change its behaviour.
func TestListAdminUsersUnchanged(t *testing.T) {
	t.Parallel()

	const want = `SELECT id, username, name, email, email_verified_at, active, organization_id, version,
  created_at, updated_at
FROM scrty_users u
WHERE u.deleted_at IS NULL
  AND ($1::text = '' OR u.username ILIKE $1 OR u.name ILIKE $1 OR u.email ILIKE $1)
  AND ($2::boolean IS NULL OR u.active = $2::boolean)
  AND ($3::text = '' OR EXISTS (SELECT 1 FROM scrty_assigned_roles r
       WHERE r.user_id = u.id AND r.role_name = $3::text))
  AND ($4::text IS NULL OR EXISTS (SELECT 1 FROM scrty_user_attributes a
       WHERE a.user_id = u.id AND a.name = $4::text AND a.value = $5::text))
  AND ($6::text = '' OR (lower(u.username), u.id) > (lower($6::text), $7::uuid))
ORDER BY lower(u.username), u.id
LIMIT $8`

	assert.Equal(t, want, pgschema.ListAdminUsers)
}

// TestAdminUserListingStatements checks that the offset listing and the count
// apply exactly the cursor listing's filters, $1 to $5, so the three cannot
// drift apart: the offset listing keeps the order and takes a limit and an
// offset instead of the cursor, and the count has neither.
func TestAdminUserListingStatements(t *testing.T) {
	t.Parallel()

	const (
		filters = `WHERE u.deleted_at IS NULL
  AND ($1::text = '' OR u.username ILIKE $1 OR u.name ILIKE $1 OR u.email ILIKE $1)
  AND ($2::boolean IS NULL OR u.active = $2::boolean)
  AND ($3::text = '' OR EXISTS (SELECT 1 FROM scrty_assigned_roles r
       WHERE r.user_id = u.id AND r.role_name = $3::text))
  AND ($4::text IS NULL OR EXISTS (SELECT 1 FROM scrty_user_attributes a
       WHERE a.user_id = u.id AND a.name = $4::text AND a.value = $5::text))`
		cursor = `(lower(u.username), u.id) >`
		order  = `ORDER BY lower(u.username), u.id`
	)

	type testCase struct {
		name   string
		stmt   string
		assert func(t *testing.T, stmt string)
	}

	cases := []testCase{
		{
			name: "the cursor listing",
			stmt: pgschema.ListAdminUsers,
			assert: func(t *testing.T, stmt string) {
				assert.Contains(t, stmt, filters+"\n  AND ($6::text = '' OR "+cursor)
				assert.True(t, strings.HasSuffix(stmt, order+"\nLIMIT $8"), stmt)
			},
		},
		{
			name: "the offset listing",
			stmt: pgschema.ListAdminUsersFrom,
			assert: func(t *testing.T, stmt string) {
				assert.Equal(t, `SELECT id, username, name, email, email_verified_at, active, organization_id, version,
  created_at, updated_at
FROM scrty_users u
`+filters+"\n"+order+"\nLIMIT $6 OFFSET $7", stmt)
				assert.NotContains(t, stmt, cursor, "an offset listing names no cursor")
			},
		},
		{
			name: "the count",
			stmt: pgschema.CountAdminUsers,
			assert: func(t *testing.T, stmt string) {
				assert.Equal(t, "SELECT count(*) FROM scrty_users u\n"+filters, stmt)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.stmt)
		})
	}
}
