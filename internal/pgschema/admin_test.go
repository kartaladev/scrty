package pgschema_test

import (
	"fmt"
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
