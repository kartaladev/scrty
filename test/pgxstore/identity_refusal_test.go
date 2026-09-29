package pgxstore_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestIdentityStore_Refusals pins what the store refuses before it runs a
// statement: text PostgreSQL cannot store, and an organization reference that
// is not a UUID in canonical lowercase text.
func TestIdentityStore_Refusals(t *testing.T) {
	t.Parallel()

	db := migratedIdentity(t)
	s := newIdentityStore(t, db.Pool)

	t.Run("text PostgreSQL cannot store", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		_, err := s.Provision(ctx, "unstorable-target", identity.WithUserName("Before"), identity.WithUserRoles("admin"))
		require.NoError(t, err)

		// unchanged asserts the user an update targets was left as stored.
		unchanged := func(t *testing.T) {
			t.Helper()
			d, err := s.LoadByUsername(t.Context(), "unstorable-target")
			require.NoError(t, err)
			assert.Equal(t, "Before", d.Name)
			require.Len(t, d.Roles, 1)
			assert.Equal(t, "admin", d.Roles[0].Name)
		}
		// absent asserts no user named username was stored.
		absent := func(t *testing.T, username string) {
			t.Helper()
			assert.Zero(t, userRowCount(t.Context(), t, db.Pool, username))
		}

		type testCase struct {
			name   string
			call   func(ctx context.Context) error
			assert func(t *testing.T, err error)
		}

		cases := []testCase{
			{
				name: "a username with a NUL byte names no user to the loader",
				call: func(ctx context.Context) error {
					_, err := s.LoadByUsername(ctx, "unstorable\x00user")
					return err
				},
				assert: func(t *testing.T, err error) { require.ErrorIs(t, err, identity.ErrUserNotFound) },
			},
			{
				name: "a username with invalid UTF-8 names no user to the loader",
				call: func(ctx context.Context) error {
					_, err := s.LoadByUsername(ctx, "unstorable\xffuser")
					return err
				},
				assert: func(t *testing.T, err error) { require.ErrorIs(t, err, identity.ErrUserNotFound) },
			},
			{
				name: "a role with a NUL byte has no privileges",
				call: func(ctx context.Context) error {
					_, err := s.LoadPrivileges(ctx, "unstorable\x00role")
					return err
				},
				assert: func(t *testing.T, err error) { require.ErrorIs(t, err, identity.ErrPrivilegesNotFound) },
			},
			{
				name: "a role with invalid UTF-8 has no privileges",
				call: func(ctx context.Context) error {
					_, err := s.LoadPrivileges(ctx, "unstorable\xffrole")
					return err
				},
				assert: func(t *testing.T, err error) { require.ErrorIs(t, err, identity.ErrPrivilegesNotFound) },
			},
			{
				name: "provisioning a username with a NUL byte names the field",
				call: func(ctx context.Context) error {
					_, err := s.Provision(ctx, "secret\x00username")
					return err
				},
				assert: func(t *testing.T, err error) {
					// No stored row can hold the username, so there is nothing to
					// look for: the refusal comes before any statement.
					storefix.AssertNamesOnly(t, err, "username", "secret\x00username", "secret")
				},
			},
			{
				name: "provisioning a name with invalid UTF-8 names the field",
				call: func(ctx context.Context) error {
					_, err := s.Provision(ctx, "unstorable-name", identity.WithUserName("secret\xffname"))
					return err
				},
				assert: func(t *testing.T, err error) {
					storefix.AssertNamesOnly(t, err, "name", "secret\xffname", "secret", "unstorable-name")
					absent(t, "unstorable-name")
				},
			},
			{
				name: "provisioning a role with a NUL byte names the field",
				call: func(ctx context.Context) error {
					_, err := s.Provision(ctx, "unstorable-role", identity.WithUserRoles("admin", "secret\x00role"))
					return err
				},
				assert: func(t *testing.T, err error) {
					storefix.AssertNamesOnly(t, err, "role", "secret\x00role", "secret", "unstorable-role")
					absent(t, "unstorable-role")
				},
			},
			{
				name: "updating a name with a NUL byte names the field",
				call: func(ctx context.Context) error {
					_, err := s.Update(ctx, "unstorable-target", identity.WithUserName("secret\x00name"))
					return err
				},
				assert: func(t *testing.T, err error) {
					storefix.AssertNamesOnly(t, err, "name", "secret\x00name", "secret", "unstorable-target")
					unchanged(t)
				},
			},
			{
				name: "updating a role with invalid UTF-8 names the field",
				call: func(ctx context.Context) error {
					_, err := s.Update(ctx, "unstorable-target",
						identity.WithUserName("After"), identity.WithUserRoles("viewer", "secret\xffrole"))
					return err
				},
				assert: func(t *testing.T, err error) {
					storefix.AssertNamesOnly(t, err, "role", "secret\xffrole", "secret", "unstorable-target")
					unchanged(t)
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				tc.assert(t, tc.call(t.Context()))
			})
		}
	})

	t.Run("organization reference that is not a canonical UUID", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		canonical := storefix.NewID(t).String()
		_, err := s.Provision(ctx, "org-ref-target",
			identity.WithUserName("Before"), identity.WithUserOrganization(&identity.Organization{ID: canonical}))
		require.NoError(t, err)

		// stored is the name and organization reference of username's row, and
		// whether there is one.
		stored := func(t *testing.T, username string) (name string, org pgtype.Text, ok bool) {
			t.Helper()
			err := db.Pool.QueryRow(t.Context(),
				`SELECT name, organization_id::text FROM users WHERE username = $1`, username).Scan(&name, &org)
			if errors.Is(err, pgx.ErrNoRows) {
				return "", org, false
			}
			require.NoError(t, err)

			return name, org, true
		}

		upper := strings.ToUpper(storefix.NewID(t).String())

		type testCase struct {
			name   string
			ref    string
			call   func(ctx context.Context, ref string) error
			assert func(t *testing.T, ref string, err error)
		}

		provision := func(username string) func(ctx context.Context, ref string) error {
			return func(ctx context.Context, ref string) error {
				_, err := s.Provision(ctx, username, identity.WithUserOrganization(&identity.Organization{ID: ref}))
				return err
			}
		}
		update := func(ctx context.Context, ref string) error {
			_, err := s.Update(ctx, "org-ref-target",
				identity.WithUserName("After"), identity.WithUserOrganization(&identity.Organization{ID: ref}))
			return err
		}
		refused := func(t *testing.T, ref string, err error) {
			t.Helper()
			require.Error(t, err)
			for _, text := range storefix.ErrorTexts(err) {
				assert.NotContains(t, text, ref)
				assert.NotContains(t, text, strings.ToLower(ref))
			}
		}
		provisionedNothing := func(username string) func(t *testing.T, ref string, err error) {
			return func(t *testing.T, ref string, err error) {
				refused(t, ref, err)
				_, _, ok := stored(t, username)
				assert.False(t, ok, "the refused provision stored a user")
			}
		}
		updatedNothing := func(t *testing.T, ref string, err error) {
			refused(t, ref, err)
			name, org, ok := stored(t, "org-ref-target")
			require.True(t, ok)
			assert.Equal(t, "Before", name)
			assert.Equal(t, pgtype.Text{String: canonical, Valid: true}, org)
		}

		cases := []testCase{
			{
				name:   "provisioning with a reference that is not a UUID",
				ref:    "acme-corp",
				call:   provision("org-ref-not-uuid"),
				assert: provisionedNothing("org-ref-not-uuid"),
			},
			{
				name:   "provisioning with an upper-case UUID",
				ref:    upper,
				call:   provision("org-ref-upper"),
				assert: provisionedNothing("org-ref-upper"),
			},
			{
				name:   "updating to a reference that is not a UUID",
				ref:    "acme-corp",
				call:   update,
				assert: updatedNothing,
			},
			{
				name:   "updating to an upper-case UUID",
				ref:    upper,
				call:   update,
				assert: updatedNothing,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				tc.assert(t, tc.ref, tc.call(t.Context(), tc.ref))
			})
		}
	})
}
