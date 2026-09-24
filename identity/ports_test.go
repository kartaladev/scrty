package identity_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// allUserFields is every field an option can set. Tests walk it rather than
// restating the list, so a field added without a matching case fails here.
var allUserFields = []identity.Field{
	identity.FieldName,
	identity.FieldEmail,
	identity.FieldRoles,
	identity.FieldOrganization,
	identity.FieldPassword,
}

func TestApplyUserOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []identity.UserOption
		assert func(t *testing.T, u *identity.NewUser)
	}

	cases := []testCase{
		{
			name: "no options sets no field",
			assert: func(t *testing.T, u *identity.NewUser) {
				for _, f := range allUserFields {
					assert.False(t, u.IsSet(f), "field %d was never named", f)
				}
			},
		},
		{
			name: "an option records itself even when its value is empty",
			opts: []identity.UserOption{identity.WithUserName("")},
			assert: func(t *testing.T, u *identity.NewUser) {
				assert.True(t, u.IsSet(identity.FieldName),
					"IsSet follows the option being applied, never the value's emptiness")
				assert.Empty(t, u.Name)
				assert.False(t, u.IsSet(identity.FieldEmail),
					"naming one field must not mark another")
			},
		},
		{
			name: "an empty role list still counts as naming roles",
			opts: []identity.UserOption{identity.WithUserRoles()},
			assert: func(t *testing.T, u *identity.NewUser) {
				assert.True(t, u.IsSet(identity.FieldRoles),
					"Update decides from IsSet, so it must see that roles were named at all")
				assert.Empty(t, u.Roles)
			},
		},
		{
			name: "a nil organization still counts as naming the organization",
			opts: []identity.UserOption{identity.WithUserOrganization(nil)},
			assert: func(t *testing.T, u *identity.NewUser) {
				assert.True(t, u.IsSet(identity.FieldOrganization))
				assert.Nil(t, u.Organization)
			},
		},
		{
			name: "every field option records itself and carries its value",
			opts: []identity.UserOption{
				identity.WithUserName("Alice Álvarez"),
				identity.WithUserEmail("alice@example.com"),
				identity.WithUserRoles("editor", "viewer"),
				identity.WithUserOrganization(&identity.Organization{ID: "o-1", Name: "acme"}),
				identity.WithUserPassword([]byte("H")),
			},
			assert: func(t *testing.T, u *identity.NewUser) {
				for _, f := range allUserFields {
					assert.True(t, u.IsSet(f), "field %d was named but reports unset", f)
				}

				assert.Equal(t, "Alice Álvarez", u.Name)
				assert.Equal(t, "alice@example.com", u.Email)
				assert.Equal(t, []string{"editor", "viewer"}, u.Roles)
				assert.Equal(t, []byte("H"), u.Password)

				if assert.NotNil(t, u.Organization) {
					assert.Equal(t, "acme", u.Organization.Name)
				}
			},
		},
		{
			name: "a later option overrides an earlier one for the same field",
			opts: []identity.UserOption{
				identity.WithUserName("first"),
				identity.WithUserName("second"),
			},
			assert: func(t *testing.T, u *identity.NewUser) {
				assert.Equal(t, "second", u.Name)
				assert.True(t, u.IsSet(identity.FieldName))
			},
		},
		{
			name: "a nil option is ignored rather than panicking",
			opts: []identity.UserOption{nil, identity.WithUserName("alice")},
			assert: func(t *testing.T, u *identity.NewUser) {
				assert.Equal(t, "alice", u.Name)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, identity.ApplyUserOptions(tc.opts...))
		})
	}
}

// stubLoader is the smallest thing that satisfies identity.UserLoader: the two
// lookups over a seeded map, plus a single injected failure standing in for a
// store that is down. It exists so the port's miss-versus-outage contract can be
// exercised without a store, since identity ships no loader of its own.
type stubLoader struct {
	byID map[identity.UserID]*identity.Details
	err  error
}

func (s stubLoader) LoadByUsername(
	_ context.Context, username string,
) (*identity.Details, error) {
	if s.err != nil {
		return nil, s.err
	}

	for _, d := range s.byID {
		if d.Username == username {
			return d, nil
		}
	}

	return nil, identity.ErrUserNotFound
}

func (s stubLoader) LoadByUserID(
	_ context.Context, id identity.UserID,
) (*identity.Details, error) {
	if s.err != nil {
		return nil, s.err
	}

	d, ok := s.byID[id]
	if !ok {
		return nil, identity.ErrUserNotFound
	}

	return d, nil
}

func TestUserLoaderLoadByUserID(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		loader identity.UserLoader
		id     identity.UserID
		assert func(t *testing.T, d *identity.Details, err error)
	}

	cases := []testCase{
		{
			name: "a hit returns the details",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{
				"u-1": {ID: "u-1", Username: "ada"},
			}},
			id: "u-1",
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				require.NotNil(t, d)
				assert.Equal(t, identity.UserID("u-1"), d.ID)
			},
		},
		{
			name:   "a miss is ErrUserNotFound",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{}},
			id:     "u-missing",
			assert: func(t *testing.T, d *identity.Details, err error) {
				assert.ErrorIs(t, err, identity.ErrUserNotFound)
				assert.Nil(t, d)
			},
		},
		{
			name:   "an outage is not ErrUserNotFound",
			loader: stubLoader{err: errors.New("dial tcp: connection refused")},
			id:     "u-1",
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, identity.ErrUserNotFound,
					"a caller must be able to tell an outage from a miss")
				assert.Nil(t, d)
			},
		},
		{
			name: "the reference is matched byte-for-byte",
			loader: stubLoader{byID: map[identity.UserID]*identity.Details{
				"u-1": {ID: "u-1"},
			}},
			id: "U-1",
			assert: func(t *testing.T, d *identity.Details, err error) {
				assert.ErrorIs(t, err, identity.ErrUserNotFound, "references are not case-folded")
				assert.Nil(t, d)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d, err := tc.loader.LoadByUserID(t.Context(), tc.id)
			tc.assert(t, d, err)
		})
	}
}
