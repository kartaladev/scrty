package password_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/password"
)

// allFields lists every exported identity.Field, so a write can be shown to
// name nothing beyond the two it means to.
var allFields = []identity.Field{
	identity.FieldName,
	identity.FieldEmail,
	identity.FieldRoles,
	identity.FieldOrganization,
	identity.FieldPassword,
	identity.FieldPasswordChangedAt,
}

func TestProvisionerWrite_RefusesWiringMistakes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		provisioner func(ctrl *gomock.Controller) identity.UserProvisioner
		assert      func(t *testing.T, write password.WriteFunc, err error)
	}

	refused := func(t *testing.T, write password.WriteFunc, err error) {
		require.ErrorIs(t, err, password.ErrConfig)
		assert.Contains(t, err.Error(), "provisioner")
		assert.Nil(t, write)
	}

	cases := []testCase{
		{
			name:        "a nil provisioner",
			provisioner: func(*gomock.Controller) identity.UserProvisioner { return nil },
			assert:      refused,
		},
		{
			name:        "a typed-nil provisioner",
			provisioner: func(*gomock.Controller) identity.UserProvisioner { return (*MockUserProvisioner)(nil) },
			assert:      refused,
		},
		{
			name: "a provisioner",
			provisioner: func(ctrl *gomock.Controller) identity.UserProvisioner {
				return NewMockUserProvisioner(ctrl)
			},
			assert: func(t *testing.T, write password.WriteFunc, err error) {
				require.NoError(t, err)
				assert.NotNil(t, write)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			write, err := password.ProvisionerWrite(tc.provisioner(gomock.NewController(t)))
			tc.assert(t, write, err)
		})
	}
}

func TestProvisionerWrite_Write(t *testing.T) {
	t.Parallel()

	fast := fastArgon2id(t)
	current := mustEncode(t, fast, "p1")
	newHash := []byte("new-hash")
	at := time.Date(2031, time.June, 1, 0, 0, 0, 0, time.UTC)
	errStore := errors.New("the store refused the update")

	type testCase struct {
		name   string
		user   *identity.Details
		update func(m *MockUserProvisioner, got **identity.NewUser)
		// invoke runs the write; nil calls it directly with newHash and at.
		invoke func(t *testing.T, write password.WriteFunc, user *identity.Details) error
		assert func(t *testing.T, err error, got *identity.NewUser)
	}

	capture := func(got **identity.NewUser, err error) func(context.Context, string, ...identity.UserOption) (*identity.Details, error) {
		return func(_ context.Context, _ string, opts ...identity.UserOption) (*identity.Details, error) {
			*got = identity.ApplyUserOptions(opts...)
			return &identity.Details{}, err
		}
	}

	namesPasswordChangeOnly := func(t *testing.T, got *identity.NewUser, wantHash func([]byte) bool) {
		t.Helper()

		require.NotNil(t, got, "Update was called")
		for _, f := range allFields {
			want := f == identity.FieldPassword || f == identity.FieldPasswordChangedAt
			assert.Equal(t, want, got.IsSet(f), "field %d named", f)
		}
		assert.True(t, wantHash(got.Password), "the new hash is named")
		assert.True(t, at.Equal(got.PasswordChangedAt), "the change time is named")
	}

	cases := []testCase{
		{
			name: "updates the username naming exactly the hash and the time",
			user: &identity.Details{ID: "u-1", Username: "ada", Password: current},
			update: func(m *MockUserProvisioner, got **identity.NewUser) {
				m.EXPECT().Update(gomock.Any(), "ada", gomock.Any()).Times(1).DoAndReturn(capture(got, nil))
			},
			assert: func(t *testing.T, err error, got *identity.NewUser) {
				require.NoError(t, err)
				namesPasswordChangeOnly(t, got, func(h []byte) bool { return string(h) == string(newHash) })
			},
		},
		{
			name: "returns the provisioner's error unchanged",
			user: &identity.Details{ID: "u-1", Username: "ada", Password: current},
			update: func(m *MockUserProvisioner, got **identity.NewUser) {
				m.EXPECT().Update(gomock.Any(), "ada", gomock.Any()).DoAndReturn(capture(got, errStore))
			},
			assert: func(t *testing.T, err error, _ *identity.NewUser) {
				require.ErrorIs(t, err, errStore)
			},
		},
		{
			name:   "a nil user is a wiring mistake and updates nothing",
			update: func(*MockUserProvisioner, **identity.NewUser) {},
			assert: func(t *testing.T, err error, got *identity.NewUser) {
				require.ErrorIs(t, err, password.ErrConfig)
				assert.Nil(t, got)
			},
		},
		{
			name: "through a guard with a fixed clock, the change records its time",
			user: &identity.Details{ID: "u-1", Username: "ada", Password: current},
			update: func(m *MockUserProvisioner, got **identity.NewUser) {
				m.EXPECT().Update(gomock.Any(), "ada", gomock.Any()).Times(1).DoAndReturn(capture(got, nil))
			},
			invoke: func(t *testing.T, write password.WriteFunc, user *identity.Details) error {
				g, err := password.NewReuseGuard(newMemHistory(), fast, 3,
					password.WithReuseClock(func() time.Time { return at }))
				require.NoError(t, err)

				return g.Change(t.Context(), user, "p2", write)
			},
			assert: func(t *testing.T, err error, got *identity.NewUser) {
				require.NoError(t, err)
				namesPasswordChangeOnly(t, got, func(h []byte) bool { return fast.Match("p2", h) })
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := NewMockUserProvisioner(gomock.NewController(t))
			var got *identity.NewUser
			tc.update(m, &got)

			write, err := password.ProvisionerWrite(m)
			require.NoError(t, err)

			if tc.invoke != nil {
				err = tc.invoke(t, write, tc.user)
			} else {
				err = write(t.Context(), tc.user, newHash, at)
			}

			tc.assert(t, err, got)
		})
	}
}
