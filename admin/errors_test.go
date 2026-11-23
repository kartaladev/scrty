package admin_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/admin"
)

func TestAlreadyExistsError_NoIdentifierInText(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "email field",
			err:  admin.AlreadyExistsError{Field: admin.FieldEmail},
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, admin.ErrAlreadyExists)
				assert.Contains(t, err.Error(), "email")
				assert.NotContains(t, err.Error(), "@")
			},
		},
		{
			name: "username field",
			err:  admin.AlreadyExistsError{Field: admin.FieldUsername},
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, admin.ErrAlreadyExists)
				assert.Contains(t, err.Error(), "username")
			},
		},
		{
			name: "role field",
			err:  admin.AlreadyExistsError{Field: admin.FieldRole},
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, admin.ErrAlreadyExists)
			},
		},
		{
			name: "identifier field",
			err:  admin.AlreadyExistsError{Field: admin.FieldID},
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, admin.ErrAlreadyExists)
				assert.Equal(t, "admin: already exists: id", err.Error())
			},
		},
		{
			name: "wrapped keeps the field reachable",
			err:  fmt.Errorf("create: %w", admin.AlreadyExistsError{Field: admin.FieldEmail}),
			assert: func(t *testing.T, err error) {
				var ae admin.AlreadyExistsError
				assert.True(t, errors.As(err, &ae))
				assert.Equal(t, admin.FieldEmail, ae.Field)
				assert.ErrorIs(t, err, admin.ErrAlreadyExists)
			},
		},
		{
			name: "matches no other reason",
			err:  admin.AlreadyExistsError{Field: admin.FieldEmail},
			assert: func(t *testing.T, err error) {
				for _, other := range []error{admin.ErrNotFound, admin.ErrStillAssigned, admin.ErrStaleUpdate,
					admin.ErrUnknownPrivilege, admin.ErrInvalidInput, admin.ErrNoActor} {
					assert.NotErrorIs(t, err, other)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.err)
		})
	}
}
