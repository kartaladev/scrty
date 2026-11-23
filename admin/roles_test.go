package admin_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
)

func TestNewRoles(t *testing.T) {
	t.Parallel()

	var nilStore *MockRoleStore

	type testCase struct {
		name   string
		store  func(t *testing.T) admin.RoleStore
		opts   []admin.RolesOption
		assert func(t *testing.T, r *admin.Roles, err error)
	}

	store := func(t *testing.T) admin.RoleStore { return NewMockRoleStore(gomock.NewController(t)) }
	refused := func(t *testing.T, r *admin.Roles, err error) {
		assert.ErrorIs(t, err, admin.ErrConfig)
		assert.Nil(t, r)
	}

	cases := []testCase{
		{name: "store only", store: store, assert: func(t *testing.T, r *admin.Roles, err error) {
			require.NoError(t, err)
			assert.NotNil(t, r)
		}},
		{name: "nil store", store: func(*testing.T) admin.RoleStore { return nil }, assert: refused},
		{name: "typed nil store", store: func(*testing.T) admin.RoleStore { return nilStore }, assert: refused},
		{name: "nil logger", store: store, opts: []admin.RolesOption{admin.WithLogger(nil)}, assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := admin.NewRoles(tc.store(t), tc.opts...)
			tc.assert(t, r, err)
		})
	}
}

func TestRoles(t *testing.T) {
	t.Parallel()

	sales := admin.Role{Name: "sales", DisplayName: "Sales", Labels: []string{"Partner"}}
	display := "Sales (Partner)"

	type testCase struct {
		name   string
		ctx    func(t *testing.T) context.Context
		setup  func(store *MockRoleStore)
		call   func(ctx context.Context, r *admin.Roles) error
		assert func(t *testing.T, err error)
	}

	invalidNoCall := func(t *testing.T, err error) { require.ErrorIs(t, err, admin.ErrInvalidInput) }
	noCall := func(*MockRoleStore) {}

	cases := []testCase{
		{
			name: "label filter reaches the store",
			setup: func(store *MockRoleStore) {
				store.EXPECT().ListRoles(gomock.Any(), "Partner").Return([]admin.Role{sales}, nil)
			},
			call: func(ctx context.Context, r *admin.Roles) error {
				got, err := r.List(ctx, "Partner")
				if err == nil && (len(got) != 1 || got[0].Name != "sales") {
					t.Errorf("listed %v", got)
				}

				return err
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "label filter beyond the bound", setup: noCall,
			call: func(ctx context.Context, r *admin.Roles) error {
				_, err := r.List(ctx, strings.Repeat("l", admin.MaxTextBytes+1))
				return err
			},
			assert: invalidNoCall,
		},
		{
			name: "duplicate role",
			setup: func(store *MockRoleStore) {
				store.EXPECT().CreateRole(gomock.Any(), sales).Return(admin.Role{}, admin.AlreadyExistsError{Field: admin.FieldRole})
			},
			call: func(ctx context.Context, r *admin.Roles) error {
				_, err := r.Create(ctx, sales)
				return err
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, admin.ErrAlreadyExists)
				var ae admin.AlreadyExistsError
				require.ErrorAs(t, err, &ae)
				assert.Equal(t, admin.FieldRole, ae.Field)
			},
		},
		{
			name: "blank name", setup: noCall,
			call: func(ctx context.Context, r *admin.Roles) error {
				_, err := r.Create(ctx, admin.Role{Name: " "})
				return err
			},
			assert: invalidNoCall,
		},
		{
			name: "role name with surrounding space", setup: noCall,
			call: func(ctx context.Context, r *admin.Roles) error {
				_, err := r.Create(ctx, admin.Role{Name: "sales "})
				return err
			},
			assert: invalidNoCall,
		},
		{
			name: "label with surrounding space", setup: noCall,
			call: func(ctx context.Context, r *admin.Roles) error {
				_, err := r.Create(ctx, admin.Role{Name: "sales", Labels: []string{" Partner"}})
				return err
			},
			assert: invalidNoCall,
		},
		{
			name: "get a role name with surrounding space", setup: noCall,
			call: func(ctx context.Context, r *admin.Roles) error {
				_, err := r.Get(ctx, " sales")
				return err
			},
			assert: invalidNoCall,
		},
		{
			name: "blank label", setup: noCall,
			call: func(ctx context.Context, r *admin.Roles) error {
				_, err := r.Create(ctx, admin.Role{Name: "sales", Labels: []string{""}})
				return err
			},
			assert: invalidNoCall,
		},
		{
			name: "create without an actor", setup: noCall,
			ctx: func(t *testing.T) context.Context { return t.Context() },
			call: func(ctx context.Context, r *admin.Roles) error {
				_, err := r.Create(ctx, sales)
				return err
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, admin.ErrNoActor) },
		},
		{
			name: "still assigned passes through",
			setup: func(store *MockRoleStore) {
				store.EXPECT().DeleteRole(gomock.Any(), "sales", int64(3), false).Return(admin.ErrStillAssigned)
			},
			call:   func(ctx context.Context, r *admin.Roles) error { return r.Delete(ctx, "sales", 3, false) },
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, admin.ErrStillAssigned) },
		},
		{
			name: "update with an empty change", setup: noCall,
			call: func(ctx context.Context, r *admin.Roles) error {
				_, err := r.Update(ctx, "sales", 3, admin.RoleChange{})
				return err
			},
			assert: invalidNoCall,
		},
		{
			name: "update with version zero", setup: noCall,
			call: func(ctx context.Context, r *admin.Roles) error {
				_, err := r.Update(ctx, "sales", 0, admin.RoleChange{DisplayName: &display})
				return err
			},
			assert: invalidNoCall,
		},
		{
			name: "stale update passes through",
			setup: func(store *MockRoleStore) {
				store.EXPECT().UpdateRole(gomock.Any(), "sales", int64(3), gomock.Any()).Return(admin.Role{}, admin.ErrStaleUpdate)
			},
			call: func(ctx context.Context, r *admin.Roles) error {
				_, err := r.Update(ctx, "sales", 3, admin.RoleChange{DisplayName: &display})
				return err
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, admin.ErrStaleUpdate) },
		},
		{
			name: "storage failure matches no reason",
			setup: func(store *MockRoleStore) {
				store.EXPECT().GetRole(gomock.Any(), "sales").Return(admin.Role{}, errStorage)
			},
			call: func(ctx context.Context, r *admin.Roles) error {
				_, err := r.Get(ctx, "sales")
				return err
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errStorage)
				for _, reason := range reasons {
					assert.NotErrorIs(t, err, reason)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockRoleStore(gomock.NewController(t))
			tc.setup(store)

			r, err := admin.NewRoles(store)
			require.NoError(t, err)

			ctx := actorCtx(t)
			if tc.ctx != nil {
				ctx = tc.ctx(t)
			}

			tc.assert(t, tc.call(ctx, r))
		})
	}
}
