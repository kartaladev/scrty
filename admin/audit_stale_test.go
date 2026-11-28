package admin_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
)

// TestAudit_BeforeIsTheVersionTheWriteReplaced pins that a before record read
// at a version other than the one the caller named is refused as stale and
// nothing is written or reported. Every case shares one shape: the store's
// read lags (version 4) while the caller names version 5 and the write would
// accept it.
func TestAudit_BeforeIsTheVersionTheWriteReplaced(t *testing.T) {
	t.Parallel()

	display := "Sales (Partner)"
	leadView := admin.Grant{Group: "crm", Resource: "lead", Privilege: "view", Granted: true}

	type testCase struct {
		name string
		call func(t *testing.T, ctrl *gomock.Controller, audit *auditRecorder) error
	}

	userCall := func(call func(u *admin.Users) error) func(*testing.T, *gomock.Controller, *auditRecorder) error {
		return func(t *testing.T, ctrl *gomock.Controller, audit *auditRecorder) error {
			store := NewMockUserStore(ctrl)
			store.EXPECT().GetUser(gomock.Any(), eventUser).Return(admin.User{ID: eventUser, Version: 4}, nil)
			store.EXPECT().UpdateUser(gomock.Any(), eventUser, int64(5), gomock.Any()).
				Return(admin.User{ID: eventUser, Version: 6}, false, nil).AnyTimes()
			store.EXPECT().SetActive(gomock.Any(), eventUser, int64(5), gomock.Any()).
				Return(admin.User{ID: eventUser, Version: 6}, true, nil).AnyTimes()
			store.EXPECT().DeleteUser(gomock.Any(), eventUser, int64(5)).Return(nil).AnyTimes()

			return call(newUsers(t, store, admin.WithAudit(audit.sink)))
		}
	}

	roleCall := func(call func(r *admin.Roles) error) func(*testing.T, *gomock.Controller, *auditRecorder) error {
		return func(t *testing.T, ctrl *gomock.Controller, audit *auditRecorder) error {
			store := NewMockRoleStore(ctrl)
			store.EXPECT().GetRole(gomock.Any(), "sales").Return(admin.Role{Name: "sales", Version: 4}, nil)
			store.EXPECT().UpdateRole(gomock.Any(), "sales", int64(5), gomock.Any()).
				Return(admin.Role{Name: "sales", Version: 6}, nil).AnyTimes()
			store.EXPECT().DeleteRole(gomock.Any(), "sales", int64(5), gomock.Any()).Return(nil).AnyTimes()

			r, err := admin.NewRoles(store, admin.WithAudit(audit.sink))
			require.NoError(t, err)

			return call(r)
		}
	}

	assignCall := func(call func(a *admin.Assignments) error) func(*testing.T, *gomock.Controller, *auditRecorder) error {
		return func(t *testing.T, ctrl *gomock.Controller, audit *auditRecorder) error {
			store := NewMockAssignmentStore(ctrl)
			store.EXPECT().ListAssignments(gomock.Any(), eventUser).
				Return([]*identity.AssignedRole{{Name: "sales"}}, int64(4), nil).Times(1)
			store.EXPECT().AddAssignment(gomock.Any(), eventUser, int64(5), gomock.Any()).Return(int64(6), nil).AnyTimes()
			store.EXPECT().RemoveAssignment(gomock.Any(), eventUser, int64(5), gomock.Any()).Return(int64(6), nil).AnyTimes()
			store.EXPECT().SetPrimary(gomock.Any(), eventUser, int64(5), gomock.Any()).Return(int64(6), nil).AnyTimes()
			store.EXPECT().ListAssignments(gomock.Any(), eventUser).
				Return(nil, int64(6), nil).AnyTimes()

			a, err := admin.NewAssignments(store, admin.WithAudit(audit.sink))
			require.NoError(t, err)

			return call(a)
		}
	}

	cases := []testCase{
		{name: "user update", call: userCall(func(u *admin.Users) error {
			_, err := u.Update(actorCtx(t), eventUser, 5, admin.UserChange{Name: &display})

			return err
		})},
		{name: "user deactivation", call: userCall(func(u *admin.Users) error {
			_, err := u.Deactivate(actorCtx(t), eventUser, 5)

			return err
		})},
		{name: "user deletion", call: userCall(func(u *admin.Users) error {
			return u.Delete(actorCtx(t), eventUser, 5)
		})},
		{name: "role update", call: roleCall(func(r *admin.Roles) error {
			_, err := r.Update(actorCtx(t), "sales", 5, admin.RoleChange{DisplayName: &display})

			return err
		})},
		{name: "role deletion", call: roleCall(func(r *admin.Roles) error {
			return r.Delete(actorCtx(t), "sales", 5, false)
		})},
		{
			name: "grant replacement",
			call: func(t *testing.T, ctrl *gomock.Controller, audit *auditRecorder) error {
				store := NewMockGrantStore(ctrl)
				store.EXPECT().GetGrants(gomock.Any(), "sales").Return([]admin.Grant{leadView}, int64(4), nil).Times(1)
				store.EXPECT().ReplaceGrants(gomock.Any(), "sales", int64(5), gomock.Any()).Return(int64(6), nil).AnyTimes()
				store.EXPECT().GetGrants(gomock.Any(), "sales").Return(nil, int64(6), nil).AnyTimes()

				g, err := admin.NewGrants(store, crmCatalogue(t), admin.WithAudit(audit.sink))
				require.NoError(t, err)

				_, err = g.Replace(actorCtx(t), "sales", 5, admin.ResourceGrants{
					Group: "crm", Resource: "lead", Grants: []admin.Grant{leadView},
				})

				return err
			},
		},
		{name: "assignment added", call: assignCall(func(a *admin.Assignments) error {
			_, err := a.Add(actorCtx(t), eventUser, 5, admin.Assignment{Role: "sales"})

			return err
		})},
		{name: "assignment removed", call: assignCall(func(a *admin.Assignments) error {
			_, err := a.Remove(actorCtx(t), eventUser, 5, "g1")

			return err
		})},
		{name: "primary set", call: assignCall(func(a *admin.Assignments) error {
			_, err := a.SetPrimary(actorCtx(t), eventUser, 5, "g1")

			return err
		})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			audit := &auditRecorder{}
			err := tc.call(t, gomock.NewController(t), audit)

			require.ErrorIs(t, err, admin.ErrStaleUpdate)
			assert.Empty(t, audit.all())
		})
	}
}
