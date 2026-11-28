package admin_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/eventsink"
	"github.com/kartaladev/scrty/pkg/id"
)

const (
	eventUser  = identity.UserID("0192f1e2-3c4d-7e5f-8a9b-0c1d2e3f4a5b")
	secretMail = "ada.secret@example.com"
)

// adminCall builds a service over mocks whose store calls succeed, wires sink
// into it, and makes one write.
type adminCall func(t *testing.T, ctrl *gomock.Controller, sink event.Sink) error

func usersCall(setup func(store *MockUserStore), call func(ctx context.Context, u *admin.Users) error) adminCall {
	return func(t *testing.T, ctrl *gomock.Controller, sink event.Sink) error {
		store := NewMockUserStore(ctrl)
		setup(store)

		uid := id.MustParse(string(eventUser))
		u := newUsers(t, store, admin.WithEventSink(sink), admin.WithClock(fixedClock()),
			admin.WithIDGenerator(fixedIDs(t, uid)))

		return call(actorCtx(t), u)
	}
}

func rolesCall(setup func(store *MockRoleStore), call func(ctx context.Context, r *admin.Roles) error) adminCall {
	return func(t *testing.T, ctrl *gomock.Controller, sink event.Sink) error {
		store := NewMockRoleStore(ctrl)
		setup(store)

		r, err := admin.NewRoles(store, admin.WithEventSink(sink))
		require.NoError(t, err)

		return call(actorCtx(t), r)
	}
}

func grantsCall(setup func(store *MockGrantStore), call func(ctx context.Context, g *admin.Grants) error) adminCall {
	return func(t *testing.T, ctrl *gomock.Controller, sink event.Sink) error {
		store := NewMockGrantStore(ctrl)
		setup(store)

		g, err := admin.NewGrants(store, crmCatalogue(t), admin.WithEventSink(sink))
		require.NoError(t, err)

		return call(actorCtx(t), g)
	}
}

func assignmentsCall(setup func(store *MockAssignmentStore), call func(ctx context.Context, a *admin.Assignments) error) adminCall {
	return func(t *testing.T, ctrl *gomock.Controller, sink event.Sink) error {
		store := NewMockAssignmentStore(ctrl)
		setup(store)

		a, err := admin.NewAssignments(store, admin.WithEventSink(sink))
		require.NoError(t, err)

		return call(actorCtx(t), a)
	}
}

func TestEvents_OneAfterCommit(t *testing.T) {
	t.Parallel()

	mail := secretMail
	name := "Ada L."
	display := "Sales (Partner)"
	stored := admin.User{ID: eventUser, Username: "ada", Email: secretMail, Version: 4}

	type testCase struct {
		name    string
		call    adminCall
		event   string
		target  string
		user    identity.UserID
		changed []string
	}

	cases := []testCase{
		{
			name: "user created", event: event.UserCreated, target: string(eventUser), user: eventUser,
			call: usersCall(func(s *MockUserStore) {
				s.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(stored, nil)
			}, func(ctx context.Context, u *admin.Users) error {
				_, err := u.Create(ctx, admin.NewUser{Username: "ada", Email: secretMail})
				return err
			}),
		},
		{
			name: "email changed", event: event.UserUpdated, target: string(eventUser), user: eventUser,
			changed: []string{"email", "email_verified_at"},
			call: usersCall(func(s *MockUserStore) {
				s.EXPECT().UpdateUser(gomock.Any(), eventUser, int64(4), gomock.Any()).Return(stored, false, nil)
			}, func(ctx context.Context, u *admin.Users) error {
				_, err := u.Update(ctx, eventUser, 4, admin.UserChange{Email: &mail})
				return err
			}),
		},
		{
			name: "stored email re-sent keeps its verification", event: event.UserUpdated, target: string(eventUser),
			user: eventUser, changed: []string{"email"},
			call: usersCall(func(s *MockUserStore) {
				verified := stored
				verified.EmailVerifiedAt = testNow
				s.EXPECT().UpdateUser(gomock.Any(), eventUser, int64(4), gomock.Any()).Return(verified, false, nil)
			}, func(ctx context.Context, u *admin.Users) error {
				_, err := u.Update(ctx, eventUser, 4, admin.UserChange{Email: &mail})
				return err
			}),
		},
		{
			name: "name and attributes changed", event: event.UserUpdated, target: string(eventUser), user: eventUser,
			changed: []string{"name", "attributes"},
			call: usersCall(func(s *MockUserStore) {
				s.EXPECT().UpdateUser(gomock.Any(), eventUser, int64(4), gomock.Any()).Return(stored, false, nil)
			}, func(ctx context.Context, u *admin.Users) error {
				_, err := u.Update(ctx, eventUser, 4, admin.UserChange{
					Name: &name, Attributes: map[string]string{"phone": "+62 21 555"},
				})
				return err
			}),
		},
		{
			name: "user deactivated", event: event.UserArchived, target: string(eventUser), user: eventUser,
			changed: []string{"active"},
			call: usersCall(func(s *MockUserStore) {
				s.EXPECT().SetActive(gomock.Any(), eventUser, int64(4), false).Return(stored, true, nil)
			}, func(ctx context.Context, u *admin.Users) error {
				_, err := u.Deactivate(ctx, eventUser, 4)
				return err
			}),
		},
		{
			name: "user reactivated", event: event.UserReactivated, target: string(eventUser), user: eventUser,
			changed: []string{"active"},
			call: usersCall(func(s *MockUserStore) {
				s.EXPECT().SetActive(gomock.Any(), eventUser, int64(4), true).Return(stored, true, nil)
			}, func(ctx context.Context, u *admin.Users) error {
				_, err := u.Reactivate(ctx, eventUser, 4)
				return err
			}),
		},
		{
			name: "user deleted", event: event.UserDeleted, target: string(eventUser), user: eventUser,
			call: usersCall(func(s *MockUserStore) {
				s.EXPECT().DeleteUser(gomock.Any(), eventUser, int64(4)).Return(nil)
			}, func(ctx context.Context, u *admin.Users) error {
				return u.Delete(ctx, eventUser, 4)
			}),
		},
		{
			name: "password reset", event: event.AuthnPasswordChange, target: string(eventUser), user: eventUser,
			changed: []string{"password"},
			call: usersCall(func(s *MockUserStore) {
				s.EXPECT().GetUser(gomock.Any(), eventUser).Return(stored, nil)
				s.EXPECT().CurrentPasswordHash(gomock.Any(), eventUser).Return(nil, nil)
				s.EXPECT().SetPassword(gomock.Any(), eventUser, int64(4), gomock.Any(), testNow).Return(stored, nil)
			}, func(ctx context.Context, u *admin.Users) error {
				_, err := u.SetPassword(ctx, eventUser, 4, []byte(goodPassword))
				return err
			}),
		},
		{
			name: "role created", event: event.AuthzAdmin, target: "sales",
			changed: []string{"name", "display_name"},
			call: rolesCall(func(s *MockRoleStore) {
				s.EXPECT().CreateRole(gomock.Any(), gomock.Any()).Return(admin.Role{Name: "sales", Version: 1}, nil)
			}, func(ctx context.Context, r *admin.Roles) error {
				_, err := r.Create(ctx, admin.Role{Name: "sales", DisplayName: "Sales"})
				return err
			}),
		},
		{
			name: "role renamed", event: event.AuthzAdmin, target: "sales", changed: []string{"display_name"},
			call: rolesCall(func(s *MockRoleStore) {
				s.EXPECT().UpdateRole(gomock.Any(), "sales", int64(2), gomock.Any()).Return(admin.Role{Name: "sales"}, nil)
			}, func(ctx context.Context, r *admin.Roles) error {
				_, err := r.Update(ctx, "sales", 2, admin.RoleChange{DisplayName: &display})
				return err
			}),
		},
		{
			name: "role deleted", event: event.AuthzAdmin, target: "sales",
			call: rolesCall(func(s *MockRoleStore) {
				s.EXPECT().DeleteRole(gomock.Any(), "sales", int64(2), true).Return(nil)
			}, func(ctx context.Context, r *admin.Roles) error {
				return r.Delete(ctx, "sales", 2, true)
			}),
		},
		{
			name: "grants replaced", event: event.PrivilegePermissionsChanged, target: "sales",
			changed: []string{"crm/lead"},
			call: grantsCall(func(s *MockGrantStore) {
				s.EXPECT().ReplaceGrants(gomock.Any(), "sales", int64(4), gomock.Any()).Return(int64(5), nil)
			}, func(ctx context.Context, g *admin.Grants) error {
				_, err := g.Replace(ctx, "sales", 4, admin.ResourceGrants{Group: "crm", Resource: "lead",
					Grants: []admin.Grant{{Privilege: "view", Granted: true}}})
				return err
			}),
		},
		{
			name: "assignment added", event: event.AuthzChange, target: string(eventUser), user: eventUser,
			changed: []string{"roles"},
			call: assignmentsCall(func(s *MockAssignmentStore) {
				s.EXPECT().AddAssignment(gomock.Any(), eventUser, int64(4), gomock.Any()).Return(int64(5), nil)
			}, func(ctx context.Context, a *admin.Assignments) error {
				_, err := a.Add(ctx, eventUser, 4, admin.Assignment{Role: "sales"})
				return err
			}),
		},
		{
			name: "assignment removed", event: event.AuthzChange, target: string(eventUser), user: eventUser,
			changed: []string{"roles"},
			call: assignmentsCall(func(s *MockAssignmentStore) {
				s.EXPECT().RemoveAssignment(gomock.Any(), eventUser, int64(4), "g-1").Return(int64(5), nil)
			}, func(ctx context.Context, a *admin.Assignments) error {
				_, err := a.Remove(ctx, eventUser, 4, "g-1")
				return err
			}),
		},
		{
			name: "primary marked", event: event.AuthzChange, target: string(eventUser), user: eventUser,
			changed: []string{"primary"},
			call: assignmentsCall(func(s *MockAssignmentStore) {
				s.EXPECT().SetPrimary(gomock.Any(), eventUser, int64(4), "g-2").Return(int64(5), nil)
			}, func(ctx context.Context, a *admin.Assignments) error {
				_, err := a.SetPrimary(ctx, eventUser, 4, "g-2")
				return err
			}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := &eventRecorder{}
			require.NoError(t, tc.call(t, gomock.NewController(t), rec.sink))

			events := rec.all()
			require.Len(t, events, 1)

			e := events[0]
			assert.Equal(t, tc.event, e.Name)
			assert.Equal(t, event.OutcomeSuccess, e.Outcome)
			assert.Equal(t, "admin-1", e.Actor)
			assert.Equal(t, tc.target, e.Target)
			assert.Equal(t, tc.user, e.User)
			assert.Equal(t, tc.changed, e.Changed)
			assert.False(t, e.At.IsZero())

			dump := fmt.Sprintf("%+v", e)
			for _, value := range []string{secretMail, "+62 21 555", "Ada L.", goodPassword, "Sales (Partner)"} {
				assert.NotContains(t, dump, value)
			}
		})
	}
}

func TestEvents_NoneOnRefusalOrNoop(t *testing.T) {
	t.Parallel()

	mail := secretMail
	inactive := admin.User{ID: eventUser, Version: 4}
	active := admin.User{ID: eventUser, Version: 4, Active: true}

	type testCase struct {
		name   string
		call   adminCall
		assert func(t *testing.T, err error)
	}

	succeeds := func(t *testing.T, err error) { require.NoError(t, err) }
	fails := func(t *testing.T, err error) { require.Error(t, err) }

	cases := []testCase{
		{
			name: "deactivating an inactive user", assert: succeeds,
			call: usersCall(func(s *MockUserStore) {
				s.EXPECT().SetActive(gomock.Any(), eventUser, int64(4), false).Return(inactive, false, nil)
			}, func(ctx context.Context, u *admin.Users) error {
				_, err := u.Deactivate(ctx, eventUser, 4)
				return err
			}),
		},
		{
			name: "reactivating an active user", assert: succeeds,
			call: usersCall(func(s *MockUserStore) {
				s.EXPECT().SetActive(gomock.Any(), eventUser, int64(4), true).Return(active, false, nil)
			}, func(ctx context.Context, u *admin.Users) error {
				_, err := u.Reactivate(ctx, eventUser, 4)
				return err
			}),
		},
		{
			name: "stale update", assert: fails,
			call: usersCall(func(s *MockUserStore) {
				s.EXPECT().UpdateUser(gomock.Any(), eventUser, int64(4), gomock.Any()).Return(admin.User{}, false, admin.ErrStaleUpdate)
			}, func(ctx context.Context, u *admin.Users) error {
				_, err := u.Update(ctx, eventUser, 4, admin.UserChange{Email: &mail})
				return err
			}),
		},
		{
			name: "storage failure on create", assert: fails,
			call: usersCall(func(s *MockUserStore) {
				s.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(admin.User{}, errStorage)
			}, func(ctx context.Context, u *admin.Users) error {
				_, err := u.Create(ctx, admin.NewUser{Username: "ada"})
				return err
			}),
		},
		{
			name: "delete refused without an actor", assert: fails,
			call: usersCall(func(*MockUserStore) {}, func(ctx context.Context, u *admin.Users) error {
				return u.Delete(context.WithoutCancel(identity.WithPrincipal(ctx, nil)), eventUser, 4)
			}),
		},
		{
			name: "role still assigned", assert: fails,
			call: rolesCall(func(s *MockRoleStore) {
				s.EXPECT().DeleteRole(gomock.Any(), "sales", int64(2), false).Return(admin.ErrStillAssigned)
			}, func(ctx context.Context, r *admin.Roles) error {
				return r.Delete(ctx, "sales", 2, false)
			}),
		},
		{
			name: "unknown privilege", assert: fails,
			call: grantsCall(func(*MockGrantStore) {}, func(ctx context.Context, g *admin.Grants) error {
				_, err := g.Replace(ctx, "sales", 4, admin.ResourceGrants{Group: "crm", Resource: "lead",
					Grants: []admin.Grant{{Privilege: "purge", Granted: true}}})
				return err
			}),
		},
		{
			name: "unknown role assigned", assert: fails,
			call: assignmentsCall(func(s *MockAssignmentStore) {
				s.EXPECT().AddAssignment(gomock.Any(), eventUser, int64(4), gomock.Any()).Return(int64(0), admin.ErrNotFound)
			}, func(ctx context.Context, a *admin.Assignments) error {
				_, err := a.Add(ctx, eventUser, 4, admin.Assignment{Role: "ghost"})
				return err
			}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := &eventRecorder{}
			tc.assert(t, tc.call(t, gomock.NewController(t), rec.sink))
			assert.Empty(t, rec.all())
		})
	}
}

// TestEvents_DefaultReportsNothing pins that a service built with no sink, on
// a context no chain reports through, emits nothing and still succeeds.
func TestEvents_DefaultReportsNothing(t *testing.T) {
	t.Parallel()

	store := NewMockRoleStore(gomock.NewController(t))
	store.EXPECT().DeleteRole(gomock.Any(), "sales", int64(2), false).Return(nil)

	r, err := admin.NewRoles(store)
	require.NoError(t, err)
	require.NoError(t, r.Delete(actorCtx(t), "sales", 2, false))
}

// TestEvents_PanickingSinkDoesNotFailTheCall pins that a sink's panic is
// recovered: the committed change is still reported as a success.
func TestEvents_PanickingSinkDoesNotFailTheCall(t *testing.T) {
	t.Parallel()

	store := NewMockRoleStore(gomock.NewController(t))
	store.EXPECT().DeleteRole(gomock.Any(), "sales", int64(2), false).Return(nil)

	r, err := admin.NewRoles(store, admin.WithEventSink(func(context.Context, event.Event) { panic("sink down") }),
		admin.WithLogger(discardLogger()))
	require.NoError(t, err)
	require.NoError(t, r.Delete(actorCtx(t), "sales", 2, false))
}

// TestEvents_ThroughTheChain pins that on a request whose chain reports
// security events, a service reports through the chain and its own sink is not
// called, so one outcome is reported once.
func TestEvents_ThroughTheChain(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context, chain *eventRecorder) context.Context
		assert func(t *testing.T, chain, own []event.Event)
	}

	cases := []testCase{
		{
			name: "a chain's emitter receives the event instead of the service's sink",
			ctx: func(ctx context.Context, chain *eventRecorder) context.Context {
				return eventsink.With(ctx, chain.sink)
			},
			assert: func(t *testing.T, chain, own []event.Event) {
				require.Len(t, chain, 1)
				assert.Equal(t, event.AuthzAdmin, chain[0].Name)
				assert.Equal(t, "admin-1", chain[0].Actor)
				assert.Empty(t, own)
			},
		},
		{
			name: "without a chain the service's sink receives it",
			ctx:  func(ctx context.Context, _ *eventRecorder) context.Context { return ctx },
			assert: func(t *testing.T, chain, own []event.Event) {
				assert.Empty(t, chain)
				require.Len(t, own, 1)
				assert.Equal(t, event.AuthzAdmin, own[0].Name)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockRoleStore(gomock.NewController(t))
			store.EXPECT().DeleteRole(gomock.Any(), "sales", int64(2), false).Return(nil)

			chain, own := &eventRecorder{}, &eventRecorder{}
			r, err := admin.NewRoles(store, admin.WithEventSink(own.sink))
			require.NoError(t, err)

			require.NoError(t, r.Delete(tc.ctx(actorCtx(t), chain), "sales", 2, false))
			tc.assert(t, chain.all(), own.all())
		})
	}
}
