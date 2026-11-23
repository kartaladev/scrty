package admin_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
)

// byteFields returns the paths of every []byte reachable from t's fields.
func byteFields(t reflect.Type, path string, seen map[reflect.Type]bool) []string {
	if seen[t] {
		return nil
	}

	seen[t] = true

	switch t.Kind() {
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return []string{path}
		}

		return byteFields(t.Elem(), path+"[]", seen)
	case reflect.Array, reflect.Pointer:
		return byteFields(t.Elem(), path, seen)
	case reflect.Map:
		return append(byteFields(t.Key(), path+"{key}", seen), byteFields(t.Elem(), path+"{}", seen)...)
	case reflect.Struct:
		var out []string
		for i := range t.NumField() {
			f := t.Field(i)
			out = append(out, byteFields(f.Type, path+"."+f.Name, seen)...)
		}

		return out
	default:
		return nil
	}
}

func TestAudit_BeforeAfterWithoutHash(t *testing.T) {
	t.Parallel()

	hash := []byte("$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo")
	stored := admin.User{ID: eventUser, Username: "ada", Email: secretMail, Version: 4}

	type testCase struct {
		name   string
		value  func(t *testing.T) any
		assert func(t *testing.T, v any)
	}

	noBytes := func(t *testing.T, v any) {
		assert.Empty(t, byteFields(reflect.TypeOf(v), reflect.TypeOf(v).String(), map[reflect.Type]bool{}))
	}

	cases := []testCase{
		{name: "change", value: func(*testing.T) any { return admin.Change{} }, assert: noBytes},
		{name: "user", value: func(*testing.T) any { return admin.User{} }, assert: noBytes},
		{name: "role", value: func(*testing.T) any { return admin.Role{} }, assert: noBytes},
		{name: "grants", value: func(*testing.T) any { return []admin.Grant{} }, assert: noBytes},
		{name: "assignments", value: func(*testing.T) any { return []identity.AssignedRole{} }, assert: noBytes},
		{
			name: "a password reset's records",
			value: func(t *testing.T) any {
				ctrl := gomock.NewController(t)
				store := NewMockUserStore(ctrl)
				store.EXPECT().GetUser(gomock.Any(), eventUser).Return(stored, nil)
				store.EXPECT().CurrentPasswordHash(gomock.Any(), eventUser).Return(hash, nil)
				store.EXPECT().SetPassword(gomock.Any(), eventUser, int64(4), gomock.Any(), gomock.Any()).
					Return(admin.User{ID: eventUser, Username: "ada", Email: secretMail, Version: 5}, nil)

				audit := &auditRecorder{}
				_, err := newUsers(t, store, admin.WithAudit(audit.sink)).
					SetPassword(actorCtx(t), eventUser, 4, []byte(goodPassword))
				require.NoError(t, err)

				changes := audit.all()
				require.Len(t, changes, 1)

				return changes[0]
			},
			assert: func(t *testing.T, v any) {
				c, ok := v.(admin.Change)
				require.True(t, ok)
				assert.Equal(t, event.AuthnPasswordChange, c.Action)
				assert.Equal(t, "admin-1", c.Actor)
				assert.Equal(t, string(eventUser), c.Target)
				require.IsType(t, admin.User{}, c.Before)
				require.IsType(t, admin.User{}, c.After)
				assert.Equal(t, int64(4), c.Before.(admin.User).Version)
				assert.Equal(t, int64(5), c.After.(admin.User).Version)

				for _, rec := range []any{c.Before, c.After} {
					noBytes(t, rec)
					assert.NotContains(t, fmt.Sprintf("%+v", rec), string(hash))
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.value(t))
		})
	}
}

// TestAudit_Delivers pins each service's before and after records, read only
// when an audit sink is configured.
func TestAudit_Delivers(t *testing.T) {
	t.Parallel()

	mail := secretMail
	display := "Sales (Partner)"
	before := admin.User{ID: eventUser, Email: "old@example.com", Version: 4, Attributes: map[string]string{"a": "1"}}
	after := admin.User{ID: eventUser, Email: secretMail, Version: 5, Attributes: map[string]string{"a": "1"}}
	leadView := admin.Grant{Group: "crm", Resource: "lead", Privilege: "view", Granted: true}
	leadUpdate := admin.Grant{Group: "crm", Resource: "lead", Privilege: "update", Granted: true, Scope: identity.ScopeOwn}

	type testCase struct {
		name   string
		call   func(t *testing.T, ctrl *gomock.Controller, opts ...admin.Option) error
		assert func(t *testing.T, c admin.Change)
	}

	cases := []testCase{
		{
			name: "user update reads the user first",
			call: func(t *testing.T, ctrl *gomock.Controller, opts ...admin.Option) error {
				store := NewMockUserStore(ctrl)
				gomock.InOrder(
					store.EXPECT().GetUser(gomock.Any(), eventUser).Return(before, nil),
					store.EXPECT().UpdateUser(gomock.Any(), eventUser, int64(4), gomock.Any()).Return(after, nil),
				)

				var uo []admin.UsersOption
				for _, o := range opts {
					uo = append(uo, o)
				}

				_, err := newUsers(t, store, uo...).Update(actorCtx(t), eventUser, 4, admin.UserChange{Email: &mail})

				return err
			},
			assert: func(t *testing.T, c admin.Change) {
				assert.Equal(t, event.UserUpdated, c.Action)
				assert.Equal(t, before, c.Before)
				assert.Equal(t, after, c.After)
			},
		},
		{
			name: "user creation has no before",
			call: func(t *testing.T, ctrl *gomock.Controller, opts ...admin.Option) error {
				store := NewMockUserStore(ctrl)
				store.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(after, nil)

				var uo []admin.UsersOption
				for _, o := range opts {
					uo = append(uo, o)
				}

				_, err := newUsers(t, store, uo...).Create(actorCtx(t), admin.NewUser{Username: "ada"})

				return err
			},
			assert: func(t *testing.T, c admin.Change) {
				assert.Equal(t, event.UserCreated, c.Action)
				assert.Nil(t, c.Before)
				assert.Equal(t, after, c.After)
			},
		},
		{
			name: "user deletion has no after",
			call: func(t *testing.T, ctrl *gomock.Controller, opts ...admin.Option) error {
				store := NewMockUserStore(ctrl)
				store.EXPECT().GetUser(gomock.Any(), eventUser).Return(before, nil)
				store.EXPECT().DeleteUser(gomock.Any(), eventUser, int64(4)).Return(nil)

				var uo []admin.UsersOption
				for _, o := range opts {
					uo = append(uo, o)
				}

				return newUsers(t, store, uo...).Delete(actorCtx(t), eventUser, 4)
			},
			assert: func(t *testing.T, c admin.Change) {
				assert.Equal(t, before, c.Before)
				assert.Nil(t, c.After)
			},
		},
		{
			name: "role update",
			call: func(t *testing.T, ctrl *gomock.Controller, opts ...admin.Option) error {
				store := NewMockRoleStore(ctrl)
				store.EXPECT().GetRole(gomock.Any(), "sales").Return(admin.Role{Name: "sales", DisplayName: "Sales", Version: 2}, nil)
				store.EXPECT().UpdateRole(gomock.Any(), "sales", int64(2), gomock.Any()).
					Return(admin.Role{Name: "sales", DisplayName: display, Version: 3}, nil)

				var ro []admin.RolesOption
				for _, o := range opts {
					ro = append(ro, o)
				}

				r, err := admin.NewRoles(store, ro...)
				require.NoError(t, err)

				_, err = r.Update(actorCtx(t), "sales", 2, admin.RoleChange{DisplayName: &display})

				return err
			},
			assert: func(t *testing.T, c admin.Change) {
				assert.Equal(t, event.AuthzAdmin, c.Action)
				assert.Equal(t, "sales", c.Target)
				assert.Equal(t, admin.Role{Name: "sales", DisplayName: "Sales", Version: 2}, c.Before)
				assert.Equal(t, admin.Role{Name: "sales", DisplayName: display, Version: 3}, c.After)
			},
		},
		{
			name: "grant replacement reads the grants before and after",
			call: func(t *testing.T, ctrl *gomock.Controller, opts ...admin.Option) error {
				store := NewMockGrantStore(ctrl)
				gomock.InOrder(
					store.EXPECT().GetGrants(gomock.Any(), "sales").Return([]admin.Grant{leadView}, int64(4), nil),
					store.EXPECT().ReplaceGrants(gomock.Any(), "sales", int64(4), gomock.Any()).Return(int64(5), nil),
					store.EXPECT().GetGrants(gomock.Any(), "sales").Return([]admin.Grant{leadUpdate}, int64(5), nil),
				)

				var gopts []admin.GrantsOption
				for _, o := range opts {
					gopts = append(gopts, o)
				}

				g, err := admin.NewGrants(store, crmCatalogue(t), gopts...)
				require.NoError(t, err)

				_, err = g.Replace(actorCtx(t), "sales", 4, admin.ResourceGrants{Group: "crm", Resource: "lead",
					Grants: []admin.Grant{{Privilege: "update", Granted: true, Scope: identity.ScopeOwn}}})

				return err
			},
			assert: func(t *testing.T, c admin.Change) {
				assert.Equal(t, []admin.Grant{leadView}, c.Before)
				assert.Equal(t, []admin.Grant{leadUpdate}, c.After)
			},
		},
		{
			name: "grant replacement whose after read fails still delivers",
			call: func(t *testing.T, ctrl *gomock.Controller, opts ...admin.Option) error {
				store := NewMockGrantStore(ctrl)
				gomock.InOrder(
					store.EXPECT().GetGrants(gomock.Any(), "sales").Return([]admin.Grant{leadView}, int64(4), nil),
					store.EXPECT().ReplaceGrants(gomock.Any(), "sales", int64(4), gomock.Any()).Return(int64(5), nil),
					store.EXPECT().GetGrants(gomock.Any(), "sales").Return(nil, int64(0), errStorage),
				)

				var gopts []admin.GrantsOption
				for _, o := range opts {
					gopts = append(gopts, o)
				}

				g, err := admin.NewGrants(store, crmCatalogue(t), gopts...)
				require.NoError(t, err)

				_, err = g.Replace(actorCtx(t), "sales", 4, admin.ResourceGrants{Group: "crm", Resource: "lead"})

				return err
			},
			assert: func(t *testing.T, c admin.Change) {
				assert.Equal(t, []admin.Grant{leadView}, c.Before)
				assert.Nil(t, c.After)
			},
		},
		{
			name: "grant replacement whose after read shows a later version delivers no after",
			call: func(t *testing.T, ctrl *gomock.Controller, opts ...admin.Option) error {
				store := NewMockGrantStore(ctrl)
				gomock.InOrder(
					store.EXPECT().GetGrants(gomock.Any(), "sales").Return([]admin.Grant{leadView}, int64(4), nil),
					store.EXPECT().ReplaceGrants(gomock.Any(), "sales", int64(4), gomock.Any()).Return(int64(5), nil),
					store.EXPECT().GetGrants(gomock.Any(), "sales").Return([]admin.Grant{leadUpdate}, int64(6), nil),
				)

				var gopts []admin.GrantsOption
				for _, o := range opts {
					gopts = append(gopts, o)
				}

				g, err := admin.NewGrants(store, crmCatalogue(t), gopts...)
				require.NoError(t, err)

				_, err = g.Replace(actorCtx(t), "sales", 4, admin.ResourceGrants{Group: "crm", Resource: "lead"})

				return err
			},
			assert: func(t *testing.T, c admin.Change) {
				assert.Equal(t, []admin.Grant{leadView}, c.Before)
				assert.Nil(t, c.After)
			},
		},
		{
			name: "assignment whose after read shows a later version delivers no after",
			call: func(t *testing.T, ctrl *gomock.Controller, opts ...admin.Option) error {
				store := NewMockAssignmentStore(ctrl)
				sales := &identity.AssignedRole{ID: "g-1", Name: "sales"}
				gomock.InOrder(
					store.EXPECT().ListAssignments(gomock.Any(), eventUser).Return(nil, int64(4), nil),
					store.EXPECT().AddAssignment(gomock.Any(), eventUser, int64(4), gomock.Any()).Return(int64(5), nil),
					store.EXPECT().ListAssignments(gomock.Any(), eventUser).Return([]*identity.AssignedRole{sales}, int64(7), nil),
				)

				var ao []admin.AssignmentsOption
				for _, o := range opts {
					ao = append(ao, o)
				}

				a, err := admin.NewAssignments(store, ao...)
				require.NoError(t, err)

				_, err = a.Add(actorCtx(t), eventUser, 4, admin.Assignment{Role: "sales"})

				return err
			},
			assert: func(t *testing.T, c admin.Change) {
				assert.Equal(t, []identity.AssignedRole{}, c.Before)
				assert.Nil(t, c.After)
			},
		},
		{
			name: "assignment added",
			call: func(t *testing.T, ctrl *gomock.Controller, opts ...admin.Option) error {
				store := NewMockAssignmentStore(ctrl)
				sales := &identity.AssignedRole{ID: "g-1", Name: "sales", Primary: true}
				gomock.InOrder(
					store.EXPECT().ListAssignments(gomock.Any(), eventUser).Return(nil, int64(4), nil),
					store.EXPECT().AddAssignment(gomock.Any(), eventUser, int64(4), gomock.Any()).Return(int64(5), nil),
					store.EXPECT().ListAssignments(gomock.Any(), eventUser).Return([]*identity.AssignedRole{sales}, int64(5), nil),
				)

				var ao []admin.AssignmentsOption
				for _, o := range opts {
					ao = append(ao, o)
				}

				a, err := admin.NewAssignments(store, ao...)
				require.NoError(t, err)

				_, err = a.Add(actorCtx(t), eventUser, 4, admin.Assignment{Role: "sales", Primary: true})

				return err
			},
			assert: func(t *testing.T, c admin.Change) {
				assert.Equal(t, event.AuthzChange, c.Action)
				assert.Equal(t, []identity.AssignedRole{}, c.Before)
				assert.Equal(t, []identity.AssignedRole{{ID: "g-1", Name: "sales", Primary: true}}, c.After)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			audit := &auditRecorder{}
			require.NoError(t, tc.call(t, gomock.NewController(t), admin.WithAudit(audit.sink)))

			changes := audit.all()
			require.Len(t, changes, 1)
			assert.Equal(t, "admin-1", changes[0].Actor)
			tc.assert(t, changes[0])
		})
	}
}

// TestAudit_RecordIsACopy pins that an audit sink changing the record it was
// given does not change what the caller received.
func TestAudit_RecordIsACopy(t *testing.T) {
	t.Parallel()

	store := NewMockUserStore(gomock.NewController(t))
	store.EXPECT().CreateUser(gomock.Any(), gomock.Any()).
		Return(admin.User{ID: eventUser, Attributes: map[string]string{"phone": "1"}}, nil)

	sink := func(_ context.Context, c admin.Change) error {
		after, ok := c.After.(admin.User)
		if ok {
			after.Attributes["phone"] = "changed"
		}

		return nil
	}

	got, err := newUsers(t, store, admin.WithAudit(sink)).Create(actorCtx(t), admin.NewUser{Username: "ada"})
	require.NoError(t, err)
	assert.Equal(t, "1", got.Attributes["phone"])
}

// syncBuffer is a bytes.Buffer safe for the logger's concurrent writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func TestAudit_SinkFailureLogged(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		sink admin.AuditSink
	}

	cases := []testCase{
		{name: "error", sink: func(context.Context, admin.Change) error {
			return errors.New("audit store refused " + secretMail)
		}},
		{name: "panic", sink: func(context.Context, admin.Change) error { panic("audit down " + secretMail) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mail := secretMail
			store := NewMockUserStore(gomock.NewController(t))
			store.EXPECT().GetUser(gomock.Any(), eventUser).Return(admin.User{ID: eventUser, Email: "old@example.com", Version: 4}, nil)
			store.EXPECT().UpdateUser(gomock.Any(), eventUser, int64(4), gomock.Any()).
				Return(admin.User{ID: eventUser, Email: secretMail, Version: 5}, nil)

			logs := &syncBuffer{}
			logger := slog.New(slog.NewJSONHandler(logs, nil))

			got, err := newUsers(t, store, admin.WithAudit(tc.sink), admin.WithLogger(logger)).
				Update(actorCtx(t), eventUser, 4, admin.UserChange{Email: &mail})
			require.NoError(t, err)
			assert.Equal(t, int64(5), got.Version)

			out := logs.String()
			assert.Contains(t, out, `"action":"user_updated"`)
			assert.Contains(t, out, `"target":"`+string(eventUser)+`"`)
			assert.NotContains(t, out, secretMail)
			assert.NotContains(t, out, "old@example.com")
		})
	}
}
