package admin_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
)

// renamingStore is a user store that also implements admin.UsernameUpdater.
// Each mock keeps its own expectations; set them through the named fields.
type renamingStore struct {
	*MockUserStore
	*MockUsernameUpdater
}

func newRenamingStore(ctrl *gomock.Controller) renamingStore {
	return renamingStore{MockUserStore: NewMockUserStore(ctrl), MockUsernameUpdater: NewMockUsernameUpdater(ctrl)}
}

var errBoom = errors.New("session store unavailable")

const (
	oldUsername = "ada"
	newUsername = "ada.lovelace"
)

// adaBefore is the stored user a rename replaces; adaRenamed is the user the
// store returns after the rename, verified so the email keeps its verification.
var (
	adaBefore  = admin.User{ID: eventUser, Username: oldUsername, Email: secretMail, EmailVerifiedAt: testNow, Version: 4}
	adaRenamed = admin.User{ID: eventUser, Username: newUsername, Email: secretMail, EmailVerifiedAt: testNow, Version: 5}
)

func ptr[T any](v T) *T { return &v }

// noValues asserts that text carries neither username nor the email.
func noValues(t *testing.T, text string) {
	t.Helper()

	for _, v := range []string{oldUsername, newUsername, secretMail} {
		assert.NotContains(t, text, v)
	}
}

func TestUpdate_UsernameValidation(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		username string
		setup    func(s renamingStore)
		assert   func(t *testing.T, u admin.User, err error)
	}

	refused := func(t *testing.T, _ admin.User, err error) {
		require.ErrorIs(t, err, admin.ErrInvalidInput)
		assert.NotErrorIs(t, err, admin.ErrConfig)
		assert.Contains(t, err.Error(), "username", "the refusal names the username, not an empty change")
		noValues(t, err.Error())
	}
	noCall := func(renamingStore) {}

	cases := []testCase{
		{name: "blank", username: "", setup: noCall, assert: refused},
		{name: "only white space", username: "   ", setup: noCall, assert: refused},
		{name: "leading white space", username: " ada", setup: noCall, assert: refused},
		{name: "trailing white space", username: "ada ", setup: noCall, assert: refused},
		{name: "NUL", username: "ada\x00", setup: noCall, assert: refused},
		{name: "other control character", username: "ada\x07", setup: noCall, assert: refused},
		{name: "invalid UTF-8", username: "ada\xff", setup: noCall, assert: refused},
		{name: "over MaxTextBytes", username: strings.Repeat("a", admin.MaxTextBytes+1), setup: noCall, assert: refused},
		{
			name: "a username alone is a change", username: newUsername,
			setup: func(s renamingStore) {
				s.MockUsernameUpdater.EXPECT().
					UpdateUserRenaming(gomock.Any(), eventUser, int64(4), admin.UserChange{Username: ptr(newUsername)}).
					Return(adaRenamed, true, nil).Times(1)
			},
			assert: func(t *testing.T, u admin.User, err error) {
				require.NoError(t, err)
				assert.Equal(t, newUsername, u.Username)
			},
		},
		{
			name: "exactly MaxTextBytes is accepted", username: strings.Repeat("a", admin.MaxTextBytes),
			setup: func(s renamingStore) {
				s.MockUsernameUpdater.EXPECT().UpdateUserRenaming(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(adaRenamed, true, nil).Times(1)
			},
			assert: func(t *testing.T, _ admin.User, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newRenamingStore(gomock.NewController(t))
			tc.setup(store)

			u, err := newUsers(t, store).Update(actorCtx(t), eventUser, 4, admin.UserChange{Username: &tc.username})
			tc.assert(t, u, err)
		})
	}
}

func TestUpdate_RenameRouting(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  func(ctrl *gomock.Controller) admin.UserStore
		change admin.UserChange
		assert func(t *testing.T, u admin.User, err error, audits []admin.Change)
	}

	// plainStore implements UserStore only, and must not be called at all.
	plainStore := func(ctrl *gomock.Controller) admin.UserStore {
		s := NewMockUserStore(ctrl)
		s.EXPECT().GetUser(gomock.Any(), gomock.Any()).Times(0)
		s.EXPECT().UpdateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		return s
	}

	cases := []testCase{
		{
			name: "store without support refuses before any store call", store: plainStore,
			change: admin.UserChange{Username: ptr(newUsername), Name: ptr("Ada")},
			assert: func(t *testing.T, _ admin.User, err error, audits []admin.Change) {
				require.ErrorIs(t, err, admin.ErrConfig)
				for _, r := range reasons {
					assert.NotErrorIs(t, err, r)
				}
				assert.NotErrorIs(t, err, admin.ErrSessionsNotRevoked)
				noValues(t, err.Error())
				assert.Empty(t, audits)
			},
		},
		{
			name: "invalid username without support is invalid input", store: plainStore,
			change: admin.UserChange{Username: ptr(" ada")},
			assert: func(t *testing.T, _ admin.User, err error, _ []admin.Change) {
				require.ErrorIs(t, err, admin.ErrInvalidInput)
				assert.NotErrorIs(t, err, admin.ErrConfig)
			},
		},
		{
			name: "other fields on a store without support", change: admin.UserChange{Name: ptr("Ada L.")},
			store: func(ctrl *gomock.Controller) admin.UserStore {
				s := NewMockUserStore(ctrl)
				s.EXPECT().GetUser(gomock.Any(), eventUser).Return(adaBefore, nil)
				s.EXPECT().UpdateUser(gomock.Any(), eventUser, int64(4), admin.UserChange{Name: ptr("Ada L.")}).
					Return(adaBefore, nil).Times(1)

				return s
			},
			assert: func(t *testing.T, _ admin.User, err error, audits []admin.Change) {
				require.NoError(t, err)
				assert.Len(t, audits, 1)
			},
		},
		{
			name: "other fields on a store with support go to UpdateUser", change: admin.UserChange{Name: ptr("Ada L.")},
			store: func(ctrl *gomock.Controller) admin.UserStore {
				s := newRenamingStore(ctrl)
				s.MockUserStore.EXPECT().GetUser(gomock.Any(), eventUser).Return(adaBefore, nil)
				s.MockUserStore.EXPECT().UpdateUser(gomock.Any(), eventUser, int64(4), gomock.Any()).Return(adaBefore, nil).Times(1)
				s.MockUsernameUpdater.EXPECT().UpdateUserRenaming(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				return s
			},
			assert: func(t *testing.T, _ admin.User, err error, _ []admin.Change) { require.NoError(t, err) },
		},
		{
			name: "rename routes to UpdateUserRenaming", change: admin.UserChange{Username: ptr(newUsername), Name: ptr("Ada")},
			store: func(ctrl *gomock.Controller) admin.UserStore {
				s := newRenamingStore(ctrl)
				s.MockUserStore.EXPECT().GetUser(gomock.Any(), eventUser).Return(adaBefore, nil)
				s.MockUserStore.EXPECT().UpdateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				s.MockUsernameUpdater.EXPECT().
					UpdateUserRenaming(gomock.Any(), eventUser, int64(4), admin.UserChange{Username: ptr(newUsername), Name: ptr("Ada")}).
					Return(adaRenamed, true, nil).Times(1)

				return s
			},
			assert: func(t *testing.T, u admin.User, err error, _ []admin.Change) {
				require.NoError(t, err)
				assert.Equal(t, adaRenamed, u)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			audit := &auditRecorder{}
			u := newUsers(t, tc.store(gomock.NewController(t)), admin.WithAudit(audit.sink))

			got, err := u.Update(actorCtx(t), eventUser, 4, tc.change)
			tc.assert(t, got, err, audit.all())
		})
	}
}

func TestUpdate_RenameReported(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		change admin.UserChange
		setup  func(s renamingStore)
		assert func(t *testing.T, err error, events []event.Event, audits []admin.Change)
	}

	renames := func(updated admin.User, err error) func(s renamingStore) {
		return func(s renamingStore) {
			s.MockUserStore.EXPECT().GetUser(gomock.Any(), eventUser).Return(adaBefore, nil)
			s.MockUsernameUpdater.EXPECT().UpdateUserRenaming(gomock.Any(), eventUser, int64(4), gomock.Any()).
				Return(updated, err == nil, err)
		}
	}

	cases := []testCase{
		{
			name: "username alone", change: admin.UserChange{Username: ptr(newUsername)}, setup: renames(adaRenamed, nil),
			assert: func(t *testing.T, err error, events []event.Event, _ []admin.Change) {
				require.NoError(t, err)
				require.Len(t, events, 1)
				assert.Equal(t, []string{"username"}, events[0].Changed)
			},
		},
		{
			name: "username and email, the email still verified", change: admin.UserChange{Username: ptr(newUsername), Email: ptr(secretMail)},
			setup: renames(adaRenamed, nil),
			assert: func(t *testing.T, err error, events []event.Event, audits []admin.Change) {
				require.NoError(t, err)
				require.Len(t, events, 1)
				assert.Equal(t, event.UserUpdated, events[0].Name)
				assert.Equal(t, string(eventUser), events[0].Target)
				assert.Equal(t, "admin-1", events[0].Actor)
				assert.Equal(t, []string{"username", "email"}, events[0].Changed)
				noValues(t, fmt.Sprintf("%+v", events[0]))

				require.Len(t, audits, 1)
				assert.Equal(t, adaBefore, audits[0].Before)
				assert.Equal(t, adaRenamed, audits[0].After)
			},
		},
		{
			name: "username and email, the email left unverified", change: admin.UserChange{Username: ptr(newUsername), Email: ptr(secretMail)},
			setup: renames(func() admin.User { u := adaRenamed; u.EmailVerifiedAt = time.Time{}; return u }(), nil),
			assert: func(t *testing.T, err error, events []event.Event, _ []admin.Change) {
				require.NoError(t, err)
				require.Len(t, events, 1)
				assert.Equal(t, []string{"username", "email", "email_verified_at"}, events[0].Changed)
			},
		},
		{
			name: "refused rename reports nothing", change: admin.UserChange{Username: ptr(newUsername)},
			setup: renames(admin.User{}, admin.AlreadyExistsError{Field: admin.FieldUsername}),
			assert: func(t *testing.T, err error, events []event.Event, audits []admin.Change) {
				var ae admin.AlreadyExistsError
				require.ErrorAs(t, err, &ae)
				assert.Equal(t, admin.FieldUsername, ae.Field)
				noValues(t, err.Error())
				assert.Empty(t, events)
				assert.Empty(t, audits)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newRenamingStore(gomock.NewController(t))
			tc.setup(store)

			events, audit := &eventRecorder{}, &auditRecorder{}
			u := newUsers(t, store, admin.WithEventSink(events.sink), admin.WithAudit(audit.sink))

			_, err := u.Update(actorCtx(t), eventUser, 4, tc.change)
			tc.assert(t, err, events.all(), audit.all())
		})
	}
}

func TestUpdate_SessionRevocation(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// revoke wires a MockSessionRevoker; false leaves the default.
		revoke bool
		change admin.UserChange
		// setup sets the store's and the revoker's expectations; cancel
		// cancels the context Update runs on.
		setup  func(s renamingStore, r *MockSessionRevoker, cancel context.CancelFunc)
		assert func(t *testing.T, u admin.User, err error, events []event.Event)
	}

	rename := admin.UserChange{Username: ptr(newUsername)}

	cases := []testCase{
		{
			name: "default revokes nothing", change: rename,
			setup: func(s renamingStore, _ *MockSessionRevoker, _ context.CancelFunc) {
				s.MockUsernameUpdater.EXPECT().UpdateUserRenaming(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(adaRenamed, true, nil)
			},
			assert: func(t *testing.T, u admin.User, err error, events []event.Event) {
				require.NoError(t, err)
				assert.Equal(t, adaRenamed, u)
				assert.Len(t, events, 1)
			},
		},
		{
			name: "renamed revokes the user's sessions once", revoke: true, change: rename,
			setup: func(s renamingStore, r *MockSessionRevoker, _ context.CancelFunc) {
				gomock.InOrder(
					s.MockUsernameUpdater.EXPECT().UpdateUserRenaming(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
						Return(adaRenamed, true, nil),
					r.EXPECT().DeleteByUser(gomock.Any(), eventUser).Return(nil).Times(1),
				)
			},
			assert: func(t *testing.T, u admin.User, err error, events []event.Event) {
				require.NoError(t, err)
				assert.Equal(t, adaRenamed, u)
				assert.Len(t, events, 1)
			},
		},
		{
			name: "current username re-sent revokes nothing", revoke: true,
			change: admin.UserChange{Username: ptr(oldUsername), Name: ptr("Ada L.")},
			setup: func(s renamingStore, r *MockSessionRevoker, _ context.CancelFunc) {
				s.MockUsernameUpdater.EXPECT().UpdateUserRenaming(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(adaBefore, false, nil)
				r.EXPECT().DeleteByUser(gomock.Any(), gomock.Any()).Times(0)
			},
			assert: func(t *testing.T, _ admin.User, err error, events []event.Event) {
				require.NoError(t, err)
				require.Len(t, events, 1)
				assert.Equal(t, []string{"username", "name"}, events[0].Changed)
			},
		},
		{
			name: "no username in the update revokes nothing", revoke: true, change: admin.UserChange{Name: ptr("Ada L.")},
			setup: func(s renamingStore, r *MockSessionRevoker, _ context.CancelFunc) {
				s.MockUserStore.EXPECT().UpdateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(adaBefore, nil)
				r.EXPECT().DeleteByUser(gomock.Any(), gomock.Any()).Times(0)
			},
			assert: func(t *testing.T, _ admin.User, err error, _ []event.Event) { require.NoError(t, err) },
		},
		{
			name: "refused rename revokes nothing", revoke: true, change: rename,
			setup: func(s renamingStore, r *MockSessionRevoker, _ context.CancelFunc) {
				s.MockUsernameUpdater.EXPECT().UpdateUserRenaming(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(admin.User{}, false, admin.AlreadyExistsError{Field: admin.FieldUsername})
				r.EXPECT().DeleteByUser(gomock.Any(), gomock.Any()).Times(0)
			},
			assert: func(t *testing.T, _ admin.User, err error, events []event.Event) {
				require.ErrorIs(t, err, admin.ErrAlreadyExists)
				assert.NotErrorIs(t, err, admin.ErrSessionsNotRevoked)
				assert.Empty(t, events)
			},
		},
		{
			name: "stale rename revokes nothing", revoke: true, change: rename,
			setup: func(s renamingStore, r *MockSessionRevoker, _ context.CancelFunc) {
				s.MockUsernameUpdater.EXPECT().UpdateUserRenaming(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(admin.User{}, false, admin.ErrStaleUpdate)
				r.EXPECT().DeleteByUser(gomock.Any(), gomock.Any()).Times(0)
			},
			assert: func(t *testing.T, _ admin.User, err error, events []event.Event) {
				require.ErrorIs(t, err, admin.ErrStaleUpdate)
				assert.Empty(t, events)
			},
		},
		{
			name: "revocation fails: user returned, event emitted", revoke: true, change: rename,
			setup: func(s renamingStore, r *MockSessionRevoker, _ context.CancelFunc) {
				s.MockUsernameUpdater.EXPECT().UpdateUserRenaming(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(adaRenamed, true, nil)
				r.EXPECT().DeleteByUser(gomock.Any(), eventUser).Return(errBoom).Times(1)
			},
			assert: func(t *testing.T, u admin.User, err error, events []event.Event) {
				require.ErrorIs(t, err, admin.ErrSessionsNotRevoked)
				require.ErrorIs(t, err, errBoom)
				for _, r := range reasons {
					if errors.Is(r, admin.ErrSessionsNotRevoked) {
						continue // the one reason this failure matches
					}

					assert.NotErrorIs(t, err, r)
				}
				noValues(t, err.Error())
				assert.Equal(t, adaRenamed, u)
				require.Len(t, events, 1)
				assert.Equal(t, []string{"username"}, events[0].Changed)
			},
		},
		{
			name: "context cancelled after commit", revoke: true, change: rename,
			setup: func(s renamingStore, r *MockSessionRevoker, cancel context.CancelFunc) {
				s.MockUsernameUpdater.EXPECT().UpdateUserRenaming(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(context.Context, identity.UserID, int64, admin.UserChange) (admin.User, bool, error) {
						cancel()
						return adaRenamed, true, nil
					})
				r.EXPECT().DeleteByUser(gomock.Any(), eventUser).
					DoAndReturn(func(ctx context.Context, _ identity.UserID) error { return ctx.Err() }).Times(1)
			},
			assert: func(t *testing.T, u admin.User, err error, events []event.Event) {
				require.ErrorIs(t, err, admin.ErrSessionsNotRevoked)
				require.ErrorIs(t, err, context.Canceled)
				assert.Equal(t, adaRenamed, u)
				assert.Len(t, events, 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			store := newRenamingStore(ctrl)
			revoker := NewMockSessionRevoker(ctrl)

			ctx, cancel := context.WithCancel(actorCtx(t))
			defer cancel()

			tc.setup(store, revoker, cancel)

			events := &eventRecorder{}
			opts := []admin.UsersOption{admin.WithEventSink(events.sink)}
			if tc.revoke {
				opts = append(opts, admin.WithSessionRevocation(revoker))
			}

			u, err := newUsers(t, store, opts...).Update(ctx, eventUser, 4, tc.change)
			tc.assert(t, u, err, events.all())
		})
	}
}

func TestNewUsers_SessionRevocationWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  func(ctrl *gomock.Controller) admin.UserStore
		option func(ctrl *gomock.Controller) admin.UsersOption
		assert func(t *testing.T, u *admin.Users, err error)
	}

	renaming := func(ctrl *gomock.Controller) admin.UserStore { return newRenamingStore(ctrl) }
	plain := func(ctrl *gomock.Controller) admin.UserStore { return NewMockUserStore(ctrl) }
	refused := func(t *testing.T, u *admin.Users, err error) {
		require.ErrorIs(t, err, admin.ErrConfig)
		assert.Nil(t, u)
	}

	cases := []testCase{
		{
			name: "a revoker over a renaming store", store: renaming,
			option: func(ctrl *gomock.Controller) admin.UsersOption {
				return admin.WithSessionRevocation(NewMockSessionRevoker(ctrl))
			},
			assert: func(t *testing.T, u *admin.Users, err error) {
				require.NoError(t, err)
				assert.NotNil(t, u)
			},
		},
		{
			name: "nil revoker", store: renaming,
			option: func(*gomock.Controller) admin.UsersOption { return admin.WithSessionRevocation(nil) },
			assert: refused,
		},
		{
			name: "typed-nil revoker", store: renaming,
			option: func(*gomock.Controller) admin.UsersOption {
				return admin.WithSessionRevocation((*MockSessionRevoker)(nil))
			},
			assert: refused,
		},
		{
			name: "revoker over a store that cannot rename", store: plain,
			option: func(ctrl *gomock.Controller) admin.UsersOption {
				return admin.WithSessionRevocation(NewMockSessionRevoker(ctrl))
			},
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			u, err := admin.NewUsers(tc.store(ctrl), tc.option(ctrl))
			tc.assert(t, u, err)
		})
	}
}
