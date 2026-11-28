package admin_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
)

// pagerStore is a user store that also implements admin.UserPager. Each mock
// keeps its own expectations; set them through the named fields.
type pagerStore struct {
	*MockUserStore
	*MockUserPager
}

func newPagerStore(ctrl *gomock.Controller) pagerStore {
	return pagerStore{MockUserStore: NewMockUserStore(ctrl), MockUserPager: NewMockUserPager(ctrl)}
}

var errPager = errors.New("page store unavailable")

// noAdminReason asserts that err matches none of the administration reasons.
func noAdminReason(t *testing.T, err error) {
	t.Helper()

	for _, reason := range []error{
		admin.ErrNotFound, admin.ErrAlreadyExists, admin.ErrStaleUpdate, admin.ErrInvalidInput,
		admin.ErrNoActor, admin.ErrConfig, admin.ErrStillAssigned, admin.ErrUnknownPrivilege,
	} {
		assert.NotErrorIs(t, err, reason)
	}
}

func usersN(n int) []admin.User {
	out := make([]admin.User, n)
	for i := range out {
		out[i] = admin.User{ID: identity.UserID("u"), Username: "user"}
	}

	return out
}

// storeFor returns the pager store, or only its UserStore half when plain.
func storeFor(s pagerStore, plain bool) admin.UserStore {
	if plain {
		return s.MockUserStore
	}

	return s
}

func TestList_OffsetValidation(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		plain  bool // the store lacks UserPager
		opts   []admin.UsersOption
		filter admin.UserFilter
		setup  func(s pagerStore)
		assert func(t *testing.T, page admin.UserPage, err error)
	}

	refused := func(t *testing.T, _ admin.UserPage, err error) {
		require.ErrorIs(t, err, admin.ErrInvalidInput)
		assert.NotErrorIs(t, err, admin.ErrConfig)
	}
	noCall := func(pagerStore) {}
	reaches := func(offset int) func(s pagerStore) {
		return func(s pagerStore) {
			s.MockUserPager.EXPECT().ListUsersFrom(gomock.Any(), gomock.Any(), offset).Return(nil, nil)
		}
	}
	ok := func(t *testing.T, _ admin.UserPage, err error) { assert.NoError(t, err) }

	cases := []testCase{
		{name: "negative offset", filter: admin.UserFilter{Offset: -1}, setup: noCall, assert: refused},
		{
			name:   "offset and cursor together",
			filter: admin.UserFilter{Offset: 10, Cursor: cursorOf(1, "ada", "u-1")}, setup: noCall, assert: refused,
		},
		{name: "offset beyond the maximum", filter: admin.UserFilter{Offset: 10_001}, setup: noCall, assert: refused},
		{
			// Validation precedes the capability check: a bound is the caller's mistake, not the wiring's.
			name: "offset beyond the maximum on a store without support", plain: true,
			filter: admin.UserFilter{Offset: 10_001}, setup: noCall, assert: refused,
		},
		{name: "offset at the maximum", filter: admin.UserFilter{Offset: 10_000}, setup: reaches(10_000), assert: ok},
		{
			name: "consumer maximum", opts: []admin.UsersOption{admin.WithMaxListOffset(50_000)},
			filter: admin.UserFilter{Offset: 40_000}, setup: reaches(40_000), assert: ok,
		},
		{
			name: "consumer maximum refuses beyond it", opts: []admin.UsersOption{admin.WithMaxListOffset(50)},
			filter: admin.UserFilter{Offset: 51}, setup: noCall, assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newPagerStore(gomock.NewController(t))
			tc.setup(s)

			page, err := newUsers(t, storeFor(s, tc.plain), tc.opts...).List(t.Context(), tc.filter)
			tc.assert(t, page, err)
		})
	}
}

func TestNewUsers_MaxListOffset(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		plain  bool
		opt    admin.UsersOption
		assert func(t *testing.T, u *admin.Users, err error)
	}

	config := func(t *testing.T, u *admin.Users, err error) {
		require.ErrorIs(t, err, admin.ErrConfig)
		assert.Nil(t, u)
	}
	built := func(t *testing.T, u *admin.Users, err error) {
		require.NoError(t, err)
		assert.NotNil(t, u)
	}

	cases := []testCase{
		{name: "negative maximum", opt: admin.WithMaxListOffset(-1), assert: config},
		{name: "over a store without UserPager", plain: true, opt: admin.WithMaxListOffset(100), assert: config},
		{name: "zero maximum allows only the first page", opt: admin.WithMaxListOffset(0), assert: built},
		{name: "the default needs no option, on a plain store", plain: true, opt: nil, assert: built},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newPagerStore(gomock.NewController(t))

			u, err := admin.NewUsers(storeFor(s, tc.plain), tc.opt)
			tc.assert(t, u, err)
		})
	}
}

func TestList_OffsetRouting(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		plain  bool
		filter admin.UserFilter
		setup  func(s pagerStore)
		assert func(t *testing.T, page admin.UserPage, err error)
	}

	cases := []testCase{
		{
			name:   "jump to a page",
			filter: admin.UserFilter{Offset: 100, PageSize: 50, Search: "ada"},
			setup: func(s pagerStore) {
				s.MockUserPager.EXPECT().
					ListUsersFrom(gomock.Any(), admin.UserQuery{Search: "ada", Limit: 50}, 100).
					Return(usersN(50), nil)
			},
			assert: func(t *testing.T, page admin.UserPage, err error) {
				require.NoError(t, err)
				assert.Len(t, page.Users, 50)
				assert.Empty(t, page.Next, "a page from an offset does not continue by cursor")
			},
		},
		{
			name:   "offset zero with a cursor continues the cursor listing",
			filter: admin.UserFilter{Cursor: cursorOf(1, "ada", "u-1"), PageSize: 2},
			setup: func(s pagerStore) {
				s.MockUserStore.EXPECT().
					ListUsers(gomock.Any(), admin.UserQuery{AfterUsername: "ada", AfterID: "u-1", Limit: 2}).
					Return(usersN(1), nil)
			},
			assert: func(t *testing.T, page admin.UserPage, err error) {
				require.NoError(t, err)
				assert.Len(t, page.Users, 1)
			},
		},
		{
			name: "offset zero on a store with support", filter: admin.UserFilter{PageSize: 2},
			setup: func(s pagerStore) {
				s.MockUserStore.EXPECT().ListUsers(gomock.Any(), admin.UserQuery{Limit: 2}).Return(usersN(2), nil)
			},
			assert: func(t *testing.T, page admin.UserPage, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, page.Next, "offset zero is the first page and carries Next")
			},
		},
		{
			name: "offset zero on a store without support", plain: true, filter: admin.UserFilter{PageSize: 2},
			setup: func(s pagerStore) {
				s.MockUserStore.EXPECT().ListUsers(gomock.Any(), admin.UserQuery{Limit: 2}).Return(usersN(2), nil)
			},
			assert: func(t *testing.T, page admin.UserPage, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, page.Next)
			},
		},
		{
			name: "store without support", plain: true, filter: admin.UserFilter{Offset: 50},
			setup: func(pagerStore) {},
			assert: func(t *testing.T, page admin.UserPage, err error) {
				require.ErrorIs(t, err, admin.ErrConfig)
				assert.NotErrorIs(t, err, admin.ErrInvalidInput)
				assert.Empty(t, page.Users)
			},
		},
		{
			name: "cursor listing on a store without support", plain: true,
			filter: admin.UserFilter{Cursor: cursorOf(1, "ada", "u-1"), PageSize: 5},
			setup: func(s pagerStore) {
				s.MockUserStore.EXPECT().ListUsers(gomock.Any(), gomock.Any()).Return(usersN(3), nil)
			},
			assert: func(t *testing.T, page admin.UserPage, err error) {
				require.NoError(t, err)
				assert.Len(t, page.Users, 3)
				assert.Empty(t, page.Next)
			},
		},
		{
			name: "oversized result is truncated", filter: admin.UserFilter{Offset: 5, PageSize: 50},
			setup: func(s pagerStore) {
				s.MockUserPager.EXPECT().ListUsersFrom(gomock.Any(), gomock.Any(), 5).Return(usersN(51), nil)
			},
			assert: func(t *testing.T, page admin.UserPage, err error) {
				require.NoError(t, err)
				assert.Len(t, page.Users, 50)
				assert.Empty(t, page.Next)
			},
		},
		{
			name: "store error matches no administration reason", filter: admin.UserFilter{Offset: 5},
			setup: func(s pagerStore) {
				s.MockUserPager.EXPECT().ListUsersFrom(gomock.Any(), gomock.Any(), 5).Return(nil, errPager)
			},
			assert: func(t *testing.T, page admin.UserPage, err error) {
				require.ErrorIs(t, err, errPager)
				noAdminReason(t, err)
				assert.Empty(t, page.Users)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newPagerStore(gomock.NewController(t))
			tc.setup(s)

			page, err := newUsers(t, storeFor(s, tc.plain)).List(t.Context(), tc.filter)
			tc.assert(t, page, err)
		})
	}
}
