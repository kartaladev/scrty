package admin_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
)

func TestCount(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		plain  bool // the store lacks UserPager
		filter admin.UserFilter
		setup  func(s pagerStore)
		assert func(t *testing.T, n int64, err error)
	}

	tooLong := strings.Repeat("a", admin.MaxSearchBytes+1)
	invalid := func(t *testing.T, n int64, err error) {
		require.ErrorIs(t, err, admin.ErrInvalidInput)
		assert.NotErrorIs(t, err, admin.ErrConfig)
		assert.Zero(t, n)
	}
	noCall := func(pagerStore) {}

	cases := []testCase{
		{
			name:   "count beside a page",
			filter: admin.UserFilter{Search: "ada", Role: "editor", PageSize: 10, Offset: 20, Cursor: "x"},
			setup: func(s pagerStore) {
				// The page size, offset and cursor are the page's, not the count's; the count's query holds the
				// filters alone, and an undecodable cursor does not refuse it.
				s.MockUserPager.EXPECT().
					CountUsers(gomock.Any(), admin.UserQuery{Search: "ada", Role: "editor"}).
					Return(int64(999), nil)
			},
			assert: func(t *testing.T, n int64, err error) {
				require.NoError(t, err)
				assert.EqualValues(t, 999, n)
			},
		},
		{
			name:   "an offset beyond the maximum does not refuse a count",
			filter: admin.UserFilter{Offset: 1_000_000},
			setup: func(s pagerStore) {
				s.MockUserPager.EXPECT().CountUsers(gomock.Any(), gomock.Any()).Return(int64(3), nil)
			},
			assert: func(t *testing.T, n int64, err error) {
				require.NoError(t, err)
				assert.EqualValues(t, 3, n)
			},
		},
		{name: "invalid search", filter: admin.UserFilter{Search: tooLong}, setup: noCall, assert: invalid},
		{name: "invalid role", filter: admin.UserFilter{Role: tooLong}, setup: noCall, assert: invalid},
		{
			name:   "invalid attribute",
			filter: admin.UserFilter{Attribute: &admin.AttributeMatch{Name: "", Value: "v"}}, setup: noCall, assert: invalid,
		},
		{
			name: "invalid search on a store without support is the caller's mistake", plain: true,
			filter: admin.UserFilter{Search: tooLong}, setup: noCall, assert: invalid,
		},
		{
			name: "store without support", plain: true, filter: admin.UserFilter{Search: "ada"}, setup: noCall,
			assert: func(t *testing.T, n int64, err error) {
				require.ErrorIs(t, err, admin.ErrConfig)
				assert.Zero(t, n)
			},
		},
		{
			name: "negative count",
			setup: func(s pagerStore) {
				s.MockUserPager.EXPECT().CountUsers(gomock.Any(), gomock.Any()).Return(int64(-1), nil)
			},
			assert: func(t *testing.T, n int64, err error) {
				require.Error(t, err)
				noAdminReason(t, err)
				assert.Zero(t, n)
			},
		},
		{
			name: "store error matches no administration reason",
			setup: func(s pagerStore) {
				s.MockUserPager.EXPECT().CountUsers(gomock.Any(), gomock.Any()).Return(int64(0), errPager)
			},
			assert: func(t *testing.T, n int64, err error) {
				require.ErrorIs(t, err, errPager)
				noAdminReason(t, err)
				assert.Zero(t, n)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newPagerStore(gomock.NewController(t))
			tc.setup(s)

			n, err := newUsers(t, storeFor(s, tc.plain)).Count(t.Context(), tc.filter)
			tc.assert(t, n, err)
		})
	}
}
