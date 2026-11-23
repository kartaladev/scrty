package admin_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
)

func TestNewAssignments(t *testing.T) {
	t.Parallel()

	var nilStore *MockAssignmentStore

	_, err := admin.NewAssignments(nil)
	require.ErrorIs(t, err, admin.ErrConfig)

	_, err = admin.NewAssignments(nilStore)
	require.ErrorIs(t, err, admin.ErrConfig)
}

func TestAssignments(t *testing.T) {
	t.Parallel()

	const ada = identity.UserID("0192f1e2-3c4d-7e5f-8a9b-0c1d2e3f4a5b")

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		ctx    func(t *testing.T) context.Context
		setup  func(store *MockAssignmentStore)
		call   func(ctx context.Context, a *admin.Assignments) (int64, error)
		assert func(t *testing.T, version int64, err error)
	}

	add := func(as admin.Assignment) func(ctx context.Context, a *admin.Assignments) (int64, error) {
		return func(ctx context.Context, a *admin.Assignments) (int64, error) { return a.Add(ctx, ada, 3, as) }
	}
	invalidNoCall := func(t *testing.T, _ int64, err error) { require.ErrorIs(t, err, admin.ErrInvalidInput) }
	noCall := func(*MockAssignmentStore) {}

	cases := []testCase{
		{
			name: "primary grant with no dates",
			setup: func(store *MockAssignmentStore) {
				store.EXPECT().AddAssignment(gomock.Any(), ada, int64(3), admin.Assignment{Role: "sales", Primary: true}).Return(int64(4), nil)
			},
			call: add(admin.Assignment{Role: "sales", Primary: true}),
			assert: func(t *testing.T, version int64, err error) {
				require.NoError(t, err)
				assert.Equal(t, int64(4), version)
			},
		},
		{
			name: "end after start",
			setup: func(store *MockAssignmentStore) {
				store.EXPECT().AddAssignment(gomock.Any(), ada, int64(3), gomock.Any()).Return(int64(4), nil)
			},
			call:   add(admin.Assignment{Role: "audit", Start: start, End: start.Add(time.Hour)}),
			assert: func(t *testing.T, _ int64, err error) { require.NoError(t, err) },
		},
		{
			name: "end equal to start", setup: noCall, assert: invalidNoCall,
			call: add(admin.Assignment{Role: "audit", Start: start, End: start}),
		},
		{
			name: "end before start", setup: noCall, assert: invalidNoCall,
			call: add(admin.Assignment{Role: "audit", Start: start, End: start.Add(-time.Hour)}),
		},
		{
			name: "blank role", setup: noCall, assert: invalidNoCall,
			call: add(admin.Assignment{Role: ""}),
		},
		{
			name: "unknown role passes through",
			setup: func(store *MockAssignmentStore) {
				store.EXPECT().AddAssignment(gomock.Any(), ada, int64(3), gomock.Any()).Return(int64(0), admin.ErrNotFound)
			},
			call:   add(admin.Assignment{Role: "ghost"}),
			assert: func(t *testing.T, _ int64, err error) { require.ErrorIs(t, err, admin.ErrNotFound) },
		},
		{
			name: "no actor", setup: noCall,
			ctx:    func(t *testing.T) context.Context { return t.Context() },
			call:   add(admin.Assignment{Role: "sales"}),
			assert: func(t *testing.T, _ int64, err error) { require.ErrorIs(t, err, admin.ErrNoActor) },
		},
		{
			name: "no actor is refused before the input is checked", setup: noCall,
			ctx:    func(t *testing.T) context.Context { return t.Context() },
			call:   add(admin.Assignment{Role: ""}),
			assert: func(t *testing.T, _ int64, err error) { require.ErrorIs(t, err, admin.ErrNoActor) },
		},
		{
			name: "no actor with a blank grant", setup: noCall,
			ctx:    func(t *testing.T) context.Context { return t.Context() },
			call:   func(ctx context.Context, a *admin.Assignments) (int64, error) { return a.Remove(ctx, ada, 3, "") },
			assert: func(t *testing.T, _ int64, err error) { require.ErrorIs(t, err, admin.ErrNoActor) },
		},
		{
			name: "remove a blank grant", setup: noCall, assert: invalidNoCall,
			call: func(ctx context.Context, a *admin.Assignments) (int64, error) { return a.Remove(ctx, ada, 3, " ") },
		},
		{
			name: "mark primary with version zero", setup: noCall, assert: invalidNoCall,
			call: func(ctx context.Context, a *admin.Assignments) (int64, error) {
				return a.SetPrimary(ctx, ada, 0, "g-1")
			},
		},
		{
			name: "mark primary reaches the store",
			setup: func(store *MockAssignmentStore) {
				store.EXPECT().SetPrimary(gomock.Any(), ada, int64(3), "g-2").Return(int64(4), nil)
			},
			call: func(ctx context.Context, a *admin.Assignments) (int64, error) {
				return a.SetPrimary(ctx, ada, 3, "g-2")
			},
			assert: func(t *testing.T, version int64, err error) {
				require.NoError(t, err)
				assert.Equal(t, int64(4), version)
			},
		},
		{
			name: "list a blank user", setup: noCall, assert: invalidNoCall,
			call: func(ctx context.Context, a *admin.Assignments) (int64, error) {
				_, v, err := a.List(ctx, "")
				return v, err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockAssignmentStore(gomock.NewController(t))
			tc.setup(store)

			a, err := admin.NewAssignments(store)
			require.NoError(t, err)

			ctx := actorCtx(t)
			if tc.ctx != nil {
				ctx = tc.ctx(t)
			}

			version, err := tc.call(ctx, a)
			tc.assert(t, version, err)
		})
	}
}
