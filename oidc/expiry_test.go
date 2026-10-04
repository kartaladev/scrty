package oidc_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/pkg/id"
)

// expiryT0 is when every flow and handoff in the expiry tests was issued.
var expiryT0 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

var errExpiryStore = errors.New("store unavailable")

// flowExpiryManager returns a login manager over flows, reading time from clk.
func flowExpiryManager(t *testing.T, flows oidc.FlowStore, clk clockwork.Clock) *oidc.Manager {
	t.Helper()

	reg, err := oidc.NewRegistry(newTestProvider(t).Provider("corp"))
	require.NoError(t, err)
	m, err := oidc.NewManager(reg, stubBroker{}, oidc.WithClock(clk), oidc.WithFlowStore(flows))
	require.NoError(t, err)

	return m
}

// handoffExpiryManager returns a handoff manager over store, reading time from
// clk.
func handoffExpiryManager(t *testing.T, store oidc.HandoffStore, clk clockwork.Clock) *oidc.HandoffManager {
	t.Helper()

	h, err := oidc.NewHandoffManager(store, NewMockUserLoader(gomock.NewController(t)), oidc.WithHandoffClock(clk))
	require.NoError(t, err)

	return h
}

// expiryHandoff is a record issued at expiryT0 that expires after ttl.
func expiryHandoff(tokenID string, n byte, ttl time.Duration) oidc.HandoffRecord {
	rec := handoffStoreRecord(tokenID)
	rec.ID = id.MustParse("01926a4e-0000-7000-8000-0000000000" + string([]byte{'a', 'a' + n}))
	rec.CreatedAt = expiryT0
	rec.ExpiresAt = expiryT0.Add(ttl)

	return rec
}

func TestExpiryTask(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// task builds the task under test, seeding whatever it sweeps, and
		// returns a check of what is left after the run.
		task   func(t *testing.T, ctx context.Context) (expiry.Task, func(t *testing.T))
		assert func(t *testing.T, task expiry.Task, removed int, err error)
	}

	cases := []testCase{
		{
			name: "flows: the expired flow goes and the live one stays",
			task: func(t *testing.T, ctx context.Context) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryT0)
				flows, err := oidc.NewMemoryFlowStore(oidc.WithMemoryFlowStoreClock(clk))
				require.NoError(t, err)
				_, err = flows.Begin(ctx, oidc.Flow{Provider: "corp", State: "s-old", ExpiresAt: expiryT0.Add(time.Minute)})
				require.NoError(t, err)
				live, err := flows.Begin(ctx, oidc.Flow{Provider: "corp", State: "s-live", ExpiresAt: expiryT0.Add(time.Hour)})
				require.NoError(t, err)
				m := flowExpiryManager(t, flows, clk)
				clk.Advance(10 * time.Minute)

				return oidc.FlowExpiryTask(m), func(t *testing.T) {
					_, err := flows.Complete(ctx, live, "corp", "s-live")
					assert.NoError(t, err, "the live flow must survive the sweep")
				}
			},
			assert: func(t *testing.T, task expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
				assert.Equal(t, "oidc-flows", task.Name)
				assert.Zero(t, task.Interval)
			},
		},
		{
			name: "flows: the cutoff is the manager's own now",
			task: func(t *testing.T, _ context.Context) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryT0)
				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().DeleteExpired(gomock.Any(), expiryT0.Add(time.Hour)).Return(4, nil)
				m := flowExpiryManager(t, flows, clk)
				clk.Advance(time.Hour)

				return oidc.FlowExpiryTask(m), func(*testing.T) {}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 4, removed)
			},
		},
		{
			name: "flows: a store error is returned with the count",
			task: func(t *testing.T, _ context.Context) (expiry.Task, func(t *testing.T)) {
				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).Return(2, errExpiryStore)

				return oidc.FlowExpiryTask(flowExpiryManager(t, flows, clockwork.NewFakeClockAt(expiryT0))), func(*testing.T) {}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.ErrorIs(t, err, errExpiryStore)
				assert.Equal(t, 2, removed)
			},
		},
		{
			name: "handoffs: the expired handoff goes and the live one stays",
			task: func(t *testing.T, ctx context.Context) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryT0)
				store := oidc.NewMemoryHandoffStore()
				require.NoError(t, store.Insert(ctx, expiryHandoff("tok-old", 1, time.Minute)))
				require.NoError(t, store.Insert(ctx, expiryHandoff("tok-live", 2, time.Hour)))
				h := handoffExpiryManager(t, store, clk)
				clk.Advance(10 * time.Minute)

				return oidc.HandoffExpiryTask(h), func(t *testing.T) {
					_, err := store.FindByTokenID(ctx, "tok-old")
					require.ErrorIs(t, err, oidc.ErrHandoffNotFound)
					_, err = store.FindByTokenID(ctx, "tok-live")
					assert.NoError(t, err, "the live handoff must survive the sweep")
				}
			},
			assert: func(t *testing.T, task expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
				assert.Equal(t, "oidc-handoffs", task.Name)
				assert.Zero(t, task.Interval)
			},
		},
		{
			name: "handoffs: the cutoff is the manager's own now",
			task: func(t *testing.T, _ context.Context) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryT0)
				store := NewMockHandoffStore(gomock.NewController(t))
				store.EXPECT().DeleteExpired(gomock.Any(), expiryT0.Add(time.Hour)).Return(3, nil)
				h := handoffExpiryManager(t, store, clk)
				clk.Advance(time.Hour)

				return oidc.HandoffExpiryTask(h), func(*testing.T) {}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 3, removed)
			},
		},
		{
			name: "handoffs: a store error is returned with the count",
			task: func(t *testing.T, _ context.Context) (expiry.Task, func(t *testing.T)) {
				store := NewMockHandoffStore(gomock.NewController(t))
				store.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).Return(1, errExpiryStore)

				return oidc.HandoffExpiryTask(handoffExpiryManager(t, store, clockwork.NewFakeClockAt(expiryT0))), func(*testing.T) {}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.ErrorIs(t, err, errExpiryStore)
				assert.Equal(t, 1, removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			task, after := tc.task(t, ctx)
			require.NotNil(t, task.Run, "the task must have a Run")

			removed, err := task.Run(ctx)
			tc.assert(t, task, removed, err)
			after(t)
		})
	}
}
