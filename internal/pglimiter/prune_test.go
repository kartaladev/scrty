package pglimiter_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/pglimiter"
	"github.com/kartaladev/scrty/internal/pgschema"
)

// dbNow is the time the database clock reports to a prune.
var dbNow = time.Date(2026, 10, 10, 12, 0, 0, 654321000, time.UTC)

// counted is an Exec result reporting n rows affected.
func counted(ctrl *gomock.Controller, n int64) pglimiter.Result {
	res := NewMockResult(ctrl)
	res.EXPECT().RowsAffected().Return(n, nil)
	return res
}

// expectClock scripts the one read of the database clock a prune makes.
func expectClock(ctrl *gomock.Controller, r *MockRunner) any {
	return r.EXPECT().QueryRow(gomock.Any(), pgschema.LimiterClock).Return(rowScanning(ctrl, nil, dbNow)).Times(1)
}

// expectBatches scripts one prune batch per count, in order, each with now
// and batch as its arguments.
func expectBatches(ctrl *gomock.Controller, r *MockRunner, now any, batch int, counts ...int64) []any {
	calls := make([]any, 0, len(counts))
	for _, n := range counts {
		calls = append(calls, r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, now, batch).Return(counted(ctrl, n), nil))
	}
	return calls
}

func TestPrune(t *testing.T) {
	t.Parallel()

	errBatch := errors.New("server says secret-xyz")
	errClock := errors.New("server says secret-abc")
	errCount := errors.New("driver says secret-rows")

	type testCase struct {
		name     string
		batch    int
		appClock bool
		// script receives the cancel of the ctx Prune runs with.
		script func(ctrl *gomock.Controller, r *MockRunner, cancel context.CancelFunc)
		assert func(t *testing.T, removed int, err error)
	}

	cases := []testCase{
		{
			name:  "empty table",
			batch: 1000,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				gomock.InOrder(append([]any{expectClock(ctrl, r)}, expectBatches(ctrl, r, dbNow, 1000, 0)...)...)
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Zero(t, removed)
			},
		},
		{
			name:  "short first batch stops",
			batch: 1000,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				gomock.InOrder(append([]any{expectClock(ctrl, r)}, expectBatches(ctrl, r, dbNow, 1000, 400)...)...)
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 400, removed)
			},
		},
		{
			name:  "full batches then short",
			batch: 2,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				gomock.InOrder(append([]any{expectClock(ctrl, r)}, expectBatches(ctrl, r, dbNow, 2, 2, 2, 1)...)...)
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 5, removed)
			},
		},
		{
			name:     "application clock",
			batch:    2,
			appClock: true,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				// No QueryRow is expected: the database clock is not read.
				expectBatches(ctrl, r, testNow, 2, 1)
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name:  "database clock read once",
			batch: 2,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				gomock.InOrder(append([]any{expectClock(ctrl, r)}, expectBatches(ctrl, r, dbNow, 2, 2, 0)...)...)
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 2, removed)
			},
		},
		{
			name:     "cancelled during first batch",
			batch:    2,
			appClock: true,
			script: func(ctrl *gomock.Controller, r *MockRunner, cancel context.CancelFunc) {
				r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, testNow, 2).
					DoAndReturn(func(context.Context, string, ...any) (pglimiter.Result, error) {
						cancel() // the batch commits, and ctx ends before the next
						return counted(ctrl, 2), nil
					})
			},
			assert: func(t *testing.T, removed int, err error) {
				assert.Equal(t, 2, removed, "the committed batch is counted")
				require.ErrorIs(t, err, context.Canceled)
				assert.EqualError(t, err, "pgx: rate-limit prune: stopped after 2 keys: context canceled")
			},
		},
		{
			name:     "failed second batch",
			batch:    2,
			appClock: true,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				gomock.InOrder(
					r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, testNow, 2).Return(counted(ctrl, 2), nil),
					r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, testNow, 2).Return(nil, errBatch),
				)
			},
			assert: func(t *testing.T, removed int, err error) {
				assert.Equal(t, 2, removed, "the first batch's keys are counted")
				require.Error(t, err)
				assert.EqualError(t, err, "pgx: rate-limit prune: a batch could not be deleted")
				assert.NotContains(t, err.Error(), "secret-xyz")
				assert.ErrorIs(t, err, errBatch, "the cause is kept")
			},
		},
		{
			name:     "batch whose Exec hits the deadline keeps the cause and the earlier count",
			batch:    2,
			appClock: true,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				gomock.InOrder(
					r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, testNow, 2).Return(counted(ctrl, 2), nil),
					r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, testNow, 2).Return(nil, context.DeadlineExceeded),
				)
			},
			assert: func(t *testing.T, removed int, err error) {
				assert.Equal(t, 2, removed, "the committed batch is counted")
				require.Error(t, err)
				assert.ErrorIs(t, err, context.DeadlineExceeded, "the cause is kept")
			},
		},
		{
			name:     "unreadable row count fails the batch",
			batch:    2,
			appClock: true,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				res := NewMockResult(ctrl)
				res.EXPECT().RowsAffected().Return(int64(0), errCount)
				r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, testNow, 2).Return(res, nil)
			},
			assert: func(t *testing.T, removed int, err error) {
				assert.Zero(t, removed)
				require.Error(t, err)
				assert.EqualError(t, err, "pgx: rate-limit prune: a batch's row count could not be read")
				assert.NotContains(t, err.Error(), "secret-rows")
				assert.ErrorIs(t, err, errCount, "the cause is kept")
			},
		},
		{
			name:  "clock read fails",
			batch: 2,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				r.EXPECT().QueryRow(gomock.Any(), pgschema.LimiterClock).Return(rowScanning(ctrl, errClock))
			},
			assert: func(t *testing.T, removed int, err error) {
				assert.Zero(t, removed)
				require.Error(t, err)
				assert.EqualError(t, err, "pgx: rate-limit prune: the database clock could not be read")
				assert.NotContains(t, err.Error(), "secret-abc")
				assert.ErrorIs(t, err, errClock, "the cause is kept")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cfg := pglimiter.DefaultConfig()
			if tc.appClock {
				cfg = withClock(cfg)
			}
			cfg.PruneBatchSize = tc.batch
			ctrl := gomock.NewController(t)
			r := NewMockRunner(ctrl)
			tc.script(ctrl, r, cancel)

			removed, err := pglimiter.Prune(ctx, r, "pgx", cfg)
			tc.assert(t, removed, err)
		})
	}
}
