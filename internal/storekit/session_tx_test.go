package storekit_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// handle stands in for a driver's statement handle: the one a call resolved
// to, the caller's transaction, or one the store began.
type handle string

const (
	base   handle = "base"
	own    handle = "own"
	caller handle = "caller"
)

// outcome runs f, and reports the value of any panic it raised and its error.
func outcome(f func() error) (panicked any, err error) {
	defer func() { panicked = recover() }()

	return nil, f()
}

// notCancelled matches a context that is not done.
func notCancelled() gomock.Matcher {
	return gomock.Cond(func(ctx context.Context) bool { return ctx.Err() == nil })
}

func TestAtomically(t *testing.T) {
	t.Parallel()

	var (
		errFn      = errors.New("fn failed")
		errBegin   = errors.New("begin failed")
		errCommit  = errors.New("commit failed")
		errOpen    = errors.New("savepoint failed")
		errRewind  = errors.New("rollback to savepoint failed")
		errRelease = errors.New("release failed")
	)

	type testCase struct {
		name    string
		ambient bool
		ctx     func(ctx context.Context) context.Context
		// expect sets the driver calls the case requires, in order.
		expect func(m *MockTransactor[handle])
		fn     func(q handle) error
		assert func(t *testing.T, ran []handle, err error, panicked any)
	}

	sp := func(m *MockTransactor[handle], ctx any, stmt string) *MockTransactorExecSavepointCall[handle] {
		return m.EXPECT().ExecSavepoint(ctx, caller, stmt+"sp_1")
	}

	cases := []testCase{
		{
			name: "owned: success commits on the handle Begin returned",
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().Begin(gomock.Any(), base).Return(own, nil),
					m.EXPECT().Commit(gomock.Any()).Return(nil),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			fn: func(handle) error { return nil },
			assert: func(t *testing.T, ran []handle, err error, panicked any) {
				require.NoError(t, err)
				assert.Nil(t, panicked)
				assert.Equal(t, []handle{own}, ran)
			},
		},
		{
			name: "owned: a failure rolls back, never commits, and is returned as it is",
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().Begin(gomock.Any(), base).Return(own, nil),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			fn: func(handle) error { return errFn },
			assert: func(t *testing.T, _ []handle, err error, _ any) {
				assert.Same(t, errFn, err)
			},
		},
		{
			name: "owned: a sentinel stays bare",
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().Begin(gomock.Any(), base).Return(own, nil),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			fn: func(handle) error { return session.ErrSessionRenewalConflict },
			assert: func(t *testing.T, _ []handle, err error, _ any) {
				assert.Equal(t, session.ErrSessionRenewalConflict, err)
			},
		},
		{
			name: "owned: a commit failure is returned, and the rollback still runs",
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().Begin(gomock.Any(), base).Return(own, nil),
					m.EXPECT().Commit(gomock.Any()).Return(errCommit),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			fn: func(handle) error { return nil },
			assert: func(t *testing.T, _ []handle, err error, _ any) {
				assert.Same(t, errCommit, err)
			},
		},
		{
			name: "owned: a begin failure runs nothing",
			expect: func(m *MockTransactor[handle]) {
				m.EXPECT().Begin(gomock.Any(), base).Return("", errBegin)
			},
			fn: func(handle) error { return nil },
			assert: func(t *testing.T, ran []handle, err error, _ any) {
				assert.Same(t, errBegin, err)
				assert.Empty(t, ran)
			},
		},
		{
			name: "owned: a panic rolls back and goes on",
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().Begin(gomock.Any(), base).Return(own, nil),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			fn: func(handle) error { panic("boom") },
			assert: func(t *testing.T, _ []handle, _ error, panicked any) {
				assert.Equal(t, "boom", panicked)
			},
		},
		{
			name:    "joined: success releases the savepoint and never commits",
			ambient: true,
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().SavepointName().Return("sp_1"),
					sp(m, gomock.Any(), "SAVEPOINT ").Return(nil),
					sp(m, gomock.Any(), "RELEASE SAVEPOINT ").Return(nil),
				)
			},
			fn: func(handle) error { return nil },
			assert: func(t *testing.T, ran []handle, err error, _ any) {
				require.NoError(t, err)
				assert.Equal(t, []handle{caller}, ran)
			},
		},
		{
			name:    "joined: a failure rolls back to the savepoint, releases it, and is returned as it is",
			ambient: true,
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().SavepointName().Return("sp_1"),
					sp(m, gomock.Any(), "SAVEPOINT ").Return(nil),
					sp(m, gomock.Any(), "ROLLBACK TO SAVEPOINT ").Return(nil),
					sp(m, gomock.Any(), "RELEASE SAVEPOINT ").Return(nil),
				)
			},
			fn: func(handle) error { return errFn },
			assert: func(t *testing.T, _ []handle, err error, _ any) {
				assert.Same(t, errFn, err)
			},
		},
		{
			name:    "joined: a failed rollback to the savepoint is joined, and nothing is released",
			ambient: true,
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().SavepointName().Return("sp_1"),
					sp(m, gomock.Any(), "SAVEPOINT ").Return(nil),
					sp(m, gomock.Any(), "ROLLBACK TO SAVEPOINT ").Return(errRewind),
				)
			},
			fn: func(handle) error { return errFn },
			assert: func(t *testing.T, _ []handle, err error, _ any) {
				require.ErrorIs(t, err, errFn)
				require.ErrorIs(t, err, errRewind)
			},
		},
		{
			name:    "joined: a failed release after a failure is joined",
			ambient: true,
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().SavepointName().Return("sp_1"),
					sp(m, gomock.Any(), "SAVEPOINT ").Return(nil),
					sp(m, gomock.Any(), "ROLLBACK TO SAVEPOINT ").Return(nil),
					sp(m, gomock.Any(), "RELEASE SAVEPOINT ").Return(errRelease),
				)
			},
			fn: func(handle) error { return errFn },
			assert: func(t *testing.T, _ []handle, err error, _ any) {
				require.ErrorIs(t, err, errFn)
				require.ErrorIs(t, err, errRelease)
			},
		},
		{
			name:    "joined: a failed release after success is returned",
			ambient: true,
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().SavepointName().Return("sp_1"),
					sp(m, gomock.Any(), "SAVEPOINT ").Return(nil),
					sp(m, gomock.Any(), "RELEASE SAVEPOINT ").Return(errRelease),
				)
			},
			fn: func(handle) error { return nil },
			assert: func(t *testing.T, _ []handle, err error, _ any) {
				assert.Same(t, errRelease, err)
			},
		},
		{
			name:    "joined: a savepoint that cannot be opened runs nothing",
			ambient: true,
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().SavepointName().Return("sp_1"),
					sp(m, gomock.Any(), "SAVEPOINT ").Return(errOpen),
				)
			},
			fn: func(handle) error { return nil },
			assert: func(t *testing.T, ran []handle, err error, _ any) {
				assert.Same(t, errOpen, err)
				assert.Empty(t, ran)
			},
		},
		{
			name:    "joined: a panic rolls back to the savepoint, releases it, and goes on",
			ambient: true,
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().SavepointName().Return("sp_1"),
					sp(m, gomock.Any(), "SAVEPOINT ").Return(nil),
					sp(m, gomock.Any(), "ROLLBACK TO SAVEPOINT ").Return(nil),
					sp(m, gomock.Any(), "RELEASE SAVEPOINT ").Return(nil),
				)
			},
			fn: func(handle) error { panic("boom") },
			assert: func(t *testing.T, _ []handle, _ error, panicked any) {
				assert.Equal(t, "boom", panicked)
			},
		},
		{
			name:    "joined: a panic closing the savepoint closes it again, and goes on",
			ambient: true,
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().SavepointName().Return("sp_1"),
					sp(m, gomock.Any(), "SAVEPOINT ").Return(nil),
					sp(m, gomock.Any(), "ROLLBACK TO SAVEPOINT ").Do(
						func(context.Context, handle, string) error { panic("closing") }),
					sp(m, gomock.Any(), "ROLLBACK TO SAVEPOINT ").Do(
						func(context.Context, handle, string) error { panic("again") }),
					sp(m, gomock.Any(), "RELEASE SAVEPOINT ").Return(nil),
				)
			},
			fn: func(handle) error { return errFn },
			assert: func(t *testing.T, _ []handle, _ error, panicked any) {
				assert.Equal(t, "closing", panicked)
			},
		},
		{
			name:    "joined: the savepoint is closed even when ctx is done",
			ambient: true,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			expect: func(m *MockTransactor[handle]) {
				gomock.InOrder(
					m.EXPECT().SavepointName().Return("sp_1"),
					sp(m, gomock.Any(), "SAVEPOINT ").Return(nil),
					sp(m, notCancelled(), "ROLLBACK TO SAVEPOINT ").Return(nil),
					sp(m, notCancelled(), "RELEASE SAVEPOINT ").Return(nil),
				)
			},
			fn: func(handle) error { return errFn },
			assert: func(t *testing.T, _ []handle, err error, _ any) {
				assert.Same(t, errFn, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			m := NewMockTransactor[handle](gomock.NewController(t))
			tc.expect(m)

			q := base
			if tc.ambient {
				q = caller
			}
			var ran []handle
			panicked, err := outcome(func() error {
				return storekit.Atomically(ctx, m, q, tc.ambient, func(q handle) error {
					ran = append(ran, q)
					return tc.fn(q)
				})
			})
			tc.assert(t, ran, err, panicked)
		})
	}
}

func TestCheckSupersession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		op     session.Supersession
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "a supersession with a family successor and a retention after its window passes",
			op:   supersession(now, nil),
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "no successor is refused",
			op: func() session.Supersession {
				op := supersession(now, nil)
				op.Successor = nil
				return op
			}(),
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err, "a supersession needs a successor")
			},
		},
		{
			name: "a successor in no family is refused",
			op: func() session.Supersession {
				op := supersession(now, nil)
				op.Successor.FamilyID = id.Nil
				return op
			}(),
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err, "a successor with no family cannot be stored")
			},
		},
		{
			name: "a retention before the end of the window is refused",
			op: func() session.Supersession {
				op := supersession(now, nil)
				op.RetainUntil = op.AcceptUntil.Add(-time.Second)
				return op
			}(),
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err, "the retention deadline is before the end of the window")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.CheckSupersession(tc.op))
		})
	}
}

// supersession is a valid supersession of "old" at now, observing observed.
func supersession(now time.Time, observed []byte) session.Supersession {
	return session.Supersession{
		Old:               "old",
		ObservedSuccessor: observed,
		AcceptUntil:       now.Add(time.Minute),
		RetainUntil:       now.Add(time.Hour),
		Now:               now,
		Successor: &session.Session{
			ID:       "new",
			FamilyID: id.MustParse("01890000-0000-7000-8000-000000000001"),
		},
	}
}

func TestSupersede(t *testing.T) {
	t.Parallel()

	var (
		now      = time.Date(2026, 10, 22, 9, 0, 0, 123456789, time.UTC)
		observed = []byte("observed successor digest")
		old      = storekit.SessionDigest("old")
		next     = storekit.SessionDigest("new")
		errStmt  = errors.New("statement failed")
	)

	// retain is what the fake driver binds the retention deadline as.
	const retain = "retain until"

	type testCase struct {
		name     string
		ambient  bool
		observed []byte
		op       func(op session.Supersession) session.Supersession
		// expect sets the statements the case requires on q, in order, after
		// the transaction is opened; the transaction's end is the case's too.
		expect func(m *MockSessionTx[handle], q handle, op session.Supersession)
		assert func(t *testing.T, err error)
	}

	lock := func(m *MockSessionTx[handle], q handle, op session.Supersession) *MockSessionTxExecCall[handle] {
		return m.EXPECT().Exec(gomock.Any(), q, pgschema.SessionLockSupersession,
			old, storekit.OptionalDigestArg(op.ObservedSuccessor))
	}
	supersedeOld := func(m *MockSessionTx[handle], q handle, op session.Supersession) *MockSessionTxExecCall[handle] {
		return m.EXPECT().Exec(gomock.Any(), q, pgschema.SessionSupersedeOld,
			old, storekit.OptionalDigestArg(op.ObservedSuccessor), storekit.Time(op.Now),
			storekit.Time(op.AcceptUntil), next, retain)
	}
	supersedePrevious := func(m *MockSessionTx[handle], q handle, op session.Supersession) *MockSessionTxExecCall[handle] {
		return m.EXPECT().Exec(gomock.Any(), q, pgschema.SessionSupersedePrevious,
			op.ObservedSuccessor, storekit.Time(op.Now), op.RequireUnpresentedSuccessor, retain)
	}
	refusal := func(m *MockSessionTx[handle], q handle, cause int) *MockSessionTxQueryIntCall[handle] {
		return m.EXPECT().QueryInt(gomock.Any(), q, pgschema.SessionSupersedeRefusal, old).Return(cause, nil)
	}
	owned := func(m *MockSessionTx[handle]) *MockSessionTxBeginCall[handle] {
		return m.EXPECT().Begin(gomock.Any(), base).Return(own, nil)
	}

	cases := []testCase{
		{
			name:     "a renewal runs lock, old, previous, insert in order, and commits",
			observed: observed,
			op: func(op session.Supersession) session.Supersession {
				op.RequireUnpresentedSuccessor = true
				return op
			},
			expect: func(m *MockSessionTx[handle], q handle, op session.Supersession) {
				gomock.InOrder(
					owned(m),
					lock(m, q, op).Return(2, nil),
					supersedeOld(m, q, op).Return(1, nil),
					supersedePrevious(m, q, op).Return(1, nil),
					m.EXPECT().InsertSuccessor(gomock.Any(), q).Return(true, nil),
					m.EXPECT().Commit(gomock.Any()).Return(nil),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a first rotation binds no observed successor and supersedes no previous one",
			expect: func(m *MockSessionTx[handle], q handle, op session.Supersession) {
				gomock.InOrder(
					owned(m),
					m.EXPECT().Exec(gomock.Any(), q, pgschema.SessionLockSupersession, old, nil).Return(1, nil),
					m.EXPECT().Exec(gomock.Any(), q, pgschema.SessionSupersedeOld, old, nil,
						storekit.Time(op.Now), storekit.Time(op.AcceptUntil), next, retain).Return(1, nil),
					m.EXPECT().InsertSuccessor(gomock.Any(), q).Return(true, nil),
					m.EXPECT().Commit(gomock.Any()).Return(nil),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name:     "a lost race is the renewal conflict, bare, and nothing is committed",
			observed: observed,
			expect: func(m *MockSessionTx[handle], q handle, op session.Supersession) {
				gomock.InOrder(
					owned(m),
					lock(m, q, op).Return(2, nil),
					supersedeOld(m, q, op).Return(0, nil),
					refusal(m, q, pgschema.SupersedeRefusalOther),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			assert: func(t *testing.T, err error) {
				assert.Equal(t, session.ErrSessionRenewalConflict, err)
			},
		},
		{
			name: "an old session not stored is not found, bare",
			expect: func(m *MockSessionTx[handle], q handle, op session.Supersession) {
				gomock.InOrder(
					owned(m),
					lock(m, q, op).Return(0, nil),
					supersedeOld(m, q, op).Return(0, nil),
					refusal(m, q, pgschema.SupersedeRefusalMissing),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			assert: func(t *testing.T, err error) {
				assert.Equal(t, session.ErrSessionNotFound, err)
			},
		},
		{
			name: "an old session in no family is the store's own refusal",
			expect: func(m *MockSessionTx[handle], q handle, op session.Supersession) {
				gomock.InOrder(
					owned(m),
					lock(m, q, op).Return(1, nil),
					supersedeOld(m, q, op).Return(0, nil),
					refusal(m, q, pgschema.SupersedeRefusalNoFamily),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err, "store: op: a session with no family cannot be superseded")
			},
		},
		{
			name:     "a previous successor that moved on is successor advanced, and nothing is inserted",
			observed: observed,
			expect: func(m *MockSessionTx[handle], q handle, op session.Supersession) {
				gomock.InOrder(
					owned(m),
					lock(m, q, op).Return(2, nil),
					supersedeOld(m, q, op).Return(1, nil),
					supersedePrevious(m, q, op).Return(0, nil),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			assert: func(t *testing.T, err error) {
				assert.Equal(t, session.ErrSuccessorAdvanced, err)
			},
		},
		{
			name: "a successor identifier in use is the store's own refusal",
			expect: func(m *MockSessionTx[handle], q handle, op session.Supersession) {
				gomock.InOrder(
					owned(m),
					lock(m, q, op).Return(1, nil),
					supersedeOld(m, q, op).Return(1, nil),
					m.EXPECT().InsertSuccessor(gomock.Any(), q).Return(false, nil),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err, "store: op: the successor's identifier is already in use")
			},
		},
		{
			name:     "a failed statement is returned as it is, and rolls the transaction back",
			observed: observed,
			expect: func(m *MockSessionTx[handle], q handle, op session.Supersession) {
				gomock.InOrder(
					owned(m),
					lock(m, q, op).Return(2, nil),
					supersedeOld(m, q, op).Return(1, nil),
					supersedePrevious(m, q, op).Return(0, errStmt),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			assert: func(t *testing.T, err error) {
				assert.Same(t, errStmt, err)
			},
		},
		{
			name: "a failed refusal read is returned as it is",
			expect: func(m *MockSessionTx[handle], q handle, op session.Supersession) {
				gomock.InOrder(
					owned(m),
					lock(m, q, op).Return(1, nil),
					supersedeOld(m, q, op).Return(0, nil),
					m.EXPECT().QueryInt(gomock.Any(), q, pgschema.SessionSupersedeRefusal, old).Return(0, errStmt),
					m.EXPECT().Rollback(gomock.Any()),
				)
			},
			assert: func(t *testing.T, err error) {
				assert.Same(t, errStmt, err)
			},
		},
		{
			name:    "joined: a failed statement rolls back to the savepoint and never commits",
			ambient: true,
			expect: func(m *MockSessionTx[handle], q handle, op session.Supersession) {
				gomock.InOrder(
					m.EXPECT().SavepointName().Return("sp_1"),
					m.EXPECT().ExecSavepoint(gomock.Any(), q, "SAVEPOINT sp_1").Return(nil),
					lock(m, q, op).Return(0, errStmt),
					m.EXPECT().ExecSavepoint(gomock.Any(), q, "ROLLBACK TO SAVEPOINT sp_1").Return(nil),
					m.EXPECT().ExecSavepoint(gomock.Any(), q, "RELEASE SAVEPOINT sp_1").Return(nil),
				)
			},
			assert: func(t *testing.T, err error) {
				assert.Same(t, errStmt, err)
			},
		},
		{
			name:    "joined: a renewal releases the savepoint and never commits",
			ambient: true,
			expect: func(m *MockSessionTx[handle], q handle, op session.Supersession) {
				gomock.InOrder(
					m.EXPECT().SavepointName().Return("sp_1"),
					m.EXPECT().ExecSavepoint(gomock.Any(), q, "SAVEPOINT sp_1").Return(nil),
					lock(m, q, op).Return(1, nil),
					supersedeOld(m, q, op).Return(1, nil),
					m.EXPECT().InsertSuccessor(gomock.Any(), q).Return(true, nil),
					m.EXPECT().ExecSavepoint(gomock.Any(), q, "RELEASE SAVEPOINT sp_1").Return(nil),
				)
			},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a supersession CheckSupersession refuses runs no statement",
			op: func(op session.Supersession) session.Supersession {
				op.Successor = nil
				return op
			},
			expect: func(*MockSessionTx[handle], handle, session.Supersession) {},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err, "store: op: a supersession needs a successor")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			op := supersession(now, tc.observed)
			if tc.op != nil {
				op = tc.op(op)
			}
			m := NewMockSessionTx[handle](gomock.NewController(t))
			m.EXPECT().Failed(gomock.Any()).DoAndReturn(func(err error) error {
				return fmt.Errorf("store: op: %w", err)
			}).AnyTimes()
			m.EXPECT().NullTime(op.RetainUntil).Return(retain).AnyTimes()

			q, stmts := base, own
			if tc.ambient {
				q, stmts = caller, caller
			}
			tc.expect(m, stmts, op)

			tc.assert(t, storekit.Supersede(t.Context(), m, q, tc.ambient, op))
		})
	}
}
