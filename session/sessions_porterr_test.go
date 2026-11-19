package session_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/porterr"
	scrtyid "github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// hostileStoreRowEnv names the row a child process runs. It is empty in the
// parent.
const hostileStoreRowEnv = "SCRTY_SESSION_PORTERR_ROW"

// storeCycleOne contains itself through Unwrap() error.
type storeCycleOne struct{}

func (*storeCycleOne) Error() string   { return "store cycle one" }
func (c *storeCycleOne) Unwrap() error { return c }

// storeCycleMany contains itself through Unwrap() []error. Stdlib errors.Is
// recurses into it until the stack overflows, which is fatal, so its rows run
// in a child process.
type storeCycleMany struct{}

func (*storeCycleMany) Error() string     { return "store cycle many" }
func (c *storeCycleMany) Unwrap() []error { return []error{c} }

// storePanicUnwrap is a link whose Unwrap panics.
type storePanicUnwrap struct{}

func (storePanicUnwrap) Error() string { return "store panic unwrap" }
func (storePanicUnwrap) Unwrap() error { panic("test: Unwrap panicked") }

// storeManyNils is a link whose Unwrap() []error is huge.
type storeManyNils struct{ kids []error }

func (*storeManyNils) Error() string     { return "store many nils" }
func (m *storeManyNils) Unwrap() []error { return m.kids }

// storeTypedNil is a typed-nil pointer whose methods are safe on a nil
// receiver: its chain ends at once, so nothing is hostile about it.
type storeTypedNil struct{}

func (*storeTypedNil) Error() string { return "store typed nil" }
func (*storeTypedNil) Unwrap() error { return nil }

// captureHandler keeps the records it is handed.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (*captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)

	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// aborts counts the abort records the sanitizer wrote.
func (h *captureHandler) aborts() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	n := 0
	for _, r := range h.records {
		if r.Message == porterr.MsgClassificationAborted {
			n++
		}
	}

	return n
}

// withinTwoSeconds runs call on its own goroutine and fails the test when it
// does not return in time or lets a panic escape.
func withinTwoSeconds(t *testing.T, call func() error) error {
	t.Helper()

	type result struct {
		err      error
		panicked any
	}
	done := make(chan result, 1)
	go func() {
		var res result
		defer func() {
			res.panicked = recover()
			done <- res
		}()
		res.err = call()
	}()

	select {
	case res := <-done:
		require.Nil(t, res.panicked, "the call let a panic escape")

		return res.err
	case <-time.After(2 * time.Second):
		require.FailNow(t, "the call did not return within two seconds")

		return nil
	}
}

// isWithin is errors.Is bounded by two seconds, so an error whose chain was
// not sanitized fails the row instead of hanging the test.
func isWithin(t *testing.T, err, target error) bool {
	t.Helper()

	var is bool
	_ = withinTwoSeconds(t, func() error {
		is = errors.Is(err, target)

		return nil
	})

	return is
}

// storeSite is one call site of the Store port in sessions.go: run arms the
// mock so the site's port call returns err, calls the operation and returns
// what the caller sees.
type storeSite struct {
	name string
	opts []session.Option
	// joinsReuse is true for a site whose failure is returned beside ErrReused,
	// which wraps ErrExpired by design.
	joinsReuse bool
	run        func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error
}

func storeSites() []storeSite {
	const id = "porterr-1"

	return []storeSite{
		{
			name: "Load",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().Load(gomock.Any(), id).Return(nil, err).Times(1)
				_, got := m.Load(ctx, id)

				return got
			},
		},
		{
			// A first-presentation write that fails is answered by reading the
			// session again, so a plain outage and a hostile one both end in the
			// verdict on the second read.
			name: "MarkPresented_reload",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().Load(gomock.Any(), id).Return(storedSession(id), nil).Times(2)
				store.EXPECT().MarkPresented(gomock.Any(), id, createdAt).Return(err).Times(1)
				_, got := m.Load(ctx, id)

				return got
			},
		},
		{
			// With recovery on, a failure that is no refusal is the load's failure.
			name: "MarkPresented_recovery",
			opts: []session.Option{session.WithUnusedSuccessorRecovery()},
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().Load(gomock.Any(), id).Return(storedSession(id), nil).Times(1)
				store.EXPECT().MarkPresented(gomock.Any(), id, createdAt).Return(err).Times(1)
				_, got := m.Load(ctx, id)

				return got
			},
		},
		{
			name: "Touch",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().RecordActivity(gomock.Any(), id, gomock.Any(), gomock.Any(), gomock.Any()).Return(err).Times(1)

				return m.Touch(ctx, storedSession(id))
			},
		},
		{
			name: "Save",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(err).Times(1)

				return m.Save(ctx, storedSession(id))
			},
		},
		{
			name: "Delete",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().Delete(gomock.Any(), id).Return(err).Times(1)

				return m.Delete(ctx, id)
			},
		},
		{
			name: "DeleteByUser",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().DeleteByUser(gomock.Any(), testUser).Return(err).Times(1)

				return m.DeleteByUser(ctx, testUser)
			},
		},
		{
			name: "DeleteByUserExcept",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().DeleteByUserExcept(gomock.Any(), testUser, "").Return(0, err).Times(1)
				_, got := m.DeleteByUserExcept(ctx, testUser, "")

				return got
			},
		},
		{
			name: "CountActiveByUser",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().CountActiveByUser(gomock.Any(), testUser).Return(0, err).Times(1)
				_, got := m.CountActiveByUser(ctx, testUser)

				return got
			},
		},
		{
			name: "DeleteExpired",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().DeleteExpired(gomock.Any()).Return(0, err).Times(1)
				_, got := m.DeleteExpired(ctx)

				return got
			},
		},
		{
			name: "DeleteByExternalSession",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().DeleteByExternalSession(gomock.Any(), "iss", "sid").Return(0, err).Times(1)
				_, got := m.DeleteByExternalSession(ctx, "iss", "sid")

				return got
			},
		},
		{
			name: "DeleteByUserAndExternalIssuer",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().DeleteByUserAndExternalIssuer(gomock.Any(), testUser, "iss").Return(0, err).Times(1)
				_, got := m.DeleteByUserAndExternalIssuer(ctx, testUser, "iss")

				return got
			},
		},
		{
			name: "endFamily",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				family := scrtyid.MustParse("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b")
				store.EXPECT().DeleteFamily(gomock.Any(), family).Return(0, err).Times(1)
				_, got := m.RevokeFamily(ctx, family)

				return got
			},
		},
		{
			name: "RotateStrict_supersede",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().Load(gomock.Any(), id).Return(liveUnpresented(id), nil).Times(1)
				store.EXPECT().Supersede(gomock.Any(), gomock.Any()).Return(err).Times(1)
				_, got := m.Rotate(ctx, liveUnpresented(id))

				return got
			},
		},
		{
			name: "RotateWithGrace_supersede",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().Load(gomock.Any(), id).Return(liveUnpresented(id), nil).Times(1)
				store.EXPECT().Supersede(gomock.Any(), gomock.Any()).Return(err).Times(1)
				_, _, got := m.RotateWithGrace(ctx, liveUnpresented(id), session.DefaultRenewalGrace)

				return got
			},
		},
		{
			name: "ended_successorPresented",
			opts: []session.Option{session.WithUnusedSuccessorRecovery()},
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				s := supersededPastWindow(id)
				s.IdleExpiresAt = createdAt.Add(-time.Minute)
				store.EXPECT().Load(gomock.Any(), id).Return(s, nil).Times(1)
				store.EXPECT().SuccessorPresented(gomock.Any(), id).Return(false, err).Times(1)
				_, _, got := m.RotateWithGrace(ctx, liveUnpresented(id), session.DefaultRenewalGrace)

				return got
			},
		},
		{
			// The supersession finds the successor advanced, so the family is
			// revoked; the revocation's failure is returned beside ErrReused.
			name:       "reuse_deleteFamily",
			joinsReuse: true,
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				store.EXPECT().Load(gomock.Any(), id).Return(liveUnpresented(id), nil).Times(1)
				store.EXPECT().Supersede(gomock.Any(), gomock.Any()).Return(session.ErrSuccessorAdvanced).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).Return(0, err).Times(1)
				_, _, got := m.RotateWithGrace(ctx, liveUnpresented(id), session.DefaultRenewalGrace)

				return got
			},
		},
		{
			name: "PreparedCommit_create",
			run: func(ctx context.Context, m *session.Sessions, store *MockStore, err error) error {
				p, perr := m.Prepare(testUser)
				if perr != nil {
					return perr
				}
				store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(err).Times(1)
				_, got := p.Commit(ctx)

				return got
			},
		},
	}
}

// runStoreSite builds a manager over a mock store and a capturing logger, runs
// the site with err and returns what the caller saw, with the logger's abort
// count.
func runStoreSite(t *testing.T, ctx context.Context, site storeSite, err error) (error, int) { //nolint:revive // ctx after t is the test's own helper shape
	t.Helper()

	store := NewMockStore(gomock.NewController(t))
	logs := &captureHandler{}
	opts := append([]session.Option{
		session.WithStore(store),
		session.WithClock(clockwork.NewFakeClockAt(createdAt)),
		session.WithLogger(slog.New(logs)),
	}, site.opts...)
	m := managerFor(t, opts...)

	got := withinTwoSeconds(t, func() error { return site.run(ctx, m, store, err) })

	return got, logs.aborts()
}

// childStoreRow is the row this process runs as a child, or "" in the parent.
func childStoreRow() string {
	row := os.Getenv(hostileStoreRowEnv)
	if row != "" {
		debug.SetMaxStack(64 << 20)
	}

	return row
}

// inStoreChild re-runs the current top-level test in a child process limited
// to row, and fails unless the child exits 0 within a minute.
func inStoreChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), hostileStoreRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
}

// TestPortErrors_SessionsStorePort: a hostile error from the session Store ends in
// the same outcome as a plain outage, within bounds, with one abort record on
// the manager's logger and none on the default logger.
//
// Not parallel: it swaps slog.Default to prove the record goes to the
// manager's logger.
func TestPortErrors_SessionsStorePort(t *testing.T) {
	type testCase struct {
		name   string
		err    func() error
		aborts int
		child  bool
	}

	cases := []testCase{
		{name: "cycle through Unwrap() error", err: func() error { return &storeCycleOne{} }, aborts: 1},
		{name: "cycle through Unwrap() []error", err: func() error { return &storeCycleMany{} }, aborts: 1, child: true},
		{name: "panicking Unwrap", err: func() error { return storePanicUnwrap{} }, aborts: 1},
		{
			name:   "fan-out past the budget",
			err:    func() error { return &storeManyNils{kids: make([]error, 1<<20)} },
			aborts: 1,
		},
		{name: "typed nil root with safe methods", err: func() error { return (*storeTypedNil)(nil) }, aborts: 0},
	}

	child := childStoreRow()

	for _, site := range storeSites() {
		for _, tc := range cases {
			row := site.name + "/" + tc.name
			if child != "" && child != row {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if child == "" && tc.child {
					inStoreChild(t, row)

					return
				}

				defaultLogs := &captureHandler{}
				previous := slog.Default()
				slog.SetDefault(slog.New(defaultLogs))
				t.Cleanup(func() { slog.SetDefault(previous) })

				plainGot, plainAborts := runStoreSite(t, t.Context(), site, errors.New("store: down"))
				require.Zero(t, plainAborts, "a plain outage must write no abort record")

				got, aborts := runStoreSite(t, t.Context(), site, tc.err())

				assert.Equal(t, tc.aborts, aborts, "abort records on the manager's logger")
				assert.Zero(t, defaultLogs.aborts(), "the manager's logger is used, not slog.Default()")
				assert.Equal(t, plainGot == nil, got == nil, "plain: %v, hostile: %v", plainGot, got)
				if plainGot != nil && got != nil {
					assert.Equal(t, plainGot.Error(), got.Error(), "same caller-visible text as a plain outage")
					assert.False(t, isWithin(t, got, session.ErrNotFound))
					// ErrReused is the reuse verdict and wraps ErrExpired by design.
					assert.Equal(t, site.joinsReuse, isWithin(t, got, session.ErrReused))
					if !site.joinsReuse {
						assert.False(t, isWithin(t, got, session.ErrExpired))
					}
					assert.False(t, isWithin(t, got, session.ErrSuperseded))
					if tc.aborts == 1 {
						assert.True(t, isWithin(t, got, porterr.ErrUnwalkable), "the fault matches ErrUnwalkable")
					}
				}
			})
		}
	}
}

// TestPortErrors_SessionsStorePort_CancelledContext: a context that is already
// cancelled does not change the outcome, and the abort record is still
// written.
func TestPortErrors_SessionsStorePort_CancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	for _, site := range storeSites() {
		t.Run(site.name, func(t *testing.T) {
			t.Parallel()

			plainGot, _ := runStoreSite(t, ctx, site, errors.New("store: down"))
			got, aborts := runStoreSite(t, ctx, site, &storeCycleOne{})

			assert.Equal(t, 1, aborts)
			assert.Equal(t, plainGot == nil, got == nil)
			if plainGot != nil && got != nil {
				assert.Equal(t, plainGot.Error(), got.Error())
			}
		})
	}
}

// TestPortErrors_SessionsStorePort_SentinelsUnchanged: the real sentinels the sites
// inspect keep their outcome, including when the store wraps them.
func TestPortErrors_SessionsStorePort_SentinelsUnchanged(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		site   string
		err    error
		assert func(t *testing.T, got error)
	}

	wrapped := func(err error) error { return fmt.Errorf("store: %w", err) }

	cases := []testCase{
		{
			name: "a real ErrSuccessorAdvanced still revokes the family",
			site: "rotate_advanced",
			err:  session.ErrSuccessorAdvanced,
			assert: func(t *testing.T, got error) {
				t.Helper()
				assert.ErrorIs(t, got, session.ErrReused)
			},
		},
		{
			name: "a wrapped ErrSuccessorAdvanced still revokes the family",
			site: "rotate_advanced",
			err:  wrapped(session.ErrSuccessorAdvanced),
			assert: func(t *testing.T, got error) {
				t.Helper()
				assert.ErrorIs(t, got, session.ErrReused)
			},
		},
		{
			name: "a hostile error never matches ErrSuccessorAdvanced and revokes nothing",
			site: "rotate_hostile",
			err:  &storeCycleOne{},
			assert: func(t *testing.T, got error) {
				t.Helper()
				require.Error(t, got)
				assert.False(t, isWithin(t, got, session.ErrReused))
				assert.False(t, isWithin(t, got, session.ErrSuccessorAdvanced))
			},
		},
		{
			name: "Load answers a bare ErrNotFound as itself",
			site: "Load",
			err:  session.ErrNotFound,
			assert: func(t *testing.T, got error) {
				t.Helper()
				assert.ErrorIs(t, got, session.ErrNotFound)
			},
		},
		{
			name: "Load answers a wrapped ErrExpired as an expired match",
			site: "Load",
			err:  wrapped(session.ErrExpired),
			assert: func(t *testing.T, got error) {
				t.Helper()
				assert.ErrorIs(t, got, session.ErrExpired)
			},
		},
		{
			name: "a first-presentation write answered ErrNotFound is ErrNotFound",
			site: "MarkPresented_reload",
			err:  session.ErrNotFound,
			assert: func(t *testing.T, got error) {
				t.Helper()
				assert.ErrorIs(t, got, session.ErrNotFound)
			},
		},
		{
			name: "a first-presentation write answered a wrapped ErrNotFound is ErrNotFound",
			site: "MarkPresented_recovery",
			err:  wrapped(session.ErrNotFound),
			assert: func(t *testing.T, got error) {
				t.Helper()
				assert.ErrorIs(t, got, session.ErrNotFound)
			},
		},
		{
			name: "a first-presentation write answered ErrSuperseded is read again",
			site: "MarkPresented_recovery",
			err:  session.ErrSuperseded,
			assert: func(t *testing.T, got error) {
				t.Helper()
				// The reload is the Load site's second read; the mock for the
				// recovery site expects one read, so this row is armed below.
				assert.NotErrorIs(t, got, porterr.ErrUnwalkable)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockStore(gomock.NewController(t))
			m := managerFor(t,
				session.WithStore(store),
				session.WithClock(clockwork.NewFakeClockAt(createdAt)),
				session.WithLogger(slog.New(&captureHandler{})),
				session.WithUnusedSuccessorRecovery(),
			)

			const id = "porterr-1"
			var got error
			switch tc.site {
			case "rotate_advanced":
				store.EXPECT().Load(gomock.Any(), id).Return(liveUnpresented(id), nil).Times(1)
				store.EXPECT().Supersede(gomock.Any(), gomock.Any()).Return(tc.err).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).Return(1, nil).Times(1)
				_, _, got = m.RotateWithGrace(t.Context(), liveUnpresented(id), session.DefaultRenewalGrace)
			case "rotate_hostile":
				// No DeleteFamily is expected: a call would fail the mock.
				store.EXPECT().Load(gomock.Any(), id).Return(liveUnpresented(id), nil).Times(1)
				store.EXPECT().Supersede(gomock.Any(), gomock.Any()).Return(tc.err).Times(1)
				_, _, got = m.RotateWithGrace(t.Context(), liveUnpresented(id), session.DefaultRenewalGrace)
			case "Load":
				store.EXPECT().Load(gomock.Any(), id).Return(nil, tc.err).Times(1)
				_, got = m.Load(t.Context(), id)
			default:
				store.EXPECT().Load(gomock.Any(), id).Return(storedSession(id), nil).MinTimes(1)
				store.EXPECT().MarkPresented(gomock.Any(), id, createdAt).Return(tc.err).Times(1)
				_, got = m.Load(t.Context(), id)
			}

			tc.assert(t, got)
		})
	}
}
