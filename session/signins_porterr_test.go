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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// portErrCycleOne is an error whose Unwrap returns itself.
type portErrCycleOne struct{}

func (e *portErrCycleOne) Error() string { return "cycle one" }
func (e *portErrCycleOne) Unwrap() error { return e }

// portErrPanicUnwrap is an error whose Unwrap panics.
type portErrPanicUnwrap struct{}

func (*portErrPanicUnwrap) Error() string { return "panic unwrap" }
func (*portErrPanicUnwrap) Unwrap() error { panic("unwrap exploded") }

// portErrCycleMany is an error whose Unwrap() []error holds itself. Stdlib
// errors.Is on it overflows the stack, a fatal error, so its rows run in a
// child process.
type portErrCycleMany struct{}

func (*portErrCycleMany) Error() string { return "cycle many" }

func (e *portErrCycleMany) Unwrap() []error { return []error{e} }

// portRecorder keeps the records a logger was handed.
type portRecorder struct {
	mu      sync.Mutex
	reasons []string
}

func (*portRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *portRecorder) Handle(_ context.Context, rec slog.Record) error {
	reason := ""
	rec.Attrs(func(a slog.Attr) bool {
		if a.Key == "reason" {
			reason = a.Value.String()
		}

		return true
	})
	if rec.Message == porterr.MsgClassificationAborted {
		r.mu.Lock()
		r.reasons = append(r.reasons, reason)
		r.mu.Unlock()
	}

	return nil
}

func (r *portRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *portRecorder) WithGroup(string) slog.Handler      { return r }

func (r *portRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.reasons)
}

const portRowEnv = "SCRTY_SESSION_PORTERR_ROW"

// portFamilyStore is a Store that also reads one family, so readFamily takes
// its family read.
type portFamilyStore struct {
	session.Store
	session.FamilyReader
}

// portSite is one place the session store's error enters the library.
type portSite struct {
	name string
	// ownLogger is true when the site reports to the manager's logger, false
	// when it reports to slog.Default().
	ownLogger bool
	// earlyCtx is true when a cancelled ctx returns before the store is asked.
	earlyCtx bool
	call     func(ctx context.Context, err error, ctrl *gomock.Controller, opts []session.Option) error
}

func portSites() []portSite {
	family := id.MustParse("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b")
	owned := []*session.Session{{ID: "s1", UserID: testUser, FamilyID: family}}
	mk := func(ctrl *gomock.Controller, opts []session.Option, setup func(*MockStore)) *session.Sessions {
		store := NewMockStore(ctrl)
		setup(store)

		return portMust(session.New(append([]session.Option{session.WithStore(store)}, opts...)...))
	}

	return []portSite{
		{
			name: "ListSignIns/ListByUser", ownLogger: true,
			call: func(ctx context.Context, err error, ctrl *gomock.Controller, opts []session.Option) error {
				m := mk(ctrl, opts, func(s *MockStore) {
					s.EXPECT().ListByUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, err).AnyTimes()
				})
				_, got := m.ListSignIns(ctx, testUser, nil)

				return got
			},
		},
		{
			name: "EndSignIn/ListByUser", ownLogger: true, earlyCtx: true,
			call: func(ctx context.Context, err error, ctrl *gomock.Controller, opts []session.Option) error {
				m := mk(ctrl, opts, func(s *MockStore) {
					s.EXPECT().ListByUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, err).AnyTimes()
				})

				return m.EndSignIn(ctx, testUser, family.String())
			},
		},
		{
			name: "EndSignIn/DeleteFamily", ownLogger: true, earlyCtx: true,
			call: func(ctx context.Context, err error, ctrl *gomock.Controller, opts []session.Option) error {
				m := mk(ctrl, opts, func(s *MockStore) {
					s.EXPECT().ListByUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(owned, nil).AnyTimes()
					s.EXPECT().DeleteFamily(gomock.Any(), family).Return(0, err).AnyTimes()
				})

				return m.EndSignIn(ctx, testUser, family.String())
			},
		},
		{
			name: "EndOtherSignIns/DeleteByUserExcept", ownLogger: true,
			call: func(ctx context.Context, err error, ctrl *gomock.Controller, opts []session.Option) error {
				m := mk(ctrl, opts, func(s *MockStore) {
					s.EXPECT().DeleteByUserExcept(gomock.Any(), testUser, "s1").Return(0, err).AnyTimes()
				})
				_, got := m.EndOtherSignIns(ctx, testUser, owned[0])

				return got
			},
		},
		{
			name: "SignInState/readFamily/ListByUser", ownLogger: true,
			call: func(ctx context.Context, err error, ctrl *gomock.Controller, opts []session.Option) error {
				m := mk(ctrl, opts, func(s *MockStore) {
					s.EXPECT().ListByUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, err).AnyTimes()
				})
				_, got := m.SignInState(ctx, testUser, family)

				return got
			},
		},
		{
			name: "SignInState/readFamily/ListByFamily", ownLogger: true,
			call: func(ctx context.Context, err error, ctrl *gomock.Controller, opts []session.Option) error {
				reader := NewMockFamilyReader(ctrl)
				reader.EXPECT().ListByFamily(gomock.Any(), gomock.Any(), family, gomock.Any()).Return(nil, err).AnyTimes()
				m := portMust(session.New(append([]session.Option{
					session.WithStore(portFamilyStore{Store: NewMockStore(ctrl), FamilyReader: reader}),
				}, opts...)...))
				_, got := m.SignInState(ctx, testUser, family)

				return got
			},
		},
	}
}

func portMust[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}

	return v
}

// portOutcome is what a caller can tell of an answer: its text and which
// sentinels it matches.
func portOutcome(err error) string {
	return fmt.Sprintf("%v|list=%t|notfound=%t|canceled=%t|nil=%t",
		err, errors.Is(err, session.ErrListUnavailable), errors.Is(err, session.ErrNotFound),
		errors.Is(err, context.Canceled), err == nil)
}

// portWithin runs call and fails the test when it hangs or panics.
func portWithin(t *testing.T, call func() error) string {
	t.Helper()

	type result struct {
		out      string
		panicked any
	}

	done := make(chan result, 1)
	go func() {
		var r result
		defer func() {
			r.panicked = recover()
			done <- r
		}()
		r.out = portOutcome(call())
	}()

	select {
	case r := <-done:
		require.Nil(t, r.panicked, "the call panicked")

		return r.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the call did not return within 5s")

		return ""
	}
}

// portRun runs site against a store failing with err and reports the answer
// and the abort records seen on the manager's logger and on slog.Default().
func portRun(t *testing.T, site portSite, err error, cancelled bool) (answer string, own, def int) {
	t.Helper()

	ownRec, defRec := &portRecorder{}, &portRecorder{}
	prev := slog.Default()
	slog.SetDefault(slog.New(defRec))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx := t.Context()
	if cancelled {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		cancel()
	}

	ctrl := gomock.NewController(t)
	opts := []session.Option{session.WithLogger(slog.New(ownRec))}
	answer = portWithin(t, func() error { return site.call(ctx, err, ctrl, opts) })

	return answer, ownRec.count(), defRec.count()
}

func portRowChild() string {
	row := os.Getenv(portRowEnv)
	if row != "" {
		debug.SetMaxStack(64 << 20)
	}

	return row
}

func portInChild(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")
	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), portRowEnv+"=cycleMany")

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
	requireChildRan(t, out, "signins/cycleMany")
}

// TestPortErrors_SessionStoreHostile pins that a hostile error from the session
// store, or the family read, never hangs or panics a flow, and that the flow
// answers it as it answers a plain outage, with one abort record.
func TestPortErrors_SessionStoreHostile(t *testing.T) { //nolint:paralleltest // swaps slog.Default
	type testCase struct {
		name string
		err  func() error
		// reason is the abort reason expected; empty for a plain outage.
		reason string
	}

	child := portRowChild()
	ran := 0
	cases := []testCase{
		{name: "plain", err: func() error { return errors.New("db down") }},
		{name: "cycleOne", err: func() error { return &portErrCycleOne{} }, reason: "budget"},
		{name: "panicUnwrap", err: func() error { return &portErrPanicUnwrap{} }, reason: "panic"},
		{name: "cycleMany", err: func() error { return &portErrCycleMany{} }, reason: "budget"},
	}

	if child == "" {
		t.Run("cycleMany in a child process", func(t *testing.T) { portInChild(t) })
	}

	for _, site := range portSites() {
		for _, tc := range cases {
			if child != "" && tc.name != child {
				continue
			}
			if child == "" && tc.name == "cycleMany" {
				continue
			}
			for _, cancelled := range []bool{false, true} {
				if cancelled && site.earlyCtx {
					continue
				}
				name := site.name + "/" + tc.name
				if cancelled {
					name += "/cancelled"
				}
				t.Run(name, func(t *testing.T) {
					ran++
					plain, _, _ := portRun(t, site, errors.New("db down"), cancelled)
					got, own, def := portRun(t, site, tc.err(), cancelled)

					assert.Equal(t, plain, got, "a hostile error is answered as a plain outage")

					wantOwn, wantDef := 0, 0
					if tc.reason != "" {
						if site.ownLogger {
							wantOwn = 1
						} else {
							wantDef = 1
						}
					}
					assert.Equal(t, wantOwn, own, "records on the site's own logger")
					assert.Equal(t, wantDef, def, "records on slog.Default()")
				})
			}
		}
	}

	if child != "" && ran > 0 && !t.Failed() {
		fmt.Println(childRanMarker("signins/" + child))
	}
}
