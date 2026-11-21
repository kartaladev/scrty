package password_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
)

// portErrRowEnv names the row a child process runs. A cycle through
// Unwrap() []error overflows the stack, which is fatal and cannot be
// recovered, so only a child can watch for it.
const portErrRowEnv = "SCRTY_PASSWORD_PORTERR_ROW"

// portErrRanMarker prefixes the line a child prints on stdout, followed by the
// row's name, only after the row ran and passed. A child whose row name
// matches no case skips every row and exits 0, so only this line proves a row
// ran. Stdout reaches the parent's CombinedOutput without -v.
const portErrRanMarker = "SCRTY_PASSWORD_PORTERR_RAN: "

// requireChildRan fails unless one whole line of the child's output is the
// marker for row: not a substring, so a suffix or a prefix does not count.
func requireChildRan(t *testing.T, out []byte, row string) {
	t.Helper()

	want := portErrRanMarker + row

	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimRight(line, "\r") == want {
			return
		}
	}

	require.Fail(t, "the child never ran the row: its name matches no case",
		"row %q: no output line equals %q", row, want)
}

// hostileCycleOne contains itself through Unwrap() error.
type hostileCycleOne struct{}

func (*hostileCycleOne) Error() string   { return "cycle one: secret-hash" }
func (c *hostileCycleOne) Unwrap() error { return c }

// hostileCycleMany contains itself through Unwrap() []error.
type hostileCycleMany struct{}

func (*hostileCycleMany) Error() string     { return "cycle many: secret-hash" }
func (c *hostileCycleMany) Unwrap() []error { return []error{c} }

// hostilePanicUnwrap is a link whose Unwrap panics.
type hostilePanicUnwrap struct{}

func (hostilePanicUnwrap) Error() string { return "panic unwrap: secret-hash" }
func (hostilePanicUnwrap) Unwrap() error { panic("test: Unwrap panicked") }

// portErrRow is one error a port may return.
type portErrRow struct {
	name    string
	err     func() error
	hostile bool // the walk aborts on it, so the sanitizer records it
	child   bool // run in a child process: it overflows the stack unsanitized
}

func portErrRows() []portErrRow {
	return []portErrRow{
		{name: "plain outage", err: func() error { return errors.New("port: down") }},
		{name: "cycle through Unwrap() error", err: func() error { return &hostileCycleOne{} }, hostile: true},
		{name: "panicking Unwrap", err: func() error { return hostilePanicUnwrap{} }, hostile: true},
		{name: "cycle through Unwrap() []error", err: func() error { return &hostileCycleMany{} }, hostile: true, child: true},
	}
}

// eachPortErrRow runs body once per row. A child-process row runs in a child
// that exits 0 within a minute only if body passes there.
func eachPortErrRow(t *testing.T, body func(t *testing.T, row portErrRow)) {
	t.Helper()

	only := os.Getenv(portErrRowEnv)

	for _, row := range portErrRows() {
		switch {
		case only != "":
			if row.name == only {
				debug.SetMaxStack(64 << 20)
				body(t, row)

				if !t.Failed() && !t.Skipped() {
					_, _ = os.Stdout.WriteString(portErrRanMarker + row.name + "\n")
				}
			}
		case row.child:
			t.Run(row.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()

				top, _, _ := strings.Cut(t.Name(), "/")

				//nolint:gosec // G204: re-runs this test binary with this test's own name
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
				cmd.Env = append(os.Environ(), portErrRowEnv+"="+row.name)

				out, err := cmd.CombinedOutput()
				require.NoError(t, ctx.Err(), "the child did not finish within a minute")
				require.NoError(t, err, "the child failed:\n%s", headLines(out))
				requireChildRan(t, out, row.name)
			})
		default:
			t.Run(row.name, func(t *testing.T) { body(t, row) })
		}
	}
}

func headLines(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	return strings.Join(lines[:min(len(lines), 8)], "\n")
}

// within fails the test when call does not return in thirty seconds or panics.
// The bound only catches hangs; it is generous so a slow race build never trips it.
func within[T any](t *testing.T, call func() T) T {
	t.Helper()

	type result struct {
		v     T
		panic any
	}

	done := make(chan result, 1)

	go func() {
		var r result

		defer func() {
			r.panic = recover()
			done <- r
		}()

		r.v = call()
	}()

	select {
	case r := <-done:
		require.Nil(t, r.panic, "the call panicked")

		return r.v
	case <-time.After(30 * time.Second):
		require.FailNow(t, "the call did not return within thirty seconds")

		panic("unreachable")
	}
}

// isWithin is errors.Is, bounded: a cyclic chain fails the test instead of
// hanging it.
func isWithin(t *testing.T, err, target error) bool {
	t.Helper()

	return within(t, func() bool { return errors.Is(err, target) })
}

// abortRecords counts the sanitizer's records in h.
func abortRecords(h *recordingHandler) int {
	n := 0

	for _, r := range h.all() {
		if r.message == porterr.MsgClassificationAborted {
			n++
		}
	}

	return n
}

// swapDefaultLogger routes slog.Default() to a recorder until the test ends.
// The test must not run in parallel.
func swapDefaultLogger(t *testing.T) *recordingHandler {
	t.Helper()

	h := &recordingHandler{}
	previous := slog.Default()

	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(previous) })

	return h
}

// wantRecords asserts the sanitizer's record count for row on h.
func wantRecords(t *testing.T, row portErrRow, h *recordingHandler) {
	t.Helper()

	want := 0
	if row.hostile {
		want = 1
	}

	assert.Equal(t, want, abortRecords(h), "abort records")
}

func TestPortErrors_ReuseHistory(t *testing.T) {
	// The rows exercise the reuse rule's port calls, not the hash cost: a
	// cheap encoder keeps Change from paying for argon2id under -race.
	hP1 := mustEncode(t, plainEncoder{}, p1)

	newPolicy := func(t *testing.T, m password.History) (*password.Policy, *recordingHandler) {
		t.Helper()

		h := &recordingHandler{}
		p, err := reusePolicy(plainEncoder{}, m, 3,
			[]password.ReuseOption{password.WithReuseMatchers(plainEncoder{})},
			password.WithPolicyLogger(slog.New(h)))
		require.NoError(t, err)

		return p, h
	}

	type site struct {
		name  string
		drive func(t *testing.T, row portErrRow) (*recordingHandler, *recordingHandler, error)
	}

	sites := []site{
		{
			name: "RecentPasswords through Check",
			drive: func(t *testing.T, row portErrRow) (*recordingHandler, *recordingHandler, error) {
				def := swapDefaultLogger(t)
				m := NewMockHistory(gomock.NewController(t))
				m.EXPECT().RecentPasswords(gomock.Any(), gomock.Any(), 2).Return(nil, row.err())

				p, pol := newPolicy(t, m)

				got := within(t, func() error {
					return p.Check(t.Context(), &identity.Details{ID: "u1", Password: hP1}, p9)
				})

				return pol, def, got
			},
		},
		{
			name: "RetirePassword through Change",
			drive: func(t *testing.T, row portErrRow) (*recordingHandler, *recordingHandler, error) {
				def := swapDefaultLogger(t)
				m := NewMockHistory(gomock.NewController(t))
				m.EXPECT().RecentPasswords(gomock.Any(), gomock.Any(), 2).Return(nil, nil)
				m.EXPECT().RetirePassword(gomock.Any(), gomock.Any(), gomock.Any(), 2).Return(row.err())

				p, pol := newPolicy(t, m)

				w := &recordingWrite{}
				got := within(t, func() error {
					return p.Change(t.Context(), &identity.Details{ID: "u1", Password: hP1}, p9, w.write)
				})
				assert.Zero(t, w.calls, "a refused change writes nothing")

				return pol, def, got
			},
		},
	}

	for _, s := range sites {
		t.Run(s.name, func(t *testing.T) {
			eachPortErrRow(t, func(t *testing.T, row portErrRow) {
				pol, def, got := s.drive(t, row)

				// The outcome is the plain outage's: the history refusal.
				require.True(t, isWithin(t, got, password.ErrHistoryUnavailable), "errors.Is password.ErrHistoryUnavailable")
				assert.False(t, isWithin(t, got, password.ErrReused), "errors.Is password.ErrReused")
				assert.NotContains(t, got.Error(), "secret-hash")
				wantRecords(t, row, pol)
				assert.Zero(t, abortRecords(def), "the record goes to the policy's logger, not the default")

				if row.hostile {
					assert.True(t, isWithin(t, got, porterr.ErrUnwalkable), "errors.Is porterr.ErrUnwalkable")
				}
			})
		})
	}
}

func TestPortErrors_Breach(t *testing.T) {
	prefix, _ := sha1Hex(breachCandidate)

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type modeCase struct {
		name      string
		onFailure password.LookupFailure
		assert    func(t *testing.T, err error)
	}

	modes := []modeCase{
		{
			name:      "refuse",
			onFailure: password.Refuse,
			assert: func(t *testing.T, err error) {
				require.True(t, isWithin(t, err, password.ErrLookupUnavailable), "errors.Is password.ErrLookupUnavailable")
				assert.NotContains(t, err.Error(), "secret-hash")
			},
		},
		{
			name:      "accept",
			onFailure: password.Accept,
			assert:    func(t *testing.T, err error) { require.NoError(t, err) },
		},
	}

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			eachPortErrRow(t, func(t *testing.T, row portErrRow) {
				def := swapDefaultLogger(t)
				h := &recordingHandler{}

				src := NewMockBreachSource(gomock.NewController(t))
				src.EXPECT().Range(gomock.Any(), prefix).Return(nil, row.err())

				p, err := password.NewPolicy(
					password.WithPolicyLogger(slog.New(h)),
					password.Breached(src, m.onFailure))
				require.NoError(t, err)

				got := within(t, func() error { return p.Check(t.Context(), checkUser(), breachCandidate) })

				m.assert(t, got)
				wantRecords(t, row, h)
				assert.Zero(t, abortRecords(def), "the record goes to the policy's logger, not the default")

				if row.hostile && m.onFailure == password.Refuse {
					assert.True(t, isWithin(t, got, porterr.ErrUnwalkable), "errors.Is porterr.ErrUnwalkable")
				}
			})
		})
	}

	t.Run("a caller's hang-up still answers the context's error, without a record", func(t *testing.T) {
		h := &recordingHandler{}
		ctx := cancelled(t.Context())

		src := NewMockBreachSource(gomock.NewController(t))
		src.EXPECT().Range(gomock.Any(), prefix).Return(nil, context.Canceled)

		p, err := password.NewPolicy(
			password.WithPolicyLogger(slog.New(h)),
			password.Breached(src, password.Refuse))
		require.NoError(t, err)

		require.ErrorIs(t, p.Check(ctx, checkUser(), breachCandidate), context.Canceled)
		assert.Zero(t, abortRecords(h))
	})
}

func TestPortErrors_ProvisionerUpdate(t *testing.T) {
	replaced, upgraded := []byte("old"), []byte("new")
	user := &identity.Details{ID: "u1", Username: "ada", Password: replaced}

	newProv := func(t *testing.T, ret error) *MockUserProvisioner {
		prov := NewMockUserProvisioner(gomock.NewController(t))
		prov.EXPECT().Update(gomock.Any(), "ada", gomock.Any()).Return(nil, ret)

		return prov
	}

	t.Run("ConditionalProvisionerRehash", func(t *testing.T) {
		eachPortErrRow(t, func(t *testing.T, row portErrRow) {
			def := swapDefaultLogger(t)

			write, err := password.ConditionalProvisionerRehash(newProv(t, row.err()))
			require.NoError(t, err)

			got := within(t, func() error { return write(t.Context(), user, replaced, upgraded) })

			// The branch for a failing port: an error, never the silent nil.
			require.Error(t, got)
			assert.False(t, isWithin(t, got, identity.ErrNotUpdated), "errors.Is identity.ErrNotUpdated")
			assert.False(t, isWithin(t, got, identity.ErrUserNotFound), "errors.Is identity.ErrUserNotFound")
			assert.NotContains(t, got.Error(), "secret-hash")
			wantRecords(t, row, def)

			if row.hostile {
				assert.True(t, isWithin(t, got, porterr.ErrUnwalkable), "errors.Is porterr.ErrUnwalkable")
			}
		})
	})

	t.Run("ConditionalProvisionerRehash keeps its real sentinels", func(t *testing.T) {
		for _, ret := range []error{identity.ErrNotUpdated, identity.ErrUserNotFound} {
			def := swapDefaultLogger(t)

			write, err := password.ConditionalProvisionerRehash(newProv(t, ret))
			require.NoError(t, err)

			require.NoError(t, write(t.Context(), user, replaced, upgraded), ret.Error())
			assert.Zero(t, abortRecords(def))
		}
	})

	t.Run("ProvisionerWrite", func(t *testing.T) {
		eachPortErrRow(t, func(t *testing.T, row portErrRow) {
			def := swapDefaultLogger(t)

			write, err := password.ProvisionerWrite(newProv(t, row.err()))
			require.NoError(t, err)

			got := within(t, func() error { return write(t.Context(), user, upgraded, time.Now()) })

			require.Error(t, got)
			assert.NotContains(t, got.Error(), "secret-hash")
			wantRecords(t, row, def)

			if row.hostile {
				assert.True(t, isWithin(t, got, porterr.ErrUnwalkable), "errors.Is porterr.ErrUnwalkable")
			}
		})
	})

	t.Run("ProvisionerWrite returns a walkable error unchanged", func(t *testing.T) {
		def := swapDefaultLogger(t)
		plain := errors.New("store down")

		write, err := password.ProvisionerWrite(newProv(t, plain))
		require.NoError(t, err)

		assert.Same(t, plain, write(t.Context(), user, upgraded, time.Now()))
		assert.Zero(t, abortRecords(def))
	})
}
