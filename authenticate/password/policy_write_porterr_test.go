package password_test

import (
	"context"
	"errors"
	"fmt"
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

// hostilePanicNilUnwrap is a link whose Unwrap panics with a nil value.
type hostilePanicNilUnwrap struct{}

func (hostilePanicNilUnwrap) Error() string { return "panic nil: secret-hash" }
func (hostilePanicNilUnwrap) Unwrap() error { panic(nil) }

// hostileFanOut is a chain of nodes whose every level holds two children, so
// a walk that follows every path never finishes.
type hostileFanOut struct{ depth int }

func (hostileFanOut) Error() string { return "fan out: secret-hash" }

func (f hostileFanOut) Unwrap() []error {
	if f.depth == 0 {
		return nil
	}

	next := hostileFanOut{depth: f.depth - 1}

	return []error{next, next}
}

// typedNilErr is a nil pointer held in an error interface. Its text is fixed
// and it has no Unwrap, so the chain is walkable.
type typedNilErr struct{}

func (*typedNilErr) Error() string { return "typed nil" }

// writePortErrRow is one error a consumer's function may return, with the
// context it runs under.
type writePortErrRow struct {
	portErrRow

	cancel bool // run under an already cancelled context
}

func writePortErrRows() []writePortErrRow {
	base := portErrRows()
	rows := make([]writePortErrRow, 0, len(base)+6)

	for _, r := range base {
		rows = append(rows, writePortErrRow{portErrRow: r})
	}

	typedNil := func() error {
		var e *typedNilErr

		return e
	}

	return append(rows,
		writePortErrRow{portErrRow: portErrRow{name: "fan-out", err: func() error { return hostileFanOut{depth: 40} }, hostile: true}},
		writePortErrRow{portErrRow: portErrRow{name: "panic(nil) in Unwrap", err: func() error { return hostilePanicNilUnwrap{} }, hostile: true}},
		writePortErrRow{portErrRow: portErrRow{name: "typed nil", err: typedNil}},
		writePortErrRow{portErrRow: portErrRow{name: "plain outage, cancelled ctx", err: func() error { return errors.New("port: down") }}, cancel: true},
		writePortErrRow{portErrRow: portErrRow{name: "cycle through Unwrap() error, cancelled ctx", err: func() error { return &hostileCycleOne{} }, hostile: true}, cancel: true},
		writePortErrRow{portErrRow: portErrRow{name: "cycle through Unwrap() []error, cancelled ctx", err: func() error { return &hostileCycleMany{} }, hostile: true, child: true}, cancel: true},
	)
}

// eachWritePortErrRow is eachPortErrRow over writePortErrRows.
func eachWritePortErrRow(t *testing.T, body func(t *testing.T, row writePortErrRow)) {
	t.Helper()

	only := os.Getenv(portErrRowEnv)

	for _, row := range writePortErrRows() {
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

func (r writePortErrRow) ctx(t *testing.T) context.Context {
	t.Helper()

	if !r.cancel {
		return t.Context()
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	return ctx
}

// TestPortErrors_ChangeWrite pins that Change reads the consumer's write
// function's error through the boundary sanitizer: a hostile error comes back
// as the library's fixed error, leaves the history exactly as a plain error
// leaves it, and a walkable error comes back unchanged.
func TestPortErrors_ChangeWrite(t *testing.T) {
	hP1 := mustEncode(t, plainEncoder{}, p1)

	eachWritePortErrRow(t, func(t *testing.T, row writePortErrRow) {
		def := swapDefaultLogger(t)
		pol := &recordingHandler{}

		// The same history calls for every row: the write comes after the
		// retirement, so a hostile error must not change how many ran.
		m := NewMockHistory(gomock.NewController(t))
		m.EXPECT().RecentPasswords(gomock.Any(), gomock.Any(), 2).Return(nil, nil)
		m.EXPECT().RetirePassword(gomock.Any(), gomock.Any(), gomock.Any(), 2).Return(nil).Times(1)

		p, err := reusePolicy(plainEncoder{}, m, 3,
			[]password.ReuseOption{password.WithReuseMatchers(plainEncoder{})},
			password.WithPolicyLogger(slog.New(pol)))
		require.NoError(t, err)

		sent := row.err()
		w := &recordingWrite{fail: sent}

		got := within(t, func() error {
			return p.Change(row.ctx(t), &identity.Details{ID: "u1", Password: hP1}, p9, w.write)
		})

		require.Error(t, got)
		assert.Equal(t, 1, w.calls, "the write ran once")
		assert.False(t, isWithin(t, got, password.ErrPasswordRejected), "errors.Is password.ErrPasswordRejected")
		assert.NotContains(t, got.Error(), "secret-hash")
		wantRecords(t, row.portErrRow, pol)
		assert.Zero(t, abortRecords(def), "the record goes to the policy's logger, not the default")

		if row.hostile {
			assert.True(t, isWithin(t, got, porterr.ErrUnwalkable), "errors.Is porterr.ErrUnwalkable")
		} else {
			assert.Same(t, sent, got, "a walkable error comes back unchanged")
		}
	})
}

// TestPortErrors_ChangeWrite_WalkableWrapped pins that a wrapped sentinel
// from the write function still matches it after the boundary.
func TestPortErrors_ChangeWrite_WalkableWrapped(t *testing.T) {
	errStore := errors.New("store: down")
	def := swapDefaultLogger(t)
	pol := &recordingHandler{}

	p, err := password.NewPolicy(password.WithEncoder(plainEncoder{}), password.WithPolicyLogger(slog.New(pol)))
	require.NoError(t, err)

	w := &recordingWrite{fail: fmt.Errorf("write: %w", errStore)}
	got := p.Change(t.Context(), &identity.Details{ID: "u1"}, p9, w.write)

	require.ErrorIs(t, got, errStore)
	assert.Zero(t, abortRecords(pol))
	assert.Zero(t, abortRecords(def))
}

// TestPortErrors_ContextWords pins that Check and Change read the consumer's
// context-words function's error through the boundary sanitizer: a hostile
// error takes the plain dependency-failure branch, as a fixed error.
func TestPortErrors_ContextWords(t *testing.T) {
	type site struct {
		name  string
		drive func(t *testing.T, p *password.Policy, row writePortErrRow) (error, int)
	}

	sites := []site{
		{
			name: "Check",
			drive: func(t *testing.T, p *password.Policy, row writePortErrRow) (error, int) {
				return within(t, func() error { return p.Check(row.ctx(t), checkUser(), p9) }), 0
			},
		},
		{
			name: "Change",
			drive: func(t *testing.T, p *password.Policy, row writePortErrRow) (error, int) {
				w := &recordingWrite{}
				got := within(t, func() error {
					return p.Change(row.ctx(t), &identity.Details{ID: "u1"}, p9, w.write)
				})

				return got, w.calls
			},
		},
	}

	for _, s := range sites {
		t.Run(s.name, func(t *testing.T) {
			eachWritePortErrRow(t, func(t *testing.T, row writePortErrRow) {
				def := swapDefaultLogger(t)
				pol := &recordingHandler{}
				sent := row.err()

				p, err := password.NewPolicy(
					password.WithEncoder(plainEncoder{}),
					password.WithPolicyLogger(slog.New(pol)),
					password.ContextWords(func(context.Context, *identity.Details) ([]string, error) { return nil, sent }),
				)
				require.NoError(t, err)

				got, writes := s.drive(t, p, row)

				require.Error(t, got)
				assert.Zero(t, writes, "a failed check writes nothing")

				var rejected password.RejectedError

				assert.False(t, errors.As(got, &rejected), "the failure is not a RejectedError")
				assert.NotContains(t, got.Error(), "secret-hash")
				wantRecords(t, row.portErrRow, pol)
				assert.Zero(t, abortRecords(def), "the record goes to the policy's logger, not the default")

				if row.hostile {
					assert.True(t, isWithin(t, got, porterr.ErrUnwalkable), "errors.Is porterr.ErrUnwalkable")
				} else {
					assert.Same(t, sent, got, "a walkable error comes back unchanged")
				}
			})
		})
	}
}
