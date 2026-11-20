package mfa_test

// TestPortErrors_Reset replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/notify"
)

// rstSecret is the text every hostile error here returns.
const rstSecret = "reset-port-secret-text"

// rstRowEnv names the row a child process runs. It is empty in the parent.
const rstRowEnv = "SCRTY_MFA_RESET_PORTERR_ROW"

// rstRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const rstRanMarker = "SCRTY_MFA_RESET_PORTERR_RAN: "

var errRstDown = errors.New("reset port: connection refused")

type rstCycleOne struct{}

func (*rstCycleOne) Error() string   { return rstSecret }
func (c *rstCycleOne) Unwrap() error { return c }

type rstCycleMany struct{}

func (*rstCycleMany) Error() string     { return rstSecret }
func (c *rstCycleMany) Unwrap() []error { return []error{c} }

type rstPanicUnwrap struct{}

func (rstPanicUnwrap) Error() string { return rstSecret }
func (rstPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + rstSecret) }

type rstPanicNilUnwrap struct{}

func (rstPanicNilUnwrap) Error() string { return rstSecret }
func (rstPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

type rstTypedNil struct{}

func (*rstTypedNil) Error() string { return rstSecret }

func rstFanOut(depth int) error {
	err := errors.New(rstSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// rstSite names the reset's port call a row fails.
type rstSite string

const (
	rstRemove   rstSite = "RemoveEnrolment"
	rstSessions rstSite = "DeleteByUser"
	rstGrants   rstSite = "RevokeUserGrants"
	rstLoad     rstSite = "LoadByUserID"
	rstContact  rstSite = "the contact resolver"
	rstSend     rstSite = "Send"
)

var rstSites = []rstSite{rstRemove, rstSessions, rstGrants, rstLoad, rstContact, rstSend}

// rstOutcome is what one reset through a failing port produced.
type rstOutcome struct {
	err      error
	text     string
	calls    []string
	panicked any
	hung     bool
}

// runRstSite runs a full reset with every step on and site failing with
// portErr. It is bounded: a hang is reported, not waited for.
func runRstSite(t *testing.T, ctx context.Context, site rstSite, portErr error) rstOutcome {
	t.Helper()

	ctrl := gomock.NewController(t)
	remover := NewMockEnrolmentRemover(ctrl)
	sessions := NewMockSessionRevoker(ctrl)
	grants := NewMockGrantRevoker(ctrl)
	users := NewMockUserLoader(ctrl)
	sender := NewMockSender(ctrl)

	var (
		mu    sync.Mutex
		calls []string
	)

	step := func(name string, failing rstSite) error {
		mu.Lock()
		calls = append(calls, name)
		mu.Unlock()

		if site == failing {
			return portErr
		}

		return nil
	}

	remover.EXPECT().RemoveEnrolment(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) error { return step("remove", rstRemove) })
	sessions.EXPECT().DeleteByUser(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) error { return step("sessions", rstSessions) })
	grants.EXPECT().RevokeUserGrants(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID, string) error { return step("grants", rstGrants) })
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
			if err := step("load", rstLoad); err != nil {
				return nil, err
			}

			return &identity.Details{ID: "u-1", Username: "ada@example.com"}, nil
		})
	sender.EXPECT().Send(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, notify.Message) error { return step("send", rstSend) })

	deps := mfa.ResetDeps{
		Enrolments: []mfa.EnrolmentRemover{remover}, Sessions: sessions, Grants: grants, Users: users, Sender: sender,
		Contact: func(context.Context, *identity.Details) (string, error) {
			if err := step("contact", rstContact); err != nil {
				return "", err
			}

			return "ada@example.com", nil
		},
	}

	done := make(chan rstOutcome, 1)

	go func() {
		var out rstOutcome

		defer func() {
			out.panicked = recover()
			mu.Lock()
			out.calls = slices.Clone(calls)
			mu.Unlock()
			done <- out
		}()

		out.err = mfa.ResetEnrolment(ctx, "u-1", deps)
		if out.err != nil {
			out.text = out.err.Error()
		}
	}()

	select {
	case out := <-done:
		return out
	case <-time.After(10 * time.Second):
		return rstOutcome{hung: true}
	}
}

type rstSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *rstSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *rstSyncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	return append([]byte(nil), b.buf.Bytes()...)
}

// rstDefaultRecords points slog.Default() at a JSON buffer until the test ends.
func rstDefaultRecords(t *testing.T) *rstSyncBuffer {
	t.Helper()

	buf := &rstSyncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return buf
}

func rstAborts(t *testing.T, out []byte) []map[string]any {
	t.Helper()

	var records []map[string]any

	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}

		rec := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &rec))

		if rec["msg"] == porterr.MsgClassificationAborted {
			records = append(records, rec)
		}
	}

	return records
}

// TestPortErrors_Reset pins that a reset port failing with an error whose chain
// cannot be walked ends exactly as a plain outage does: the same returned text,
// the same steps run and skipped. The reset holds no logger, so the one abort
// record goes to slog.Default().
func TestPortErrors_Reset(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(rstRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type testCase struct {
		name string
		site rstSite
		err  error
		ctx  func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it overflows the
		// stack fatally.
		child bool

		// aborts is the number of abort records expected on slog.Default().
		aborts int
		// reason is the abort record's reason, when aborts is 1.
		reason string
	}

	var cases []testCase

	for _, site := range rstSites {
		p := string(site) + ": "

		cases = append(cases,
			testCase{name: p + "a cycle through Unwrap() error", site: site, err: &rstCycleOne{}, aborts: 1, reason: "budget"},
			testCase{name: p + "a cycle through Unwrap() []error", site: site, err: &rstCycleMany{}, child: true,
				aborts: 1, reason: "budget"},
			testCase{name: p + "a link whose Unwrap panics", site: site, err: rstPanicUnwrap{}, aborts: 1, reason: "panic"},
			testCase{name: p + "a link whose Unwrap panics with nil", site: site, err: rstPanicNilUnwrap{},
				aborts: 1, reason: "panic"},
			testCase{name: p + "a join that fans out", site: site, err: rstFanOut(25), aborts: 1, reason: "budget"},
			testCase{name: p + "a cycle on a context the caller cancelled", site: site, err: &rstCycleOne{},
				ctx: cancelled, aborts: 1, reason: "budget"},
			testCase{name: p + "a typed-nil root walks to the end", site: site, err: (*rstTypedNil)(nil)},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				rstPortErrInChild(t, tc.name)

				return
			}

			defaults := rstDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runRstSite(t, ctx, tc.site, errRstDown)
			require.False(t, plain.hung)
			require.Nil(t, plain.panicked)
			require.Error(t, plain.err, "the plain outage is returned")
			require.ErrorIs(t, plain.err, errRstDown)
			require.Empty(t, rstAborts(t, defaults.Bytes()), "a plain outage writes no abort record")

			got := runRstSite(t, ctx, tc.site, tc.err)
			require.False(t, got.hung, "the reset hung on a hostile error")
			require.Nil(t, got.panicked, "the reset panicked on a hostile error")

			require.Error(t, got.err)
			assert.Equal(t, plain.text, got.text, "the same fixed text as a plain outage")
			assert.NotContains(t, got.text, rstSecret)
			assert.Equal(t, plain.calls, got.calls, "the same steps run and the same skipped")

			aborts := rstAborts(t, defaults.Bytes())
			require.Len(t, aborts, tc.aborts)

			if tc.aborts == 1 {
				require.ErrorIs(t, got.err, porterr.ErrUnwalkable, "the fixed error, not the hostile one")
				assert.Equal(t, tc.reason, aborts[0]["reason"])

				raw, err := json.Marshal(aborts[0])
				require.NoError(t, err)
				assert.NotContains(t, string(raw), rstSecret)
			}

			if only != "" && !t.Failed() {
				_, _ = os.Stdout.WriteString(rstRanMarker + tc.name + "\n")
			}
		})
	}
}

// rstPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints a line
// equal to the marker proving it ran the row.
func rstPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), rstRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	marker := rstRanMarker + row
	ran := slices.ContainsFunc(strings.Split(string(out), "\n"), func(line string) bool {
		return strings.TrimSuffix(line, "\r") == marker
	})
	require.True(t, ran, "the child never ran row %q: no output line equals %q:\n%s", row, marker, string(out))
}
