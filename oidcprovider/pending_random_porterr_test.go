package oidcprovider_test

// TestPortErrors_PendingRandom replaces slog.Default() for its duration, so it
// does not run in parallel, and it restores the logger it found.

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// prndRowEnv names the row a child process runs. It is empty in the parent.
const prndRowEnv = "SCRTY_OIDCPROVIDER_RANDOM_PORTERR_ROW"

// prndRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const prndRanMarker = "SCRTY_OIDCPROVIDER_RANDOM_PORTERR_RAN: "

// prndSecret is text no record and no response may quote.
const prndSecret = "prnd-secret: ana@example.com" //nolint:gosec // G101: a fixture, not a credential

var errPrndOutage = errors.New("prnd: entropy source down, " + prndSecret)

type prndCycleOne struct{}

func (*prndCycleOne) Error() string   { return prndSecret }
func (c *prndCycleOne) Unwrap() error { return c }

type prndCycleMany struct{}

func (*prndCycleMany) Error() string     { return prndSecret }
func (c *prndCycleMany) Unwrap() []error { return []error{c} }

type prndPanicUnwrap struct{}

func (prndPanicUnwrap) Error() string { return prndSecret }
func (prndPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + prndSecret) }

type prndPanicNilUnwrap struct{}

func (prndPanicNilUnwrap) Error() string { return prndSecret }
func (prndPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

type prndTypedNil struct{}

func (*prndTypedNil) Error() string { return prndSecret }

func prndFanOut(depth int) error {
	err := errors.New(prndSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// prndReader reads from crypto/rand until armed, then fails every read.
type prndReader struct {
	armed atomic.Bool
	err   error
}

func (r *prndReader) Read(p []byte) (int, error) {
	if r.armed.Load() {
		return 0, r.err
	}

	return crand.Read(p)
}

// prndOutcome is what one Authorize through a failing random source produced.
type prndOutcome struct {
	failed     bool
	unwalkable bool
	errText    string
	at         string
	errorCode  string
	hasFlow    bool

	aborts   []map[string]any // on the provider's logger
	defaults []map[string]any // on slog.Default()
}

// prndRun authorizes a request while the provider's random source fails with
// portErr. It fails the test when the call hangs or lets a panic escape.
func prndRun(t *testing.T, portErr error) prndOutcome {
	t.Helper()

	defaults := &lockedBuffer{}
	slog.SetDefault(slog.New(slog.NewJSONHandler(defaults, &slog.HandlerOptions{Level: slog.LevelDebug})))

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	registry, err := oidcprovider.NewMemoryRegistry(authzClients())
	require.NoError(t, err)

	reader := &prndReader{err: portErr}

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     registry,
		Keys:         logoutSigningKeys(),
		Users:        activeUsers(t),
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	},
		oidcprovider.WithLogger(logger),
		oidcprovider.WithRandom(reader),
		oidcprovider.WithIDGenerator(id.NewV7Generator()),
	)
	require.NoError(t, err)

	reader.armed.Store(true)

	out := pe7eBounded(t, func() prndOutcome {
		var o prndOutcome

		res, err := p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: authzParams()})
		o.hasFlow = res.FlowSecret != ""

		if u, perr := url.Parse(res.Location); perr == nil && res.Location != "" {
			o.at = u.Scheme + "://" + u.Host + u.Path
			o.errorCode = u.Query().Get("error")
			assert.NotContains(t, res.Location, prndSecret)
		}

		if err != nil {
			o.failed = true
			o.errText = err.Error()
			o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
		}

		return o
	})

	reader.armed.Store(false)

	for _, rec := range pe7bJSONRecords(t, logs.String()) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)
		}
	}

	for _, rec := range pe7bJSONRecords(t, defaults.String()) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.defaults = append(out.defaults, rec)
		}
	}

	return out
}

// TestPortErrors_PendingRandom pins that an error the provider's random source
// returns, whose chain cannot be walked, while a request is parked, is
// answered as a plain error from it is (the requester is sent back to its
// redirect URI with server_error), with one abort record on the provider's
// logger, none on slog.Default(), and no hang or panic.
func TestPortErrors_PendingRandom(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(prndRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	type testCase struct {
		name   string
		err    error
		reason string
		child  bool

		assert func(t *testing.T, plain, got prndOutcome)
	}

	asOutage := func(reason string) func(t *testing.T, plain, got prndOutcome) {
		return func(t *testing.T, plain, got prndOutcome) {
			t.Helper()

			require.Equal(t, "server_error", plain.errorCode, "precondition: a plain error answers server_error")

			assert.Equal(t, plain.failed, got.failed, "the same error, or none, as for a plain error")
			assert.Equal(t, plain.at, got.at, "the same redirect")
			assert.Equal(t, plain.errorCode, got.errorCode, "the same error code")
			assert.Equal(t, plain.hasFlow, got.hasFlow, "the same flow secret, or none")

			require.Len(t, got.aborts, 1, "one abort record, on the provider's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])
			assert.Empty(t, got.defaults, "no abort record on slog.Default()")

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), prndSecret, "the record quotes the error")
		}
	}

	walked := func(t *testing.T, plain, got prndOutcome) {
		t.Helper()

		assert.Equal(t, plain.failed, got.failed)
		assert.Equal(t, plain.at, got.at)
		assert.Equal(t, plain.errorCode, got.errorCode)
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
		assert.Empty(t, got.defaults, "a walk that completes writes no abort record")
	}

	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: &prndCycleOne{}, reason: "budget"},
		{name: "a cycle through Unwrap() []error", err: &prndCycleMany{}, reason: "budget", child: true},
		{name: "a link whose Unwrap panics", err: prndPanicUnwrap{}, reason: "panic"},
		{name: "a link whose Unwrap panics with nil", err: prndPanicNilUnwrap{}, reason: "panic"},
		{name: "a join that fans out", err: prndFanOut(25), reason: "budget"},
	}

	for i := range cases {
		cases[i].assert = asOutage(cases[i].reason)
	}

	cases = append(cases,
		testCase{name: "a typed-nil root walks to the end and is answered as an error", err: (*prndTypedNil)(nil), assert: walked},
		testCase{name: "a plain error, against itself", err: errPrndOutage, assert: walked},
	)

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				prndInChild(t, tc.name)

				return
			}

			plain := prndRun(t, errPrndOutage)
			require.Empty(t, plain.aborts, "a plain error writes no abort record")
			require.Empty(t, plain.defaults, "a plain error writes no abort record")

			got := prndRun(t, tc.err)
			tc.assert(t, plain, got)

			if only != "" && !t.Failed() {
				_, _ = os.Stdout.WriteString(prndRanMarker + tc.name + "\n")
			}
		})
	}
}

// prndInChild re-runs the top-level test in a child process limited to row,
// and fails unless the child exits 0 within a minute and prints a line equal
// to the row's marker.
func prndInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), prndRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	want := prndRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
