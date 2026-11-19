package magiclink_test

// TestPortErrors_Links replaces slog.Default() for its duration, so it does not
// run in parallel, and it restores the logger it found.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/notify"
)

// mlPortErrSecret is the text every hostile error here returns, so a test can
// assert that no record and no returned error quotes it.
const mlPortErrSecret = "magiclink-port-secret-text"

// mlPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const mlPortErrRowEnv = "SCRTY_MAGICLINK_PORTERR_ROW"

// mlPortErrRanMarker prefixes the line a child prints on stdout, followed by
// the row's name, only after the row ran and passed.
const mlPortErrRanMarker = "SCRTY_MAGICLINK_PORTERR_RAN: "

// mlCycleOne contains itself through Unwrap() error.
type mlCycleOne struct{}

func (*mlCycleOne) Error() string   { return mlPortErrSecret }
func (c *mlCycleOne) Unwrap() error { return c }

// mlCycleMany contains itself through Unwrap() []error. Unsanitized, a stdlib
// walk overflows the stack fatally, so its rows run in a child process.
type mlCycleMany struct{}

func (*mlCycleMany) Error() string     { return mlPortErrSecret }
func (c *mlCycleMany) Unwrap() []error { return []error{c} }

// mlCycleWrapping is a cycle through Unwrap() []error whose first branch is
// a library sentinel: a stdlib errors.Is finds the sentinel and stops, so the
// cycle reads as that sentinel unless it is sanitized first.
type mlCycleWrapping struct{ sentinel error }

func (*mlCycleWrapping) Error() string     { return mlPortErrSecret }
func (c *mlCycleWrapping) Unwrap() []error { return []error{c.sentinel, c} }

// mlPanicUnwrap is an error whose Unwrap panics.
type mlPanicUnwrap struct{}

func (mlPanicUnwrap) Error() string { return mlPortErrSecret }
func (mlPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + mlPortErrSecret) }

// mlPanicNilUnwrap is an error whose Unwrap panics with nil.
type mlPanicNilUnwrap struct{}

func (mlPanicNilUnwrap) Error() string { return mlPortErrSecret }
func (mlPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// mlTypedNil is returned as a nil pointer inside a non-nil error.
type mlTypedNil struct{}

func (*mlTypedNil) Error() string { return mlPortErrSecret }

// mlFanOut is errors.Join(n, n) nested depth times: no cycle, but 2^depth
// paths for an unbounded walk.
func mlFanOut(depth int) error {
	err := errors.New(mlPortErrSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// errMLPortDown is the plain outage the parity runs fail with.
var errMLPortDown = errors.New("port: connection refused")

// mlReader is a random source that fails every read with err.
type mlReader struct{ err error }

func (r mlReader) Read([]byte) (int, error) { return 0, r.err }

// mlSyncBuffer is a bytes.Buffer safe for a logger on another goroutine.
type mlSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *mlSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *mlSyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// mlSite names the port call a row fails.
type mlSite string

const (
	mlResolver mlSite = "Request's address resolver"
	mlSender   mlSite = "Request's sender"
	mlRandom   mlSite = "Request's random source"
	mlCheck    mlSite = "Redeem's consumer check"
	mlLoader   mlSite = "Redeem's user loader"
)

// mlOutcome is what one call through a failing port produced. Every error
// classification is made inside the bound, so a hostile chain that reaches the
// caller raw fails the run as a hang rather than hanging the test.
type mlOutcome struct {
	result     magiclink.RequestResult
	attempts   int
	redemption magiclink.Redemption

	err         error
	text        string
	invalidLink bool
	unwalkable  bool
	plain       bool

	// unspent is whether the link survived the redemption.
	unspent bool

	// records are "LEVEL msg" for every record the manager's logger got that
	// is not the sanitizer's, and aborts the sanitizer's own records there.
	records []string
	aborts  []map[string]any
}

// runMLSite runs the call site names on ctx against a port that fails that
// call with portErr. It fails the test when the call hangs or lets a panic
// escape.
func runMLSite(t *testing.T, ctx context.Context, site mlSite, portErr error) mlOutcome {
	t.Helper()

	logs := &mlSyncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	tokens := testTokens(t)

	var (
		call  func() mlOutcome
		post  func(out *mlOutcome)
		count func() int
	)

	switch site {
	case mlResolver, mlSender, mlRandom:
		loader := activeLoader()
		opts := []magiclink.Option{magiclink.WithLogger(logger)}

		var sender interface {
			magiclinkSender
			Count() int
		}

		switch site {
		case mlResolver:
			loader = stubLoader{err: portErr}
			sender = &recordingSender{}
		case mlSender:
			sender = &failingSender{err: portErr}
		case mlRandom:
			sender = &recordingSender{}
			opts = append(opts, magiclink.WithRandom(mlReader{err: portErr}))
		}

		m, err := magiclink.New(tokens, loader, sender, "https://app.example", opts...)
		require.NoError(t, err)

		count = sender.Count
		call = func() mlOutcome {
			return mlOutcome{result: m.Request(ctx, "ada@example.com", "/home")}
		}
		post = func(out *mlOutcome) { out.attempts = count() }
	case mlCheck, mlLoader:
		loader := activeByID()
		if site == mlLoader {
			loader = stubLoader{err: portErr}
		}

		m, err := magiclink.New(tokens, loader, &recordingSender{}, "https://app.example",
			magiclink.WithLogger(logger), magiclink.WithSameDeviceBinding(false))
		require.NoError(t, err)

		presented := issueFor(t, tokens, "u-1")

		var checks []magiclink.Check
		if site == mlCheck {
			checks = append(checks, func(context.Context, identity.Principal, time.Time) error { return portErr })
		}

		call = func() mlOutcome {
			r, err := m.Redeem(ctx, presented, "", checks...)

			return mlOutcome{redemption: r, err: err}
		}
		post = func(out *mlOutcome) {
			_, err := tokens.Redeem(t.Context(), presented, "")
			out.unspent = err == nil
		}
	}

	type result struct {
		out      mlOutcome
		panicked bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				done <- result{panicked: true, value: recover()}
			}
		}()

		o := call()
		if o.err != nil {
			o.text = o.err.Error()
			o.invalidLink = errors.Is(o.err, magiclink.ErrInvalidLink)
			o.unwalkable = errors.Is(o.err, porterr.ErrUnwalkable)
			o.plain = errors.Is(o.err, errMLPortDown)
		}

		returned = true
		done <- result{out: o}
	}()

	var out mlOutcome

	select {
	case r := <-done:
		require.False(t, r.panicked, "a hostile port error escaped as a panic: %v", r.value)
		out = r.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the call, or its classification")
	}

	post(&out)

	for _, rec := range mlJSONRecords(t, logs.String()) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)

			continue
		}

		out.records = append(out.records, rec["level"].(string)+" "+rec["msg"].(string))
	}

	return out
}

// magiclinkSender is the sender port New takes.
type magiclinkSender interface {
	Send(ctx context.Context, msg notify.Message) error
	NonBlocking() bool
}

// mlJSONRecords decodes every JSON record in out.
func mlJSONRecords(t *testing.T, out string) []map[string]any {
	t.Helper()

	var records []map[string]any

	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}

		rec := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		records = append(records, rec)
	}

	return records
}

// mlDefaultRecords points slog.Default() at a JSON buffer until the test ends.
// The caller must not be parallel.
func mlDefaultRecords(t *testing.T) *mlSyncBuffer {
	t.Helper()

	buf := &mlSyncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return buf
}

// TestPortErrors_Links shows that a consumer port's hostile error — a cycle,
// a fan-out, a panicking Unwrap — is answered at every port call of the
// magic-link flow exactly as a plain outage of that port: the same uniform
// RequestResult, the same refusal, the same records, and one abort record on
// the manager's logger, none on slog.Default().
//
//nolint:paralleltest // replaces slog.Default()
func TestPortErrors_Links(t *testing.T) {
	only := os.Getenv(mlPortErrRowEnv)
	if only != "" {
		// A child lowers the stack limit, so an unbounded recursion overflows
		// quickly.
		debug.SetMaxStack(64 << 20)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type testCase struct {
		name string
		site mlSite
		err  error

		// ctx modifies the context every run of the row uses. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it overflows the
		// stack fatally.
		child bool

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got mlOutcome)
	}

	sameAsPlain := func(t *testing.T, site mlSite, plain, got mlOutcome) {
		t.Helper()

		assert.Len(t, got.result.BindingNonce, len(plain.result.BindingNonce), "the same uniform result")
		assert.Equal(t, plain.attempts, got.attempts, "the same messages sent")
		assert.Equal(t, plain.invalidLink, got.invalidLink, "the same ErrInvalidLink answer")
		assert.Equal(t, plain.err == nil, got.err == nil, "an error exactly when the plain outage has one")
		assert.Equal(t, plain.unspent, got.unspent, "the link spent or unspent alike")
		assert.Equal(t, plain.records, got.records, "the same records")
		assert.Zero(t, got.redemption, "a refused redemption establishes nothing")
		if site != mlCheck || got.unwalkable {
			// A consumer check's own error, typed nil included, is returned
			// unchanged with its own text; everything else is library text.
			assert.NotContains(t, got.text, mlPortErrSecret)
		}

		switch site {
		case mlResolver:
			require.Equal(t, []string{"ERROR magiclink: the submitted address could not be resolved"}, plain.records,
				"precondition: a plain outage logs a resolver failure")
			assert.Len(t, got.result.BindingNonce, magiclink.BindingNonceLength, "a decoy binding value")
			assert.Zero(t, got.attempts, "nothing sent")
		case mlSender:
			require.Equal(t, []string{"ERROR magiclink: the sign-in message could not be sent"}, plain.records,
				"precondition: a plain outage logs a send failure")
			assert.Len(t, got.result.BindingNonce, magiclink.BindingNonceLength)
		case mlRandom:
			require.Equal(t, []string{"ERROR magiclink: the random source failed and no link was issued"}, plain.records,
				"precondition: a plain outage logs a random-source failure")
			assert.Equal(t, magiclink.RequestResult{}, got.result, "the random-source outage's empty result")
			assert.Zero(t, got.attempts, "nothing sent")
		case mlCheck:
			require.True(t, plain.plain, "precondition: a plain consumer error is returned unchanged")
			assert.False(t, got.invalidLink, "a consumer check's error never becomes ErrInvalidLink")
			assert.True(t, got.unspent, "the refused link stays unspent")
		case mlLoader:
			require.True(t, plain.invalidLink, "precondition: a plain outage is ErrInvalidLink")
			require.Equal(t, []string{"ERROR magiclink: the link's user could not be loaded"}, plain.records,
				"precondition: a plain outage logs a loader failure")
			assert.Equal(t, magiclink.ErrInvalidLink.Error(), got.text)
			assert.True(t, got.unspent, "the refused link stays unspent")
		}
	}

	asOutage := func(site mlSite, reason string) func(t *testing.T, plain, got mlOutcome) {
		return func(t *testing.T, plain, got mlOutcome) {
			t.Helper()

			sameAsPlain(t, site, plain, got)

			if site == mlCheck {
				assert.True(t, got.unwalkable, "the check's hostile error is returned as the sanitizer's fault")
			}

			require.Len(t, got.aborts, 1, "one abort record, on the manager's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), mlPortErrSecret, "the record quotes the error")
		}
	}

	var cases []testCase

	for _, site := range []mlSite{mlResolver, mlSender, mlRandom, mlCheck, mlLoader} {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{name: prefix + "a cycle through Unwrap() error", site: site, err: &mlCycleOne{},
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", site: site, err: &mlCycleMany{}, child: true,
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a link whose Unwrap panics", site: site, err: mlPanicUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", site: site, err: mlPanicNilUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a join that fans out", site: site, err: mlFanOut(25),
				assert: asOutage(site, "budget")},
			testCase{
				name: prefix + "a cycle on a context the caller cancelled is an outage",
				site: site, err: &mlCycleOne{}, ctx: cancelled,
				assert: asOutage(site, "budget"),
			},
			testCase{
				name: prefix + "a typed-nil root walks to the end and is answered as an outage",
				site: site, err: (*mlTypedNil)(nil),
				assert: func(t *testing.T, plain, got mlOutcome) {
					t.Helper()

					sameAsPlain(t, site, plain, got)
					assert.False(t, got.unwalkable, "a walk that completes passes the error through")
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
				},
			},
		)
	}

	// A cycle whose first branch is the sentinel the site's not-found or
	// own-refusal branch tests for: unsanitized, errors.Is finds the sentinel
	// and takes that branch, an answer a plain outage never gets.
	cases = append(cases,
		testCase{
			name: string(mlResolver) + ": a cycle wrapping ErrUserNotFound is an outage, not an unknown address",
			site: mlResolver, err: &mlCycleWrapping{sentinel: identity.ErrUserNotFound},
			assert: asOutage(mlResolver, "budget"),
		},
		testCase{
			name: string(mlLoader) + ": a cycle wrapping ErrUserNotFound is an outage, not a deleted user",
			site: mlLoader, err: &mlCycleWrapping{sentinel: identity.ErrUserNotFound},
			assert: asOutage(mlLoader, "budget"),
		},
		testCase{
			name: string(mlCheck) + ": a cycle wrapping ErrInvalidLink is the fault, not ErrInvalidLink",
			site: mlCheck, err: &mlCycleWrapping{sentinel: magiclink.ErrInvalidLink},
			assert: asOutage(mlCheck, "budget"),
		},
	)

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				mlPortErrInChild(t, tc.name)

				return
			}

			defaults := mlDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runMLSite(t, ctx, tc.site, errMLPortDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runMLSite(t, ctx, tc.site, tc.err)
			tc.assert(t, plain, got)

			for _, rec := range mlJSONRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(mlPortErrRanMarker + tc.name + "\n")
			}
		})
	}
}

// mlPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints, as
// one whole line, the marker that shows it ran the row: a stack overflow is
// fatal and only a child can watch for one.
func mlPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), mlPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker line after the row
	// passed. The line must equal the marker, not merely contain it.
	want := mlPortErrRanMarker + row

	for _, line := range lines {
		if strings.TrimRight(line, "\r") == want {
			return
		}
	}

	require.Fail(t, "the child never ran the row: its name matches no case",
		"row %q: no output line equals %q", row, want)
}
