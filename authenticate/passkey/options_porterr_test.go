package passkey_test

// TestPortErrors_Options replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found. The hostile error
// types, the outage and the default-logger capture are those of the login
// rows (login_porterr_test.go, register_porterr_test.go).

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime/debug"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/internal/porterr"
)

// poptRowEnv names the row a child process runs. It is empty in the parent.
const poptRowEnv = "SCRTY_PASSKEY_OPTIONS_PORTERR_ROW"

// poptRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const poptRanMarker = "SCRTY_PASSKEY_OPTIONS_PORTERR_RAN: "

// poptChildDeadline bounds one child process.
const poptChildDeadline = time.Minute

// poptSite names the consumer call a row fails.
type poptSite string

const (
	poptLoginOptions    poptSite = "BeginLogin's RequestOptions"
	poptMFAOptions      poptSite = "BeginChallenge's RequestOptions"
	poptCreationOptions poptSite = "BeginRegistration's CreationOptions"
	poptLoginCheck      poptSite = "Authenticate's login check"
)

// poptFailing fails the call its site names, once armed, with err; the failing
// call first runs cancel when it is set.
type poptFailing struct {
	err    error
	cancel context.CancelFunc

	armed atomic.Bool
}

func (p *poptFailing) fail() error {
	if !p.armed.Load() {
		return nil
	}

	if p.cancel != nil {
		p.cancel()
	}

	return p.err
}

type poptVerifier struct {
	passkey.Verifier

	site poptSite
	p    *poptFailing
}

func (v poptVerifier) RequestOptions(ctx context.Context, in passkey.RequestInput) (json.RawMessage, error) {
	if v.site == poptLoginOptions || v.site == poptMFAOptions {
		if err := v.p.fail(); err != nil {
			return nil, err
		}
	}

	return v.Verifier.RequestOptions(ctx, in)
}

func (v poptVerifier) CreationOptions(ctx context.Context, in passkey.CreationInput) (json.RawMessage, error) {
	if v.site == poptCreationOptions {
		if err := v.p.fail(); err != nil {
			return nil, err
		}
	}

	return v.Verifier.CreationOptions(ctx, in)
}

// poptOutcome is what one call through a failing consumer produced.
type poptOutcome struct {
	err      error
	text     string
	panicked bool

	// same is true when the returned error is the very error the consumer
	// returned.
	same bool
	// unwalkable is true when the returned error matches porterr.ErrUnwalkable.
	unwalkable  bool
	authFailed  bool
	interrupted bool
	aborts      []map[string]any
}

// runOptionsSite runs the call site names with the consumer failing it with
// portErr. When cancelDuring is set the failing call cancels the caller's
// context first. It fails the test when the call hangs or panics.
func runOptionsSite(t *testing.T, site poptSite, portErr error, cancelDuring bool) poptOutcome {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	failing := &poptFailing{err: portErr}
	if cancelDuring {
		failing.cancel = cancel
	}

	var (
		logs *logBuffer
		call func() error
	)

	switch site {
	case poptCreationOptions:
		f := newFixture(t)
		f.deps.Verifier = poptVerifier{Verifier: f.deps.Verifier, site: site, p: failing}
		logs = &logBuffer{}
		m := f.manager(t, passkey.WithLogger(logs.logger()))
		s := enrolmentSession("sess-a", "u-1")

		call = func() error {
			_, err := m.BeginRegistration(ctx, s, passkey.RegistrationContext{})

			return err
		}
	default:
		e := newLoginEnv(t, nil)
		e.f.deps.Verifier = poptVerifier{Verifier: e.f.deps.Verifier, site: site, p: failing}

		var opts []passkey.Option
		if site == poptLoginCheck {
			opts = append(opts, passkey.WithLoginCheck(func(context.Context, passkey.LoginFacts) error {
				return failing.fail()
			}))
		}

		m := e.manager(t, opts...)
		logs = e.logs

		switch site {
		case poptLoginOptions:
			call = func() error {
				_, err := m.BeginLogin(ctx, e.binding)

				return err
			}
		case poptMFAOptions:
			call = func() error {
				_, err := m.MFAMethod().BeginChallenge(ctx, "u-1", slotChallenge)

				return err
			}
		default:
			body := assertion(e.begin(t), nil)
			call = func() error {
				_, err := m.Authenticate(ctx, body, e.binding)

				return err
			}
		}
	}

	failing.armed.Store(true)

	done := make(chan poptOutcome, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				_ = recover()
				done <- poptOutcome{panicked: true}
			}
		}()

		err := call()

		// Classified inside the bound: a hostile chain that reaches the caller
		// raw hangs here, and fails the run as a hang.
		out := poptOutcome{err: err}
		if err != nil {
			out.text = err.Error()
			out.same = err == portErr //nolint:errorlint // identity of the consumer's error
			out.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
			out.authFailed = errors.Is(err, authenticate.ErrAuthenticationFailed)
			out.interrupted = errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		}

		returned = true
		done <- out
	}()

	var out poptOutcome

	select {
	case out = <-done:
		require.False(t, out.panicked, "a hostile consumer error escaped as a panic")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile consumer error hung the call, or its classification")
	}

	for _, rec := range plogRecords(t, logs.String()) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// TestPortErrors_Options pins that a consumer's Verifier failing a begin's
// options, or the consumer's login check failing a login, with an error whose
// chain cannot be walked, returns the fixed fault in its place: walkable, so a
// consumer's stdlib errors.Is on it cannot hang, quoting nothing of the
// consumer's. A walkable error, a plain outage and a typed nil root among
// them, comes back unchanged, and writes no record. A hostile error writes
// exactly one abort record, on the manager's logger and never on
// slog.Default(). An Is that panics only for one sentinel is accepted by
// design: the sanitizer calls Unwrap only.
func TestPortErrors_Options(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(poptRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name string
		site poptSite
		err  error

		cancelDuring bool

		// child runs the row in a child process: unsanitized, it overflows the
		// stack fatally.
		child bool

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got poptOutcome)
	}

	sameClass := func(t *testing.T, plain, got poptOutcome) {
		t.Helper()

		require.Error(t, got.err)
		assert.Equal(t, plain.authFailed, got.authFailed)
		assert.Equal(t, plain.interrupted, got.interrupted)
	}

	asFault := func(reason string) func(t *testing.T, plain, got poptOutcome) {
		return func(t *testing.T, plain, got poptOutcome) {
			t.Helper()

			sameClass(t, plain, got)

			assert.True(t, got.unwalkable, "the fixed fault, matching ErrUnwalkable")
			assert.False(t, got.same, "the consumer's error travelled further")
			assert.NotEqual(t, plain.text, got.text, "the fixed text, not the outage's")
			assert.NotContains(t, got.text, plogSecret, "the fault quotes the consumer's error")

			require.Len(t, got.aborts, 1, "one abort record, on the manager's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), plogSecret, "the record quotes the error")
		}
	}

	unchanged := func(t *testing.T, plain, got poptOutcome) {
		t.Helper()

		sameClass(t, plain, got)

		assert.True(t, got.same, "a walkable error comes back unchanged")
		assert.False(t, got.unwalkable)
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	sites := []poptSite{poptLoginOptions, poptMFAOptions, poptCreationOptions, poptLoginCheck}

	var cases []testCase

	for _, site := range sites {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{name: prefix + "a cycle through Unwrap() error", site: site, err: &plogCycleOne{},
				assert: asFault("budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", site: site, err: &plogCycleMany{}, child: true,
				assert: asFault("budget")},
			testCase{name: prefix + "a join that fans out", site: site, err: plogFanOut(25),
				assert: asFault("budget")},
			testCase{name: prefix + "a link whose Unwrap panics", site: site, err: plogPanicUnwrap{},
				assert: asFault("panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", site: site, err: plogPanicNilUnwrap{},
				assert: asFault("panic")},
			testCase{name: prefix + "a cycle on a context the failing call cancelled", site: site,
				err: &plogCycleOne{}, cancelDuring: true, assert: asFault("budget")},
			testCase{name: prefix + "a typed-nil root comes back unchanged", site: site,
				err: (*plogTypedNil)(nil), assert: unchanged},
			testCase{name: prefix + "a plain error comes back unchanged", site: site,
				err: errors.New("consumer: refused"), assert: unchanged},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				poptPortErrInChild(t, tc.name)

				return
			}

			defaults := pregDefaultRecords(t)

			plain := runOptionsSite(t, tc.site, errPlogOutage, tc.cancelDuring)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")
			require.True(t, plain.same, "a plain outage comes back unchanged")

			got := runOptionsSite(t, tc.site, tc.err, tc.cancelDuring)
			tc.assert(t, plain, got)

			for _, rec := range plogRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(poptRanMarker + tc.name + "\n")
			}
		})
	}
}

// poptPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints, as
// one whole output line, the marker proving it ran the row.
func poptPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), poptChildDeadline)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), poptRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	marker := poptRanMarker + row
	ran := slices.ContainsFunc(strings.Split(string(out), "\n"), func(line string) bool {
		return strings.TrimSuffix(line, "\r") == marker
	})
	require.True(t, ran, "the child never ran row %q: no output line equals %q:\n%s", row, marker, string(out))
}
