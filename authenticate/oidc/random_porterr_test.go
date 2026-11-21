package oidc_test

// TestPortErrors_Random replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/internal/porterr"
)

// pe6rRowEnv names the row a child process runs. It is empty in the parent.
const pe6rRowEnv = "SCRTY_OIDC_RANDOM_PORTERR_ROW"

// pe6rRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe6rRanMarker = "SCRTY_OIDC_RANDOM_PORTERR_RAN: "

// pe6rFailing is a random source whose every read fails with err, after
// calling onRead.
type pe6rFailing struct {
	err    error
	onRead func()
}

func (f pe6rFailing) Read([]byte) (int, error) {
	if f.onRead != nil {
		f.onRead()
	}

	return 0, f.err
}

// pe6rCounting is an unwalkable error (it unwraps to itself) that counts the
// times it is rendered.
type pe6rCounting struct{ rendered atomic.Int32 }

func (e *pe6rCounting) Error() string {
	e.rendered.Add(1)

	return "counting"
}

func (e *pe6rCounting) Unwrap() error { return e }

// pe6rSite names the random source a row fails.
type pe6rSite string

const (
	pe6rIssue     pe6rSite = "WithHandoffRandom in Issue"
	pe6rAuthorize pe6rSite = "WithRandom in Authorize"
	pe6rBegin     pe6rSite = "WithMemoryFlowStoreRandom in Authorize"
)

// pe6rClass is the returned error as every check downstream reads it, taken
// inside the run's time bound.
type pe6rClass struct {
	nilErr, unwalkable, flowStoreFull, config bool

	// quotes is set when the error's text quotes the hostile error's.
	quotes bool
}

// pe6rOutcome is what one call through a failing random source produced.
type pe6rOutcome struct {
	class pe6rClass

	code    bool
	authz   oidc.Authorization
	records []pe6aRecord
	raw     string
	aborts  []map[string]any
}

// pe6rRun calls site's flow with its random source failing with srcErr. When
// cancel is set the source cancels the caller's context before it fails. It
// fails the test when the call, or the checks of its error, hang or let a
// panic escape.
func pe6rRun(t *testing.T, p *testProvider, site pe6rSite, srcErr error, cancel bool) pe6rOutcome {
	t.Helper()

	ctx, stop := context.WithCancel(t.Context())
	defer stop()

	src := pe6rFailing{err: srcErr, onRead: func() {
		if cancel {
			stop()
		}
	}}

	logs := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var call func() (oidc.Authorization, string, error)

	switch site {
	case pe6rIssue:
		ctrl := gomock.NewController(t)
		h, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl),
			oidc.WithHandoffRandom(src), oidc.WithHandoffLogger(log),
			oidc.WithHandoffClock(clockwork.NewFakeClockAt(handoffT0)))
		require.NoError(t, err)

		call = func() (oidc.Authorization, string, error) {
			code, err := h.Issue(ctx, handoffCallback())

			return oidc.Authorization{}, code, err
		}
	case pe6rAuthorize, pe6rBegin:
		reg, err := oidc.NewRegistry(p.Provider("corp"), p.Provider("partner"))
		require.NoError(t, err)

		opts := []oidc.Option{oidc.WithOutboundClient(p.Outbound(t)), oidc.WithLogger(log)}
		if site == pe6rAuthorize {
			opts = append(opts, oidc.WithRandom(src))
		} else {
			store, err := oidc.NewMemoryFlowStore(oidc.WithMemoryFlowStoreRandom(src))
			require.NoError(t, err)

			opts = append(opts, oidc.WithFlowStore(store))
		}

		m, err := oidc.NewRelyingParty(reg, NewMockIdentityBroker(gomock.NewController(t)), opts...)
		require.NoError(t, err)

		call = func() (oidc.Authorization, string, error) {
			a, err := m.Authorize(ctx, "corp", "/after")

			return a, "", err
		}
	}

	type result struct {
		out      pe6rOutcome
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

		var out pe6rOutcome

		authz, code, rerr := call()
		out.authz, out.code = authz, code != ""

		// Every check a caller makes of the error, inside the bound.
		out.class = pe6rClass{
			nilErr:        rerr == nil,
			unwalkable:    errors.Is(rerr, porterr.ErrUnwalkable),
			flowStoreFull: errors.Is(rerr, oidc.ErrFlowStoreFull),
			config:        errors.Is(rerr, oidc.ErrConfig),
		}
		if rerr != nil {
			out.class.quotes = strings.Contains(rerr.Error(), pe6aSecret)
		}

		returned = true
		done <- result{out: out}
	}()

	var out pe6rOutcome

	select {
	case res := <-done:
		require.False(t, res.panicked, "a hostile random source error escaped as a panic: %v", res.value)
		out = res.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile random source error hung the flow or a check of its error")
	}

	out.raw = logs.String()

	for _, rec := range pe6aJSONRecords(t, out.raw) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)

			continue
		}

		reason, _ := rec["reason"].(string)
		provider, _ := rec["provider"].(string)
		out.records = append(out.records, pe6aRecord{
			level: rec["level"].(string), msg: rec["msg"].(string), reason: reason, provider: provider,
		})
	}

	return out
}

// TestPortErrors_Random pins that each consumer-replaceable random source of
// the OIDC client (the handoff's, the relying party's, the in-memory flow
// store's) failing with an error whose chain cannot be walked is answered
// exactly as a plain read failure: no code and no authorization, the same
// answer to every sentinel check, the same records, and an error that quotes
// nothing of the source's. The sanitizer writes one record, to the component's
// logger, and none to slog.Default().
func TestPortErrors_Random(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe6rRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	p := newTestProvider(t)

	type testCase struct {
		name   string
		site   pe6rSite
		err    error
		cancel bool

		// child runs the row in a child process: unsanitized, it may
		// overflow the stack fatally.
		child bool

		assert func(t *testing.T, plain, got pe6rOutcome)
	}

	sameAsPlain := func(t *testing.T, plain, got pe6rOutcome) {
		t.Helper()

		wantClass := plain.class
		wantClass.unwalkable = got.class.unwalkable // asserted by the caller
		assert.Equal(t, wantClass, got.class, "the same answer to every check of the error")
		assert.False(t, got.class.quotes, "the returned error quotes the source's")
		assert.Equal(t, plain.code, got.code, "the same code")
		assert.Equal(t, plain.authz, got.authz, "the same authorization")
		assert.Equal(t, plain.records, got.records, "the same records, levels and reasons")
		assert.NotContains(t, got.raw, pe6aSecret, "a record quotes the error")
	}

	asOutage := func(reason string) func(t *testing.T, plain, got pe6rOutcome) {
		return func(t *testing.T, plain, got pe6rOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)
			assert.True(t, got.class.unwalkable, "the error is the sanitizer's fault")

			require.Len(t, got.aborts, 1, "one abort record, on the component's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])
		}
	}

	var cases []testCase

	for _, site := range []pe6rSite{pe6rIssue, pe6rAuthorize, pe6rBegin} {
		prefix := string(site) + ": "

		counting := &pe6rCounting{}

		cases = append(cases,
			testCase{
				name: prefix + "an unwalkable cause is never rendered before the sanitizer replaces it",
				site: site, err: counting,
				assert: func(t *testing.T, plain, got pe6rOutcome) {
					t.Helper()

					asOutage("budget")(t, plain, got)
					assert.Zero(t, counting.rendered.Load(), "the cause's Error was called before the sanitizer walked it")
				},
			},
			testCase{name: prefix + "a cycle through Unwrap() error", site: site, err: &pe6aCycleOne{},
				assert: asOutage("budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", site: site, err: &pe6aCycleMany{}, child: true,
				assert: asOutage("budget")},
			testCase{name: prefix + "a link whose Unwrap panics", site: site, err: pe6aPanicUnwrap{},
				assert: asOutage("panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", site: site, err: pe6aPanicNilUnwrap{},
				assert: asOutage("panic")},
			testCase{name: prefix + "a join that fans out", site: site, err: pe6aFanOut(25),
				assert: asOutage("budget")},
			testCase{name: prefix + "a cycle after the source cancelled the caller's context", site: site,
				err: &pe6aCycleOne{}, cancel: true, assert: asOutage("budget")},
			testCase{
				name: prefix + "a typed-nil root walks to the end and is answered as an outage",
				site: site, err: (*pe6aTypedNil)(nil),
				assert: func(t *testing.T, plain, got pe6rOutcome) {
					t.Helper()

					// A walkable error passes unchanged, so the text comes back
					// exactly where the plain failure's does: Authorize wraps
					// a flow store's error and hides it.
					assert.Equal(t, site != pe6rBegin, got.class.quotes, "the source's text comes back as it did before")
					got.class.quotes = false

					sameAsPlain(t, plain, got)
					assert.False(t, got.class.unwalkable, "a walkable error passes unchanged")
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
				},
			},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe6rInChild(t, tc.name)

				return
			}

			defaults := pe6aDefaultRecords(t)

			plain := pe6rRun(t, p, tc.site, errPe6aPortDown, tc.cancel)
			require.Empty(t, plain.aborts, "a plain failure writes no abort record")
			require.False(t, plain.class.nilErr, "precondition: a plain failure fails the call")
			require.False(t, plain.class.unwalkable || plain.class.flowStoreFull, "precondition: a plain failure is no fault or refusal")
			require.False(t, plain.code, "precondition: no code")

			got := pe6rRun(t, p, tc.site, tc.err, tc.cancel)
			tc.assert(t, plain, got)

			for _, rec := range pe6aJSONRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe6rRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe6rInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints a line equal
// to the marker that shows it ran the row: a stack overflow is fatal and only
// a child can watch for one.
func pe6rInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe6rRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	want := pe6rRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
