package oidcprovider_test

// TestPortErrors_ProviderReads and TestPortErrors_DropReportRegistry replace
// slog.Default() for their duration, so they do not run in parallel, and they
// restore the logger they found.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
)

// pe7aSecret is the text every hostile error here returns, so a test can
// assert no record, error or redirect quotes it.
const pe7aSecret = "pe7a-port-secret-text"

// pe7aRowEnv names the row a child process runs. It is empty in the parent.
const pe7aRowEnv = "SCRTY_OIDCPROVIDER_PE7A_PORTERR_ROW"

// pe7aRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe7aRanMarker = "SCRTY_OIDCPROVIDER_PE7A_PORTERR_RAN: "

// pe7aErrDown is the plain outage the parity runs fail with.
var pe7aErrDown = errors.New("pe7a: connection refused, " + pe7aSecret)

// pe7aCycleOne contains itself through Unwrap() error.
type pe7aCycleOne struct{}

func (*pe7aCycleOne) Error() string   { return pe7aSecret }
func (c *pe7aCycleOne) Unwrap() error { return c }

// pe7aCycleMany contains itself through Unwrap() []error. Unsanitized, a
// stdlib walk overflows the stack fatally, so its rows run in a child process.
type pe7aCycleMany struct{}

func (*pe7aCycleMany) Error() string     { return pe7aSecret }
func (c *pe7aCycleMany) Unwrap() []error { return []error{c} }

// pe7aCycleAround holds sentinel first and then itself, through
// Unwrap() []error: a stdlib errors.Is asking for sentinel answers yes at
// once, and one asking for anything else overflows the stack. Its rows run in
// a child process.
type pe7aCycleAround struct{ sentinel error }

func (*pe7aCycleAround) Error() string     { return pe7aSecret }
func (c *pe7aCycleAround) Unwrap() []error { return []error{c.sentinel, c} }

// pe7aPanicUnwrap is an error whose Unwrap panics.
type pe7aPanicUnwrap struct{}

func (pe7aPanicUnwrap) Error() string { return pe7aSecret }
func (pe7aPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + pe7aSecret) }

// pe7aPanicNilUnwrap is an error whose Unwrap panics with nil.
type pe7aPanicNilUnwrap struct{}

func (pe7aPanicNilUnwrap) Error() string { return pe7aSecret }
func (pe7aPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// pe7aTypedNil is returned as a nil pointer inside a non-nil error.
type pe7aTypedNil struct{}

func (*pe7aTypedNil) Error() string { return pe7aSecret }

// pe7aFanOut is errors.Join(n, n) nested depth times over leaf: no cycle, but
// 2^depth paths for an unbounded walk, and a depth-first errors.Is reaches
// leaf on its first path.
func pe7aFanOut(depth int, leaf error) error {
	err := leaf
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// pe7aSite names the port call a row fails.
type pe7aSite string

const (
	// pe7aRegistry is ClientRegistry.Client, reached through the token
	// endpoint's client authentication by client_secret_basic.
	pe7aRegistry pe7aSite = "the token endpoint's registry read"
	// pe7aAssertionID is AssertionIDStore.Record, reached through the token
	// endpoint's client authentication by private_key_jwt.
	pe7aAssertionID pe7aSite = "the token endpoint's assertion ID record"
	// pe7aHintKeys is KeySource.VerificationKeys, reached through the
	// authorization endpoint judging an id_token_hint.
	pe7aHintKeys pe7aSite = "the authorization endpoint's hint key read"
)

// pe7aOutcome is what one call through a failing port produced. Every error
// classification is made inside the bound, so a hostile chain that reaches the
// caller raw fails the run as a hang rather than hanging the test.
type pe7aOutcome struct {
	err  error
	text string

	dependency bool
	notFound   bool
	canceled   bool
	unwalkable bool
	// code is the protocol refusal's code, empty when the error is none.
	code string

	// location and flowSecret are the authorization endpoint's answer.
	location   string
	flowSecret string

	// aborts are the sanitizer's records on the provider's logger.
	aborts []map[string]any
}

// pe7aRun runs the endpoint that reaches site's port call, on ctx, against a
// port that fails that call with portErr. It fails the test when the call
// hangs or lets a panic escape.
func pe7aRun(t *testing.T, ctx context.Context, site pe7aSite, hintKey *rsa.PrivateKey, portErr error) pe7aOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var call func() pe7aOutcome

	switch site {
	case pe7aRegistry:
		registry := NewMockClientRegistry(gomock.NewController(t))
		registry.EXPECT().Client(gomock.Any(), "billing-web").Return(nil, portErr).Times(1)

		deps := validDeps(t)
		deps.Clients, deps.Registry = nil, registry
		p, err := oidcprovider.New(deps, oidcprovider.WithLogger(logger))
		require.NoError(t, err)

		call = func() pe7aOutcome {
			_, err := p.Token(ctx, oidcprovider.TokenRequest{
				Credentials: oidcprovider.ClientCredentials{Authorization: basic("billing-web", basicSecret)},
				Form:        form("grant_type", "authorization_code", "code", "c-1"),
			})

			return pe7aOutcome{err: err}
		}
	case pe7aAssertionID:
		store := NewMockAssertionIDStore(gomock.NewController(t))
		store.EXPECT().Record(gomock.Any(), keyClientID, gomock.Any(), gomock.Any()).Return(false, portErr).Times(1)

		p := assertionProvider(t, clientKeys(t), oidcprovider.WithAssertionIDStore(store), oidcprovider.WithLogger(logger))
		creds := presenting(es256(t, claimsFor(keyClientID)))

		call = func() pe7aOutcome {
			_, err := p.Token(ctx, oidcprovider.TokenRequest{
				Credentials: creds,
				Form:        form("grant_type", "authorization_code", "code", "c-1"),
			})

			return pe7aOutcome{err: err}
		}
	case pe7aHintKeys:
		keys := NewMockKeySource(gomock.NewController(t))
		keys.EXPECT().VerificationKeys(gomock.Any()).Return(nil, portErr).Times(1)

		p, f := newAuthzProvider(t, keys, nil, oidcprovider.WithLogger(logger))
		params := authzParams()
		params.Set("id_token_hint", signed(t, "RS256", hintKey, map[string]any{"kid": publishedKid, "typ": "JWT"}, hintClaims(nil)))

		call = func() pe7aOutcome {
			res, err := p.Authorize(ctx, oidcprovider.AuthorizeInput{Params: params})
			if len(f.parked) != 0 {
				return pe7aOutcome{err: errors.New("pe7a: the request was parked")}
			}

			return pe7aOutcome{err: err, location: res.Location, flowSecret: res.FlowSecret}
		}
	default:
		require.FailNow(t, "unknown site", "%s", site)
	}

	type result struct {
		out      pe7aOutcome
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
			// ErrDependency first: a library fault lists its sentinels before
			// its cause, so this check never reaches a raw port error.
			o.dependency = errors.Is(o.err, oidcprovider.ErrDependency)
			o.notFound = errors.Is(o.err, oidcprovider.ErrClientNotFound)
			o.canceled = errors.Is(o.err, context.Canceled)
			o.unwalkable = errors.Is(o.err, porterr.ErrUnwalkable)

			var refusal *oidcprovider.Error
			if errors.As(o.err, &refusal) {
				o.code = refusal.Code
			}
		}

		returned = true
		done <- result{out: o}
	}()

	var out pe7aOutcome

	select {
	case r := <-done:
		require.False(t, r.panicked, "a hostile port error escaped as a panic: %v", r.value)
		out = r.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the call, or its classification")
	}

	for _, rec := range pe7aJSONRecords(t, logs.String()) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// pe7aJSONRecords decodes every JSON record in out.
func pe7aJSONRecords(t *testing.T, out string) []map[string]any {
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

// pe7aDefaultRecords points slog.Default() at a JSON buffer until the test
// ends. The caller must not be parallel.
func pe7aDefaultRecords(t *testing.T) *lockedBuffer {
	t.Helper()

	buf := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return buf
}

// pe7aNoDefaultAborts fails when slog.Default() received an abort record.
func pe7aNoDefaultAborts(t *testing.T, defaults *lockedBuffer) {
	t.Helper()

	for _, rec := range pe7aJSONRecords(t, defaults.String()) {
		assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
	}
}

// pe7aRow is one hostile port error, shared by both tables.
type pe7aRow struct {
	name   string
	err    error
	reason string
	// child runs the row in a child process: unsanitized, it overflows the
	// stack fatally.
	child bool
	// cancel runs the row on a context the caller cancelled.
	cancel bool
}

// pe7aRows are the hostile errors every site is tried with. A typed-nil root
// is not among them: its walk completes, so it writes no record.
func pe7aRows() []pe7aRow {
	return []pe7aRow{
		{name: "a cycle through Unwrap() error", err: &pe7aCycleOne{}, reason: "budget"},
		{name: "a cycle through Unwrap() []error", err: &pe7aCycleMany{}, reason: "budget", child: true},
		{name: "a link whose Unwrap panics", err: pe7aPanicUnwrap{}, reason: "panic"},
		{name: "a link whose Unwrap panics with nil", err: pe7aPanicNilUnwrap{}, reason: "panic"},
		{name: "a join that fans out", err: pe7aFanOut(25, errors.New(pe7aSecret)), reason: "budget"},
		{
			name: "a join that fans out over ErrClientNotFound",
			err:  pe7aFanOut(25, oidcprovider.ErrClientNotFound), reason: "budget",
		},
		{
			name: "a cycle around ErrClientNotFound",
			err:  &pe7aCycleAround{sentinel: oidcprovider.ErrClientNotFound}, reason: "budget", child: true,
		},
		{
			name: "a cycle around context.Canceled on a context the caller cancelled",
			err:  &pe7aCycleAround{sentinel: context.Canceled}, reason: "budget", child: true, cancel: true,
		},
		{
			name: "a cycle on a context the caller cancelled",
			err:  &pe7aCycleOne{}, reason: "budget", cancel: true,
		},
	}
}

// TestPortErrors_ProviderReads pins that the registry read, the assertion ID
// record and the hint's verification key read, failing with an error whose
// chain cannot be walked, are answered exactly as a plain outage of that port
// is:
//
//   - the token endpoint returns ErrDependency with the same fixed text, never
//     invalid_client, never ErrClientNotFound and never a caller's hang-up;
//   - the authorization endpoint redirects with the same server_error answer,
//     byte for byte, and parks nothing.
//
// The sanitizer writes one record, to the provider's logger, and none to
// slog.Default().
func TestPortErrors_ProviderReads(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7aRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	hintKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type testCase struct {
		name  string
		site  pe7aSite
		err   error
		child bool

		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got pe7aOutcome)
	}

	sameAsPlain := func(t *testing.T, site pe7aSite, plain, got pe7aOutcome) {
		t.Helper()

		switch site {
		case pe7aRegistry, pe7aAssertionID:
			require.True(t, plain.dependency, "precondition: a plain outage is a dependency failure")
			require.Empty(t, plain.code, "precondition: a plain outage is no protocol refusal")
			assert.True(t, got.dependency, "answered as ErrDependency")
			assert.False(t, got.notFound, "never answered as an unknown client")
			assert.False(t, got.canceled, "never answered as the caller leaving")
		case pe7aHintKeys:
			require.NoError(t, plain.err, "precondition: a plain outage is answered at the redirect URI")
			require.Contains(t, plain.location, "error=server_error", "precondition: as server_error")
			assert.NoError(t, got.err)
		}

		assert.Equal(t, plain.text, got.text, "the same fixed text")
		assert.Equal(t, plain.dependency, got.dependency, "the same dependency-failure class")
		assert.Equal(t, plain.notFound, got.notFound, "the same unknown-client class")
		assert.Equal(t, plain.canceled, got.canceled, "the same hang-up class")
		assert.Equal(t, plain.code, got.code, "the same protocol code")
		assert.Equal(t, plain.location, got.location, "the same redirect, byte for byte")
		assert.Equal(t, plain.flowSecret, got.flowSecret, "the same flow secret")
		assert.NotContains(t, got.text, pe7aSecret)
		assert.NotContains(t, got.location, pe7aSecret)
	}

	asOutage := func(site pe7aSite, reason string) func(t *testing.T, plain, got pe7aOutcome) {
		return func(t *testing.T, plain, got pe7aOutcome) {
			t.Helper()

			sameAsPlain(t, site, plain, got)

			if site != pe7aHintKeys {
				assert.True(t, got.unwalkable, "the failure carries the sanitizer's fault")
			}

			require.Len(t, got.aborts, 1, "one abort record, on the provider's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), pe7aSecret, "the record quotes the error")
		}
	}

	var cases []testCase

	for _, site := range []pe7aSite{pe7aRegistry, pe7aAssertionID, pe7aHintKeys} {
		prefix := string(site) + ": "

		for _, row := range pe7aRows() {
			tc := testCase{name: prefix + row.name, site: site, err: row.err, child: row.child, assert: asOutage(site, row.reason)}
			if row.cancel {
				tc.ctx = cancelled
			}

			cases = append(cases, tc)
		}

		cases = append(cases, testCase{
			name: prefix + "a typed-nil root walks to the end and is answered as an outage",
			site: site, err: (*pe7aTypedNil)(nil),
			assert: func(t *testing.T, plain, got pe7aOutcome) {
				t.Helper()

				sameAsPlain(t, site, plain, got)
				assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
			},
		})
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7aInChild(t, tc.name)

				return
			}

			defaults := pe7aDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7aRun(t, ctx, tc.site, hintKey, pe7aErrDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := pe7aRun(t, ctx, tc.site, hintKey, tc.err)
			tc.assert(t, plain, got)

			pe7aNoDefaultAborts(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7aRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe7aDrop is what a dropped delivery's report did when the registry it asked
// failed.
type pe7aDrop struct {
	reported bool
	// aborts are the provider's log lines carrying the sanitizer's record.
	aborts []string
}

// pe7aRunDrop drops one delivery while the registry fails with registryErr,
// and reports whether the drop was reported within ten seconds. The registry
// answers again once the drop is reported or the wait is over, so the queued
// delivery the worker reads later is not failed with it.
func pe7aRunDrop(t *testing.T, registryErr error) pe7aDrop {
	t.Helper()

	memory, err := oidcprovider.NewMemoryRegistry(oneClient())
	require.NoError(t, err)

	registry := &registryAnswering{ClientRegistry: memory, answer: func(context.Context) error { return registryErr }}

	var log eventLog

	g := newGate(true)
	x := newEnding(t, nil, registry, oidcprovider.WithSecurityEvents(log.sink), oidcprovider.WithLogoutDelivery(g),
		oidcprovider.WithLogoutDeliveryPool(1, 1), oidcprovider.WithLogoutDeliveryTimeout(2*time.Second))

	var opened sync.Once

	finish := func() { opened.Do(func() { close(g.open) }) }
	t.Cleanup(finish)

	ctx := context.WithoutCancel(t.Context())
	dropReported := func() bool {
		return slices.Contains(causesOf(named(log.all(), event.LogoutDeliveryFailed)), "queue_full")
	}

	x.end(ctx, t, "billing-web") // takes the worker
	require.Eventually(t, func() bool { return g.entered.Load() == 1 }, 10*time.Second, time.Millisecond)
	x.end(ctx, t, "billing-web") // takes the queue's one place
	registry.armed.Store(true)
	x.end(ctx, t, "billing-web") // dropped, with the registry failing

	deadline := time.Now().Add(10 * time.Second)
	for !dropReported() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	out := pe7aDrop{reported: dropReported()}
	registry.armed.Store(false)
	finish()
	drained(t, x.p)

	for line := range strings.Lines(x.logs.String()) {
		if strings.Contains(line, porterr.MsgClassificationAborted) {
			out.aborts = append(out.aborts, line)
		}
	}

	return out
}

// TestPortErrors_DropReportRegistry pins that a dropped delivery's report,
// which asks the registry whether the client had anyone to tell, takes a
// registry error whose chain cannot be walked as it takes a plain registry
// outage: unknown, so the drop is reported. It is never taken as the client
// being gone, and it never hangs the report. The sanitizer writes one record,
// to the provider's logger, and none to slog.Default().
func TestPortErrors_DropReportRegistry(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7aRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name   string
		err    error
		child  bool
		assert func(t *testing.T, plain, got pe7aDrop)
	}

	reportedOnce := func(reason string) func(t *testing.T, plain, got pe7aDrop) {
		return func(t *testing.T, plain, got pe7aDrop) {
			t.Helper()

			require.True(t, plain.reported, "precondition: a plain registry outage leaves it unknown, and it is reported")
			assert.True(t, got.reported, "the drop is reported, as for a plain outage")
			require.Len(t, got.aborts, 1, "one abort record, on the provider's logger")
			assert.Contains(t, got.aborts[0], "reason="+reason)
			assert.NotContains(t, got.aborts[0], pe7aSecret, "the record quotes the error")
		}
	}

	var cases []testCase

	for _, row := range pe7aRows() {
		if row.cancel {
			// The report runs detached from the caller's context.
			continue
		}

		cases = append(cases, testCase{name: "drop report: " + row.name, err: row.err, child: row.child, assert: reportedOnce(row.reason)})
	}

	cases = append(cases, testCase{
		name: "drop report: a typed-nil root walks to the end and is reported",
		err:  (*pe7aTypedNil)(nil),
		assert: func(t *testing.T, plain, got pe7aDrop) {
			t.Helper()

			require.True(t, plain.reported)
			assert.True(t, got.reported)
			assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
		},
	})

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7aInChild(t, tc.name)

				return
			}

			defaults := pe7aDefaultRecords(t)

			plain := pe7aRunDrop(t, pe7aErrDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := pe7aRunDrop(t, tc.err)
			tc.assert(t, plain, got)

			pe7aNoDefaultAborts(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7aRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe7aInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func pe7aInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe7aRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker: not a substring of the output, and
	// not a line with a suffix.
	want := pe7aRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
