package oidc_test

// TestPortErrors_Login replaces slog.Default() for its duration, so it does
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
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/assurance"
	"github.com/kartaladev/scrty/internal/porterr"
)

// pe6aRowEnv names the row a child process runs. It is empty in the parent.
const pe6aRowEnv = "SCRTY_OIDC_LOGIN_PORTERR_ROW"

// pe6aRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe6aRanMarker = "SCRTY_OIDC_LOGIN_PORTERR_RAN: "

// pe6aSecret is the text of every hostile error. No returned error and no
// record may quote it.
const pe6aSecret = "port-secret-6a: dsn=postgres://admin:hunter2@db" //nolint:gosec // G101: a fixture, not a credential

// pe6aCycleOne contains itself through Unwrap() error.
type pe6aCycleOne struct{}

func (*pe6aCycleOne) Error() string   { return pe6aSecret }
func (c *pe6aCycleOne) Unwrap() error { return c }

// pe6aCycleMany contains itself through Unwrap() []error. Unsanitized, the
// stdlib walk overflows the stack fatally, so its rows run in a child process.
type pe6aCycleMany struct{}

func (*pe6aCycleMany) Error() string     { return pe6aSecret }
func (c *pe6aCycleMany) Unwrap() []error { return []error{c} }

// pe6aPanicUnwrap is an error whose Unwrap panics.
type pe6aPanicUnwrap struct{}

func (pe6aPanicUnwrap) Error() string { return pe6aSecret }
func (pe6aPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + pe6aSecret) }

// pe6aPanicNilUnwrap is an error whose Unwrap panics with nil.
type pe6aPanicNilUnwrap struct{}

func (pe6aPanicNilUnwrap) Error() string { return pe6aSecret }
func (pe6aPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// pe6aTypedNil is returned as a nil pointer inside a non-nil error.
type pe6aTypedNil struct{}

func (*pe6aTypedNil) Error() string { return pe6aSecret }

// pe6aClaimCycle claims to be claim through its own Is and contains itself
// through Unwrap() error. A check that believed its Is would read an outage
// as the refusal claim names.
type pe6aClaimCycle struct{ claim error }

func (*pe6aClaimCycle) Error() string   { return pe6aSecret }
func (c *pe6aClaimCycle) Unwrap() error { return c }
func (c *pe6aClaimCycle) Is(target error) bool {
	return target == c.claim //nolint:errorlint // identity of a sentinel
}

// pe6aClaimCycleMany wraps claim beside itself through Unwrap() []error: a
// depth-first match finds the sentinel before the cycle.
type pe6aClaimCycleMany struct{ claim error }

func (*pe6aClaimCycleMany) Error() string { return pe6aSecret }
func (c *pe6aClaimCycleMany) Unwrap() []error {
	return []error{c.claim, c}
}

// pe6aFanOut is errors.Join(n, n) nested depth times: no cycle, but 2^depth
// paths for an unbounded walk.
func pe6aFanOut(depth int) error {
	err := errors.New(pe6aSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// errPe6aPortDown is the plain outage every parity run fails with.
var errPe6aPortDown = errors.New("port: connection refused")

// pe6aSite names the port call a row fails.
type pe6aSite string

const (
	pe6aBegin          pe6aSite = "FlowStore.Begin in Authorize"
	pe6aBroker         pe6aSite = "IdentityBroker.Broker in Callback"
	pe6aCompleteCB     pe6aSite = "FlowStore.Complete in Callback"
	pe6aCompleteAbort  pe6aSite = "FlowStore.Complete in AbortFlow"
	pe6aDeleteExpired  pe6aSite = "FlowStore.DeleteExpired in PurgeExpiredFlows"
	pe6aMeetsAssurance pe6aSite = "AssuranceEvaluator.MeetsAssurance"
)

// pe6aClass is the returned error as every check downstream reads it, taken
// inside the run's time bound.
type pe6aClass struct {
	nilErr, unwalkable, flowUnspent, invalidState, noLinked, provisioningRefused, flowStoreFull bool

	// quotes is set when the error's text quotes the hostile error's.
	quotes bool
}

// pe6aRecord is one record the relying party's logger wrote, other than an
// abort record, reduced to what a consumer routes on.
type pe6aRecord struct {
	level, msg, reason, provider string
}

// pe6aOutcome is what one call through a failing port produced.
type pe6aOutcome struct {
	class pe6aClass

	// authz, result, ended, count and met are the site's other results.
	authz  oidc.Authorization
	result oidc.CallbackResult
	ended  bool
	count  int
	met    bool

	// flowLive is whether the default store still holds the flow (broker
	// site only): the broker runs after the flow is spent.
	flowLive bool

	records []pe6aRecord
	raw     string
	aborts  []map[string]any
}

// pe6aRun calls the site's flow, against provider p, on a relying party
// whose port fails the site's call with portErr. Runs share p and are
// sequential, so its token endpoint answers one flow at a time. When cancel is set the port cancels the caller's
// context before it fails. It fails the test when the call, or the checks of
// its error, hang or let a panic escape.
func pe6aRun(t *testing.T, p *testProvider, site pe6aSite, portErr error, cancel bool) pe6aOutcome {
	t.Helper()

	reg, err := oidc.NewRegistry(p.Provider("corp"), p.Provider("partner"))
	require.NoError(t, err)

	ctx, stop := context.WithCancel(t.Context())
	defer stop()

	fail := func() {
		if cancel {
			stop()
		}
	}

	ctrl := gomock.NewController(t)
	flows := NewMockFlowStore(ctrl)
	broker := NewMockIdentityBroker(ctrl)
	logs := &bytes.Buffer{}
	now := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)

	opts := []oidc.Option{
		oidc.WithOutboundClient(p.Outbound(t)),
		oidc.WithClock(clockwork.NewFakeClockAt(now)),
		oidc.WithLogger(slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
	}

	switch site {
	case pe6aBegin:
		flows.EXPECT().Begin(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, oidc.Flow) (string, error) {
			fail()

			return "", portErr
		}).Times(1)
	case pe6aCompleteCB, pe6aCompleteAbort:
		flows.EXPECT().Complete(gomock.Any(), "the-handle", "corp", "the-state").
			DoAndReturn(func(context.Context, string, string, string) (oidc.Flow, error) {
				fail()

				return oidc.Flow{}, portErr
			}).Times(1)
	case pe6aDeleteExpired:
		flows.EXPECT().DeleteExpired(gomock.Any(), now).DoAndReturn(func(context.Context, time.Time) (int, error) {
			fail()

			return 3, portErr
		}).Times(1)
	case pe6aBroker:
		broker.EXPECT().Broker(gomock.Any(), gomock.Any()).
			DoAndReturn(func(context.Context, oidc.ExternalIdentity) (*identity.Principal, error) {
				fail()

				return nil, portErr
			}).Times(1)
	case pe6aMeetsAssurance:
		ev := NewMockAssuranceEvaluator(ctrl)
		ev.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any()).
			DoAndReturn(func(context.Context, oidc.AssuranceInput) (bool, error) {
				fail()

				// Met alongside the error: the flow must still fail closed.
				return true, portErr
			}).Times(1)
		opts = append(opts, oidc.WithAssuranceEvaluator(ev))
	}

	if site != pe6aBroker && site != pe6aMeetsAssurance {
		opts = append(opts, oidc.WithFlowStore(flows))
	}

	m, err := oidc.NewRelyingParty(reg, broker, opts...)
	require.NoError(t, err)

	var env *callbackEnv
	if site == pe6aBroker {
		// A genuine login up to the broker, through the default store.
		env = &callbackEnv{m: m, p: p, broker: broker, logs: &bytes.Buffer{}, now: now}
		env.auth, err = m.Authorize(t.Context(), "corp", "/after")
		require.NoError(t, err)
		env.flow = authorizeFlow(t, m, env.auth.Handle)
		env.reissue(t, nil)
		logs.Reset()
	}

	type result struct {
		out      pe6aOutcome
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

		var (
			out  pe6aOutcome
			rerr error
		)

		switch site {
		case pe6aBegin:
			out.authz, rerr = m.Authorize(ctx, "corp", "/after")
		case pe6aBroker:
			out.result, rerr = m.Callback(ctx, "corp", "the-code", env.flow.State, env.auth.Handle)
		case pe6aCompleteCB:
			out.result, rerr = m.Callback(ctx, "corp", "the-code", "the-state", "the-handle")
		case pe6aCompleteAbort:
			out.ended, rerr = m.AbortFlow(ctx, "corp", "the-state", "the-handle")
		case pe6aDeleteExpired:
			out.count, rerr = m.PurgeExpiredFlows(ctx)
		case pe6aMeetsAssurance:
			out.met, rerr = m.MeetsAssurance(ctx, "u-1",
				assurance.NewFederated("corp", p.Issuer(), []string{"mfa"}, ""))
		}

		// Every check a caller makes of the error, inside the bound.
		out.class = pe6aClass{
			nilErr:              rerr == nil,
			unwalkable:          errors.Is(rerr, porterr.ErrUnwalkable),
			flowUnspent:         errors.Is(rerr, oidc.ErrFlowUnspent),
			invalidState:        errors.Is(rerr, oidc.ErrInvalidState),
			noLinked:            errors.Is(rerr, oidc.ErrNoLinkedAccount),
			provisioningRefused: errors.Is(rerr, oidc.ErrProvisioningRefused),
			flowStoreFull:       errors.Is(rerr, oidc.ErrFlowStoreFull),
		}
		if rerr != nil {
			out.class.quotes = strings.Contains(rerr.Error(), pe6aSecret)
		}

		returned = true
		done <- result{out: out}
	}()

	var out pe6aOutcome

	select {
	case res := <-done:
		require.False(t, res.panicked, "a hostile port error escaped as a panic: %v", res.value)
		out = res.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the flow or a check of its error")
	}

	if site == pe6aBroker {
		store, ok := oidc.WiringOf(m).Flows.(*oidc.MemoryFlowStore)
		require.True(t, ok)
		_, out.flowLive = oidc.FlowForTest(store, env.auth.Handle)
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

// pe6aJSONRecords decodes every JSON record in out.
func pe6aJSONRecords(t *testing.T, out string) []map[string]any {
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

// pe6aDefaultRecords points slog.Default() at a JSON buffer until the test
// ends. The caller must not be parallel.
func pe6aDefaultRecords(t *testing.T) *bytes.Buffer {
	t.Helper()

	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return buf
}

// pe6aSiteShape pins what a plain outage of site produces, so a parity row
// cannot pass by two equally wrong outcomes.
func pe6aSiteShape(t *testing.T, site pe6aSite, plain pe6aOutcome) {
	t.Helper()

	c := plain.class
	require.False(t, c.nilErr, "precondition: a plain outage fails the call")
	require.False(t, c.invalidState || c.noLinked || c.provisioningRefused || c.flowStoreFull,
		"precondition: a plain outage is no refusal")

	switch site {
	case pe6aCompleteCB:
		require.True(t, c.flowUnspent, "precondition: a flow store fault leaves the flow unspent")
		require.Contains(t, plain.records,
			pe6aRecord{level: "ERROR", msg: "oidc callback failed", reason: "flow-store", provider: "corp"})
	case pe6aCompleteAbort:
		require.False(t, plain.ended, "precondition: a flow store fault ends no flow")
		require.Contains(t, plain.records,
			pe6aRecord{level: "ERROR", msg: "oidc callback failed", reason: "flow-store", provider: "corp"})
	case pe6aBroker:
		require.False(t, c.flowUnspent, "precondition: the flow is spent before the broker runs")
		require.False(t, plain.flowLive, "precondition: the flow is spent")
	case pe6aDeleteExpired:
		require.Equal(t, 3, plain.count, "precondition: the store's count comes back")
	case pe6aMeetsAssurance:
		require.False(t, plain.met, "precondition: an evaluator error is never met")
	}
}

// TestPortErrors_Login pins that each port call of the login flow — the flow
// store's Begin, Complete (from Callback and from AbortFlow) and
// DeleteExpired, the identity broker, and the assurance evaluator — failing
// with an error whose chain cannot be walked is answered exactly as a plain
// outage of that port: the same results, the same answer to every sentinel
// check a caller makes, the same records, and an error that quotes nothing of
// the port's. A chain that claims a refusal (ErrInvalidState,
// ErrNoLinkedAccount, ErrProvisioningRefused, ErrFlowStoreFull) but cannot be
// walked is an outage, never that refusal. The sanitizer writes one record, to
// the relying party's logger, and none to slog.Default().
func TestPortErrors_Login(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe6aRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	p := newTestProvider(t)

	type testCase struct {
		name string
		site pe6aSite
		err  error

		// cancel makes the port cancel the caller's context before it fails,
		// in both runs of the row.
		cancel bool

		// child runs the row in a child process: unsanitized, it may
		// overflow the stack fatally.
		child bool

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got pe6aOutcome)
	}

	sameAsPlain := func(t *testing.T, plain, got pe6aOutcome) {
		t.Helper()

		wantClass := plain.class
		wantClass.unwalkable = got.class.unwalkable // asserted by the caller
		assert.Equal(t, wantClass, got.class, "the same answer to every check of the error")
		assert.False(t, got.class.quotes, "the returned error quotes the port's")
		assert.Equal(t, plain.authz, got.authz, "the same authorization")
		assert.Equal(t, plain.result, got.result, "the same callback result")
		assert.Equal(t, plain.ended, got.ended, "the same AbortFlow answer")
		assert.Equal(t, plain.count, got.count, "the same purge count")
		assert.Equal(t, plain.met, got.met, "the same assurance answer")
		assert.Equal(t, plain.flowLive, got.flowLive, "the same flow state")
		assert.Equal(t, plain.records, got.records, "the same records, levels and reasons")
		assert.NotContains(t, got.raw, pe6aSecret, "a record quotes the error")
	}

	asOutage := func(reason string) func(t *testing.T, plain, got pe6aOutcome) {
		return func(t *testing.T, plain, got pe6aOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)
			assert.True(t, got.class.unwalkable, "the error is the sanitizer's fault")

			require.Len(t, got.aborts, 1, "one abort record, on the relying party's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])
		}
	}

	var cases []testCase

	sites := []pe6aSite{pe6aBegin, pe6aBroker, pe6aCompleteCB, pe6aCompleteAbort, pe6aDeleteExpired, pe6aMeetsAssurance}
	for _, site := range sites {
		prefix := string(site) + ": "

		cases = append(cases,
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
			testCase{name: prefix + "a cycle after the port cancelled the caller's context", site: site,
				err: &pe6aCycleOne{}, cancel: true, assert: asOutage("budget")},
			testCase{
				name: prefix + "a typed-nil root walks to the end and is answered as an outage",
				site: site, err: (*pe6aTypedNil)(nil),
				assert: func(t *testing.T, plain, got pe6aOutcome) {
					t.Helper()

					// A walkable error passes unchanged, so a site that
					// returns the port's error raw returns this one's text
					// too, as it returns the plain outage's. Only the wrapped
					// sites hide it.
					raw := site == pe6aBroker || site == pe6aDeleteExpired || site == pe6aMeetsAssurance
					assert.Equal(t, raw, got.class.quotes, "the port's text comes back exactly where it did before")
					got.class.quotes = false

					sameAsPlain(t, plain, got)
					assert.False(t, got.class.unwalkable, "a walkable error passes unchanged")
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
				},
			},
		)
	}

	// The refusals each site's callers branch on, claimed by a chain that
	// cannot be walked.
	claims := map[pe6aSite][]error{
		pe6aBegin:         {oidc.ErrFlowStoreFull},
		pe6aBroker:        {oidc.ErrNoLinkedAccount, oidc.ErrProvisioningRefused},
		pe6aCompleteCB:    {oidc.ErrInvalidState},
		pe6aCompleteAbort: {oidc.ErrInvalidState},
	}

	for _, site := range sites {
		for _, claim := range claims[site] {
			prefix := string(site) + ": "
			cases = append(cases,
				testCase{
					name: prefix + "a cycle whose Is claims " + claim.Error() + " is an outage",
					site: site, err: &pe6aClaimCycle{claim: claim}, assert: asOutage("budget"),
				},
				testCase{
					name: prefix + "a cycle wrapping " + claim.Error() + " beside itself is an outage",
					site: site, err: &pe6aClaimCycleMany{claim: claim}, child: true, assert: asOutage("budget"),
				},
			)
		}
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe6aInChild(t, tc.name)

				return
			}

			defaults := pe6aDefaultRecords(t)

			plain := pe6aRun(t, p, tc.site, errPe6aPortDown, tc.cancel)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")
			pe6aSiteShape(t, tc.site, plain)

			got := pe6aRun(t, p, tc.site, tc.err, tc.cancel)
			tc.assert(t, plain, got)

			for _, rec := range pe6aJSONRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe6aRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe6aInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func pe6aInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe6aRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := pe6aRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
