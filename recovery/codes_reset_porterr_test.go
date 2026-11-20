package recovery_test

// TestPortErrors_CodesReset replaces slog.Default() for its duration, so it
// does not run in parallel, and it restores the logger it found.

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

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/recovery"
)

// crPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const crPortErrRowEnv = "SCRTY_RECOVERY_CODESRESET_PORTERR_ROW"

// crPortErrRanMarker prefixes the line a child prints, followed by the row's
// name, after the row ran and passed.
const crPortErrRanMarker = "SCRTY_RECOVERY_CODESRESET_PORTERR_RAN: "

// errCRPortDown is the plain outage every parity run fails with.
var errCRPortDown = errors.New("port: connection refused")

// crSite names the port call a row fails.
type crSite string

const (
	crFactory   crSite = "the code limiter factory at construction"
	crReplace   crSite = "the code store's ReplaceSet"
	crRemaining crSite = "the code store's Remaining"
	crMatch     crSite = "the code store's Match"
	crSpend     crSite = "the code store's Spend"
	crHeld      crSite = "an authenticator kind's Held"
	crPolicy    crSite = "the reset policy"
	crRemove    crSite = "an authenticator kind's Remove"
)

// crStore is a code store over a real one that fails the one method the site
// names, so the set it leaves behind can be read from the real store.
type crStore struct {
	*recovery.MemoryCodeStore

	site crSite
	err  error
}

func (s crStore) ReplaceSet(ctx context.Context, user identity.UserID, hashes [][]byte, at time.Time) error {
	if s.site == crReplace {
		return s.err
	}

	return s.MemoryCodeStore.ReplaceSet(ctx, user, hashes, at)
}

func (s crStore) Match(ctx context.Context, user identity.UserID, hash []byte) (bool, error) {
	if s.site == crMatch {
		return false, s.err
	}

	return s.MemoryCodeStore.Match(ctx, user, hash)
}

func (s crStore) Spend(ctx context.Context, user identity.UserID, hash []byte, at time.Time) (bool, error) {
	if s.site == crSpend {
		return false, s.err
	}

	return s.MemoryCodeStore.Spend(ctx, user, hash, at)
}

func (s crStore) Remaining(ctx context.Context, user identity.UserID) (int, error) {
	if s.site == crRemaining {
		return 0, s.err
	}

	return s.MemoryCodeStore.Remaining(ctx, user)
}

// crOutcome is what one call through a failing port produced. Every error
// classification is made inside the bound.
type crOutcome struct {
	text string

	failed     bool
	config     bool
	dependency bool
	malformed  bool
	refused    bool
	throttled  bool
	unwalkable bool

	// kept is how many codes the store still holds unspent, and planned how
	// many authenticators the plan names.
	kept    int
	planned int

	// records are the component's records other than abort records, raw all of
	// its output, and aborts the sanitizer's records where the site writes
	// them.
	records []cmpRecord
	raw     string
	aborts  []map[string]any

	// elsewhere is how many abort records landed on the logger the site does
	// not use.
	elsewhere int
}

func (o *crOutcome) crClassify(err error) {
	if err == nil {
		return
	}

	o.failed = true
	o.text = err.Error()
	o.config = errors.Is(err, recovery.ErrConfig)
	o.dependency = errors.Is(err, recovery.ErrDependency)
	o.malformed = errors.Is(err, recovery.ErrMalformed)
	o.refused = errors.Is(err, recovery.ErrRefused)
	o.throttled = errors.Is(err, recovery.ErrCodeThrottled)
	o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
}

// crSplit fills the outcome's records from the output of the component's
// logger (own) and of slog.Default() (def). The reset sites have no logger, so
// their abort record is expected on def.
func (o *crOutcome) crSplit(t *testing.T, onDefault bool, own, def string) {
	t.Helper()

	o.raw = own + def

	pick := func(raw string, expected bool) {
		for _, rec := range limJSONRecords(t, raw) {
			if rec["msg"] == porterr.MsgClassificationAborted {
				if expected {
					o.aborts = append(o.aborts, rec)
				} else {
					o.elsewhere++
				}

				continue
			}

			reason, _ := rec["reason"].(string)
			o.records = append(o.records, cmpRecord{level: rec["level"].(string), msg: rec["msg"].(string), reason: reason})
		}
	}

	pick(own, !onDefault)
	pick(def, onDefault)
}

// crBounded runs call and fails the test when it hangs or lets a panic escape.
func crBounded(t *testing.T, call func() crOutcome) crOutcome {
	t.Helper()

	type result struct {
		out      crOutcome
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

		out := call()
		returned = true
		done <- result{out: out}
	}()

	select {
	case res := <-done:
		require.False(t, res.panicked, "a hostile port error escaped the flow as a panic: %v", res.value)

		return res.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the flow, or the classification of its error")
	}

	return crOutcome{}
}

// runCRSite runs the flow that reaches the site's call, on ctx, against a port
// that fails that call with portErr.
func runCRSite(t *testing.T, ctx context.Context, site crSite, portErr error) crOutcome {
	t.Helper()

	own := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(own, &slog.HandlerOptions{Level: slog.LevelDebug}))
	def := limDefaultRecords(t)
	ctrl := gomock.NewController(t)

	var out crOutcome

	onDefault := false

	switch site {
	case crFactory:
		f := NewMockLimiterFactory(ctrl)
		f.EXPECT().NewLimiter(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, portErr).Times(1)

		out = crBounded(t, func() crOutcome {
			_, err := recovery.NewCodes(recovery.WithCodesLimiterFactory(f), recovery.WithCodesLogger(logger))

			o := crOutcome{}
			o.crClassify(err)

			return o
		})
	case crReplace, crRemaining, crMatch, crSpend:
		base := recovery.NewMemoryCodeStore()

		healthy, err := recovery.NewCodes(recovery.WithCodesStore(base))
		require.NoError(t, err)

		codes, err := healthy.Generate(t.Context(), anaID)
		require.NoError(t, err)

		hash, err := healthy.Check(t.Context(), anaID, codes[0])
		require.NoError(t, err)

		c, err := recovery.NewCodes(recovery.WithCodesStore(crStore{MemoryCodeStore: base, site: site, err: portErr}),
			recovery.WithCodesLogger(logger))
		require.NoError(t, err)

		out = crBounded(t, func() crOutcome {
			var err error

			switch site {
			case crReplace:
				_, err = c.Generate(ctx, anaID)
			case crRemaining:
				_, err = c.Remaining(ctx, anaID)
			case crMatch:
				err = c.Confirm(ctx, anaID, codes[0])
			case crSpend:
				err = c.Spend(ctx, anaID, hash)
			}

			o := crOutcome{}
			o.crClassify(err)

			return o
		})

		out.kept, err = base.Remaining(t.Context(), anaID)
		require.NoError(t, err)
	default:
		onDefault = true
		out = runCRReset(t, ctx, ctrl, site, portErr)
	}

	out.crSplit(t, onDefault, own.String(), def.String())

	return out
}

// runCRReset runs the planner's listing, policy or removal against a kind or
// policy that fails with portErr. The planner has no logger.
func runCRReset(t *testing.T, ctx context.Context, ctrl *gomock.Controller, site crSite, portErr error) crOutcome {
	t.Helper()

	first := namedKind(ctrl, recovery.MFAKind)
	second := namedKind(ctrl, "passkey")

	var (
		policy recovery.ResetPolicy
		mode   = recovery.ResetAll
	)

	switch site {
	case crHeld:
		first.EXPECT().Held(gomock.Any(), anaID).Return(nil, portErr).Times(1)
	case crPolicy:
		mode = recovery.ResetCustom
		policy = func(context.Context, recovery.ResetInput) ([]recovery.AuthenticatorRef, error) { return nil, portErr }

		first.EXPECT().Held(gomock.Any(), anaID).Return([]recovery.AuthenticatorRef{refTOTP}, nil).Times(1)
		second.EXPECT().Held(gomock.Any(), anaID).Return([]recovery.AuthenticatorRef{refPasskey}, nil).Times(1)
	case crRemove:
		first.EXPECT().Remove(gomock.Any(), anaID, []recovery.AuthenticatorRef{refTOTP}).Return(portErr).Times(1)
		// The second kind has no expectation: a removal after the first
		// failed would fail the mock.
	}

	p, err := recovery.NewPlanner([]recovery.AuthenticatorKind{first, second}, mode, policy)
	require.NoError(t, err)

	return crBounded(t, func() crOutcome {
		o := crOutcome{}

		if site == crRemove {
			o.crClassify(p.Execute(ctx, anaID, []recovery.AuthenticatorRef{refTOTP, refPasskey}))

			return o
		}

		plan, err := p.Plan(ctx, anaID, nil, nil)
		o.planned = len(plan)
		o.crClassify(err)

		return o
	})
}

// TestPortErrors_CodesReset pins that each of these port calls failing with an
// error whose chain cannot be walked is answered exactly as a plain outage of
// that port is:
//
//   - the code limiter factory's error is a configuration error at
//     construction, never a panic or a hang;
//   - the code store failing at ReplaceSet, Remaining, Match or Spend returns a
//     dependency failure, the set left as it was, a lookup that failed never
//     read as a match or as no such code;
//   - an authenticator kind's listing, the reset policy and a kind's removal
//     refuse with a dependency failure, and nothing is removed after a failed
//     removal.
//
// The sanitizer writes one record, to the codes manager's logger, or to
// slog.Default() for the reset sites, which have none, and none elsewhere. A
// context the caller cancelled, with a cycle claiming context.Canceled, is
// never taken for a hang-up. An Is that panics only for the site's own
// sentinel is accepted (design decision 11): it passes the sanitizer.
func TestPortErrors_CodesReset(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(crPortErrRowEnv)
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
		site crSite
		err  error

		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it may
		// overflow the stack fatally.
		child bool

		assert func(t *testing.T, plain, got crOutcome)
	}

	sameAsPlain := func(t *testing.T, plain, got crOutcome) {
		t.Helper()

		assert.Equal(t, plain.failed, got.failed, "an error returned alike")
		assert.Equal(t, plain.config, got.config, "ErrConfig")
		assert.Equal(t, plain.dependency, got.dependency, "ErrDependency")
		assert.Equal(t, plain.malformed, got.malformed, "ErrMalformed")
		assert.Equal(t, plain.refused, got.refused, "ErrRefused")
		assert.Equal(t, plain.throttled, got.throttled, "ErrCodeThrottled")
		assert.Equal(t, plain.kept, got.kept, "the code set left alike")
		assert.Equal(t, plain.planned, got.planned, "the plan alike")
		assert.Equal(t, plain.records, got.records, "the same records, levels and reasons")
	}

	asOutage := func(site crSite, reason string) func(t *testing.T, plain, got crOutcome) {
		return func(t *testing.T, plain, got crOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)

			require.True(t, plain.failed, "precondition: a plain outage fails the call")

			switch site {
			case crFactory:
				require.True(t, plain.config, "precondition: a plain outage is a configuration error")
			case crReplace:
				assert.Equal(t, 10, got.kept, "the previous set stands")
			case crRemaining, crMatch, crSpend:
				assert.Equal(t, 10, got.kept, "nothing is spent")
				assert.False(t, got.refused, "a fault is neither no such code nor a lost race")
			case crHeld, crPolicy, crRemove:
				assert.Zero(t, got.planned, "no plan")
			}

			assert.True(t, got.unwalkable, "the answer carries the fault standing for the error")
			assert.NotContains(t, got.text, limPortErrSecret, "the returned error quotes the port's")
			assert.NotContains(t, got.raw, limPortErrSecret, "a record quotes the port's error")

			require.Len(t, got.aborts, 1, "one abort record, where the site writes it")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])
			assert.Zero(t, got.elsewhere, "an abort record went to the logger the site does not use")
		}
	}

	// walked is a chain the sanitizer reads to its end: answered as a plain
	// error is, with no abort record.
	walked := func(t *testing.T, plain, got crOutcome) {
		t.Helper()

		sameAsPlain(t, plain, got)
		assert.False(t, got.unwalkable, "a walkable error replaced by a fault")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
		assert.Zero(t, got.elsewhere)
	}

	sites := []crSite{crFactory, crReplace, crRemaining, crMatch, crSpend, crHeld, crPolicy, crRemove}

	var cases []testCase

	for _, site := range sites {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{name: prefix + "a cycle through Unwrap() error", site: site, err: &limCycleOne{},
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", site: site, err: &limCycleMany{}, child: true,
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a link whose Unwrap panics", site: site, err: limPanicUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", site: site, err: limPanicNilUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a join that fans out", site: site, err: limFanOut(25),
				assert: asOutage(site, "budget")},
			testCase{
				name: prefix + "a typed-nil root walks to the end and is answered as a plain error",
				site: site, err: (*limTypedNil)(nil),
				assert: walked,
			},
		)
	}

	// A caller's cancellation reaches the sites that run on its context; the
	// factory runs at construction, with none (accepted: nothing to observe).
	for _, site := range sites[1:] {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{
				name: prefix + "a cycle on a context the caller cancelled is an outage",
				site: site, err: &limCycleOne{}, ctx: cancelled,
				assert: asOutage(site, "budget"),
			},
			testCase{
				name: prefix + "a cycle claiming context.Canceled on a cancelled context is an outage",
				site: site, err: &recClaimCycle{claims: context.Canceled}, ctx: cancelled,
				assert: asOutage(site, "budget"),
			},
			testCase{
				name: prefix + "a cycle wrapping context.Canceled beside itself is an outage",
				site: site, err: &recWrapCycleMany{wraps: context.Canceled}, ctx: cancelled, child: true,
				assert: asOutage(site, "budget"),
			},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				crPortErrInChild(t, tc.name)

				return
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runCRSite(t, ctx, tc.site, errCRPortDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")
			require.Zero(t, plain.elsewhere, "a plain outage writes no abort record")

			got := runCRSite(t, ctx, tc.site, tc.err)
			tc.assert(t, plain, got)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(crPortErrRanMarker + tc.name + "\n")
			}
		})
	}
}

// crPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints the
// marker that shows it ran the row: a stack overflow is fatal and only a
// child can watch for one.
func crPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), crPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := crPortErrRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
