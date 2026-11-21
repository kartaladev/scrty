package oidc_test

// TestPortErrors_Handoff replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found. It reuses the
// hostile error types and log helpers of login_porterr_test.go (pe6a*),
// read-only.

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
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
)

// pe6cRowEnv names the row a child process runs. It is empty in the parent.
const pe6cRowEnv = "SCRTY_OIDC_HANDOFF_PORTERR_ROW"

// pe6cRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe6cRanMarker = "SCRTY_OIDC_HANDOFF_PORTERR_RAN: "

// pe6cPurged is the count a failing DeleteExpired reports beside its error.
const pe6cPurged = 3

// errPe6cPortDown is the plain outage every parity run fails with.
var errPe6cPortDown = errors.New("port-6c: connection refused")

// pe6cSite names the port call a row fails.
type pe6cSite string

const (
	pe6cNewID   pe6cSite = "id.Generator.NewID in Issue"
	pe6cInsert  pe6cSite = "HandoffStore.Insert in Issue"
	pe6cFind    pe6cSite = "HandoffStore.FindByTokenID in Redeem"
	pe6cLoad    pe6cSite = "UserLoader.LoadByUserID in Redeem"
	pe6cConsume pe6cSite = "HandoffStore.Consume in Redeem"
	pe6cPurge   pe6cSite = "HandoffStore.DeleteExpired in PurgeExpired"
)

// pe6cRedeems reports whether site is reached through Redeem.
func pe6cRedeems(site pe6cSite) bool {
	return site == pe6cFind || site == pe6cLoad || site == pe6cConsume
}

// pe6cClass is the returned error as every check downstream reads it, taken
// inside the run's time bound.
type pe6cClass struct {
	nilErr, unwalkable, invalidHandoff, sentinelItself, handoffNotFound, userNotFound, cancelled bool

	// quotes is set when the error's text quotes the run's port error.
	quotes bool
}

// pe6cRecord is one record the handoff manager's logger wrote, other than an
// abort record, reduced to what a consumer routes on.
type pe6cRecord struct {
	level, msg, reason, op string
}

// pe6cOutcome is what one call through a failing port produced.
type pe6cOutcome struct {
	class pe6cClass

	// code is whether Issue returned a code; principal is whom Redeem
	// authenticated; purged is the count PurgeExpired returned.
	code      bool
	principal identity.UserID
	purged    int

	// The state the call left behind: records the store accepted, whether the
	// issued code was consumed, and whether a later redemption through a
	// healthy port succeeds (and a third one then fails).
	inserts            int64
	consumed           bool
	redeemable, reused bool

	records []pe6cRecord
	raw     string
	aborts  []map[string]any
}

// pe6cRun calls the handoff manager with site's port failing with portErr.
// When cancel is set the port cancels the caller's context before it fails.
// It fails the test when the call, or the checks of its error, hang or let a
// panic escape.
func pe6cRun(t *testing.T, site pe6cSite, portErr error, cancel bool) pe6cOutcome {
	t.Helper()

	// Identity, not errors.Is: the hostile errors cannot be walked.
	portText := pe6aSecret
	if portErr == errPe6cPortDown { //nolint:errorlint // identity of the parity error
		portText = errPe6cPortDown.Error()
	}

	ctx, stop := context.WithCancel(t.Context())
	defer stop()

	// failing is cleared once the run is over, so the follow-up redemptions
	// go through a healthy port.
	var failing atomic.Bool
	failing.Store(true)

	fail := func(at pe6cSite) error {
		if at != site || !failing.Load() {
			return nil
		}
		if cancel {
			stop()
		}

		return portErr
	}

	clk := clockwork.NewFakeClockAt(handoffT0)
	mem := oidc.NewMemoryHandoffStore()

	// A code issued before the run, for the redemption sites.
	var code string
	if pe6cRedeems(site) {
		issuer, err := oidc.NewHandoff(mem, NewMockUserLoader(gomock.NewController(t)), oidc.WithHandoffClock(clk))
		require.NoError(t, err)
		code, err = issuer.Issue(t.Context(), handoffCallback())
		require.NoError(t, err)
	}

	var inserts atomic.Int64

	ctrl := gomock.NewController(t)
	store := NewMockHandoffStore(ctrl)
	users := NewMockUserLoader(ctrl)
	ids := NewMockHandoffIDGenerator(ctrl)

	ids.EXPECT().NewID().DoAndReturn(func() (id.ID, error) {
		if err := fail(pe6cNewID); err != nil {
			return id.Nil, err
		}

		return id.MustParse("01926a4e-0000-7000-8000-0000000006c1"), nil
	}).AnyTimes()
	store.EXPECT().Insert(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, rec oidc.HandoffRecord) error {
		if err := fail(pe6cInsert); err != nil {
			return err
		}
		inserts.Add(1)

		return mem.Insert(ctx, rec)
	}).AnyTimes()
	store.EXPECT().FindByTokenID(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, tokenID string) (*oidc.HandoffRecord, error) {
			if err := fail(pe6cFind); err != nil {
				return nil, err
			}

			return mem.FindByTokenID(ctx, tokenID)
		}).AnyTimes()
	store.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, tokenID string, at time.Time) error {
			if err := fail(pe6cConsume); err != nil {
				return err
			}

			return mem.Consume(ctx, tokenID, at)
		}).AnyTimes()
	store.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, before time.Time) (int, error) {
			if err := fail(pe6cPurge); err != nil {
				return pe6cPurged, err
			}

			return mem.DeleteExpired(ctx, before)
		}).AnyTimes()
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
			if err := fail(pe6cLoad); err != nil {
				return nil, err
			}

			return handoffUser(), nil
		}).AnyTimes()

	logs := &bytes.Buffer{}
	h, err := oidc.NewHandoff(store, users,
		oidc.WithHandoffClock(clk),
		oidc.WithHandoffIDGenerator(ids),
		oidc.WithHandoffLogger(slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	require.NoError(t, err)

	type result struct {
		out      pe6cOutcome
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
			out  pe6cOutcome
			rerr error
		)

		switch {
		case site == pe6cPurge:
			out.purged, rerr = h.PurgeExpired(ctx)
		case pe6cRedeems(site):
			var res oidc.HandoffResult
			res, rerr = h.Redeem(ctx, code)
			out.principal = res.Principal.ID
		default:
			var issued string
			issued, rerr = h.Issue(ctx, handoffCallback())
			out.code = issued != ""
		}

		// Every check a caller makes of the error, inside the bound.
		out.class = pe6cClass{
			nilErr:          rerr == nil,
			unwalkable:      errors.Is(rerr, porterr.ErrUnwalkable),
			invalidHandoff:  errors.Is(rerr, oidc.ErrInvalidHandoff),
			sentinelItself:  rerr == oidc.ErrInvalidHandoff, //nolint:errorlint // Redeem returns the sentinel itself
			handoffNotFound: errors.Is(rerr, oidc.ErrHandoffNotFound),
			userNotFound:    errors.Is(rerr, identity.ErrUserNotFound),
			cancelled:       errors.Is(rerr, context.Canceled),
		}
		if rerr != nil {
			out.class.quotes = strings.Contains(rerr.Error(), portText)
		}

		returned = true
		done <- result{out: out}
	}()

	var out pe6cOutcome

	select {
	case res := <-done:
		require.False(t, res.panicked, "a hostile port error escaped as a panic: %v", res.value)
		out = res.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the handoff manager or a check of its error")
	}

	out.inserts = inserts.Load()
	out.raw = logs.String()

	for _, rec := range pe6aJSONRecords(t, out.raw) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)

			continue
		}

		reason, _ := rec["reason"].(string)
		op, _ := rec["op"].(string)
		out.records = append(out.records, pe6cRecord{
			level: rec["level"].(string), msg: rec["msg"].(string), reason: reason, op: op,
		})
	}

	if pe6cRedeems(site) {
		tokenID, _ := splitHandoffCode(t, code)
		rec, err := mem.FindByTokenID(t.Context(), tokenID)
		require.NoError(t, err)
		out.consumed = rec.ConsumedAt != nil

		// The state left behind, read through a healthy port: whether the
		// code can still be redeemed, and that it cannot be redeemed twice.
		failing.Store(false)
		_, err = h.Redeem(t.Context(), code)
		out.redeemable = err == nil
		_, err = h.Redeem(t.Context(), code)
		out.reused = err == nil
	}

	return out
}

// pe6cSiteShape pins what a plain outage of site produces, so a parity row
// cannot pass by two equally wrong outcomes.
func pe6cSiteShape(t *testing.T, site pe6cSite, plain pe6cOutcome) {
	t.Helper()

	c := plain.class
	require.False(t, c.nilErr, "precondition: a plain outage fails the call")
	require.False(t, c.handoffNotFound || c.userNotFound, "precondition: a plain outage is no not-found")
	require.Zero(t, plain.inserts, "precondition: no plain outage stores a handoff")
	require.False(t, plain.code, "precondition: no plain outage returns a code")
	require.Empty(t, plain.principal, "precondition: no plain outage authenticates anyone")
	require.False(t, plain.reused, "precondition: a code is never redeemed twice")

	switch site {
	case pe6cFind, pe6cLoad, pe6cConsume:
		require.True(t, c.sentinelItself, "precondition: a failed redemption is ErrInvalidHandoff itself")
		require.False(t, plain.consumed, "precondition: a failed redemption spends nothing")
		require.True(t, plain.redeemable, "precondition: the code stays redeemable after an outage")

		op := map[pe6cSite]string{pe6cFind: "find", pe6cConsume: "consume"}[site]
		reason := "handoff-store"
		if site == pe6cLoad {
			reason = "user-loader"
		}
		require.Equal(t, []pe6cRecord{{level: "ERROR", msg: "oidc handoff redemption refused", reason: reason, op: op}},
			plain.records, "precondition: an outage is one ERROR record naming the dependency")
	case pe6cPurge:
		require.Equal(t, pe6cPurged, plain.purged, "precondition: the store's count comes back beside its error")
		require.True(t, c.quotes, "precondition: a plain store error comes back as it was")
		require.Empty(t, plain.records)
	case pe6cInsert:
		require.False(t, c.invalidHandoff)
		require.False(t, c.quotes, "precondition: a store error's text is replaced (diag.Wrap)")
		require.Empty(t, plain.records)
	default:
		require.False(t, c.invalidHandoff)
		require.True(t, c.quotes, "precondition: a plain generator error's text is wrapped")
		require.Empty(t, plain.records)
	}
}

// TestPortErrors_Handoff pins that each port call of the handoff manager —
// the record ID generator and the store's Insert in Issue, the store's
// FindByTokenID and Consume and the user loader in Redeem, and the store's
// DeleteExpired in PurgeExpired — failing with an error whose chain cannot be
// walked is answered exactly as a plain outage of that port: the same answer
// to every sentinel check a caller makes, the same records (level, message,
// reason, op), the same state (records stored, the code consumed or still
// redeemable, never redeemed twice, the purge count), and nothing quoting the
// port's error. A chain that claims the not-found sentinel the site branches
// on (ErrHandoffNotFound, identity.ErrUserNotFound) is an outage, never that
// refusal. The sanitizer writes one record, to the manager's logger, and none
// to slog.Default().
func TestPortErrors_Handoff(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe6cRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name string
		site pe6cSite
		err  error

		// cancel makes the port cancel the caller's context before it fails,
		// in both runs of the row.
		cancel bool

		// child runs the row in a child process: unsanitized, it may
		// overflow the stack fatally.
		child bool

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got pe6cOutcome)
	}

	sameAsPlain := func(t *testing.T, plain, got pe6cOutcome) {
		t.Helper()

		wantClass := plain.class
		wantClass.unwalkable = got.class.unwalkable // asserted by the caller
		wantClass.quotes = got.class.quotes         // asserted by the caller
		assert.Equal(t, wantClass, got.class, "the same answer to every check of the error")
		assert.Equal(t, plain.code, got.code, "the same code result")
		assert.Equal(t, plain.principal, got.principal, "the same principal")
		assert.Equal(t, plain.purged, got.purged, "the same purge count")
		assert.Equal(t, plain.inserts, got.inserts, "the same handoffs stored")
		assert.Equal(t, plain.consumed, got.consumed, "the code consumed as a plain outage leaves it")
		assert.Equal(t, plain.redeemable, got.redeemable, "the code redeemable as a plain outage leaves it")
		assert.False(t, got.reused, "a code is never redeemed twice")
		assert.Equal(t, plain.records, got.records, "the same records: level, message, reason, op")
	}

	asOutage := func(reason string) func(t *testing.T, plain, got pe6cOutcome) {
		return func(t *testing.T, plain, got pe6cOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)
			assert.False(t, got.class.quotes, "the returned error quotes the port's")
			assert.NotContains(t, got.raw, pe6aSecret, "a record quotes the port's error")

			if !plain.class.sentinelItself {
				assert.True(t, got.class.unwalkable, "the error is the sanitizer's fault")
			}

			require.Len(t, got.aborts, 1, "one abort record, on the handoff manager's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])
		}
	}

	var cases []testCase

	sites := []pe6cSite{pe6cNewID, pe6cInsert, pe6cFind, pe6cLoad, pe6cConsume, pe6cPurge}
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
				assert: func(t *testing.T, plain, got pe6cOutcome) {
					t.Helper()

					// A walkable error passes unchanged, so its text comes back
					// exactly where a plain outage's does.
					sameAsPlain(t, plain, got)
					assert.Equal(t, plain.class.quotes, got.class.quotes, "the port's text comes back where it did")
					assert.False(t, got.class.unwalkable, "a walkable error passes unchanged")
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
				},
			},
		)
	}

	// The not-found sentinels each site branches on, claimed by a chain that
	// cannot be walked.
	claims := map[pe6cSite]error{
		pe6cFind:    oidc.ErrHandoffNotFound,
		pe6cLoad:    identity.ErrUserNotFound,
		pe6cConsume: oidc.ErrHandoffNotFound,
	}

	for _, site := range sites {
		claim, ok := claims[site]
		if !ok {
			continue
		}

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

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe6cInChild(t, tc.name)

				return
			}

			defaults := pe6aDefaultRecords(t)

			plain := pe6cRun(t, tc.site, errPe6cPortDown, tc.cancel)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")
			pe6cSiteShape(t, tc.site, plain)

			got := pe6cRun(t, tc.site, tc.err, tc.cancel)
			tc.assert(t, plain, got)

			for _, rec := range pe6aJSONRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe6cRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe6cInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// line that shows it ran the row: a stack overflow is fatal and only a child
// can watch for one.
func pe6cInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe6cRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := pe6cRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
