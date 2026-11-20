package onetime_test

// TestPortErrors_Tokens replaces slog.Default() for its duration, so it does
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/internal/depfault"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// ptRowEnv names the row a child process runs. It is empty in the parent.
const ptRowEnv = "SCRTY_ONETIME_PORTERR_ROW"

// ptRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const ptRanMarker = "SCRTY_ONETIME_PORTERR_RAN: "

// ptSecret is text no record and no returned error may quote.
const ptSecret = "pt-secret: ana@example.com"

// ptErrDown is the plain outage every parity run fails with.
var ptErrDown = errors.New("pt: connection refused, " + ptSecret)

// ptCycleOne contains itself through Unwrap() error.
type ptCycleOne struct{}

func (*ptCycleOne) Error() string   { return ptSecret }
func (c *ptCycleOne) Unwrap() error { return c }

// ptCycleMany contains itself through Unwrap() []error. Unsanitized, a stdlib
// walk overflows the stack fatally, so its rows run in a child process.
type ptCycleMany struct{}

func (*ptCycleMany) Error() string     { return ptSecret }
func (c *ptCycleMany) Unwrap() []error { return []error{c} }

// ptCycleAround holds sentinel first and then itself: a stdlib errors.Is for
// sentinel answers yes at once, and one for anything else overflows the
// stack. Its rows run in a child process.
type ptCycleAround struct{ sentinel error }

func (*ptCycleAround) Error() string     { return ptSecret }
func (c *ptCycleAround) Unwrap() []error { return []error{c.sentinel, c} }

// ptPanicUnwrap is an error whose Unwrap panics.
type ptPanicUnwrap struct{}

func (ptPanicUnwrap) Error() string { return ptSecret }
func (ptPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + ptSecret) }

// ptPanicNilUnwrap is an error whose Unwrap panics with nil.
type ptPanicNilUnwrap struct{}

func (ptPanicNilUnwrap) Error() string { return ptSecret }
func (ptPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// ptTypedNil is returned as a nil pointer inside a non-nil error.
type ptTypedNil struct{}

func (*ptTypedNil) Error() string { return ptSecret }

// ptFanOut is errors.Join(n, n) nested depth times over leaf: 2^depth paths
// for an unbounded walk, and a depth-first errors.Is reaches leaf at once.
func ptFanOut(depth int, leaf error) error {
	err := leaf
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// ptBuffer is a buffer safe for the concurrent writes of a logger.
type ptBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *ptBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *ptBuffer) records(t *testing.T) []map[string]any {
	t.Helper()

	b.mu.Lock()
	out := b.buf.String()
	b.mu.Unlock()

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

// ptSite names the store call (or the refusal check) a row fails, and through
// it the manager operation it runs.
type ptSite string

const (
	ptInsert       ptSite = "Issue's Store.Insert"
	ptInsertWithin ptSite = "IssueWithin's Store.InsertWithin"
	ptFind         ptSite = "Redeem's Store.FindByID"
	ptConsume      ptSite = "Redeem's Store.Consume"
	ptCount        ptSite = "IssuedCount's Store.CountRecentBySubject"
	ptPurge        ptSite = "the expiry task's Reaper.DeleteExpiredBefore"
	ptRefusal      ptSite = "Redeem's refusal check"
)

// ptSentinel is the library sentinel the site's caller, or the manager,
// branches on: a hostile chain built over it must not be read as it.
func ptSentinel(site ptSite) error {
	switch site {
	case ptInsertWithin:
		return onetime.ErrIssueLimitReached
	case ptPurge:
		return onetime.ErrReapUnsupported
	case ptRefusal:
		return onetime.ErrInvalidToken
	default:
		return onetime.ErrTokenNotFound
	}
}

// ptReaping is a store that can purge, made of the two generated mocks.
type ptReaping struct {
	*MockStore
	*MockReaper
}

// ptOutcome is what one run through a failing store produced, and the state
// it left. Every error classification is made inside the bound.
type ptOutcome struct {
	ok   bool
	text string

	invalid          bool
	limitReached     bool
	notFound         bool
	reapUnsupported  bool
	purgeUnsupported bool
	canceled         bool
	unwalkable       bool

	// issued is whether a presented token was handed out; n is the count or
	// the number removed.
	issued bool
	n      int

	// consumed is whether the seeded token was spent; stored is how many
	// records the store holds afterwards.
	consumed bool
	stored   int

	// storeFailures are the levels of the manager's store-failure records.
	storeFailures []string

	// watchFailed and watchUnwalkable read the depfault Watch, in a wrapped run.
	watchFailed     bool
	watchUnwalkable bool

	// aborts are the sanitizer's records on the manager's logger, and
	// defaults the ones on slog.Default().
	aborts   []map[string]any
	defaults []map[string]any
}

// ptRun builds a manager over a mocked store that answers through a memory
// store, seeds one token, then runs site's operation on ctx while site's call
// fails with portErr. wrapped puts depfault.Store between the manager and the
// store, with a Watch on ctx. It fails the test when the operation hangs or
// lets a panic escape.
func ptRun(t *testing.T, ctx context.Context, site ptSite, wrapped bool, portErr error) ptOutcome {
	t.Helper()

	defaults := &ptBuffer{}
	slog.SetDefault(slog.New(slog.NewJSONHandler(defaults, &slog.HandlerOptions{Level: slog.LevelDebug})))

	logs := &ptBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mem, err := onetime.NewMemoryStore()
	require.NoError(t, err)

	var armed atomic.Bool

	failing := func(at ptSite) bool { return armed.Load() && site == at }

	ctrl := gomock.NewController(t)

	store := NewMockStore(ctrl)
	store.EXPECT().Insert(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, tok onetime.Token) error {
			if failing(ptInsert) {
				return portErr
			}

			return mem.Insert(context.WithoutCancel(ctx), tok)
		}).AnyTimes()
	store.EXPECT().InsertWithin(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, tok onetime.Token, since time.Time, limit int) (bool, error) {
			if failing(ptInsertWithin) {
				return false, portErr
			}

			return mem.InsertWithin(context.WithoutCancel(ctx), tok, since, limit)
		}).AnyTimes()
	store.EXPECT().FindByID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, tokenID id.ID) (*onetime.Token, error) {
			if failing(ptFind) {
				return nil, portErr
			}

			return mem.FindByID(context.WithoutCancel(ctx), tokenID)
		}).AnyTimes()
	store.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, tokenID id.ID, at time.Time) error {
			if failing(ptConsume) {
				return portErr
			}

			return mem.Consume(context.WithoutCancel(ctx), tokenID, at)
		}).AnyTimes()
	store.EXPECT().CountRecentBySubject(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, purpose, subject string, since time.Time) (int, error) {
			if failing(ptCount) {
				return 0, portErr
			}

			return mem.CountRecentBySubject(context.WithoutCancel(ctx), purpose, subject, since)
		}).AnyTimes()

	reaper := NewMockReaper(ctrl)
	reaper.EXPECT().DeleteExpiredBefore(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, purpose string, retainSince time.Time) (int, error) {
			if failing(ptPurge) {
				return 0, portErr
			}

			return mem.DeleteExpiredBefore(context.WithoutCancel(ctx), purpose, retainSince)
		}).AnyTimes()

	var port onetime.Store = ptReaping{MockStore: store, MockReaper: reaper}
	if wrapped {
		port = depfault.Store(port, logger)
	}

	m, err := onetime.New("pt-purpose", onetime.WithStore(port), onetime.WithLogger(logger))
	require.NoError(t, err)

	presented, _, err := m.Issue(t.Context(), "s-1")
	require.NoError(t, err, "precondition: the seed token is issued")

	var watch *depfault.Watch
	if wrapped {
		ctx, watch = depfault.Watching(ctx)
	}

	var flow func(ctx context.Context) (issued bool, n int, err error)

	switch site {
	case ptInsert:
		flow = func(ctx context.Context) (bool, int, error) {
			p, _, err := m.Issue(ctx, "s-1")

			return p != "", 0, err
		}
	case ptInsertWithin:
		flow = func(ctx context.Context) (bool, int, error) {
			p, _, err := m.IssueWithin(ctx, "s-1", 5)

			return p != "", 0, err
		}
	case ptFind, ptConsume:
		flow = func(ctx context.Context) (bool, int, error) {
			_, err := m.Redeem(ctx, presented, "")

			return false, 0, err
		}
	case ptRefusal:
		flow = func(ctx context.Context) (bool, int, error) {
			_, err := m.Redeem(ctx, presented, "", func(context.Context, onetime.Token) error { return portErr })

			return false, 0, err
		}
	case ptCount:
		flow = func(ctx context.Context) (bool, int, error) {
			n, err := m.IssuedCount(ctx, "s-1")

			return false, n, err
		}
	case ptPurge:
		flow = func(ctx context.Context) (bool, int, error) {
			n, err := onetime.ExpiryTaskNamed("pt", m).Run(ctx)

			return false, n, err
		}
	default:
		require.FailNow(t, "no flow for site "+string(site))
	}

	armed.Store(true)

	type result struct {
		out      ptOutcome
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

		issued, n, err := flow(ctx)

		o := ptOutcome{ok: err == nil, issued: issued, n: n}
		if err != nil {
			o.text = err.Error()
			o.invalid = errors.Is(err, onetime.ErrInvalidToken)
			o.limitReached = errors.Is(err, onetime.ErrIssueLimitReached)
			o.notFound = errors.Is(err, onetime.ErrTokenNotFound)
			o.reapUnsupported = errors.Is(err, onetime.ErrReapUnsupported)
			o.purgeUnsupported = errors.Is(err, expiry.ErrPurgeUnsupported)
			o.canceled = errors.Is(err, context.Canceled)
			o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
		}

		if watch != nil {
			if failure := watch.Failure(); failure != nil {
				o.watchFailed = true
				o.watchUnwalkable = errors.Is(failure, porterr.ErrUnwalkable)
			}
		}

		returned = true
		done <- result{out: o}
	}()

	var out ptOutcome

	select {
	case r := <-done:
		require.False(t, r.panicked, "a port error escaped as a panic: %v", r.value)
		out = r.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the operation, or its classification")
	}

	armed.Store(false)

	tok, err := mem.FindByID(t.Context(), mustTokenID(t, presented))
	require.NoError(t, err)
	out.consumed = !tok.ConsumedAt.IsZero()
	out.stored = mem.Len()

	for _, rec := range logs.records(t) {
		switch msg, _ := rec["msg"].(string); {
		case msg == porterr.MsgClassificationAborted:
			out.aborts = append(out.aborts, rec)
		case strings.HasPrefix(msg, "onetime: "):
			level, _ := rec["level"].(string)
			out.storeFailures = append(out.storeFailures, level)
		}
	}

	for _, rec := range defaults.records(t) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.defaults = append(out.defaults, rec)
		}
	}

	return out
}

// mustTokenID is the identifier half of a presented token.
func mustTokenID(t *testing.T, presented string) id.ID {
	t.Helper()

	raw, _, found := strings.Cut(presented, ".")
	require.True(t, found, "precondition: a presented token has an identifier")

	tokenID, err := id.Parse(raw)
	require.NoError(t, err)

	return tokenID
}

// ptSameAsPlain asserts got is the outcome and state a plain outage at the
// same site produced.
func ptSameAsPlain(t *testing.T, site ptSite, plain, got ptOutcome) {
	t.Helper()

	require.False(t, plain.ok, "precondition: a plain outage is no success")
	require.False(t, plain.limitReached, "precondition: a plain outage is no limit reached")
	require.False(t, plain.reapUnsupported, "precondition: a plain outage is no reaping unsupported")

	assert.False(t, got.ok, "never answered success")
	if site != ptRefusal {
		assert.Equal(t, plain.text, got.text, "the same text")
	}
	assert.Equal(t, plain.invalid, got.invalid, "the same invalid-token class")
	assert.False(t, got.limitReached, "an outage never reads as the issue limit reached")
	assert.Equal(t, plain.notFound, got.notFound, "the same not-found class")
	assert.False(t, got.reapUnsupported, "an outage never reads as a store that cannot purge")
	assert.Equal(t, plain.purgeUnsupported, got.purgeUnsupported, "the same purge-unsupported class")
	assert.Equal(t, plain.canceled, got.canceled, "the same hang-up class")
	assert.Equal(t, plain.issued, got.issued, "a token is issued, or not, as for a plain outage")
	assert.Equal(t, plain.n, got.n, "the same count as for a plain outage")
	assert.Equal(t, plain.consumed, got.consumed, "the token is spent, or not, as for a plain outage")
	assert.Equal(t, plain.stored, got.stored, "the store holds what it holds after a plain outage")
	assert.Equal(t, plain.storeFailures, got.storeFailures, "the same store-failure records")
	assert.Equal(t, plain.watchFailed, got.watchFailed, "the Watch records a failure, or not, as for a plain outage")
}

type ptRow struct {
	name   string
	err    error
	reason string
	child  bool
	cancel bool
}

func ptRows(sentinel error) []ptRow {
	return []ptRow{
		{name: "a cycle through Unwrap() error", err: &ptCycleOne{}, reason: "budget"},
		{name: "a cycle through Unwrap() []error", err: &ptCycleMany{}, reason: "budget", child: true},
		{name: "a link whose Unwrap panics", err: ptPanicUnwrap{}, reason: "panic"},
		{name: "a link whose Unwrap panics with nil", err: ptPanicNilUnwrap{}, reason: "panic"},
		{name: "a join that fans out", err: ptFanOut(25, errors.New(ptSecret)), reason: "budget"},
		{name: "a join that fans out over the site's sentinel", err: ptFanOut(25, sentinel), reason: "budget"},
		{name: "a cycle around the site's sentinel", err: &ptCycleAround{sentinel: sentinel}, reason: "budget", child: true},
		{
			name: "a join that fans out over context.Canceled on a context the caller cancelled",
			err:  ptFanOut(25, context.Canceled), reason: "budget", cancel: true,
		},
		{
			name: "a cycle around context.Canceled on a context the caller cancelled",
			err:  &ptCycleAround{sentinel: context.Canceled}, reason: "budget", child: true, cancel: true,
		},
		{name: "a cycle on a context the caller cancelled", err: &ptCycleOne{}, reason: "budget", cancel: true},
	}
}

func ptSites() []ptSite {
	return []ptSite{ptInsert, ptInsertWithin, ptFind, ptConsume, ptCount, ptPurge, ptRefusal}
}

// TestPortErrors_Tokens pins that an error a consumer's store, or a refusal
// check, returns whose chain cannot be walked is answered exactly as a plain
// outage is: the same refusal, the same state, the same Watch content, with
// one abort record and no hang or panic. A store under depfault.Store is
// sanitized there first, to the manager's logger, and the manager's own
// sanitizer then passes the fault through without a second record.
func TestPortErrors_Tokens(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(ptRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type testCase struct {
		name    string
		site    ptSite
		wrapped bool
		err     error
		child   bool

		ctx func(ctx context.Context) context.Context

		assert func(t *testing.T, plain, got ptOutcome)
	}

	asOutage := func(site ptSite, wrapped bool, reason string) func(t *testing.T, plain, got ptOutcome) {
		return func(t *testing.T, plain, got ptOutcome) {
			t.Helper()

			ptSameAsPlain(t, site, plain, got)
			assert.NotContains(t, got.text, ptSecret, "the error quotes the consumer's")

			switch site {
			case ptFind, ptConsume:
				assert.True(t, got.invalid, "answered as ErrInvalidToken, like a missing token")
				assert.False(t, got.unwalkable, "the manager conceals the outage")
			default:
				assert.True(t, got.unwalkable, "the failure carries the sanitizer's fault")
			}

			if wrapped && (site == ptFind || site == ptConsume) {
				assert.True(t, got.watchUnwalkable, "the Watch holds the sanitizer's fault")
			}

			// Under depfault.Store the store's error is sanitized there, to the
			// logger the manager shares, and the manager passes the fault on.
			aborts, elsewhere := got.aborts, got.defaults
			where := "the manager's logger"

			require.Len(t, aborts, 1, "one abort record, on "+where)
			assert.Equal(t, "ERROR", aborts[0]["level"])
			assert.Equal(t, reason, aborts[0]["reason"])
			assert.Empty(t, elsewhere, "no abort record anywhere else")

			raw, err := json.Marshal(aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), ptSecret, "the record quotes the error")
		}
	}

	walked := func(site ptSite) func(t *testing.T, plain, got ptOutcome) {
		return func(t *testing.T, plain, got ptOutcome) {
			t.Helper()

			ptSameAsPlain(t, site, plain, got)
			assert.False(t, got.unwalkable, "a walkable error is passed on unchanged")
			assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
			assert.Empty(t, got.defaults, "a walk that completes writes no abort record")
		}
	}

	var cases []testCase

	for _, site := range ptSites() {
		for _, wrapped := range []bool{false, true} {
			if wrapped && site == ptRefusal {
				continue
			}

			prefix := string(site) + ": "
			if wrapped {
				prefix = string(site) + " under depfault.Store: "
			}

			for _, row := range ptRows(ptSentinel(site)) {
				tc := testCase{
					name: prefix + row.name, site: site, wrapped: wrapped, err: row.err, child: row.child,
					assert: asOutage(site, wrapped, row.reason),
				}
				if row.cancel {
					tc.ctx = cancelled
				}

				cases = append(cases, tc)
			}

			cases = append(cases,
				testCase{
					name: prefix + "a typed-nil root walks to the end and is answered as an outage",
					site: site, wrapped: wrapped, err: (*ptTypedNil)(nil), assert: walked(site),
				},
				testCase{
					name: prefix + "a plain outage, against itself",
					site: site, wrapped: wrapped, err: ptErrDown, assert: walked(site),
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
				ptInChild(t, tc.name)

				return
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := ptRun(t, ctx, tc.site, tc.wrapped, ptErrDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")
			require.Empty(t, plain.defaults, "a plain outage writes no abort record")

			got := ptRun(t, ctx, tc.site, tc.wrapped, tc.err)
			tc.assert(t, plain, got)

			if only != "" && !t.Failed() {
				_, _ = os.Stdout.WriteString(ptRanMarker + tc.name + "\n")
			}
		})
	}
}

// TestPortErrors_TokensRefusalIsReturnedUnchanged pins that a walkable
// refusal check's error is the very value Redeem returns, and the token stays
// redeemable.
func TestPortErrors_TokensRefusalIsReturnedUnchanged(t *testing.T) {
	t.Parallel()

	m, err := onetime.New("pt-purpose")
	require.NoError(t, err)

	presented, _, err := m.Issue(t.Context(), "s-1")
	require.NoError(t, err)

	refusal := errors.New("pt: enrol in MFA first")

	_, err = m.Redeem(t.Context(), presented, "", func(context.Context, onetime.Token) error { return refusal })
	assert.True(t, err == refusal, "the refusal is returned unchanged") //nolint:errorlint // identity

	_, err = m.Redeem(t.Context(), presented, "")
	require.NoError(t, err, "the token stayed redeemable")
}

// ptInChild re-runs the top-level test in a child process limited to row, and
// fails unless the child exits 0 within a minute and prints a line equal to
// the row's marker.
func ptInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), ptRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	want := ptRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
