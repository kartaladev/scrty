// TestKeys_PortErrors pins that an error the consumer's KeyStore returns is
// sanitized where it enters the manager: a chain that cannot be walked (a
// cycle, a fan-out past the budget, an Unwrap that panics) is replaced by a
// fixed fault before the manager wraps, logs or hands it to the error hook or
// to New's caller, so nothing downstream inspects a hostile chain with the
// standard library. Each row is one site (New's load, New's mint, the rotation
// write, the reload and housekeeping listing, the housekeeping delete) crossed
// with one kind of error, and checks the same invariants: the run is reported
// as failed exactly as for a plain store error, the hook (or New's caller)
// sees the fixed fault and not the raw error, the keys logger holds exactly one
// abort record per hostile error, the default logger none, and no record or
// error text quotes the consumer's secret.
//
// It is a matrix of rows sharing one invariant set, so the rows are generated
// and the checks are closures per row. Every row runs in a child process, which
// prints a marker line only once its row has run and passed: a hostile chain
// that overflows the stack in the library ends the child, not the package. The
// reported errors are read with the bounded walk, never the standard library's,
// so a row that fails says so instead of hanging. It is not parallel with
// other tests, because goleak counts goroutines process-wide and the default
// logger is process-wide; only the parent's child launches run in parallel.
package signingkey_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/internal/recovered"
	"github.com/kartaladev/scrty/token/signingkey"
)

// portRowEnv names the row a child process of TestKeys_PortErrors runs. It is
// empty in the parent.
const portRowEnv = "SCRTY_SIGNINGKEY_PORTERR_ROW"

// portRan is what a child prints, on a line of its own followed by the row's
// name, once it has run its row to the end and every check passed.
const portRan = "signingkey-porterr-row-ran:"

// portSite is the KeyStore call a row makes fail.
type portSite int

const (
	// portNewLoad is the listing New makes before anything is minted.
	portNewLoad portSite = iota
	// portNewStore is the write of the key New mints.
	portNewStore
	// portRotate is the rotation loop's write.
	portRotate
	// portLoopLoad is the listing of the reload and housekeeping loops.
	portLoopLoad
	// portDelete is the housekeeping loop's delete of retired keys.
	portDelete
)

func (s portSite) label() string {
	return [...]string{"New's load", "New's mint write", "rotation write", "reload and housekeeping listing", "housekeeping delete"}[s]
}

// construction reports whether the site is on New's path rather than a loop's.
func (s portSite) construction() bool { return s == portNewLoad || s == portNewStore }

// times is how many armed calls at the site fail before the store behaves.
func (s portSite) times() int {
	if s == portLoopLoad {
		return 2 // one run: the reload's listing and the housekeeping's
	}

	return 1
}

// what is the fixed word a recovered panic at the site is recorded by.
func (s portSite) what() string {
	switch s {
	case portNewLoad, portLoopLoad:
		return "key store load"
	case portDelete:
		return "key store delete"
	default:
		return "key store write"
	}
}

// failedMsgs are the failure records a run of the site writes.
func (s portSite) failedMsgs() []string {
	switch s {
	case portRotate:
		return []string{"signingkey: rotate failed"}
	case portLoopLoad:
		return []string{"signingkey: reload failed", "signingkey: housekeep failed"}
	case portDelete:
		return []string{"signingkey: housekeep failed"}
	default:
		return nil
	}
}

// portMode is how the reported error is expected to look.
type portMode int

const (
	// portPlain: the store's own error, reachable in the chain.
	portPlain portMode = iota
	// portTypedNil: a typed-nil error the walk reads to the end, so it passes.
	portTypedNil
	// portFault: the fixed fault, matching porterr.ErrUnwalkable, with none of
	// the raw error in its chain.
	portFault
)

// The consumer's hostile errors. Each Error quotes the secret.
type (
	portPlainError struct{}
	portCycleOne   struct{}
	portCycleMany  struct{}
	portPanicOne   struct{}
	portPanicNil   struct{}
	portNilPointer struct{ cause error }
)

func (*portPlainError) Error() string { return "store: " + hostileSecret }

func (*portCycleOne) Error() string   { return "cycle one: " + hostileSecret }
func (c *portCycleOne) Unwrap() error { return c }

func (*portCycleMany) Error() string     { return "cycle many: " + hostileSecret }
func (c *portCycleMany) Unwrap() []error { return []error{c} }

func (portPanicOne) Error() string { return "panic unwrap: " + hostileSecret }
func (portPanicOne) Unwrap() error { panic("unwrap: " + hostileSecret) }

func (portPanicNil) Error() string { return "panic nil unwrap: " + hostileSecret }
func (portPanicNil) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// Error is nil-safe, so only a walk that dereferences the receiver would panic.
func (*portNilPointer) Error() string { return "typed nil store error" }

// portFanOut is errors.Join(n, n) nested deep: no cycle, but 2^depth paths for
// an unbounded walk.
func portFanOut() error {
	var err error = &portPlainError{}
	for range 24 {
		err = errors.Join(err, err)
	}

	return err
}

// portKind is one kind of error a store returns.
type portKind struct {
	name   string
	mk     func() error
	mode   portMode
	reason string // the abort reason, for portFault
}

func portKinds() []portKind {
	return []portKind{
		{name: "a plain store error", mk: func() error { return &portPlainError{} }, mode: portPlain},
		{name: "a cycle through Unwrap() error", mk: func() error { return &portCycleOne{} }, mode: portFault, reason: "budget"},
		{name: "a cycle through Unwrap() []error", mk: func() error { return &portCycleMany{} }, mode: portFault, reason: "budget"},
		{name: "a fan-out past the budget", mk: portFanOut, mode: portFault, reason: "budget"},
		{name: "an Unwrap that panics", mk: func() error { return portPanicOne{} }, mode: portFault, reason: "panic"},
		{name: "an Unwrap that panics with nil", mk: func() error { return portPanicNil{} }, mode: portFault, reason: "panic"},
		{name: "a typed-nil error", mk: func() error { return (*portNilPointer)(nil) }, mode: portTypedNil},
	}
}

// portStore is the in-memory store with a hostile consumer's behaviour at one
// site, armed on demand: the first times armed calls at the site return the
// kind's error, and every other call delegates.
type portStore struct {
	signingkey.KeyStore

	site  portSite
	mk    func() error
	times int

	armed  atomic.Bool
	struck atomic.Int32
	loads  atomic.Int32

	mu       sync.Mutex
	returned []error
}

// strike returns the hostile error when site is the armed site and a call is
// still due to fail.
func (s *portStore) strike(site portSite) error {
	if s.site != site || !s.armed.Load() {
		return nil
	}

	if int(s.struck.Add(1)) > s.times {
		return nil
	}

	err := s.mk()

	s.mu.Lock()
	s.returned = append(s.returned, err)
	s.mu.Unlock()

	return err
}

func (s *portStore) raws() []error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]error(nil), s.returned...)
}

func (s *portStore) Store(ctx context.Context, rec signingkey.Record) error {
	if err := s.strike(portNewStore); err != nil {
		return err
	}

	if err := s.strike(portRotate); err != nil {
		return err
	}

	return s.KeyStore.Store(ctx, rec)
}

func (s *portStore) LoadAll(ctx context.Context) ([]signingkey.Record, error) {
	if s.armed.Load() {
		s.loads.Add(1)
	}

	if err := s.strike(portNewLoad); err != nil {
		return nil, err
	}

	if err := s.strike(portLoopLoad); err != nil {
		return nil, err
	}

	return s.KeyStore.LoadAll(ctx)
}

func (s *portStore) Delete(ctx context.Context, kids ...string) error {
	if err := s.strike(portDelete); err != nil {
		return err
	}

	return s.KeyStore.Delete(ctx, kids...)
}

// portAbortPanicker writes every record through its handler and then panics on
// the abort record: a consumer's handler that breaks on the record the
// sanitizer writes.
type portAbortPanicker struct{ slog.Handler }

func (h portAbortPanicker) Handle(ctx context.Context, r slog.Record) error {
	err := h.Handler.Handle(ctx, r)
	if r.Message == porterr.MsgClassificationAborted {
		panic("handler: " + hostileSecret)
	}

	return err
}

func (h portAbortPanicker) WithAttrs(a []slog.Attr) slog.Handler {
	return portAbortPanicker{h.Handler.WithAttrs(a)}
}

func (h portAbortPanicker) WithGroup(n string) slog.Handler {
	return portAbortPanicker{h.Handler.WithGroup(n)}
}

// portOutcome is what a row observed.
type portOutcome struct {
	newErr   error
	built    bool
	hooked   []error
	records  []map[string]any // the keys logger's
	defaults []map[string]any // slog.Default()'s
	raws     []error          // what the store returned
	struck   int
	loads    int
	rotated  bool
	deleted  bool
}

// portRow is one site crossed with one kind of error.
type portRow struct {
	name      string
	site      portSite
	kind      portKind
	cancelled bool // New's context is already done
	panicLog  bool // the keys logger's handler panics on the abort record
	assert    func(t *testing.T, got portOutcome)
}

// chainOf walks err with the bounded walk, failing the row when it cannot be
// read: an error handed on that the library's own walk gives up on is a raw
// hostile error.
func chainOf(t *testing.T, err error) errwalk.Chain {
	t.Helper()

	chain, abort := errwalk.Flatten(err)
	require.NoError(t, abort, "the error handed on has a chain that cannot be walked: the raw error leaked")

	return chain
}

func chainHas(chain errwalk.Chain, target error) bool {
	for _, node := range chain {
		if node == target { //nolint:errorlint // identity of the very error the store returned
			return true
		}
	}

	return false
}

// checkReported is the invariant set for one error handed to the hook or
// returned by New.
func checkReported(t *testing.T, row portRow, got portOutcome, err error) {
	t.Helper()

	require.Error(t, err)
	assert.NotContains(t, err.Error(), hostileSecret, "the error quotes the consumer's error")

	chain := chainOf(t, err)

	_, isFault, abort := errwalk.As[*porterr.Fault](chain)
	require.NoError(t, abort)

	unwalkable, abort := errwalk.Is(chain, porterr.ErrUnwalkable)
	require.NoError(t, abort)

	switch {
	case row.panicLog:
		panicked, abort := errwalk.Is(chain, recovered.ErrPanicked)
		require.NoError(t, abort)
		assert.True(t, panicked, "a handler that panics on the abort record is reported as the consumer's code panicking")
		assert.False(t, isFault, "the fault never reached the caller")
	case row.kind.mode == portFault:
		assert.True(t, isFault, "the error is not the sanitizer's fault")
		assert.True(t, unwalkable, "the fault matches porterr.ErrUnwalkable")

		for _, raw := range got.raws {
			assert.False(t, chainHas(chain, raw), "the raw error is still in the chain")
		}
	case row.kind.mode == portPlain:
		assert.False(t, isFault, "a plain store error is not replaced")
		assert.False(t, unwalkable)
		assert.True(t, slices.ContainsFunc(got.raws, func(raw error) bool { return chainHas(chain, raw) }),
			"the store's own error stays reachable")
	default:
		assert.False(t, isFault, "a typed nil walks to the end and is not replaced")
	}
}

// portAssert builds the checks every row shares.
func portAssert(row portRow) func(t *testing.T, got portOutcome) {
	return func(t *testing.T, got portOutcome) {
		t.Helper()

		wantStruck := row.site.times()
		require.Equal(t, wantStruck, got.struck, "the store returned its error as often as the site calls it")

		for _, rec := range got.records {
			assert.NotContains(t, fmt.Sprint(rec), hostileSecret, "a record quotes the consumer's text")
		}

		var aborts []map[string]any

		for _, rec := range got.records {
			if rec["msg"] == porterr.MsgClassificationAborted {
				aborts = append(aborts, rec)
			}
		}

		wantAborts := 0
		if row.kind.mode == portFault {
			wantAborts = wantStruck
		}

		assert.Len(t, aborts, wantAborts, "abort records on the manager's logger: one per hostile error, none otherwise")

		for _, rec := range aborts {
			assert.Equal(t, "ERROR", rec["level"])
			assert.Equal(t, row.kind.reason, rec["reason"])

			if row.kind.reason == "panic" {
				assert.NotEmpty(t, rec["panic_type"], "the record names the panic's type")
				assert.NotEmpty(t, rec["frames"], "the record names where the panic happened")
			}
		}

		for _, rec := range got.defaults {
			assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
		}

		if row.site.construction() {
			assert.False(t, got.built, "New returned a manager over a failed store")
			assert.Empty(t, got.hooked, "construction never reaches the hook")
			checkReported(t, row, got, got.newErr)

			return
		}

		require.Len(t, got.hooked, wantStruck, "failed runs reported to the hook")

		for _, err := range got.hooked {
			assert.NotContains(t, err.Error(), hostileSecret, "the hook was handed the consumer's text")
			checkReported(t, row, got, err)
		}

		for _, msg := range row.site.failedMsgs() {
			failed := 0

			for _, rec := range got.records {
				if rec["msg"] == msg {
					failed++
				}
			}

			assert.GreaterOrEqual(t, failed, 1, "the failure is still logged: %s", msg)
		}

		if row.panicLog {
			panics := 0

			for _, rec := range got.records {
				if rec["msg"] == msgConsumerPanicked {
					panics++

					assert.Equal(t, row.site.what(), rec["what"])
					assert.Equal(t, "string", rec["panic_type"])
				}
			}

			assert.Equal(t, wantStruck, panics, "one consumer-panicked record per handler panic")
		}

		switch row.site {
		case portRotate:
			assert.True(t, got.rotated, "the rotation after the failed one worked: the loop went on")
		case portLoopLoad:
			assert.Equal(t, 2*wantStruck, got.loads, "the loops listed again after the failed run")
		case portDelete:
			assert.True(t, got.deleted, "the delete after the failed one worked: the loop went on")
		default:
		}
	}
}

func portRows() []portRow {
	var rows []portRow

	add := func(row portRow) {
		row.assert = portAssert(row)
		rows = append(rows, row)
	}

	for _, site := range []portSite{portNewLoad, portNewStore, portRotate, portLoopLoad, portDelete} {
		for _, kind := range portKinds() {
			add(portRow{name: site.label() + ": " + kind.name, site: site, kind: kind})
		}
	}

	hostile := portKinds()[1]

	add(portRow{
		name: portNewLoad.label() + ": " + hostile.name + ", context already cancelled",
		site: portNewLoad, kind: hostile, cancelled: true,
	})

	for _, site := range []portSite{portRotate, portLoopLoad, portDelete} {
		add(portRow{
			name: site.label() + ": " + hostile.name + ", logger handler panics on the abort record",
			site: site, kind: hostile, panicLog: true,
		})
	}

	return rows
}

// runPortRow runs one row for real and returns what it observed. It is only
// called in the child.
func runPortRow(t *testing.T, row portRow) portOutcome {
	t.Helper()

	defRec, defLogger := newLogRecorder()
	prev := slog.Default()

	slog.SetDefault(defLogger)
	t.Cleanup(func() { slog.SetDefault(prev) })

	logs, logger := newLogRecorder()
	if row.panicLog {
		logger = slog.New(portAbortPanicker{slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})})
	}

	mem := signingkey.NewMemoryKeyStore()

	oldKid := ""

	if row.site == portDelete {
		// Two stored keys from long ago: the older is past its grace and not the
		// newest, so the first housekeeping run deletes it.
		for i, age := range []time.Duration{200 * time.Hour, 150 * time.Hour} {
			rec := realRecordFor(t, signingkey.ES256, epoch.Add(-age))
			if i == 0 {
				oldKid = rec.Kid
			}

			require.NoError(t, mem.Store(t.Context(), rec))
		}
	}

	store := &portStore{KeyStore: mem, site: row.site, mk: row.kind.mk, times: row.site.times()}
	fake := newClock()
	hooked := &failureReport{}

	opts := []signingkey.Option{
		signingkey.WithAlgs(signingkey.ES256),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(fake),
		signingkey.WithLogger(logger),
		signingkey.WithErrorHook(hooked.hook),
		signingkey.WithKeyLifetime(24 * time.Hour),
		signingkey.WithRotateInterval(20 * time.Millisecond),
		signingkey.WithReloadInterval(10 * time.Millisecond),
		signingkey.WithHousekeepingInterval(10 * time.Millisecond),
	}

	collect := func(got portOutcome) portOutcome {
		got.records = logs.records(t)
		got.defaults = defRec.records(t)
		got.hooked, _ = hooked.snapshot()
		got.raws = store.raws()
		got.struck = min(int(store.struck.Load()), row.site.times())
		got.loads = int(store.loads.Load())

		return got
	}

	if row.site.construction() {
		ctx := t.Context()

		if row.cancelled {
			var cancel context.CancelFunc

			ctx, cancel = context.WithCancel(ctx)
			cancel()
		}

		store.armed.Store(true)

		km, err := signingkey.New(ctx, opts...)
		if km != nil {
			shutdownAndVerify(t, km)
		}

		return collect(portOutcome{newErr: err, built: km != nil})
	}

	km, err := signingkey.New(t.Context(), opts...)
	require.NoError(t, err)
	shutdownAndVerify(t, km)

	before := currentKid(t, km, signingkey.ES256)

	require.NoError(t, km.Start(t.Context()))
	awaitParked(t, fake, loopCount)

	store.armed.Store(true)
	store.loads.Store(0)

	for range 2 {
		advance(t, fake, 20*time.Millisecond, loopCount)
	}

	store.armed.Store(false)

	got := portOutcome{rotated: currentKid(t, km, signingkey.ES256) != before}

	if row.site == portDelete {
		recs, loadErr := mem.LoadAll(t.Context())
		require.NoError(t, loadErr)

		got.deleted = true

		for _, rec := range recs {
			if rec.Kid == oldKid {
				got.deleted = false
			}
		}
	}

	return collect(got)
}

// portInChild re-runs the test binary on the one row and requires the child to
// exit 0 within a minute and to print the marker line of that row, as one line
// equal to the marker.
func portInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), portRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 14)], "\n"))

	ran := false

	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	for sc.Scan() {
		if sc.Text() == portRan+row {
			ran = true
		}
	}

	require.NoError(t, sc.Err())
	assert.True(t, ran, "the child printed no line %q: it did not run its row", portRan+row)
}

func TestKeys_PortErrors(t *testing.T) { //nolint:paralleltest // goleak counts goroutines process-wide
	childRow := os.Getenv(portRowEnv)

	for _, row := range portRows() {
		t.Run(row.name, func(t *testing.T) {
			if childRow == "" {
				t.Parallel()
				portInChild(t, row.name)

				return
			}

			if childRow != row.name {
				t.Skip("another row's child")
			}

			row.assert(t, runPortRow(t, row))

			if !t.Failed() {
				fmt.Fprintln(os.Stdout, portRan+row.name)
			}
		})
	}
}
