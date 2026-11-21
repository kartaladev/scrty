// TestKeys_ConsumerPanics pins that consumer code the rotation, reload and
// housekeeping loops call, on goroutines the manager started, cannot take the
// process down: a panic from the key store, the error hook or the clock is
// recovered where it is called, is reported as a failed run, and the loop goes
// on. A panic in those loops ends the process, so every row runs in a child
// process: the child prints a marker line only once its row has run to the end
// and every check passed. It is a matrix of rows sharing one invariant set
// (the same outcome checks, parameterised by site), not one SUT call with
// varying inputs, so the rows are generated and the checks are closures per
// row. It is not parallel with other tests, because goleak counts goroutines
// process-wide; only the parent's child launches run in parallel.
package signingkey_test

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/recovered"
	"github.com/kartaladev/scrty/token/signingkey"
)

// hostileRowEnv names the row a child process of TestKeys_ConsumerPanics runs.
// It is empty in the parent.
const hostileRowEnv = "SCRTY_SIGNINGKEY_PANIC_ROW"

// hostileRan is what a child prints, on a line of its own followed by the row's
// name, once it has run its row to the end and every check passed.
const hostileRan = "signingkey-panic-row-ran:"

// hostileSecret is the text every panic value carries. A record or an error
// that quotes it has leaked the consumer's panic.
const hostileSecret = "hostile-secret-text-from-the-consumer"

const msgConsumerPanicked = "consumer code panicked"

// hostileSite is the consumer call a row makes panic.
type hostileSite int

const (
	siteStoreWrite hostileSite = iota
	siteStoreLoad
	siteStoreDelete
	siteHook
	siteClockNow
	siteClockAfter
)

// panicKind is how the consumer's code panics, or that it does not.
type panicKind int

const (
	kindValue panicKind = iota
	kindNil
	kindRuntime
	kindNone
)

func (k panicKind) String() string {
	return [...]string{"value", "nil", "runtime error", "no panic"}[k]
}

// panicType is the Go type the recovered record names for the panic.
func (k panicKind) panicType() string {
	switch k {
	case kindValue:
		return "string"
	case kindNil:
		return "*runtime.PanicNilError"
	case kindRuntime:
		return "runtime.boundsError"
	default:
		return ""
	}
}

// fire panics the way k says, and returns for kindNone.
func (k panicKind) fire() {
	switch k {
	case kindValue:
		panic(hostileSecret)
	case kindNil:
		panic(nil) //nolint:govet // the hostile case under test
	case kindRuntime:
		var s []int

		idx := 3
		s[idx]++ //nolint:gosec // G602: the panic is the point: a runtime error from the consumer
	case kindNone:
	}
}

// hostile decides when the consumer's code panics: only at its site, only once
// armed, and for the first times calls (every call when times is 0).
type hostile struct {
	site   hostileSite
	kind   panicKind
	times  int
	armed  atomic.Bool
	struck atomic.Int32
	stores atomic.Int32
}

func (h *hostile) strike(site hostileSite) {
	if h.site != site || !h.armed.Load() {
		return
	}

	n := int(h.struck.Add(1))
	if h.times == 0 || n <= h.times {
		h.kind.fire()
	}
}

// hostileStore is the in-memory store with a hostile consumer's behaviour at
// the armed site.
type hostileStore struct {
	signingkey.KeyStore

	h *hostile
}

func (s *hostileStore) Store(ctx context.Context, rec signingkey.Record) error {
	if s.h.armed.Load() {
		s.h.stores.Add(1)
	}

	s.h.strike(siteStoreWrite)

	if s.h.site == siteHook && s.h.armed.Load() {
		return errStoreWrite // the failure the panicking hook is told about
	}

	return s.KeyStore.Store(ctx, rec)
}

func (s *hostileStore) LoadAll(ctx context.Context) ([]signingkey.Record, error) {
	s.h.strike(siteStoreLoad)

	return s.KeyStore.LoadAll(ctx)
}

func (s *hostileStore) Delete(ctx context.Context, kids ...string) error {
	s.h.strike(siteStoreDelete)

	return s.KeyStore.Delete(ctx, kids...)
}

// hostileClock is a controlled clock with a hostile consumer's behaviour at the
// armed site.
type hostileClock struct {
	*clockwork.FakeClock

	h *hostile
}

func (c *hostileClock) Now() time.Time {
	c.h.strike(siteClockNow)

	return c.FakeClock.Now()
}

func (c *hostileClock) After(d time.Duration) <-chan time.Time {
	c.h.strike(siteClockAfter)

	return c.FakeClock.After(d)
}

// outcome is what a row observed.
type outcome struct {
	hooked  []error
	records []map[string]any
	rotated bool
	deleted bool
}

// want is what a row's checks expect.
type want struct {
	what      string
	kind      panicKind
	hooks     int
	panics    int
	atLeast   bool  // hooks and panics are lower bounds (rows driven by real time)
	rotated   *bool // nil: not checked
	deleted   *bool // nil: not checked
	hookFault bool  // the hook is told of a plain store failure, not a panic
}

func flag(b bool) *bool { return &b }

type hostileCase struct {
	name    string
	site    hostileSite
	kind    panicKind
	times   int
	seedOld bool
	assert  func(t *testing.T, got outcome)
}

// checkOutcome is the invariant set every row shares.
func checkOutcome(w want) func(t *testing.T, got outcome) {
	return func(t *testing.T, got outcome) {
		t.Helper()

		var panics []map[string]any

		for _, rec := range got.records {
			assert.NotContains(t, fmt.Sprint(rec), hostileSecret, "a record quotes the consumer's panic value")

			if rec["msg"] == msgConsumerPanicked {
				panics = append(panics, rec)
			}
		}

		for _, err := range got.hooked {
			assert.NotContains(t, err.Error(), hostileSecret, "the hook was handed the panic value")

			if w.kind != kindNone && !w.hookFault {
				assert.ErrorIs(t, err, recovered.ErrPanicked, "the run is reported as the consumer's code panicking")
			}

			if w.hookFault {
				assert.ErrorIs(t, err, errStoreWrite, "the hook is told of the store failure, never of its own panic")
			}
		}

		if w.atLeast {
			assert.GreaterOrEqual(t, len(got.hooked), w.hooks, "failed runs reported to the hook")
			assert.GreaterOrEqual(t, len(panics), w.panics, "consumer-panicked records")
		} else {
			assert.Len(t, got.hooked, w.hooks, "failed runs reported to the hook")
			assert.Len(t, panics, w.panics, "exactly one consumer-panicked record per panic")
		}

		for _, rec := range panics {
			assert.Equal(t, "ERROR", rec["level"])
			assert.Equal(t, w.what, rec["what"])
			assert.Equal(t, w.kind.panicType(), rec["panic_type"])
			assert.NotEmpty(t, rec["frames"], "the record names where the panic happened")
		}

		if w.hookFault {
			failed := 0

			for _, rec := range got.records {
				if rec["msg"] == "signingkey: rotate failed" {
					failed++
				}
			}

			assert.GreaterOrEqual(t, failed, 1, "the failure is still logged when its hook panics")
		}

		if w.rotated != nil {
			assert.Equal(t, *w.rotated, got.rotated, "a rotation that came after the outage worked")
		}

		if w.deleted != nil {
			assert.Equal(t, *w.deleted, got.deleted, "the retired key's deletion")
		}
	}
}

// hostileSpec is one site's expectations per run, and for a panic that happens
// once. A run is one advance of the controlled clock, which runs every loop once.
type hostileSpec struct {
	site     hostileSite
	label    string
	what     string
	hooksRun int // failed runs reported per run while the consumer panics every call
	panicRun int // recovered records per run
	once     bool
	seedOld  bool
	rotated  func(kind panicKind, once bool) *bool
	deleted  func(kind panicKind, once bool) *bool
}

const hostileRuns = 2

func hostileCases() []hostileCase {
	specs := []hostileSpec{
		{
			site: siteStoreWrite, label: "key store write", what: "key store write",
			hooksRun: 1, panicRun: 1, once: true,
			// A panicking write leaves the previous key signing; the next run works.
			rotated: func(k panicKind, once bool) *bool { return flag(k == kindNone || once) },
		},
		{
			site: siteStoreLoad, label: "key store load", what: "key store load",
			hooksRun: 2, panicRun: 2, once: true, // reload and housekeeping both list the store
			rotated: func(panicKind, bool) *bool { return flag(true) },
		},
		{
			site: siteStoreDelete, label: "key store delete", what: "key store delete",
			hooksRun: 1, panicRun: 1, once: true, seedOld: true,
			deleted: func(k panicKind, once bool) *bool { return flag(k == kindNone || once) },
		},
		{
			site: siteHook, label: "error hook", what: "error hook",
			hooksRun: 1, panicRun: 1,
			rotated: func(panicKind, bool) *bool { return flag(false) }, // the store refuses every write
		},
		{
			site: siteClockNow, label: "clock now", what: "clock now",
			// rotation, reload and housekeeping each fail on Now and then again
			// on the Now that stamps their failure's sampling.
			hooksRun: 3, panicRun: 6,
			rotated: func(k panicKind, _ bool) *bool { return flag(k == kindNone) },
		},
		{
			site: siteClockAfter, label: "clock after", what: "clock after",
			hooksRun: 3, panicRun: 3, // lower bounds: each loop, once
			rotated: func(panicKind, bool) *bool { return flag(true) },
		},
	}

	var cases []hostileCase

	add := func(spec hostileSpec, kind panicKind, times int, name string) {
		w := want{what: spec.what, kind: kind, hookFault: spec.site == siteHook}

		switch {
		case spec.site == siteClockAfter && kind != kindNone:
			w.atLeast = true
			w.hooks, w.panics = spec.hooksRun, spec.panicRun
		case kind == kindNone && spec.site == siteHook:
			w.hooks = hostileRuns * spec.hooksRun
		case kind == kindNone:
		case times == 1:
			w.hooks, w.panics = 1, 1
		default:
			w.hooks, w.panics = hostileRuns*spec.hooksRun, hostileRuns*spec.panicRun
		}

		if spec.site == siteHook && kind != kindNone {
			w.hooks = hostileRuns * spec.hooksRun
		}

		if spec.rotated != nil {
			w.rotated = spec.rotated(kind, times == 1)
		}

		if spec.deleted != nil {
			w.deleted = spec.deleted(kind, times == 1)
		}

		cases = append(cases, hostileCase{
			name: name, site: spec.site, kind: kind, times: times, seedOld: spec.seedOld,
			assert: checkOutcome(w),
		})
	}

	for _, spec := range specs {
		for _, kind := range []panicKind{kindValue, kindNil, kindRuntime} {
			add(spec, kind, 0, fmt.Sprintf("%s panics twice with %s", spec.label, kind))
		}

		if spec.once {
			add(spec, kindValue, 1, spec.label+" panics once then works")
		}

		add(spec, kindNone, 0, spec.label+" does not panic")
	}

	return cases
}

// runHostileRow runs one row's loops for real and returns what it observed.
// It is only called in the child.
func runHostileRow(t *testing.T, tc hostileCase) outcome {
	t.Helper()

	h := &hostile{site: tc.site, kind: tc.kind, times: tc.times}
	fake := newClock()
	clk := &hostileClock{FakeClock: fake, h: h}
	mem := signingkey.NewMemoryKeyStore()

	oldKid := ""

	if tc.seedOld {
		// Two stored keys from long ago: the older is past its grace and not
		// the newest, so the first housekeeping run deletes it.
		for i, age := range []time.Duration{200 * time.Hour, 150 * time.Hour} {
			rec := realRecordFor(t, signingkey.ES256, epoch.Add(-age))
			if i == 0 {
				oldKid = rec.Kid
			}

			require.NoError(t, mem.Store(t.Context(), rec))
		}
	}

	hooked := &failureReport{}
	logs, logger := newLogRecorder()

	km, err := signingkey.New(t.Context(),
		signingkey.WithAlgs(signingkey.ES256),
		signingkey.WithKeyStore(&hostileStore{KeyStore: mem, h: h}),
		signingkey.WithClock(clk),
		signingkey.WithLogger(logger),
		signingkey.WithErrorHook(func(err error) {
			hooked.hook(err)
			h.strike(siteHook)
		}),
		signingkey.WithKeyLifetime(24*time.Hour),
		signingkey.WithRotateInterval(20*time.Millisecond),
		signingkey.WithReloadInterval(10*time.Millisecond),
		signingkey.WithHousekeepingInterval(10*time.Millisecond),
	)
	require.NoError(t, err)
	shutdownAndVerify(t, km)

	before := currentKid(t, km, signingkey.ES256)

	require.NoError(t, km.Start(t.Context()))
	awaitParked(t, fake, loopCount)
	h.armed.Store(true)

	if tc.site == siteClockAfter && tc.kind != kindNone {
		// The clock cannot be waited on, so no loop parks on it again: each
		// falls back to waiting on its own, and keeps running its step.
		fake.Advance(20 * time.Millisecond)
		require.Eventually(t, func() bool {
			return h.struck.Load() >= 2*loopCount && h.stores.Load() >= 2
		}, 10*time.Second, 5*time.Millisecond, "the loops did not keep running after the clock's After panicked")
	} else {
		for range hostileRuns {
			advance(t, fake, 20*time.Millisecond, loopCount)
		}
	}

	h.armed.Store(false)

	got := outcome{hooked: nil, records: logs.records(t)}
	got.hooked, _ = hooked.snapshot()
	got.rotated = currentKid(t, km, signingkey.ES256) != before

	if tc.seedOld {
		recs, loadErr := mem.LoadAll(t.Context())
		require.NoError(t, loadErr)

		got.deleted = true

		for _, rec := range recs {
			if rec.Kid == oldKid {
				got.deleted = false
			}
		}
	}

	return got
}

// hostileInChild re-runs the test binary on the one row and requires the child
// to exit 0 within a minute and to print the marker line of that row, as one
// line equal to the marker.
func hostileInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), hostileRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	ran := false

	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	for sc.Scan() {
		if sc.Text() == hostileRan+row {
			ran = true
		}
	}

	require.NoError(t, sc.Err())
	assert.True(t, ran, "the child printed no line %q: it did not run its row", hostileRan+row)
}

func TestKeys_ConsumerPanics(t *testing.T) { //nolint:paralleltest // goleak counts goroutines process-wide
	childRow := os.Getenv(hostileRowEnv)

	for _, tc := range hostileCases() {
		t.Run(tc.name, func(t *testing.T) {
			if childRow == "" {
				t.Parallel()
				hostileInChild(t, tc.name)

				return
			}

			if childRow != tc.name {
				t.Skip("another row's child")
			}

			tc.assert(t, runHostileRow(t, tc))

			if !t.Failed() {
				_, _ = fmt.Fprintln(os.Stdout, hostileRan+tc.name)
			}
		})
	}
}
