package webauthn_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/authenticate/passkey/webauthn"
)

// The whole metadata refresh runs inside the source's single flight, on a
// goroutine singleflight starts: the consumer's fetch and clock, and the
// library's decode of the fetched bytes and build of the cache. A panic there
// has no request recovery above it, so before the source recovered it, it
// ended the process. These rows pin that a panic in the refresh is answered
// as a metadata outage instead: every
// registration waiting on the flight is refused exactly as on a fetch error,
// one Error record is written without the panic value's text, and the next
// registration fetches again and succeeds.

const (
	mdPanicRowEnv  = "SCRTY_WEBAUTHN_PANIC_ROW"
	mdPanicMessage = "consumer code panicked"
	mdPanicWhat    = "metadata refresh"
)

// mdFuncClock is a clock.Clock backed by a function.
type mdFuncClock func() time.Time

func (f mdFuncClock) Now() time.Time { return f() }

// mdPanicRanMarker is the line a child prints once its row has run and passed.
// The parent requires one line of the child's output to equal it.
func mdPanicRanMarker(row string) string { return "WEBAUTHN-PANIC-ROW-RAN:" + row }

// mdRecord is what a captured record keeps: its level, message, and every
// attribute's value as text.
type mdRecord struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

// mdCapture keeps every record handed to it.
type mdCapture struct {
	mu   *sync.Mutex
	recs *[]mdRecord
}

func newMDCapture() mdCapture { return mdCapture{mu: &sync.Mutex{}, recs: &[]mdRecord{}} }

func (mdCapture) Enabled(context.Context, slog.Level) bool { return true }

func (h mdCapture) Handle(_ context.Context, r slog.Record) error {
	rec := mdRecord{level: r.Level, msg: r.Message, attrs: map[string]string{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})

	h.mu.Lock()
	defer h.mu.Unlock()
	*h.recs = append(*h.recs, rec)

	return nil
}

func (h mdCapture) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h mdCapture) WithGroup(string) slog.Handler      { return h }

func (h mdCapture) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.recs = nil
}

func (h mdCapture) records() []mdRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]mdRecord(nil), *h.recs...)
}

// mdPanicRun is what one row observed.
type mdPanicRun struct {
	waiters []outcome // the registrations that waited on the failing fetch
	next    outcome   // the registration made after them
	calls   int32     // calls to the fetch while it failed
	records []mdRecord
}

// mdRunPanickingFetch registers waiters callers at once against a source
// whose fetch, held until every caller waits on it, runs failing; then one
// more registration, whose fetch answers a valid BLOB. It runs in a synctest
// bubble: synctest.Wait is the barrier that every waiter has joined the
// flight, and a deadlock fails the bubble instead of hanging.
//
// flightClock, when non nil, is the consumer clock the source is built with:
// its first call (the caller's freshness check) answers the time, its second
// (the flight's refresh) runs flightClock, and once healed it answers the time.
func mdRunPanickingFetch(t *testing.T, logs mdCapture, waiters int, failing func() ([]byte, error), flightClock func()) mdPanicRun {
	t.Helper()

	var run mdPanicRun

	synctest.Test(t, func(t *testing.T) {
		e := newAttestationEnv(t)
		raw := blob{no: 1, nextUpdate: time.Now().Add(72 * time.Hour), entries: []map[string]any{mdsEntry(e.aaguid, e.attRoot, "FIDO_CERTIFIED")}}.
			sign(t, e.signer, e.mdsRoot.cert)

		var (
			healed atomic.Bool
			calls  atomic.Int32
		)

		release := make(chan struct{})
		fetch := func(ctx context.Context) ([]byte, error) {
			if healed.Load() {
				return raw, nil
			}

			calls.Add(1)

			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}

			return failing()
		}

		opts := []webauthn.MDSOption{webauthn.WithMDSRoot(e.mdsRoot.cert)}
		if flightClock != nil {
			var nowCalls atomic.Int32

			opts = append(opts, webauthn.WithMDSClock(mdFuncClock(func() time.Time {
				if !healed.Load() && nowCalls.Add(1) == 2 {
					flightClock()
				}

				return time.Now()
			})))
		}

		src := webauthn.MetadataBlob(fetch, opts...)
		r := &gatedRegistrar{env: e, v: newVerifier(t, webauthn.WithTrustedAttestation(src))}

		bodies := make([][]byte, waiters+1)
		for i := range bodies {
			bodies[i] = r.body(t)
		}

		logs.reset()

		run.waiters = make([]outcome, waiters)

		var wg sync.WaitGroup
		for i := range waiters {
			wg.Go(func() { run.waiters[i] = r.register(t.Context(), bodies[i]) })
		}

		synctest.Wait() // every waiter now waits on the one fetch in flight
		close(release)
		wg.Wait()

		run.calls = calls.Load()
		run.records = logs.records()

		healed.Store(true)
		run.next = r.register(t.Context(), bodies[waiters])
	})

	return run
}

// TestMetadataSource_FetchPanics pins that a consumer metadata fetch that
// panics refuses the registrations waiting on it as a metadata outage does,
// and the process keeps running.
//
// Each panicking row runs in a child process: before the fix, the panic is
// re-raised on singleflight's goroutine and the child dies. The parent
// requires the child to exit 0 and print a line equal to the row's marker.
//
// It swaps slog.Default to capture records, so neither it nor its rows run in
// parallel.
func TestMetadataSource_FetchPanics(t *testing.T) { //nolint:paralleltest // swaps slog.Default
	childRow := os.Getenv(mdPanicRowEnv)

	logs := newMDCapture()
	prev := slog.Default()
	slog.SetDefault(slog.New(logs))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// The plain outage every panicking row is compared with.
	plain := mdRunPanickingFetch(t, logs, 1, func() ([]byte, error) {
		return nil, errors.New("metadata service unavailable")
	}, nil)
	require.Len(t, plain.waiters, 1)
	require.ErrorIs(t, plain.waiters[0].err, passkey.ErrAttestationRefused)
	outageText := plain.waiters[0].err.Error()

	// refusedAsOutage asserts that every waiter was refused as on a plain
	// outage, from one fetch, that the next registration was trusted, and that
	// exactly one panic record of panicType was written without the secret.
	refusedAsOutage := func(waiters int, wantCalls int32, panicType func(t *testing.T, got string)) func(t *testing.T, run mdPanicRun) {
		return func(t *testing.T, run mdPanicRun) {
			t.Helper()

			require.Len(t, run.waiters, waiters)

			for i, o := range run.waiters {
				assert.Nil(t, o.nc, "waiter %d got a credential", i)
				require.ErrorIs(t, o.err, passkey.ErrAttestationRefused, "waiter %d", i)
				assert.Equal(t, outageText, o.err.Error(), "waiter %d: the refusal differs from the outage's", i)
				assert.NotContains(t, o.err.Error(), mdSecret)
			}

			assert.Equal(t, wantCalls, run.calls, "the waiters did not share one flight")

			require.Len(t, run.records, 1, "want exactly one record")
			rec := run.records[0]
			assert.Equal(t, slog.LevelError, rec.level)
			assert.Equal(t, mdPanicMessage, rec.msg)
			assert.Equal(t, mdPanicWhat, rec.attrs["what"])
			assert.NotEmpty(t, rec.attrs["frames"])
			panicType(t, rec.attrs["panic_type"])

			for k, v := range rec.attrs {
				assert.NotContains(t, v, mdSecret, "attribute %q quotes the panic value", k)
			}

			assert.NotContains(t, rec.msg, mdSecret)

			trustedOK(t, run.next.nc, run.next.err)
		}
	}

	typeIs := func(want string) func(t *testing.T, got string) {
		return func(t *testing.T, got string) {
			t.Helper()
			assert.Equal(t, want, got)
		}
	}

	type testCase struct {
		name    string
		waiters int
		failing func() ([]byte, error)
		clock   func() // runs in the flight's clock call
		child   bool
		assert  func(t *testing.T, run mdPanicRun)
	}

	cases := []testCase{
		{
			name:    "no panic",
			waiters: 1,
			failing: func() ([]byte, error) { return nil, errors.New("metadata service unavailable") },
			assert: func(t *testing.T, run mdPanicRun) {
				t.Helper()
				require.Len(t, run.waiters, 1)
				require.ErrorIs(t, run.waiters[0].err, passkey.ErrAttestationRefused)
				assert.Equal(t, outageText, run.waiters[0].err.Error())
				assert.Equal(t, int32(1), run.calls)
				assert.Empty(t, run.records, "a fetch error wrote a record")
				trustedOK(t, run.next.nc, run.next.err)
			},
		},
		{
			name:    "panic with a value",
			waiters: 1,
			failing: func() ([]byte, error) { panic("test: fetch panicked holding " + mdSecret) },
			child:   true,
			assert:  refusedAsOutage(1, 1, typeIs("string")),
		},
		{
			name:    "panic(nil)",
			waiters: 1,
			failing: func() ([]byte, error) { panic(nil) },
			child:   true,
			assert: refusedAsOutage(1, 1, func(t *testing.T, got string) {
				t.Helper()
				// *runtime.PanicNilError by default; <nil> under GODEBUG=panicnil=1.
				assert.Contains(t, []string{"*runtime.PanicNilError", "<nil>"}, got)
			}),
		},
		{
			name:    "runtime error",
			waiters: 1,
			failing: func() ([]byte, error) {
				var m map[string]int
				m[mdSecret] = 1 // assignment to entry in nil map

				return nil, nil
			},
			child: true,
			assert: refusedAsOutage(1, 1, func(t *testing.T, got string) {
				t.Helper()
				assert.True(t, strings.HasPrefix(got, "runtime."), "panic_type %q is not a runtime error", got)
			}),
		},
		{
			name:    "two waiters",
			waiters: 2,
			failing: func() ([]byte, error) { panic(fmt.Errorf("test: fetch panicked holding %s", mdSecret)) },
			child:   true,
			assert:  refusedAsOutage(2, 1, typeIs("*errors.errorString")),
		},
		{
			// The refresh's own work on the flight goroutine, outside the
			// fetch, is covered too: the clock is consumer code it reads
			// before the fetch, and the same recovery covers the decode and
			// the cache build that follow. The fetch is never reached.
			name:    "panic in the refresh outside the fetch",
			waiters: 1,
			failing: func() ([]byte, error) { return nil, errors.New("unreachable") },
			clock:   func() { panic("test: clock panicked holding " + mdSecret) },
			child:   true,
			assert:  refusedAsOutage(1, 0, typeIs("string")),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if childRow != "" && childRow != tc.name {
				t.Skip("the child runs one row only")
			}

			if tc.child && childRow == "" {
				mdRunPanicChild(t, tc.name)
				return
			}

			run := mdRunPanickingFetch(t, logs, tc.waiters, tc.failing, tc.clock)
			tc.assert(t, run)

			if childRow == tc.name && !t.Failed() {
				fmt.Println(mdPanicRanMarker(tc.name)) //nolint:forbidigo // the parent reads this line
			}
		})
	}
}

// mdRunPanicChild runs row in a child test process, where a panic re-raised
// on a library goroutine cannot take the parent down. The child must exit 0
// within a minute and print a line equal to the row's marker, so a row the
// child never ran, or died in, fails.
func mdRunPanicChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMetadataSource_FetchPanics$", "-test.count=1")
	cmd.Env = append(os.Environ(), mdPanicRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	want := mdPanicRanMarker(row)
	ran := false

	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			ran = true
		}
	}

	require.True(t, ran, "the child never ran row %q (no line equals %q); output:\n%s", row, want, out)
}
