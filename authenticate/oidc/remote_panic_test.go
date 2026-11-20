package oidc_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/internal/recovered"
	"github.com/kartaladev/scrty/outbound"
)

// A provider refresh runs inside the relying party's single flight, on a
// goroutine singleflight starts, and calls consumer code there: the HTTP
// client's Transport and the clock (WithClock). net/http does not recover a
// panic in a RoundTripper, and singleflight re-raises a flight's panic on a
// goroutine of its own, so before the flight was recovered a panicking
// Transport or clock ended the process. These rows pin that such a panic is
// answered as the fetch failure a transport error gives: every caller waiting
// on the flight gets ErrDiscoveryFailed wrapping recovered.ErrPanicked, one
// Error record is written to the relying party's logger without the panic
// value's text, the cache's lock is not left held, and once the backoff window
// that failure opens has passed the next lookup succeeds and the one after it
// is served from the cache.
//
// Each row runs in a child process, because the unrecovered panic kills the
// process that raises it.

const (
	rpPanicRowEnv  = "SCRTY_OIDC_REMOTE_PANIC_ROW"
	rpPanicSecret  = "s3cr3t-panic-value-7f2a"
	rpPanicMessage = "consumer code panicked"
	rpPanicWaiters = 4
)

// rpPanicRanMarker is the line a child prints once its row has run and passed.
// The parent requires one line of the child's output to equal it.
func rpPanicRanMarker(row string) string { return "OIDC-REMOTE-PANIC-ROW-RAN:" + row }

// rpPanicTransport answers from the provider's handler in memory, as
// InMemoryOutbound does, except that while failing is set a request for path
// waits for release and then runs fail, or is answered normally when fail is
// nil.
type rpPanicTransport struct {
	p       *testProvider
	path    string
	failing atomic.Bool
	calls   atomic.Int32 // requests for path while failing
	total   atomic.Int32 // every request
	release chan struct{}
	fail    func() (*http.Response, error)
}

func (rt *rpPanicTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.total.Add(1)
	if rt.failing.Load() && r.URL.Path == rt.path {
		rt.calls.Add(1)
		<-rt.release
		if rt.fail != nil {
			return rt.fail()
		}
	}
	rec := httptest.NewRecorder()
	rt.p.handler.ServeHTTP(rec, r)
	res := rec.Result()
	res.Request = r
	return res, nil
}

// rpPanicClock is the relying party's clock. It reads the bubble's time and
// panics once: on the first read after panicNext is set, or on the at-th read
// after arm, and also on the read arm names second.
type rpPanicClock struct {
	panicNext atomic.Bool
	at        atomic.Int32
	also      atomic.Int32
	live      atomic.Bool
	reads     atomic.Int32
}

func (c *rpPanicClock) arm(at, also int32) {
	c.reads.Store(0)
	c.at.Store(at)
	c.also.Store(also)
	c.live.Store(true)
}

func (c *rpPanicClock) Now() time.Time {
	if c.panicNext.CompareAndSwap(true, false) {
		panic("clock: " + rpPanicSecret)
	}
	if c.live.Load() {
		if n := c.reads.Add(1); n == c.at.Load() || n == c.also.Load() {
			panic("clock: " + rpPanicSecret)
		}
	}
	return time.Now()
}

// rpWarnPanicHandler is a consumer's slog handler that records everything and
// panics on a Warn record.
type rpWarnPanicHandler struct{ cacheLogCapture }

func (h rpWarnPanicHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level == slog.LevelWarn {
		panic("handler: " + rpPanicSecret)
	}
	return h.cacheLogCapture.Handle(ctx, r)
}

func (h rpWarnPanicHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h rpWarnPanicHandler) WithGroup(string) slog.Handler      { return h }

// rpPanicRun is what one row observed.
type rpPanicRun struct {
	waiters []error // what each caller waiting on the failing flight got
	next    error   // what the call made after the backoff window got
	again   error   // what the call made right after next got
	calls   int32   // requests that reached the failing transport
	cached  bool    // again sent no request: next left the cache consistent
	records []slog.Record
}

func TestRemoteFetch_ConsumerTransportPanics(t *testing.T) {
	t.Parallel()

	only := os.Getenv(rpPanicRowEnv)

	// lookup is the call the row makes: the discovery document, or the key set.
	type lookup func(ctx context.Context, m *oidc.RelyingParty) error
	discovery := func(ctx context.Context, m *oidc.RelyingParty) error {
		_, err := oidc.MetadataForTest(m, ctx, "corp")
		return err
	}
	keySet := func(ctx context.Context, m *oidc.RelyingParty) error {
		_, err := oidc.KeysForTest(m, ctx, "corp", "k1")
		return err
	}

	// A row holds the request for path while its waiters join one flight,
	// unless clockAt is set: then the clock panics on its clockAt-th read
	// from the first waiter's lookup, which runs alone, and the other waiters
	// are answered from the backoff window its failure opened.
	type testCase struct {
		name   string
		path   string
		lookup lookup
		fail   func() (*http.Response, error) // nil: the held request is answered normally
		// clockAfterRelease makes the clock panic on its first read after the
		// held request is released: the flight's read after its fetch.
		clockAfterRelease bool
		clockAt           int32
		clockAlso         int32 // a second read that panics, after clockAt's
		warnPanics        bool  // the logger's handler panics on a Warn record
		assert            func(t *testing.T, run rpPanicRun)
	}

	// panicked checks the outcome every panicking row shares; calls is the
	// number of requests that reached the failing path.
	panickedN := func(what, panicType string, calls int32, reports int) func(t *testing.T, run rpPanicRun) {
		return func(t *testing.T, run rpPanicRun) {
			t.Helper()

			assert.EqualValues(t, calls, run.calls, "every waiter shares one flight")
			for i, err := range run.waiters {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed, "waiter %d", i)
				require.ErrorIs(t, err, recovered.ErrPanicked, "waiter %d", i)
				assert.NotContains(t, err.Error(), rpPanicSecret, "waiter %d", i)
			}
			require.NoError(t, run.next, "the next lookup, after the window, succeeds")
			require.NoError(t, run.again, "the lookup after that succeeds")
			assert.True(t, run.cached, "the lookup after that is served from the cache")

			var panicked []slog.Record
			for _, r := range run.records {
				r.Attrs(func(a slog.Attr) bool {
					assert.NotContains(t, a.Value.String(), rpPanicSecret, "record %q attr %s", r.Message, a.Key)
					return true
				})
				assert.NotContains(t, r.Message, rpPanicSecret)
				if r.Message == rpPanicMessage {
					panicked = append(panicked, r)
				}
			}
			require.Len(t, panicked, reports, "one panic record per panic")
			for _, rec := range panicked {
				assert.Equal(t, slog.LevelError, rec.Level)
				attrs := map[string]string{}
				rec.Attrs(func(a slog.Attr) bool {
					attrs[a.Key] = a.Value.String()
					return true
				})
				assert.Equal(t, what, attrs["what"])
				assert.Equal(t, panicType, attrs["panic_type"])
				assert.NotEmpty(t, attrs["frames"])
			}
		}
	}
	panicked := func(what, panicType string, calls int32) func(t *testing.T, run rpPanicRun) {
		return panickedN(what, panicType, calls, 1)
	}

	cases := []testCase{
		{
			name:   "a discovery fetch whose transport panics with a value",
			path:   "/.well-known/openid-configuration",
			lookup: discovery,
			fail:   func() (*http.Response, error) { panic("transport: " + rpPanicSecret) },
			assert: panicked("discovery document refresh", "string", 1),
		},
		{
			name:   "a discovery fetch whose transport panics with nil",
			path:   "/.well-known/openid-configuration",
			lookup: discovery,
			fail:   func() (*http.Response, error) { panic(nil) }, //nolint:govet // the hostile case under test
			assert: panicked("discovery document refresh", "*runtime.PanicNilError", 1),
		},
		{
			name:   "a discovery fetch whose transport hits a runtime error",
			path:   "/.well-known/openid-configuration",
			lookup: discovery,
			fail: func() (*http.Response, error) {
				var m map[string]int
				m[rpPanicSecret] = 1 // assignment to entry in nil map
				return nil, nil
			},
			assert: panicked("discovery document refresh", "runtime.plainError", 1),
		},
		{
			name:   "a key-set fetch whose transport panics with a value",
			path:   "/jwks",
			lookup: keySet,
			fail:   func() (*http.Response, error) { panic(errors.New("transport: " + rpPanicSecret)) },
			assert: panicked("key set refresh", "*errors.errorString", 1),
		},
		{
			name:              "a discovery refresh whose clock panics after the fetch",
			path:              "/.well-known/openid-configuration",
			lookup:            discovery,
			clockAfterRelease: true,
			assert:            panicked("discovery document refresh", "string", 1),
		},
		{
			name:              "a key-set refresh whose clock panics after the fetch",
			path:              "/jwks",
			lookup:            keySet,
			clockAfterRelease: true,
			assert:            panicked("key set refresh", "string", 1),
		},
		{
			// Reads: the lookup's, then the flight's first.
			name:    "a discovery refresh whose clock panics before the fetch",
			path:    "/.well-known/openid-configuration",
			lookup:  discovery,
			clockAt: 2,
			assert:  panicked("discovery document refresh", "string", 0),
		},
		{
			// Reads: keysFor's, the cache lookup's, the flight's first, then
			// the nested metadata lookup's, which judges the cached discovery
			// document by it.
			name:    "a key-set refresh whose clock panics in its metadata lookup",
			path:    "/jwks",
			lookup:  keySet,
			clockAt: 4,
			assert:  panicked("key set refresh", "string", 0),
		},
		{
			// The failure is timed by the latest read that returned when the
			// clock panics on the flight's first read and on the failure's read
			// (reads: the lookup's, the flight's first, the failure's), so the
			// window still opens and the later callers are answered from it,
			// not by a fetch of their own.
			name:      "a discovery refresh whose clock panics twice",
			path:      "/.well-known/openid-configuration",
			lookup:    discovery,
			clockAt:   2,
			clockAlso: 3,
			assert:    panickedN("discovery document refresh", "string", 0, 2),
		},
		{
			// The relying party's logger is a consumer's handler: its panic on
			// the backoff record must not end the process, and the callers get
			// the fetch failure the transport gave.
			name:       "a discovery fetch whose log handler panics on the backoff record",
			path:       "/.well-known/openid-configuration",
			lookup:     discovery,
			fail:       func() (*http.Response, error) { return nil, errors.New("transport: connection refused") },
			warnPanics: true,
			assert: func(t *testing.T, run rpPanicRun) {
				assert.EqualValues(t, 1, run.calls, "every waiter shares one flight")
				for i, err := range run.waiters {
					require.ErrorIs(t, err, oidc.ErrDiscoveryFailed, "waiter %d", i)
					assert.NotContains(t, err.Error(), rpPanicSecret, "waiter %d", i)
				}
				require.NoError(t, run.next)
				require.NoError(t, run.again)
				assert.True(t, run.cached)
				var panics int
				for _, r := range run.records {
					assert.NotContains(t, r.Message, rpPanicSecret)
					if r.Message == rpPanicMessage {
						panics++
					}
				}
				assert.Equal(t, 1, panics, "the handler's panic is reported once")
			},
		},
		{
			name:   "a discovery fetch whose transport fails without a panic",
			path:   "/.well-known/openid-configuration",
			lookup: discovery,
			fail:   func() (*http.Response, error) { return nil, errors.New("transport: connection refused") },
			assert: func(t *testing.T, run rpPanicRun) {
				assert.EqualValues(t, 1, run.calls)
				for i, err := range run.waiters {
					require.ErrorIs(t, err, oidc.ErrDiscoveryFailed, "waiter %d", i)
				}
				require.NoError(t, run.next)
				require.NoError(t, run.again)
				assert.True(t, run.cached)
				for _, r := range run.records {
					assert.NotEqual(t, rpPanicMessage, r.Message, "no panic record without a panic")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if only == "" {
				t.Parallel()
				rpPanicInChild(t, tc.name)
				return
			}
			if only != tc.name {
				t.Skip("another row runs in this child")
			}

			p := newTestProvider(t)
			logs := newCacheLogCapture()
			var handler slog.Handler = logs
			if tc.warnPanics {
				handler = rpWarnPanicHandler{logs}
			}
			var run rpPanicRun

			synctest.Test(t, func(t *testing.T) {
				rt := &rpPanicTransport{p: p, path: tc.path, release: make(chan struct{}), fail: tc.fail}
				out, err := outbound.New(outbound.WithHTTPClient(&http.Client{Transport: rt}))
				require.NoError(t, err)
				reg, err := oidc.NewRegistry(p.Provider("corp"))
				require.NoError(t, err)
				clk := &rpPanicClock{}
				m, err := oidc.NewRelyingParty(reg, stubBroker{}, oidc.WithClock(clk),
					oidc.WithOutboundClient(out), oidc.WithLogger(slog.New(handler)))
				require.NoError(t, err)

				if tc.path == "/jwks" {
					// The key set's metadata is fetched first, healthy, so the
					// failing flight is the key set's own.
					require.NoError(t, discovery(t.Context(), m))
				}

				rt.failing.Store(true)
				run.waiters = make([]error, rpPanicWaiters)
				var wg sync.WaitGroup
				if tc.clockAt > 0 {
					close(rt.release) // nothing is held: the flight fails before its fetch
					clk.arm(tc.clockAt, tc.clockAlso)
					run.waiters[0] = tc.lookup(t.Context(), m)
					for i := 1; i < rpPanicWaiters; i++ {
						wg.Go(func() { run.waiters[i] = tc.lookup(t.Context(), m) })
					}
					wg.Wait()
				} else {
					for i := range rpPanicWaiters {
						wg.Go(func() { run.waiters[i] = tc.lookup(t.Context(), m) })
					}
					synctest.Wait() // every waiter has joined the held flight
					clk.panicNext.Store(tc.clockAfterRelease)
					close(rt.release)
					wg.Wait()
				}

				run.calls = rt.calls.Load()
				rt.failing.Store(false)
				time.Sleep(oidc.DefaultDiscoveryBackoffMax) // past the failure's backoff window
				run.next = tc.lookup(t.Context(), m)
				before := rt.total.Load()
				run.again = tc.lookup(t.Context(), m)
				run.cached = rt.total.Load() == before
			})

			run.records = logs.matching("")
			tc.assert(t, run)

			if !t.Failed() {
				os.Stdout.WriteString("\n" + rpPanicRanMarker(tc.name) + "\n") //nolint:errcheck // a lost marker fails the parent
			}
		})
	}
}

// rpPanicInChild re-runs TestRemoteFetch_ConsumerTransportPanics in a child
// process limited to row, and fails unless the child exits 0 within a minute
// and prints the marker showing it ran the row and the row passed.
func rpPanicInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), rpPanicRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")
	require.NoError(t, err, "the child failed:\n%s", out)

	want := rpPanicRanMarker(row)
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
