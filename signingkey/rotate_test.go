// The rotation tests are not parallel: goleak counts goroutines process-wide.
// They are split by store shape — the in-memory store for a rotation that
// succeeds, a generated mock for one the store rejects — because the setup, not
// the assertion, is what differs.
package signingkey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/signingkey"
)

// epoch is the instant every controlled-clock test starts at.
var epoch = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

// currentKid returns the kid currently signing for alg, requiring there to be
// one.
func currentKid(t *testing.T, km *signingkey.KeyManager, alg signingkey.Alg) string {
	t.Helper()

	kid, signer, ok := km.GetSigner(alg)
	require.True(t, ok, "there is a current %s key", alg)
	require.NotNil(t, signer, "the current %s key signs", alg)
	return kid
}

// waitForRotation returns the kid that replaced was as the current key for alg.
func waitForRotation(t *testing.T, km *signingkey.KeyManager, alg signingkey.Alg, was string) string {
	t.Helper()

	var replacement string
	require.Eventually(t, func() bool {
		kid, _, ok := km.GetSigner(alg)
		if ok && kid != was {
			replacement = kid
			return true
		}
		return false
	}, 10*time.Second, 5*time.Millisecond, "a rotation should have made a new %s key current", alg)
	return replacement
}

// stopAndVerify stops km at the end of the test and reports any goroutine it
// left behind. It snapshots the goroutines running now, so it must be called
// before the manager is started — which is also when the manager has started
// none of its own.
func stopAndVerify(t *testing.T, km *signingkey.KeyManager) {
	t.Helper()

	ignore := goleak.IgnoreCurrent()
	t.Cleanup(func() {
		require.NoError(t, km.Stop())
		goleak.VerifyNone(t, ignore)
	})
}

func TestRotationAtTheConfiguredInterval(t *testing.T) {
	clock := newFakeClock(epoch)
	store := signingkey.NewInMemoryKeyStore()
	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clock),
		signingkey.WithRotateInterval(6*time.Hour), // the consumer's interval
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(time.Hour),
		signingkey.WithLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)

	k1 := currentKid(t, km, signingkey.RS256)
	require.NoError(t, km.Start(t.Context()))

	clock.Advance(5*time.Hour + 59*time.Minute)
	assert.Never(t, func() bool {
		kid, _, ok := km.GetSigner(signingkey.RS256)
		return ok && kid != k1
	}, 300*time.Millisecond, 20*time.Millisecond,
		"nothing rotates before the consumer's 6-hour interval has elapsed")

	clock.Advance(time.Minute) // six hours since the manager was constructed
	k2 := waitForRotation(t, km, signingkey.RS256, k1)

	assert.True(t, publishes(km, k2), "the new key is published")
	assert.True(t, publishes(km, k1),
		"the key it replaced stays published until housekeeping removes it")

	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)
	require.Len(t, recs, 2, "the rotated key was written to the store")
	assert.Equal(t, k1, recs[0].Kid)
	assert.Equal(t, k2, recs[1].Kid)
	assert.Equal(t, epoch.Add(6*time.Hour), recs[1].CreatedAt,
		"the new key is stamped with the clock's time, not the wall clock's")

	clock.Advance(6 * time.Hour) // and again, every six hours
	k3 := waitForRotation(t, km, signingkey.RS256, k2)
	assert.NotEqual(t, k1, k3)
}

// logRecorder captures what the manager logs through a real slog handler, so a
// test asserts on the same records a consumer's handler would receive.
type logRecorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// newLogRecorder returns a recorder and a logger writing JSON records into it.
func newLogRecorder() (*logRecorder, *slog.Logger) {
	rec := &logRecorder{}
	return rec, slog.New(slog.NewJSONHandler(rec, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func (r *logRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.buf.Write(p)
}

// written reports how many records have been written so far. A test waits on
// it, not on the error hook, before reading the records: the manager calls the
// hook before it writes the record, so a hook having run does not mean the
// record is there yet.
func (r *logRecorder) written() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return bytes.Count(r.buf.Bytes(), []byte("\n"))
}

// records decodes every record written so far.
func (r *logRecorder) records(t *testing.T) []map[string]any {
	t.Helper()

	r.mu.Lock()
	raw := r.buf.String()
	r.mu.Unlock()

	var out []map[string]any
	for line := range strings.Lines(raw) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec), "log line %q", line)
		out = append(out, rec)
	}
	return out
}

// failureReport collects what a rotation or reload failure was observed to do.
type failureReport struct {
	mu       sync.Mutex
	hooked   []error
	rejected []string // the kids the store refused
}

func (f *failureReport) hook(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.hooked = append(f.hooked, err)
}

func (f *failureReport) reject(kid string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.rejected = append(f.rejected, kid)
}

func (f *failureReport) hooks() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.hooked)
}

func (f *failureReport) snapshot() ([]error, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.hooked), slices.Clone(f.rejected)
}

// The store failures every failure case is driven by.
var (
	errStoreWrite       = errors.New("disk full")
	errStoreUnreachable = errors.New("store unreachable")
)

// The operations a failing store can refuse, which are also the operation
// names the manager samples and logs by.
const (
	opRotate = "rotate"
	opReload = "reload"
)

// failingStore serves construction and then refuses the named operation every
// time: a rotating store records the kid it refused, so a test knows which key
// was minted and turned away.
func failingStore(t *testing.T, report *failureReport, op string) signingkey.KeyStore {
	t.Helper()

	var loads, writes atomic.Int32
	store := NewMockKeyStore(gomock.NewController(t))
	store.EXPECT().LoadAll(gomock.Any()).DoAndReturn(
		func(context.Context) ([]signingkey.Record, error) {
			if op == opReload && loads.Add(1) > 1 {
				return nil, errStoreUnreachable
			}
			return nil, nil
		}).AnyTimes()
	store.EXPECT().Store(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, rec signingkey.Record) error {
			if op == opRotate && writes.Add(1) > 1 {
				report.reject(rec.Kid)
				return errStoreWrite
			}
			return nil
		}).AnyTimes()
	return store
}

func TestRotationFailureIsObservable(t *testing.T) {
	type testCase struct {
		name string
		// logTo installs the recorder's logger and returns the options that
		// route the manager's records to it.
		logTo  func(t *testing.T, logger *slog.Logger) []signingkey.Option
		assert func(t *testing.T, rec *logRecorder, report *failureReport, previous string, km *signingkey.KeyManager)
	}

	// assertReported is shared: both cases differ only in where the records are
	// expected to arrive, and both then make the same claims about them.
	assertReported := func(t *testing.T, rec *logRecorder, report *failureReport, previous string, km *signingkey.KeyManager) {
		hooked, rejected := report.snapshot()

		require.GreaterOrEqual(t, len(hooked), 2,
			"the failure is reported and retried at the next interval")
		assert.ErrorIs(t, hooked[0], errStoreWrite,
			"the hook receives an error wrapping the store's error")

		require.GreaterOrEqual(t, len(rejected), 2, "each retry minted and offered a key")
		for _, kid := range rejected {
			require.NotEqual(t, previous, kid, "each attempt minted a distinct key")
			assert.False(t, publishes(km, kid), "a key the store rejected is never published")
		}
		assert.NotContains(t, rejected, currentKid(t, km, signingkey.EdDSA),
			"a key the store rejected is never current")

		assert.Equal(t, previous, currentKid(t, km, signingkey.EdDSA),
			"the previous key stays current")
		assert.True(t, publishes(km, previous), "and stays published, so it still signs")

		records := rec.records(t)
		require.NotEmpty(t, records, "the failure reaches the logger")
		assert.Equal(t, "ERROR", records[0]["level"])
		assert.Contains(t, records[0], "msg")
		assert.Equal(t, signingkey.EdDSA, records[0]["alg"],
			"the record names the algorithm that failed to rotate")
		assert.NotContains(t, records[0], "error",
			"the record no longer carries the store's own error text")
		assert.Equal(t, "signing-key-store", records[0]["reason"],
			"the record names the failed dependency by a fixed reason")
		assert.NotEmpty(t, records[0]["error_type"],
			"the record carries the error's type, never its text")
	}

	cases := []testCase{
		{
			name: "the configured logger receives the failure",
			logTo: func(_ *testing.T, logger *slog.Logger) []signingkey.Option {
				return []signingkey.Option{signingkey.WithLogger(logger)}
			},
			assert: assertReported,
		},
		{
			name: "with no logger configured the failure reaches slog.Default()",
			logTo: func(t *testing.T, logger *slog.Logger) []signingkey.Option {
				restore := slog.Default()
				slog.SetDefault(logger)
				t.Cleanup(func() { slog.SetDefault(restore) })
				return nil
			},
			assert: assertReported,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, logger := newLogRecorder()
			report := &failureReport{}
			clock := newFakeClock(epoch)

			opts := append([]signingkey.Option{
				signingkey.WithKeyStore(failingStore(t, report, opRotate)),
				signingkey.WithClock(clock),
				signingkey.WithAlgs(signingkey.EdDSA),
				signingkey.WithRotateInterval(time.Hour),
				signingkey.WithReloadInterval(30 * time.Minute),
				signingkey.WithHousekeepingInterval(12 * time.Hour),
				signingkey.WithLifetime(24 * time.Hour),
				signingkey.WithErrorHook(report.hook),
			}, tc.logTo(t, logger)...)

			km, err := signingkey.NewKeyManager(t.Context(), opts...)
			require.NoError(t, err)
			stopAndVerify(t, km)

			previous := currentKid(t, km, signingkey.EdDSA)
			require.NoError(t, km.Start(t.Context()))

			for attempt := 1; attempt <= 2; attempt++ {
				clock.Advance(time.Hour)
				require.Eventually(t, func() bool { return report.hooks() >= attempt },
					10*time.Second, 5*time.Millisecond,
					"rotation attempt %d should have been reported", attempt)
			}

			tc.assert(t, rec, report, previous, km)
		})
	}
}
