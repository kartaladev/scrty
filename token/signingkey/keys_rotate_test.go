// The rotation, error-hook, sampling, reload, algorithm-scope and housekeeping
// tests are not parallel: goleak counts goroutines process-wide. The rotation
// tests are split by store shape — the in-memory store for a rotation that
// succeeds, a generated mock for one the store rejects — because the setup,
// not the assertion, is what differs.
package signingkey_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/token/signingkey"
)

// Standalone: it rotates on the in-memory store and reads the store back.
func TestRotationAtTheConfiguredInterval(t *testing.T) {
	clk := newClock()
	store := signingkey.NewMemoryKeyStore()
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithRotateInterval(6*time.Hour), // the consumer's interval
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(time.Hour),
		signingkey.WithKeyLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)

	k1 := currentKid(t, km, signingkey.RS256)
	require.NoError(t, km.Start(t.Context()))

	advance(t, clk, 5*time.Hour+59*time.Minute, loopCount)
	assert.Equal(t, k1, currentKid(t, km, signingkey.RS256),
		"nothing rotates before the consumer's 6-hour interval has elapsed")

	advance(t, clk, time.Minute, loopCount) // six hours since the manager was started
	k2 := currentKid(t, km, signingkey.RS256)
	require.NotEqual(t, k1, k2, "the interval elapsed, so the key rotated")

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

	advance(t, clk, 6*time.Hour, loopCount) // and again, every six hours
	k3 := currentKid(t, km, signingkey.RS256)
	assert.NotEqual(t, k2, k3)
	assert.NotEqual(t, k1, k3)
}

// Standalone: its cases run over a store that rejects one operation.
func TestRotationFailureIsObservable(t *testing.T) {
	type testCase struct {
		name string
		// logTo installs the recorder's logger and returns the options that
		// route the manager's records to it.
		logTo  func(t *testing.T, logger *slog.Logger) []signingkey.Option
		assert func(t *testing.T, rec *logRecorder, report *failureReport, previous string, km *signingkey.Keys)
	}

	// assertReported is shared: both cases differ only in where the records are
	// expected to arrive, and both then make the same claims about them.
	assertReported := func(t *testing.T, rec *logRecorder, report *failureReport, previous string, km *signingkey.Keys) {
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
			clk := newClock()

			opts := append([]signingkey.Option{
				signingkey.WithKeyStore(failingStore(t, report, opRotate)),
				signingkey.WithClock(clk),
				signingkey.WithAlgs(signingkey.EdDSA),
				signingkey.WithRotateInterval(time.Hour),
				signingkey.WithReloadInterval(30 * time.Minute),
				signingkey.WithHousekeepingInterval(12 * time.Hour),
				signingkey.WithKeyLifetime(24 * time.Hour),
				signingkey.WithErrorHook(report.hook),
			}, tc.logTo(t, logger)...)

			km, err := signingkey.New(t.Context(), opts...)
			require.NoError(t, err)
			stopAndVerify(t, km)

			previous := currentKid(t, km, signingkey.EdDSA)
			require.NoError(t, km.Start(t.Context()))

			for attempt := 1; attempt <= 2; attempt++ {
				advance(t, clk, time.Hour, loopCount)
				require.Equal(t, attempt, report.hooks(),
					"rotation attempt %d should have been reported", attempt)
			}

			tc.assert(t, rec, report, previous, km)
		})
	}
}

// TestRotation_IsNotUndoneByAFutureDatedStoredKey pins that a stored key dated
// far ahead — a clock gone wrong on the replica that wrote it, or a row someone
// edited — never becomes the key that signs. Were the newest key current
// whatever its date, every reload would hand signing back to it after each
// rotation, and it would never age out.
// Standalone: it seeds a far-future key and rotates for two days.
func TestRotation_IsNotUndoneByAFutureDatedStoredKey(t *testing.T) {
	clk := newClock()
	store := signingkey.NewMemoryKeyStore()
	future := realRecordFor(t, signingkey.EdDSA, epoch.Add(365*24*time.Hour))
	require.NoError(t, store.Store(t.Context(), realRecordFor(t, signingkey.EdDSA, epoch)))
	require.NoError(t, store.Store(t.Context(), future))

	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(time.Hour),
		signingkey.WithKeyLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)
	require.NoError(t, km.Start(t.Context()))

	for range 48 {
		advance(t, clk, time.Hour, loopCount)
	}
	// One more reload interval, so a reload is the last thing to have run.
	advance(t, clk, time.Minute, loopCount)

	assert.NotEqual(t, future.Kid, currentKid(t, km, signingkey.EdDSA),
		"a key dated a year ahead never signs")
	assert.False(t, publishes(km, future.Kid), "and is not published")
}

// TestErrorHookMayReadTheManagerBack pins the half of WithErrorHook's contract
// a consumer can act on. The hook runs on the loop goroutine, so it must not
// call Start or Stop — that is documented, not enforceable — but reading the
// manager back is safe, which is what a hook needs in order to decide whether
// an outage has cost it its keys.
//
// The manager therefore must not hold the keyring lock across the hook, and
// nothing else in the suite observes that: a hook that only counts failures is
// happy either way. The loop must also go on reporting afterwards, and Stop
// must still return.
// Standalone: its hook reads the manager back on the loop goroutine.
func TestErrorHookMayReadTheManagerBack(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	const attempts = 3

	var (
		km     *signingkey.Keys
		report = &failureReport{}
		reads  atomic.Int32
	)

	// hook does everything WithErrorHook's godoc names as safe from the hook,
	// and counts the times all of it answered.
	hook := func(err error) {
		kid, signer, ok := km.Signer(signingkey.EdDSA)
		published, keysErr := km.VerificationKeys()
		if ok && signer != nil && kid != "" &&
			keysErr == nil && len(published) > 0 &&
			len(km.SupportedAlgs()) == 1 && km.KeyLifetime() > 0 {
			reads.Add(1)
		}
		report.hook(err)
	}

	clk := newClock()

	var err error
	km, err = signingkey.New(t.Context(),
		signingkey.WithKeyStore(failingStore(t, report, opRotate)),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithErrorHook(hook),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithKeyLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, km.Start(t.Context()))

	for attempt := 1; attempt <= attempts; attempt++ {
		// A hook that stalled its loop would keep it from parking again, which
		// advance reports as a failure rather than a hang.
		advance(t, clk, time.Hour, loopCount)
		require.Equal(t, attempt, report.hooks(),
			"rotation failure %d should have been reported: a hook that reads the "+
				"manager back must not stall the loop it runs on", attempt)
	}

	assert.GreaterOrEqual(t, reads.Load(), int32(attempts),
		"every call to the hook could read the manager back")

	// Stop is what the hook may not call; the consumer's own goroutine still
	// can, and it has to return.
	stopped := make(chan error, 1)
	go func() { stopped <- km.Stop() }()
	select {
	case stopErr := <-stopped:
		require.NoError(t, stopErr)
	case <-time.After(30 * time.Second):
		t.Fatal("Stop never returned after the error hook had read the manager back")
	}

	goleak.VerifyNone(t, ignore)
}

// TestFailureLogsAreSampled drives a store that keeps failing and pins the
// exact records that reach the logger. The counts are exact because the clock
// is controlled: the sampler reads it, so the test decides which failures fall
// in the same window.
// Standalone: it drives a failing store on a controlled sampling window.
func TestFailureLogsAreSampled(t *testing.T) {
	const (
		window     = time.Hour
		everyOther = 5 // failures driven inside the first window, after the first
		afterward  = 2 // failures driven after the second window's record
	)

	type testCase struct {
		name   string
		verb   string
		assert func(t *testing.T, recorder *logRecorder, report *failureReport)
	}

	// assertSampled is shared: the two cases differ only in which store verb
	// fails, and make the same claims about what was written.
	assertSampled := func(t *testing.T, recorder *logRecorder, report *failureReport) {
		records := recorder.records(t)
		require.Len(t, records, 2,
			"%d failures in the first window and one in the next write two records",
			everyOther)
		assert.Equal(t, float64(0), records[0]["suppressed"],
			"the first record suppressed nothing before it")
		assert.Equal(t, float64(everyOther-1), records[1]["suppressed"],
			"the next window's record states how many failures were suppressed before it")

		assert.Equal(t, everyOther+1+afterward, report.hooks(),
			"the error hook is never sampled: every failure reaches it")
	}

	cases := []testCase{
		{name: "rotation failures", verb: opRotate, assert: assertSampled},
		{name: "reload failures", verb: opReload, assert: assertSampled},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := newClock()
			report := &failureReport{}
			recorder, logger := newLogRecorder()

			km, err := signingkey.New(t.Context(),
				signingkey.WithKeyStore(failingStore(t, report, tc.verb)),
				signingkey.WithClock(clk),
				signingkey.WithAlgs(signingkey.EdDSA),
				signingkey.WithLogger(logger),
				signingkey.WithErrorHook(report.hook),
				signingkey.WithLogInterval(window),
				signingkey.WithRotateInterval(time.Minute),
				signingkey.WithReloadInterval(30*time.Second),
				signingkey.WithHousekeepingInterval(12*time.Hour),
				signingkey.WithKeyLifetime(24*time.Hour),
			)
			require.NoError(t, err)
			stopAndVerify(t, km)

			require.NoError(t, km.Start(t.Context()))

			drive := func(by time.Duration, want int) {
				advance(t, clk, by, loopCount)
				require.Equal(t, want, report.hooks(),
					"failure %d should have been reported", want)
			}

			for failure := 1; failure <= everyOther; failure++ {
				drive(time.Minute, failure)
			}
			drive(window, everyOther+1) // the window has turned over
			for failure := 1; failure <= afterward; failure++ {
				drive(time.Minute, everyOther+1+failure)
			}

			tc.assert(t, recorder, report)

			require.NoError(t, km.Stop())
			records := recorder.records(t)
			require.Len(t, records, 3, "stopping accounts for what was still suppressed")
			assert.Equal(t, float64(afterward), records[2]["suppressed"])
			assert.Equal(t, tc.verb, records[2]["op"],
				"the flushed record names the operation it stands for")
		})
	}
}

// TestSigningKeyStoreFailureRecords pins that a failure during rotation or
// reload is recorded through a fixed reason and the failing dependency's own
// error type — never the library's wrapping of it, and never its text — while
// the public algorithm identifier and key id stay.
// Standalone: it reads the records a failing store leaves in the log.
func TestSigningKeyStoreFailureRecords(t *testing.T) {
	// undecodable is a genuine record whose private half has been cut short,
	// so the store returns it and the library cannot parse it.
	undecodable := realRecordFor(t, signingkey.EdDSA, epoch)
	undecodable.Kid = "kid-undecodable"
	undecodable.Private = slices.Clone(undecodable.Private[:len(undecodable.Private)-8])
	_, parseErr := x509.ParsePKCS8PrivateKey(undecodable.Private)
	require.Error(t, parseErr)

	type testCase struct {
		name string
		// store configures the mock; construction's own LoadAll and Store
		// calls come first.
		store  func(s *MockKeyStore)
		assert func(t *testing.T, rec map[string]any)
	}

	// afterConstruction answers construction's first call with first, and
	// every later call with later.
	afterConstruction := func(first, later func() ([]signingkey.Record, error)) func(context.Context) ([]signingkey.Record, error) {
		var calls atomic.Int32
		return func(context.Context) ([]signingkey.Record, error) {
			if calls.Add(1) == 1 {
				return first()
			}
			return later()
		}
	}
	empty := func() ([]signingkey.Record, error) { return nil, nil }

	cases := []testCase{
		{
			name: "a store write failure during rotation",
			store: func(s *MockKeyStore) {
				var writes atomic.Int32
				s.EXPECT().LoadAll(gomock.Any()).Return(nil, nil).AnyTimes()
				s.EXPECT().Store(gomock.Any(), gomock.Any()).DoAndReturn(
					func(context.Context, signingkey.Record) error {
						if writes.Add(1) > 1 {
							return errRedactionFixture
						}
						return nil
					}).AnyTimes()
			},
			assert: func(t *testing.T, rec map[string]any) {
				assert.Equal(t, signingkey.EdDSA, rec["alg"], "the public algorithm identifier stays")
				assert.Equal(t, "signing-key-store", rec["reason"])
				assert.Equal(t, "*errors.errorString", rec["error_type"], "the store's own error type, not the library's wrapping")
			},
		},
		{
			name: "a store read failure during reload",
			store: func(s *MockKeyStore) {
				s.EXPECT().Store(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				s.EXPECT().LoadAll(gomock.Any()).DoAndReturn(afterConstruction(empty,
					func() ([]signingkey.Record, error) { return nil, errRedactionFixture })).AnyTimes()
			},
			assert: func(t *testing.T, rec map[string]any) {
				assert.NotContains(t, rec, "alg", "a whole-store reload belongs to no algorithm")
				assert.Equal(t, "signing-key-store", rec["reason"])
				assert.Equal(t, "*errors.errorString", rec["error_type"], "the store's own error type, not the library's wrapping")
			},
		},
		{
			name: "a stored key that cannot be decoded during reload",
			store: func(s *MockKeyStore) {
				s.EXPECT().Store(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				s.EXPECT().LoadAll(gomock.Any()).DoAndReturn(afterConstruction(empty,
					func() ([]signingkey.Record, error) { return []signingkey.Record{undecodable}, nil })).AnyTimes()
			},
			assert: func(t *testing.T, rec map[string]any) {
				assert.Equal(t, "key-decode", rec["reason"], "a decode failure is not a store failure")
				assert.Equal(t, signingkey.EdDSA, rec["alg"])
				assert.Equal(t, "kid-undecodable", rec["kid"], "the record names the public key id it could not decode")
				assert.Equal(t, fmt.Sprintf("%T", parseErr), rec["error_type"], "the decode error's own type, not the library's wrapping")
				for key, v := range rec {
					if text, ok := v.(string); ok {
						assert.NotContains(t, text, string(undecodable.Private), "key %q carries key material", key)
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := newClock()
			report := &failureReport{}
			recorder, logger := newLogRecorder()

			store := NewMockKeyStore(gomock.NewController(t))
			tc.store(store)

			km, err := signingkey.New(t.Context(),
				signingkey.WithKeyStore(store),
				signingkey.WithClock(clk),
				signingkey.WithAlgs(signingkey.EdDSA),
				signingkey.WithLogger(logger),
				signingkey.WithErrorHook(report.hook),
				signingkey.WithReloadInterval(100*time.Millisecond),
				signingkey.WithRotateInterval(time.Second),
				signingkey.WithHousekeepingInterval(12*time.Hour),
				signingkey.WithKeyLifetime(24*time.Hour),
			)
			require.NoError(t, err)
			stopAndVerify(t, km)

			require.NoError(t, km.Start(t.Context()))

			advance(t, clk, time.Second, loopCount)
			require.GreaterOrEqual(t, report.hooks(), 1, "the failure reaches the consumer's error hook")
			require.GreaterOrEqual(t, recorder.written(), 1, "the failure reaches the logger")

			records := recorder.records(t)
			require.NotEmpty(t, records, "the failure reaches the logger")
			tc.assert(t, records[0])

			for _, rec := range records {
				assert.NotContains(t, rec, "error", "no record carries the dependency's error text")
				for key, v := range rec {
					if text, ok := v.(string); ok {
						assert.NotContains(t, text, "alice@example.com", "key %q", key)
						assert.NotContains(t, text, "u-123", "key %q", key)
					}
				}
			}

			hooked, _ := report.snapshot()
			require.NotEmpty(t, hooked, "the failure reaches the consumer's error hook")
			for _, err := range hooked {
				assert.NotContains(t, err.Error(), "alice@example.com",
					"the hook receives fixed text, not the dependency's own error")
				assert.NotContains(t, err.Error(), "u-123",
					"the hook receives fixed text, not the dependency's own error")
			}
		})
	}
}

// Standalone: it runs two replicas over one store.
func TestReloadPublishesAnotherReplicasKeys(t *testing.T) {
	clk := newClock()
	store := signingkey.NewMemoryKeyStore()
	shared := []signingkey.Option{
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithReloadInterval(10 * time.Second), // the consumer's interval
		signingkey.WithHousekeepingInterval(12 * time.Hour),
	}

	// Replica A is the one that rotates. Replica B rotates so rarely that
	// everything it publishes beyond its own first key came from the store.
	replicaA, err := signingkey.New(t.Context(), append(shared,
		signingkey.WithRotateInterval(time.Minute),
		signingkey.WithKeyLifetime(24*time.Hour))...)
	require.NoError(t, err)
	replicaB, err := signingkey.New(t.Context(), append(shared,
		signingkey.WithRotateInterval(24*time.Hour),
		signingkey.WithKeyLifetime(48*time.Hour))...)
	require.NoError(t, err)

	k1 := currentKid(t, replicaA, signingkey.EdDSA)
	require.Equal(t, k1, currentKid(t, replicaB, signingkey.EdDSA),
		"both replicas start on the one stored key")

	require.NoError(t, replicaA.Start(t.Context()))
	stopAndVerify(t, replicaA)

	advance(t, clk, time.Minute, loopCount)
	k2 := currentKid(t, replicaA, signingkey.EdDSA)
	require.NotEqual(t, k1, k2, "replica A rotated")
	token := signWithCurrent(t, replicaA, "issued by replica A")

	// Replica B starts only now, so its reload is due exactly one reload
	// interval after the rotation it has to pick up — not part of it.
	require.NoError(t, replicaB.Start(t.Context()))
	stopAndVerify(t, replicaB)
	require.Equal(t, k1, currentKid(t, replicaB, signingkey.EdDSA),
		"replica B has not reloaded yet")

	// Both replicas share the clock, so both sets of loops are parked on it.
	const bothReplicas = 2 * loopCount

	advance(t, clk, 9*time.Second, bothReplicas)
	assert.False(t, publishes(replicaB, k2),
		"nothing is reloaded before the consumer's 10-second interval has elapsed")

	advance(t, clk, time.Second, bothReplicas) // ten seconds since replica A rotated
	kid, _, ok := replicaB.Signer(signingkey.EdDSA)
	require.True(t, publishes(replicaB, k2) && ok && kid == k2,
		"within one reload interval replica B publishes k2 and adopts it as current")

	setB := publishedSet(t, replicaB)
	payload, err := jws.Verify(token, jws.WithKeySet(setB))
	require.NoError(t, err, "replica B verifies a token replica A signed with k2")
	assert.Equal(t, "issued by replica A", string(payload))

	assert.True(t, publishes(replicaB, k1), "and keeps publishing the key k2 replaced")
}

// Standalone: another replica's writes land between construction and the reload.
func TestReloadSkipsExpiredKeysAndRepicksCurrent(t *testing.T) {
	clk := newClock()
	store := signingkey.NewMemoryKeyStore()
	held := realRecord(t, epoch)
	require.NoError(t, store.Store(t.Context(), held))

	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithReloadInterval(10*time.Second),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithKeyLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)

	require.Equal(t, held.Kid, currentKid(t, km, signingkey.RS256))

	// Another replica writes one key past the lifetime and one newer than
	// anything held.
	expired := realRecord(t, epoch.Add(-25*time.Hour))
	newest := realRecord(t, epoch.Add(5*time.Second))
	require.NoError(t, store.Store(t.Context(), expired))
	require.NoError(t, store.Store(t.Context(), newest))

	require.NoError(t, km.Start(t.Context()))

	advance(t, clk, 10*time.Second, loopCount)
	kid, _, ok := km.Signer(signingkey.RS256)
	require.True(t, publishes(km, newest.Kid) && ok && kid == newest.Kid,
		"a reload publishes the stored key and re-picks the latest CreatedAt as current")

	assert.False(t, publishes(km, expired.Kid),
		"a non-current key older than the lifetime is never republished")
	assert.True(t, publishes(km, held.Kid), "the key it replaced is still published")

	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)
	assert.Len(t, recs, 3, "a reload writes nothing")
}

// Standalone: its store fails every reload.
func TestReloadFailureKeepsHeldKeys(t *testing.T) {
	clk := newClock()
	report := &failureReport{}
	recorder, logger := newLogRecorder()

	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(failingStore(t, report, opReload)),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithLogger(logger),
		signingkey.WithErrorHook(report.hook),
		signingkey.WithReloadInterval(10*time.Second),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithKeyLifetime(24*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)

	held := currentKid(t, km, signingkey.EdDSA)
	token := signWithCurrent(t, km, "issued before the outage")

	require.NoError(t, km.Start(t.Context()))

	advance(t, clk, 10*time.Second, loopCount)
	require.Equal(t, 1, report.hooks(), "the reload failure reaches the consumer's error hook")
	require.Equal(t, 1, recorder.written(), "the reload failure reaches the configured logger")

	hooked, _ := report.snapshot()
	assert.ErrorIs(t, hooked[0], errStoreUnreachable,
		"the hook receives an error wrapping the store's error")

	assert.Equal(t, held, currentKid(t, km, signingkey.EdDSA),
		"the manager keeps signing with the keys it already holds")
	assert.True(t, publishes(km, held))

	set := publishedSet(t, km)
	payload, err := jws.Verify(token, jws.WithKeySet(set))
	require.NoError(t, err, "and keeps verifying the tokens they signed")
	assert.Equal(t, "issued before the outage", string(payload))

	records := recorder.records(t)
	require.NotEmpty(t, records, "the failure reaches the configured logger")
	assert.Equal(t, "ERROR", records[0]["level"])
	assert.NotContains(t, records[0], "error",
		"the record no longer carries the store's own error text")
	assert.Equal(t, "signing-key-store", records[0]["reason"],
		"the record names the failed dependency by a fixed reason")
	assert.NotEmpty(t, records[0]["error_type"],
		"the record carries the error's type, never its text")
}

// Standalone: its clock's reading steps back.
func TestReloadAfterClockStepBackKeepsASigner(t *testing.T) {
	clk := &steppedClock{FakeClock: newClock()}
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.RS256),
		signingkey.WithRotateInterval(24*time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithKeyLifetime(48*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)
	held := currentKid(t, km, signingkey.RS256)
	require.NoError(t, km.Start(t.Context()))

	// The reading steps back an hour, so the held key is dated further ahead
	// than one reload interval, then a reload runs.
	clk.back.Store(int64(time.Hour))
	advance(t, clk.FakeClock, time.Minute, loopCount)

	kid, signer, ok := km.Signer(signingkey.RS256)
	require.True(t, ok, "a reload never leaves a configured algorithm without a current key")
	assert.NotNil(t, signer)
	assert.Equal(t, held, kid, "the previous current key stays current")
}

// Standalone: a key dated just ahead is stored after Start.
func TestReloadAdoptsAKeyStoredJustAhead(t *testing.T) {
	clk := newClock()
	store := signingkey.NewMemoryKeyStore()
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.RS256),
		signingkey.WithRotateInterval(24*time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(12*time.Hour),
		signingkey.WithKeyLifetime(48*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)
	require.NoError(t, km.Start(t.Context()))

	// A replica whose clock runs 90 seconds fast stores a key, so at the first
	// reload it is dated 30 seconds ahead, within the reload interval.
	ahead := realRecord(t, epoch.Add(90*time.Second))
	require.NoError(t, store.Store(t.Context(), ahead))

	advance(t, clk, time.Minute, loopCount)

	kid, _, ok := km.Signer(signingkey.RS256)
	require.True(t, ok)
	assert.Equal(t, ahead.Kid, kid, "a key within one reload interval ahead is adopted as current")
}

// TestReloadBreaksATieAsTheStoreLists pins the tie rule across a reload: two
// keys of one algorithm created at the same instant are decided by the order
// the store lists them in, at every reload as at construction. The keys the
// manager already holds must not win the tie merely because it holds them, and
// a record it does not hold must not win merely because it is new to it.
// Standalone: its store lists records in an order of its own.
func TestReloadBreaksATieAsTheStoreLists(t *testing.T) {
	type testCase struct {
		name string
		// listed returns the records the store lists at construction, and the
		// ones it lists from the first reload on, and the kid that must be
		// current throughout.
		listed func(t *testing.T) (atStart, atReload []signingkey.Record, current string)
		assert func(t *testing.T, km *signingkey.Keys, atReload []signingkey.Record)
	}

	cases := []testCase{
		{
			name: "a tied key past its lifetime, listed earlier, stays unpublished",
			listed: func(t *testing.T) ([]signingkey.Record, []signingkey.Record, string) {
				// Both are past the lifetime; only the current key is
				// published, and it is the one the store lists later.
				earlier := realRecord(t, epoch.Add(-48*time.Hour))
				later := realRecord(t, epoch.Add(-48*time.Hour))
				recs := []signingkey.Record{earlier, later}
				return recs, recs, later.Kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, atReload []signingkey.Record) {
				assert.False(t, publishes(km, atReload[0].Kid),
					"a key past its lifetime that is not current is never republished")
			},
		},
		{
			name: "a tied key another replica stores, listed earlier, does not take signing",
			listed: func(t *testing.T) ([]signingkey.Record, []signingkey.Record, string) {
				held := realRecord(t, epoch)
				arrived := realRecord(t, epoch)
				return []signingkey.Record{held}, []signingkey.Record{arrived, held}, held.Kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, atReload []signingkey.Record) {
				assert.True(t, publishes(km, atReload[0].Kid),
					"the arriving key is within its lifetime, so it is published")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := newClock()
			atStart, atReload, current := tc.listed(t)
			store := &listingStore{recs: atStart}

			km, err := signingkey.New(t.Context(),
				signingkey.WithKeyStore(store),
				signingkey.WithClock(clk),
				signingkey.WithReloadInterval(10*time.Second),
				signingkey.WithRotateInterval(time.Hour),
				signingkey.WithHousekeepingInterval(12*time.Hour),
				signingkey.WithKeyLifetime(24*time.Hour),
			)
			require.NoError(t, err)
			stopAndVerify(t, km)
			require.Equal(t, current, currentKid(t, km, signingkey.RS256),
				"construction gives the tie to the key the store lists later")

			// Replaced before Start, so no loop reads the store concurrently.
			store.recs = atReload
			require.NoError(t, km.Start(t.Context()))

			advance(t, clk, 10*time.Second, loopCount)
			assert.Equal(t, current, currentKid(t, km, signingkey.RS256),
				"a reload gives the tie to the key the store lists later")
			tc.assert(t, km, atReload)
			assert.Zero(t, store.stored, "nothing is minted")
		})
	}
}

// TestForeignAlgorithmKeysVerifyButNeverSign pins where the configured
// algorithms bind. Two replicas may share a store while being configured
// differently, so the store holds keys for algorithms this manager was never
// asked about.
//
// Publishing them is useful: it is what lets this replica verify the other's
// tokens. Signing with them is not: SupportedAlgs would deny the algorithm
// while Signer handed out a working key for it, and a foreign key made
// current would be exempt from housekeeping for as long as the process lived.
// Standalone: its store holds keys of an algorithm the manager was not configured with.
func TestForeignAlgorithmKeysVerifyButNeverSign(t *testing.T) {
	clk := newClock()
	store := signingkey.NewMemoryKeyStore()

	// A replica configured for ES256 shares the store: one key already past
	// the lifetime, one exactly at it, which passes it one second in, and one
	// well inside it.
	expired := realRecordFor(t, signingkey.ES256, epoch.Add(-25*time.Hour))
	stale := realRecordFor(t, signingkey.ES256, epoch.Add(-24*time.Hour))
	fresh := realRecordFor(t, signingkey.ES256, epoch)
	require.NoError(t, store.Store(t.Context(), expired))
	require.NoError(t, store.Store(t.Context(), stale))
	require.NoError(t, store.Store(t.Context(), fresh))

	// This manager is configured for RS256 only.
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.RS256),
		signingkey.WithKeyLifetime(24*time.Hour),
		signingkey.WithRotateInterval(6*time.Hour),
		signingkey.WithReloadInterval(30*time.Minute),
		signingkey.WithHousekeepingInterval(time.Second),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)

	require.Equal(t, []signingkey.Alg{signingkey.RS256}, km.SupportedAlgs())

	kid, signer, ok := km.Signer(signingkey.ES256)
	assert.False(t, ok, "Signer answers only for the configured algorithms")
	assert.Empty(t, kid)
	assert.Nil(t, signer)

	require.NotEmpty(t, currentKid(t, km, signingkey.RS256),
		"and the manager minted its own RS256 key rather than counting the stored ES256 one")

	require.True(t, publishes(km, fresh.Kid),
		"another replica's key is published, so the tokens it signed verify here")
	require.True(t, publishes(km, stale.Kid))
	require.False(t, publishes(km, expired.Kid),
		"a foreign key is never the newest of a configured algorithm, so construction "+
			"publishes none past its lifetime")

	require.NoError(t, km.Start(t.Context()))

	advance(t, clk, time.Second, loopCount)
	require.False(t, publishes(km, stale.Kid),
		"housekeeping retires a foreign key past its lifetime")
	require.True(t, publishes(km, fresh.Kid), "the one inside the lifetime is kept")

	// The newest foreign key is the one a current-key exemption would protect
	// for the life of the process.
	advance(t, clk, 25*time.Hour, loopCount)
	assert.False(t, publishes(km, fresh.Kid),
		"no foreign key is current, so none is exempt from housekeeping")

	_, _, ok = km.Signer(signingkey.ES256)
	assert.False(t, ok, "and none of it made the manager an ES256 signer")
}

// TestHousekeeping drives housekeeping under a controlled clock.
//
// The housekeeping interval is shorter than the reload and rotation intervals,
// so one small advance runs housekeeping and nothing else. That isolation is
// what makes the assertions falsifiable: a reload in the same advance would
// republish the current key, and so would mask housekeeping having dropped it.
//
// Every case waits for the expired non-current key to disappear before
// asserting anything else. That is the only observable proof that housekeeping
// ran, so a claim about what it kept cannot pass merely because nothing
// happened.
//
// Construction publishes no non-current key already past its lifetime, so the
// key the case waits on is created exactly one lifetime before the start: still
// within the lifetime when the manager is built, past it one second later.
// Standalone: each case seeds a key that expires one second in, which the loop waits on.
func TestHousekeeping(t *testing.T) {
	type testCase struct {
		name string
		// seed returns the stored keys, oldest first. The last one is the
		// current key, and the first is the non-current key the case waits on,
		// which expires one second in.
		seed   func(t *testing.T) []signingkey.Record
		assert func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, current string)
	}

	cases := []testCase{
		{
			name: "a non-current key past its lifetime stops being published",
			seed: func(t *testing.T) []signingkey.Record {
				return []signingkey.Record{
					realRecord(t, epoch.Add(-24*time.Hour)),
					realRecord(t, epoch),
				}
			},
			assert: func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, current string) {
				assert.True(t, publishes(km, current), "the current key is untouched")
				assert.Equal(t, current, currentKid(t, km, signingkey.RS256))

				recs, err := store.LoadAll(t.Context())
				require.NoError(t, err)
				assert.Len(t, recs, 2,
					"housekeeping stops publishing a key; it does not prune the store")
			},
		},
		{
			name: "the current key is kept however old it is",
			seed: func(t *testing.T) []signingkey.Record {
				// Rotation is six hours away, so the newest stored key is
				// still current once it is past its lifetime. The two are
				// created at the same instant, and the tie goes to the one the
				// store lists later; an older non-current key would never be
				// published at all.
				return []signingkey.Record{
					realRecord(t, epoch.Add(-24*time.Hour)),
					realRecord(t, epoch.Add(-24*time.Hour)),
				}
			},
			assert: func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore, current string) {
				assert.True(t, publishes(km, current),
					"a current key past its lifetime is still published")
				assert.Equal(t, current, currentKid(t, km, signingkey.RS256),
					"and is still the key that signs")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := newClock()
			store := signingkey.NewMemoryKeyStore()
			seed := tc.seed(t)
			for _, rec := range seed {
				require.NoError(t, store.Store(t.Context(), rec))
			}

			km, err := signingkey.New(t.Context(),
				signingkey.WithKeyStore(store),
				signingkey.WithClock(clk),
				signingkey.WithKeyLifetime(24*time.Hour),
				signingkey.WithHousekeepingInterval(time.Second),
				signingkey.WithReloadInterval(30*time.Minute),
				signingkey.WithRotateInterval(6*time.Hour),
			)
			require.NoError(t, err)
			stopAndVerify(t, km)

			expired, current := seed[0].Kid, seed[len(seed)-1].Kid
			require.Equal(t, current, currentKid(t, km, signingkey.RS256))
			require.True(t, publishes(km, expired),
				"a key exactly one lifetime old is published to begin with")

			require.NoError(t, km.Start(t.Context()))

			advance(t, clk, time.Second, loopCount)
			require.False(t, publishes(km, expired),
				"housekeeping should have stopped publishing the expired key")

			tc.assert(t, km, store, current)
		})
	}
}

// TestHousekeepingAndRotationNeverDeadlock runs rotation and housekeeping
// together, over and over. Housekeeping takes the keyring lock itself, so being
// called while rotation held that lock would deadlock; the loops would then
// never park again, and the bounded wait for them is what turns that into a
// failure instead of a hang.
// Standalone: it runs rotation and housekeeping at the same interval.
func TestHousekeepingAndRotationNeverDeadlock(t *testing.T) {
	clk := newClock()
	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithHousekeepingInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithKeyLifetime(2*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)

	require.NoError(t, km.Start(t.Context()))

	kid := currentKid(t, km, signingkey.EdDSA)
	for round := range 12 {
		advance(t, clk, time.Hour, loopCount)
		next := currentKid(t, km, signingkey.EdDSA)
		require.NotEqual(t, kid, next, "round %d rotates", round)
		kid = next
	}

	keys, err := km.VerificationKeys()
	require.NoError(t, err)
	assert.LessOrEqual(t, len(keys), 3,
		"keys past the 2-hour lifetime stopped being published as the rounds went by")
}

// TestHousekeepingKeepsAKeyUntilItHasOutlivedTheLifetime pins the boundary
// itself. A key is published for the lifetime it was given, so one whose age is
// exactly that lifetime is still published, and one any older is not.
//
// The interval is what makes the boundary reachable: the sweep that runs at
// epoch+1s is the one that sees boundary at exactly 24 hours old. stale is an
// hour further on and is the case's proof that the sweep ran at all.
// Standalone: it seeds a key already past its lifetime, which TestHousekeeping's loop would require published.
func TestHousekeepingKeepsAKeyUntilItHasOutlivedTheLifetime(t *testing.T) {
	const (
		lifetime = 24 * time.Hour
		sweep    = time.Second
	)

	clk := newClock()
	store := signingkey.NewMemoryKeyStore()

	stale := realRecord(t, epoch.Add(sweep-lifetime-time.Hour))
	boundary := realRecord(t, epoch.Add(sweep-lifetime))
	newest := realRecord(t, epoch)
	for _, rec := range []signingkey.Record{stale, boundary, newest} {
		require.NoError(t, store.Store(t.Context(), rec))
	}

	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithKeyLifetime(lifetime),
		signingkey.WithHousekeepingInterval(sweep),
		signingkey.WithReloadInterval(30*time.Minute),
		signingkey.WithRotateInterval(6*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)

	require.Equal(t, newest.Kid, currentKid(t, km, signingkey.RS256))
	require.NoError(t, km.Start(t.Context()))

	advance(t, clk, sweep, loopCount)
	require.False(t, publishes(km, stale.Kid),
		"the sweep ran: a key an hour past its lifetime stopped being published")
	assert.True(t, publishes(km, boundary.Kid),
		"a key whose age is exactly the lifetime has not outlived it")

	advance(t, clk, sweep, loopCount)
	assert.False(t, publishes(km, boundary.Kid), "and one a sweep older has")
	assert.True(t, publishes(km, newest.Kid), "the current key is kept throughout")
}

// steppedClock is a controlled clock whose reading can be stepped back, as a
// host clock corrected by NTP is. Its waits still run on the fake clock, so a
// test advances the loops as usual.
type steppedClock struct {
	*clockwork.FakeClock
	back atomic.Int64 // nanoseconds subtracted from every reading
}

func (c *steppedClock) Now() time.Time {
	return c.FakeClock.Now().Add(-time.Duration(c.back.Load()))
}

// TestHousekeep_RetiresFarFutureKey pins that a held key now dated more than
// one lifetime ahead stops being published. A key that far ahead would
// otherwise never age out, so it would verify tokens forever.
// Standalone: its clock's reading steps back two days.
func TestHousekeep_RetiresFarFutureKey(t *testing.T) {
	clk := &steppedClock{FakeClock: newClock()}
	store := signingkey.NewMemoryKeyStore()
	ahead := realRecord(t, epoch.Add(-time.Hour))
	current := realRecord(t, epoch)
	require.NoError(t, store.Store(t.Context(), ahead))
	require.NoError(t, store.Store(t.Context(), current))

	km, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithKeyLifetime(24*time.Hour),
		signingkey.WithHousekeepingInterval(time.Second),
		signingkey.WithReloadInterval(30*time.Minute),
		signingkey.WithRotateInterval(6*time.Hour),
	)
	require.NoError(t, err)
	stopAndVerify(t, km)
	require.True(t, publishes(km, ahead.Kid), "the non-current key is published to begin with")
	require.NoError(t, km.Start(t.Context()))

	// The clock steps back two days: the non-current key is now dated nearly
	// two days ahead, more than one lifetime.
	clk.back.Store(int64(48 * time.Hour))
	advance(t, clk.FakeClock, time.Second, loopCount)

	assert.False(t, publishes(km, ahead.Kid),
		"a non-current key dated more than one lifetime ahead stops being published")
	assert.True(t, publishes(km, current.Kid), "the current key is kept")
	assert.Equal(t, current.Kid, currentKid(t, km, signingkey.RS256))
}
