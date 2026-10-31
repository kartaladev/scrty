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

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/token/signingkey"
)

// epoch is the instant every controlled-clock test starts at.
var epoch = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

// loopCount is how many background loops one started manager runs: rotation,
// reload and housekeeping, each parked on its own After between runs.
const loopCount = 3

// parkTimeout bounds how long a test waits for the loops to park on the
// controlled clock. It is a failure bound, never a way of synchronising: every
// wait returns the moment the loops have parked, and only a loop that never
// parks — one not driven by the clock at all — waits it out.
const parkTimeout = 10 * time.Second

// newClock returns a controlled clock at epoch. Its time moves only when a
// test advances it, and advancing it fires every After that has come due.
func newClock() *clockwork.FakeClock { return clockwork.NewFakeClockAt(epoch) }

// awaitParked returns once n Afters are pending on clk, which for a started
// manager is the proof that its loops are waiting for their next interval.
// Every Advance must be preceded by it: advancing before a loop has asked for
// its After would move time past an interval the loop never saw begin.
func awaitParked(t *testing.T, clk *clockwork.FakeClock, n int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), parkTimeout)
	defer cancel()
	require.NoError(t, clk.BlockUntilContext(ctx, n),
		"%d background loops should be parked on the clock", n)
}

// advance moves clk on by d once n loops are parked, and returns once they are
// parked again. A loop re-parks only after its run has finished, so on return
// every run the advance started has completed, and a test can assert on what
// it did without polling.
func advance(t *testing.T, clk *clockwork.FakeClock, d time.Duration, n int) {
	t.Helper()

	awaitParked(t, clk, n)
	clk.Advance(d)
	awaitParked(t, clk, n)
}

// currentKid returns the kid currently signing for alg, requiring there to be
// one.
func currentKid(t *testing.T, km *signingkey.Keys, alg signingkey.Alg) string {
	t.Helper()

	kid, signer, ok := km.Signer(alg)
	require.True(t, ok, "there is a current %s key", alg)
	require.NotNil(t, signer, "the current %s key signs", alg)
	return kid
}

// shutdownAndVerify shuts km down at the end of the test and reports any
// goroutine it left behind. It snapshots the goroutines running now, so it
// must be called before the manager is started — which is also when the
// manager has started none of its own.
//
// The work a manager starts outlives the test's context, which is cancelled
// before cleanups run, so the shutdown is what ends it.
func shutdownAndVerify(t *testing.T, km *signingkey.Keys) {
	t.Helper()

	ignore := goleak.IgnoreCurrent()
	t.Cleanup(func() {
		shutdownWithin(t, km, parkTimeout, "the manager's work should end once shut down")
		goleak.VerifyNone(t, ignore)
	})
}

// shutdownWithin shuts km down under a context bounded by bound, and fails the
// test if Shutdown returns an error or does not return at all. A Shutdown that
// cannot return is the failure being tested for, so it must show up as a
// failed assertion rather than as a hung package. It is safe in a cleanup.
func shutdownWithin(t *testing.T, km *signingkey.Keys, bound time.Duration, why string) {
	t.Helper()

	// t.Context is already cancelled when a cleanup runs; the shutdown keeps
	// its values but not that cancellation.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), bound)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- km.Shutdown(ctx) }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(bound + time.Second):
		t.Fatalf("Shutdown did not return within %s: %s", bound, why)
	}
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

// errRedactionFixture is the dependency error every diagnostic-redaction
// reproduction in this change quotes: a username and a user reference the
// library never saw, which no record may carry.
var errRedactionFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// listingStore returns records in the order it was given them, whatever their
// creation times. A conforming store may do this — for instance a decorating
// store that re-reads its backing rows — and the key manager must not depend on
// the order.
type listingStore struct {
	recs   []signingkey.Record
	stored int
}

func (s *listingStore) Store(_ context.Context, rec signingkey.Record) error {
	s.stored++
	s.recs = append(s.recs, rec)
	return nil
}

func (s *listingStore) LoadAll(context.Context) ([]signingkey.Record, error) {
	return s.recs, nil
}

// realRecordFor returns a genuine record for alg, created at the given time. It
// is minted by a throwaway manager so the private bytes and the thumbprint are
// real: only CreatedAt is rewritten. It is how a test stands in for another
// replica that wrote to the same store.
func realRecordFor(t *testing.T, alg signingkey.Alg, createdAt time.Time) signingkey.Record {
	t.Helper()

	store := signingkey.NewMemoryKeyStore()
	_, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithAlgs(alg),
	)
	require.NoError(t, err)

	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)
	require.Len(t, recs, 1)

	rec := recs[0]
	rec.CreatedAt = createdAt
	return rec
}

// realRecord returns a genuine RS256 record, created at the given time, which
// is the algorithm every default-configured test runs on.
func realRecord(t *testing.T, createdAt time.Time) signingkey.Record {
	t.Helper()

	return realRecordFor(t, signingkey.RS256, createdAt)
}

// signWithCurrent issues a real EdDSA JWS with the source's current key, so a
// test can check that another replica, or another implementation of the port,
// is able to verify it.
func signWithCurrent(t *testing.T, source signingkey.KeySource, payload string) []byte {
	t.Helper()

	kid, signer, ok := source.Signer(signingkey.EdDSA)
	require.True(t, ok)

	private, err := jwk.Import[jwk.Key](signer)
	require.NoError(t, err)
	require.NoError(t, private.Set(jwk.KeyIDKey, kid))

	signature, err := jws.Sign([]byte(payload), jws.WithKey(jwa.EdDSA(), private))
	require.NoError(t, err)
	return signature
}

// publishes reports whether source publishes kid. It takes the port rather
// than the manager so a consumer's own key source can be asked the same
// question, and it is safe to call from a polling closure: keys that cannot
// be obtained count as not publishing it.
func publishes(source signingkey.KeySource, kid string) bool {
	keys, err := source.VerificationKeys()
	if err != nil {
		return false
	}

	for _, key := range keys {
		if key.Kid == kid {
			return true
		}
	}

	return false
}

// publishedSet renders what source publishes as the key set the JOSE stack
// verifies against, the way a consumer that speaks JOSE would.
//
// It lives in the tests because the package itself no longer builds one:
// KeySource describes its keys with standard-library types, so turning them
// into a JOSE library's own is the job of whatever needs that library.
func publishedSet(t *testing.T, source signingkey.KeySource) jwk.Set {
	t.Helper()

	published, err := source.VerificationKeys()
	require.NoError(t, err)

	set := jwk.NewSet()
	for _, pk := range published {
		key, importErr := jwk.Import[jwk.Key](pk.Key)
		require.NoError(t, importErr)
		require.NoError(t, key.Set(jwk.KeyIDKey, pk.Kid))
		require.NoError(t, key.Set(jwk.AlgorithmKey, pk.Alg))
		require.NoError(t, key.Set(jwk.KeyUsageKey, string(jwk.ForSignature)))
		require.NoError(t, set.AddKey(key))
	}

	return set
}

func auditAlg(t *testing.T, alg signingkey.Alg) jwa.SignatureAlgorithm {
	t.Helper()
	a, ok := jwa.LookupSignatureAlgorithm(alg)
	require.True(t, ok)
	return a
}
