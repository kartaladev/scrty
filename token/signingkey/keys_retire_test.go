// The retire-time tests are not parallel, for the reason the lifecycle tests are
// not: goleak counts goroutines process-wide.
package signingkey_test

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// A key lifetime and a rotation interval no row changes without saying so: the
// library's defaults, so the arithmetic in the rows is the one a consumer who
// configures nothing gets.
const (
	retireLifetime = 24 * time.Hour
	retireRotation = time.Hour
	// retireReload is the margin a retire time carries past the window.
	retireReload = time.Minute
	// retireWindow is the longest a token may live under them.
	retireWindow = retireLifetime - retireRotation
)

// retireOptions is what every retire-time row runs on. One second runs
// housekeeping and nothing else, since reload and rotation are far longer.
func retireOptions(clk clock.Timed, store signingkey.KeyStore) []signingkey.Option {
	return []signingkey.Option{
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithKeyLifetime(retireLifetime),
		signingkey.WithRotateInterval(retireRotation),
		signingkey.WithReloadInterval(retireReload),
		signingkey.WithHousekeepingInterval(time.Second),
	}
}

// retireFixture is one row's clock and store.
type retireFixture struct {
	clk *clockwork.FakeClock
	mem *signingkey.MemoryKeyStore
}

// seed stores keys of alg created at the offsets from the epoch, in order.
func (f *retireFixture) seed(t *testing.T, alg signingkey.Alg, offsets ...time.Duration) []signingkey.Record {
	t.Helper()

	recs := make([]signingkey.Record, 0, len(offsets))
	for _, offset := range offsets {
		rec := realRecordFor(t, alg, epoch.Add(offset))
		require.NoError(t, f.mem.Store(t.Context(), rec))
		recs = append(recs, rec)
	}

	return recs
}

// start builds a manager over the fixture's store and runs its loops.
func (f *retireFixture) start(t *testing.T, opts ...signingkey.Option) *signingkey.Keys {
	t.Helper()

	km, err := signingkey.New(t.Context(), append(retireOptions(f.clk, f.mem), opts...)...)
	require.NoError(t, err)
	shutdownAndVerify(t, km)
	require.NoError(t, km.Start(t.Context()))

	return km
}

// run advances the clock by d with the loops parked, and returns once they have
// parked again.
func (f *retireFixture) run(t *testing.T, d time.Duration) {
	t.Helper()

	advance(t, f.clk, d, loopCount)
}

// restart builds a second manager over the store at the clock's present reading,
// never started, which is what a replica just restarted publishes.
func (f *retireFixture) restart(t *testing.T, opts ...signingkey.Option) *signingkey.Keys {
	t.Helper()

	km, err := signingkey.New(t.Context(),
		append(retireOptions(clockwork.NewFakeClockAt(f.clk.Now()), f.mem), opts...)...)
	require.NoError(t, err)

	return km
}

// heldKids is what km publishes, by kid.
func heldKids(t *testing.T, km *signingkey.Keys) []string {
	t.Helper()

	keys, err := km.VerificationKeys(t.Context())
	require.NoError(t, err)

	kids := make([]string, 0, len(keys))
	for _, key := range keys {
		kids = append(kids, key.Kid)
	}

	return kids
}

// signToken issues a real token through the real generator, at the clock's reading,
// with the given lifetime. Its construction also proves the lifetime is one
// token's window accepts for that source.
func signToken(t *testing.T, keys signingkey.KeySource, clk clock.Clock, lifetime time.Duration) string {
	t.Helper()

	generator, err := token.NewGenerator(keys,
		token.WithSigningAlg(signingkey.EdDSA),
		token.WithClock(clk),
		token.WithTokenLifetime(lifetime),
		token.WithoutIssuer(), token.WithoutAudience())
	require.NoError(t, err)

	issued, err := generator.Generate(t.Context(), "jti-1", &identity.Principal{ID: "u-1", Username: "alice"})
	require.NoError(t, err)

	return issued
}

// verifyToken verifies a token through the real verifier, at the clock's reading.
func verifyToken(t *testing.T, keys signingkey.KeySource, clk clock.Clock, issued string) error {
	t.Helper()

	verifier, err := token.NewVerifier(
		token.WithVerifyKeySource(keys), token.WithVerifyClock(clk),
		token.WithoutVerifyIssuer(), token.WithoutVerifyAudience())
	require.NoError(t, err)

	_, err = verifier.Verify(t.Context(), issued)

	return err
}

// signedBy issues a token at the instant at with rec's own private key, for a
// row that needs a token signed before its manager existed. The holder is what
// the process that signed it was: a manager whose only key is rec.
func signedBy(t *testing.T, rec signingkey.Record, at time.Time, lifetime time.Duration) string {
	t.Helper()

	clk := clockwork.NewFakeClockAt(at)
	holder, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(&listingStore{recs: []signingkey.Record{rec}}),
		signingkey.WithClock(clk),
		signingkey.WithAlgs(rec.Alg),
	)
	require.NoError(t, err)
	require.Equal(t, rec.Kid, currentKid(t, holder, rec.Alg))

	return signToken(t, holder, clk, lifetime)
}

// refusableStore refuses writes while refuse is set, as a store through a
// rotation outage does.
type refusableStore struct {
	*signingkey.MemoryKeyStore

	refuse atomic.Bool
}

func (s *refusableStore) Store(ctx context.Context, rec signingkey.Record) error {
	if s.refuse.Load() {
		return errors.New("store refused the write")
	}

	return s.MemoryKeyStore.Store(ctx, rec)
}

// oneAtATimeStore deletes only the last kid each Delete names, as a store that
// fails partway through a delete would. The store lists oldest first, so a key
// goes before the keys older than it.
type oneAtATimeStore struct {
	*signingkey.MemoryKeyStore
}

func (s *oneAtATimeStore) Delete(ctx context.Context, kids ...string) error {
	if len(kids) == 0 {
		return nil
	}

	return s.MemoryKeyStore.Delete(ctx, kids[len(kids)-1])
}

// undecodable returns a record of alg created at the offset from the epoch whose
// bytes no manager can decode.
func undecodable(t *testing.T, alg signingkey.Alg, offset time.Duration) signingkey.Record {
	t.Helper()

	rec := realRecordFor(t, alg, epoch.Add(offset))
	rec.Kid += "-damaged"
	rec.Private = []byte("not a key")

	return rec
}

// startReplicas starts managers built on their own clocks over one store, and
// shuts them all down at the end before checking for leaks.
func startReplicas(t *testing.T, kms ...*signingkey.Keys) {
	t.Helper()

	ignore := goleak.IgnoreCurrent()
	t.Cleanup(func() {
		for _, km := range kms {
			shutdownWithin(t, km, parkTimeout, "a replica's work should end once shut down")
		}
		goleak.VerifyNone(t, ignore)
	})
	for _, km := range kms {
		require.NoError(t, km.Start(t.Context()))
	}
}

// TestRetireTime drives the one rule for when a key retires, and the grace before
// it leaves the store, through construction, reload, housekeeping and deletion. A
// row states what is published and what is stored, each read from the manager and
// the store rather than from the rule's arithmetic.
func TestRetireTime(t *testing.T) {
	type testCase struct {
		name   string
		assert func(t *testing.T, f *retireFixture)
	}

	// A row that needs a real token runs the rotation it is about, so the key,
	// the rotation and the token all come from the code under test.
	cases := []testCase{
		{
			name: "Key replaced late stays published",
			assert: func(t *testing.T, f *retireFixture) {
				stale := f.seed(t, signingkey.EdDSA, 0)[0]
				store := &refusableStore{MemoryKeyStore: f.mem}
				store.refuse.Store(true)
				_, logger := newLogRecorder()
				km, err := signingkey.New(t.Context(),
					append(retireOptions(f.clk, store), signingkey.WithLogger(logger))...)
				require.NoError(t, err)
				shutdownAndVerify(t, km)
				require.NoError(t, km.Start(t.Context()))

				f.run(t, 27*time.Hour) // the rotation at 27h fails, the next is due at 28h
				f.run(t, time.Hour-time.Second)
				require.Equal(t, stale.Kid, currentKid(t, km, signingkey.EdDSA), "it signs up to the rotation")
				// The last token it signs, with the longest lifetime the source
				// accepts: this is the claim that the second term is exact.
				issued := signToken(t, km, f.clk, retireWindow)

				store.refuse.Store(false)
				f.run(t, time.Second) // the rotation at 28h succeeds
				require.NotEqual(t, stale.Kid, currentKid(t, km, signingkey.EdDSA), "it has been replaced")

				f.run(t, 5*time.Minute)
				assert.True(t, publishes(t, km, stale.Kid), "still published five minutes after its replacement")
				assert.NoError(t, verifyToken(t, km, f.clk, issued), "and its token verifies")
				assert.Contains(t, storedKids(t, f.mem), stale.Kid)

				f.run(t, retireWindow-5*time.Minute-2*time.Second)
				assert.True(t, publishes(t, km, stale.Kid))
				assert.NoError(t, verifyToken(t, km, f.clk, issued), "a second before it expires, it still verifies")

				f.run(t, 2*time.Second)
				assert.True(t, publishes(t, km, stale.Kid), "exactly the window after its replacement, not before")

				f.run(t, retireReload)
				assert.True(t, publishes(t, km, stale.Kid), "and one reload interval on, which is its retire time")

				f.run(t, time.Second)
				assert.False(t, publishes(t, km, stale.Kid), "and a second later it is unpublished")
				assert.Contains(t, storedKids(t, f.mem), stale.Kid, "and waits out the grace in the store")
			},
		},
		{
			name: "A replica still signing before its reload",
			// Another replica replaces the key just after this one's last reload,
			// so this one goes on signing with it for a whole reload interval: a
			// token at the cap then lives to the end of the key's retire time.
			assert: func(t *testing.T, f *retireFixture) {
				const (
					lifetime = 24 * time.Hour
					rotation = 6 * time.Hour
					reload   = 30 * time.Minute
				)
				opts := []signingkey.Option{
					signingkey.WithKeyLifetime(lifetime),
					signingkey.WithRotateInterval(rotation),
					signingkey.WithReloadInterval(reload),
				}
				replaced := f.seed(t, signingkey.EdDSA, -rotation)[0]
				km := f.start(t, opts...)
				f.seed(t, signingkey.EdDSA, 0) // another replica's rotation, on time

				f.run(t, reload-time.Second)
				require.Equal(t, replaced.Kid, currentKid(t, km, signingkey.EdDSA), "it has not reloaded, so it still signs")
				issued := signToken(t, km, f.clk, lifetime-rotation) // expires a second before the retire time

				f.run(t, lifetime-rotation-2*time.Second)
				require.NotEqual(t, replaced.Kid, currentKid(t, km, signingkey.EdDSA), "it has reloaded since")
				f.run(t, time.Second) // a housekeeping run that knows it has been replaced
				assert.NoError(t, verifyToken(t, km, f.clk, issued), "the replica that signed it verifies it, a second before it expires")
				assert.NoError(t, verifyToken(t, f.restart(t, opts...), f.clk, issued), "and so does one restarted now")

				f.run(t, 2*time.Second) // exactly the retire time
				assert.True(t, publishes(t, km, replaced.Kid), "published at exactly its retire time")

				f.run(t, time.Second)
				assert.False(t, publishes(t, km, replaced.Kid), "and retired strictly after it")
			},
		},
		{
			name: "Key replaced late survives a restart",
			assert: func(t *testing.T, f *retireFixture) {
				replacedAt := epoch.Add(-5 * time.Minute)
				recs := f.seed(t, signingkey.EdDSA, -28*time.Hour-5*time.Minute, -5*time.Minute)
				stale := recs[0]
				issued := signedBy(t, stale, replacedAt.Add(-time.Second), retireWindow)

				km := f.start(t)

				assert.True(t, publishes(t, km, stale.Kid), "construction publishes it")
				assert.NoError(t, verifyToken(t, km, f.clk, issued), "and a token it signed before it was replaced verifies")

				f.run(t, time.Minute) // a housekeeping run and a reload do not undo it
				assert.True(t, publishes(t, km, stale.Kid))
				assert.NoError(t, verifyToken(t, km, f.clk, issued))
				assert.Contains(t, storedKids(t, f.mem), stale.Kid)
			},
		},
		{
			name: "A stale current key displaced by its rotation keeps verifying",
			// The review's TestRepro_DisplacedStaleCurrentKeyGoesWhileItsTokensAreLive.
			assert: func(t *testing.T, f *retireFixture) {
				stale := f.seed(t, signingkey.EdDSA, -25*time.Hour)[0]
				km := f.start(t)

				f.run(t, retireRotation-time.Second)
				require.Equal(t, stale.Kid, currentKid(t, km, signingkey.EdDSA), "it signs up to the rotation")
				issued := signToken(t, km, f.clk, retireWindow)

				f.run(t, time.Second) // the rotation
				f.run(t, time.Second) // the next housekeeping
				require.NotEqual(t, stale.Kid, currentKid(t, km, signingkey.EdDSA))

				assert.True(t, publishes(t, km, stale.Kid))
				assert.NoError(t, verifyToken(t, km, f.clk, issued))
			},
		},
		{
			name: "A key replaced on time retires one lifetime and one reload interval after its creation",
			// Successor created at created + rotation, so the two terms agree.
			assert: func(t *testing.T, f *retireFixture) {
				created := time.Second - retireLifetime - retireReload
				recs := f.seed(t, signingkey.EdDSA, created, created+retireRotation)
				replaced := recs[0]
				km := f.start(t)
				require.True(t, publishes(t, km, replaced.Kid))

				f.run(t, time.Second) // exactly its retire time
				assert.True(t, publishes(t, km, replaced.Kid), "it has not outlived the lifetime and the margin")

				f.run(t, time.Second)
				assert.False(t, publishes(t, km, replaced.Kid), "and a second later it has")
			},
		},
		{
			name: "A consumer's lifetime and rotation move the window",
			assert: func(t *testing.T, f *retireFixture) {
				// A 10-hour lifetime and 2-hour rotation: 8 hours from the replacement,
				// and the reload interval on top.
				late := f.seed(t, signingkey.EdDSA, -20*time.Hour, -time.Second)[0]
				km := f.start(t, signingkey.WithKeyLifetime(10*time.Hour), signingkey.WithRotateInterval(2*time.Hour))
				require.True(t, publishes(t, km, late.Kid), "published at construction")

				f.run(t, 8*time.Hour+retireReload-2*time.Second)
				assert.True(t, publishes(t, km, late.Kid))

				f.run(t, time.Second) // exactly its retire time
				assert.True(t, publishes(t, km, late.Kid))

				f.run(t, time.Second)
				assert.False(t, publishes(t, km, late.Kid))
			},
		},
		{
			name: "Future-dated key does not hold back retirement",
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.EdDSA, -25*time.Hour, -24*time.Hour, 365*24*time.Hour)
				old, current, ahead := recs[0], recs[1], recs[2]
				km := f.start(t)

				f.run(t, time.Second)

				assert.False(t, publishes(t, km, old.Kid), "the key is no longer published")
				assert.Equal(t, current.Kid, currentKid(t, km, signingkey.EdDSA))
				assert.False(t, publishes(t, km, ahead.Kid))
				assert.Contains(t, storedKids(t, f.mem), ahead.Kid, "and the future-dated key stays stored")
			},
		},
		{
			name: "Future-dated key does not hold back the newest key of an unconfigured algorithm",
			// Nothing else tells the bound's presence: a configured algorithm's
			// newest key is current, and an older one has a nearer successor.
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.ES256, -25*time.Hour, 365*24*time.Hour)
				km := f.start(t)

				assert.False(t, publishes(t, km, recs[0].Kid), "construction")
				f.run(t, time.Minute)
				assert.False(t, publishes(t, km, recs[0].Kid), "reload and housekeeping")
				assert.Contains(t, storedKids(t, f.mem), recs[0].Kid, "the guard on the newest stored key")
			},
		},
		{
			name: "A key dated exactly the reload interval ahead counts as a successor",
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.ES256, -25*time.Hour, time.Minute)
				km := f.restart(t)

				assert.True(t, publishes(t, km, recs[0].Kid))
			},
		},
		{
			name: "A key dated a moment past the reload interval does not count as a successor",
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.ES256, -25*time.Hour, time.Minute+time.Second)
				km := f.restart(t)

				assert.False(t, publishes(t, km, recs[0].Kid))
				assert.True(t, publishes(t, km, recs[1].Kid), "while it is itself published, within one lifetime")
			},
		},
		{
			name: "Retired key waits out its grace",
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.EdDSA, -25*time.Hour, -24*time.Hour)
				old := recs[0]
				km := f.start(t)

				f.run(t, time.Second)

				assert.False(t, publishes(t, km, old.Kid), "no longer published")
				assert.Contains(t, storedKids(t, f.mem), old.Kid, "and still in the key store")
				assert.False(t, publishes(t, f.restart(t), old.Kid), "and a restarted replica does not publish it")

				// It retired 59 minutes before the epoch, and the grace is one lifetime.
				f.run(t, 23*time.Hour+retireReload-time.Second)
				assert.Contains(t, storedKids(t, f.mem), old.Kid, "exactly one grace past its retire time, it is stored")

				f.run(t, time.Second)
				assert.NotContains(t, storedKids(t, f.mem), old.Kid, "and a second later it is gone")
			},
		},
		{
			name: "Old key removed",
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.EdDSA, -50*time.Hour, -49*time.Hour)
				km := f.start(t)

				f.run(t, time.Second)

				assert.False(t, publishes(t, km, recs[0].Kid))
				assert.Equal(t, []string{recs[1].Kid}, storedKids(t, f.mem), "no longer in the key store")
			},
		},
		{
			name: "Consumer sets the grace",
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.EdDSA, -25*time.Hour, -24*time.Hour)
				km := f.start(t, signingkey.WithRetiredKeyGrace(0))

				f.run(t, time.Second)

				assert.False(t, publishes(t, km, recs[0].Kid))
				assert.Equal(t, []string{recs[1].Kid}, storedKids(t, f.mem), "a grace of zero deletes at the retire time")
			},
		},
		{
			name: "A grace of zero leaves a key that has only reached its retire time",
			assert: func(t *testing.T, f *retireFixture) {
				created := time.Second - retireLifetime - retireReload
				recs := f.seed(t, signingkey.EdDSA, created, created+retireRotation)
				km := f.start(t, signingkey.WithRetiredKeyGrace(0))

				f.run(t, time.Second) // exactly its retire time

				assert.True(t, publishes(t, km, recs[0].Kid))
				assert.Contains(t, storedKids(t, f.mem), recs[0].Kid)

				f.run(t, time.Second)

				assert.False(t, publishes(t, km, recs[0].Kid))
				assert.NotContains(t, storedKids(t, f.mem), recs[0].Kid)
			},
		},
		{
			name: "A consumer's longer grace keeps a key the default would delete",
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.EdDSA, -50*time.Hour, -49*time.Hour)
				km := f.start(t, signingkey.WithRetiredKeyGrace(100*time.Hour))

				f.run(t, time.Second)

				assert.False(t, publishes(t, km, recs[0].Kid), "a grace delays the delete, not the unpublishing")
				assert.Contains(t, storedKids(t, f.mem), recs[0].Kid)
			},
		},
		{
			name: "The default grace follows a consumer's lifetime",
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.EdDSA, -27*time.Hour, -26*time.Hour)
				f.start(t,
					signingkey.WithKeyLifetime(10*time.Hour),
					signingkey.WithRotateInterval(2*time.Hour),
				)

				f.run(t, time.Second) // retired 17 hours ago, past a 10-hour grace

				assert.Equal(t, []string{recs[1].Kid}, storedKids(t, f.mem))
			},
		},
		{
			name: "An explicit grace given before WithKeyLifetime stands",
			// Retired at 4h59m before the epoch, on a 10-hour lifetime and a 2-hour
			// rotation: past this grace, and inside the 10 hours a default would be.
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.EdDSA, -15*time.Hour, -13*time.Hour, -time.Hour)
				f.start(t,
					signingkey.WithRetiredKeyGrace(time.Hour),
					signingkey.WithKeyLifetime(10*time.Hour),
					signingkey.WithRotateInterval(2*time.Hour),
				)

				f.run(t, time.Second)

				assert.NotContains(t, storedKids(t, f.mem), recs[0].Kid)
			},
		},
		{
			name: "Kept keys alone is no conflict",
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.EdDSA, -50*time.Hour, -49*time.Hour)
				km := f.start(t, signingkey.WithRetiredKeysKept())

				f.run(t, time.Second)

				assert.False(t, publishes(t, km, recs[0].Kid))
				assert.Contains(t, storedKids(t, f.mem), recs[0].Kid)
			},
		},
		{
			name: "A tie goes to the key listed later, as the successor of the one before it",
			assert: func(t *testing.T, f *retireFixture) {
				at := epoch.Add(-25 * time.Hour)
				first, second := realRecordFor(t, signingkey.EdDSA, at), realRecordFor(t, signingkey.EdDSA, at)
				late := realRecordFor(t, signingkey.EdDSA, epoch.Add(-5*time.Minute))
				km, err := signingkey.New(t.Context(), retireOptions(f.clk,
					&listingStore{recs: []signingkey.Record{first, second, late}})...)
				require.NoError(t, err)

				assert.False(t, publishes(t, km, first.Kid), "its successor is the key tied with it, replaced at once")
				assert.True(t, publishes(t, km, second.Kid), "that key's successor is the one that replaced it late")
				assert.Equal(t, late.Kid, currentKid(t, km, signingkey.EdDSA))
			},
		},
		{
			name: "A key and its successor both past their retire time: only the newest stays",
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.ES256, -60*time.Hour, -59*time.Hour, -58*time.Hour)
				f.start(t)

				f.run(t, time.Second)

				assert.Equal(t, []string{recs[2].Kid}, recordKids(mustLoad(t, f.mem, signingkey.ES256)))
			},
		},
		{
			name: "A current key whose successor appears only after a reload is never dropped",
			assert: func(t *testing.T, f *retireFixture) {
				stale := f.seed(t, signingkey.EdDSA, -30*time.Hour)[0]
				km := f.start(t)
				successor := record(t, 0) // another replica's rotation

				require.NoError(t, f.mem.Store(t.Context(), successor))
				f.run(t, time.Second)
				assert.Equal(t, stale.Kid, currentKid(t, km, signingkey.EdDSA), "a housekeeping run before the reload")
				assert.True(t, publishes(t, km, stale.Kid))

				f.run(t, time.Minute)
				assert.Equal(t, successor.Kid, currentKid(t, km, signingkey.EdDSA), "the reload makes the successor current")
				assert.True(t, publishes(t, km, stale.Kid), "and the replaced key keeps its window")
				f.run(t, time.Second)
				assert.True(t, publishes(t, km, stale.Kid), "through the next housekeeping too")
			},
		},
		{
			name: "A successor the store lists and no manager can decode holds its window steadily",
			// A reload skips the record and keeps going. If only the keys held
			// counted, housekeeping would drop the older key and the next reload
			// add it back, for as long as the record stayed damaged.
			assert: func(t *testing.T, f *retireFixture) {
				// With no successor, it reaches its retire time at the reload that
				// lists the record.
				older := f.seed(t, signingkey.ES256, -retireLifetime)[0]
				_, logger := newLogRecorder()
				km := f.start(t, signingkey.WithLogger(logger))
				require.True(t, publishes(t, km, older.Kid))

				require.NoError(t, f.mem.Store(t.Context(), undecodable(t, signingkey.ES256, 0)))
				f.run(t, time.Minute) // a reload lists the damaged record
				for range 3 {
					f.run(t, time.Second) // housekeeping alone
					assert.True(t, publishes(t, km, older.Kid), "housekeeping does not drop it")
					f.run(t, time.Minute) // both
					assert.True(t, publishes(t, km, older.Kid), "and a reload has nothing to restore")
				}
			},
		},
		{
			name: "A successor not yet reloaded republishes its predecessor once, and it then stays",
			// An unconfigured algorithm's newest key retires at creation plus
			// lifetime plus the margin, as the settled rule has it. A successor
			// appearing later shows its tokens may be live, so the reload brings it
			// back.
			assert: func(t *testing.T, f *retireFixture) {
				older := f.seed(t, signingkey.ES256, time.Second-retireLifetime-retireReload)[0]
				km := f.start(t)
				require.True(t, publishes(t, km, older.Kid))

				f.run(t, 2*time.Second)
				require.False(t, publishes(t, km, older.Kid), "no successor is known, so it has retired")

				successor := realRecordFor(t, signingkey.ES256, epoch)
				require.NoError(t, f.mem.Store(t.Context(), successor))

				f.run(t, time.Minute)
				assert.True(t, publishes(t, km, older.Kid), "the reload that lists its successor publishes it")
				for range 3 {
					f.run(t, time.Second)
					assert.True(t, publishes(t, km, older.Kid), "and housekeeping now agrees")
				}
			},
		},
		{
			name: "A key whose successor went through the store's own deletion is not published again",
			// A store failing partway through a delete takes a key before the
			// ones older than it. The first chain's second key was replaced late,
			// so its deletion would, if it came early, bring the first key back.
			assert: func(t *testing.T, f *retireFixture) {
				for _, chain := range [][]time.Duration{
					{-100 * time.Hour, -90 * time.Hour, -70 * time.Hour, -time.Hour},
					{-100 * time.Hour, -99 * time.Hour, -98 * time.Hour, -97 * time.Hour},
					{-60 * time.Hour, -50 * time.Hour, -time.Hour},
					{-60 * time.Hour, -50 * time.Hour, -40 * time.Hour, -30 * time.Hour, -time.Hour},
				} {
					mem := signingkey.NewMemoryKeyStore()
					own := &retireFixture{clk: clockwork.NewFakeClockAt(f.clk.Now()), mem: mem}
					own.seed(t, signingkey.EdDSA, chain...)
					before := heldKids(t, own.restart(t))

					km, err := signingkey.New(t.Context(), append(
						retireOptions(own.clk, &oneAtATimeStore{MemoryKeyStore: mem}),
						signingkey.WithRetiredKeyGrace(0))...)
					require.NoError(t, err)
					startReplicas(t, km)

					for range len(chain) {
						own.run(t, time.Second)
						after := own.restart(t, signingkey.WithRetiredKeyGrace(0))
						for _, kid := range heldKids(t, after) {
							assert.Contains(t, before, kid,
								"chain %v: no key returns to the published set as those after it go", chain)
						}
					}
				}
			},
		},
		{
			name: "A retired key of an unconfigured algorithm comes back for one window when a far-future key's date arrives",
			// The accepted limit in the package documentation: the newest-key guard
			// kept it in the store, and from then on it has a successor, so its tokens
			// may be live.
			assert: func(t *testing.T, f *retireFixture) {
				const ahead = 365 * 24 * time.Hour
				recs := f.seed(t, signingkey.ES256, -25*time.Hour, ahead)
				retired := recs[0]
				km := f.start(t)

				f.run(t, time.Second)
				require.False(t, publishes(t, km, retired.Kid), "retired, since the far-future key does not count")
				require.Contains(t, storedKids(t, f.mem), retired.Kid, "and kept by the guard on the newest stored key")

				f.run(t, ahead) // the date arrives, and a reload sees it
				assert.True(t, publishes(t, km, retired.Kid), "the reload publishes it again")
				assert.True(t, publishes(t, f.restart(t), retired.Kid), "and so does a restarted replica")

				f.run(t, retireWindow+retireReload-time.Second) // exactly its new retire time
				assert.True(t, publishes(t, km, retired.Kid), "for one window and the margin")

				f.run(t, time.Second)
				assert.False(t, publishes(t, km, retired.Kid), "and no longer")
				assert.False(t, publishes(t, f.restart(t), retired.Kid))
			},
		},
		{
			name: "A reload does not take a listed key for the newest while a newer one is held",
			// The newest key of its algorithm is published whatever its age, so a
			// reload that saw only the listing would publish this key, which has
			// retired behind the key this replica holds. The store is one restored
			// from an older backup.
			assert: func(t *testing.T, f *retireFixture) {
				held := f.seed(t, signingkey.EdDSA, -50*time.Hour)[0]
				km := f.start(t)
				restored := f.seed(t, signingkey.EdDSA, -100*time.Hour)[0]
				require.NoError(t, f.mem.Delete(t.Context(), held.Kid))

				f.run(t, retireReload)

				assert.False(t, publishes(t, km, restored.Kid), "it has long retired")
				assert.Equal(t, held.Kid, currentKid(t, km, signingkey.EdDSA))
			},
		},
		{
			name: "A reload counts a held key the listing lacks as a listed key's successor",
			// As above, for an unconfigured algorithm, whose older key has a window
			// only through the key this replica holds.
			assert: func(t *testing.T, f *retireFixture) {
				held := f.seed(t, signingkey.ES256, -5*time.Minute)[0]
				km := f.start(t)
				restored := f.seed(t, signingkey.ES256, -30*time.Hour)[0]
				require.NoError(t, f.mem.Delete(t.Context(), held.Kid))

				f.run(t, retireReload)

				assert.True(t, publishes(t, km, restored.Kid), "replaced five minutes ago, as far as this replica knows")
				assert.True(t, publishes(t, km, held.Kid), "and the held key stays within its retire time")
			},
		},
		{
			name: "Deletion judges a key's successor from the listing alone",
			// A key removed by hand is no successor to what is stored, whatever this
			// replica still holds. If it counted, the oldest key would go now, on a
			// retire time the store's own contents do not give it.
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.EdDSA, -100*time.Hour, -99*time.Hour, -time.Hour)
				oldest, removed := recs[0], recs[1]
				km := f.start(t)
				require.True(t, publishes(t, km, removed.Kid), "held, replaced an hour ago")
				require.NoError(t, f.mem.Delete(t.Context(), removed.Kid))

				f.run(t, time.Second)

				assert.Contains(t, storedKids(t, f.mem), oldest.Kid)
			},
		},
		{
			name: "A lifetime barely longer than the rotation leaves another replica's current key until its reload",
			// The tightest configuration New accepts: a token lives a second, and a
			// grace of zero deletes at the retire time. The margin is all that stands
			// between the delete and a replica that has not reloaded yet.
			assert: func(t *testing.T, f *retireFixture) {
				const (
					lifetime = 10*time.Minute + time.Second
					rotation = 10 * time.Minute
				)
				opts := []signingkey.Option{
					signingkey.WithKeyLifetime(lifetime),
					signingkey.WithRotateInterval(rotation),
					signingkey.WithRetiredKeyGrace(0),
				}
				replaced := f.seed(t, signingkey.EdDSA, -rotation)[0]
				behind, err := signingkey.New(t.Context(), append(retireOptions(f.clk, f.mem), opts...)...)
				require.NoError(t, err)
				f.seed(t, signingkey.EdDSA, 0) // another replica's rotation, on time
				ahead, err := signingkey.New(t.Context(), append(retireOptions(f.clk, f.mem), opts...)...)
				require.NoError(t, err)
				startReplicas(t, behind, ahead)
				both := func(d time.Duration) { advance(t, f.clk, d, 2*loopCount) }

				both(2 * time.Second) // housekeeping, past the second term without the margin
				both(retireReload - 3*time.Second)
				require.Equal(t, replaced.Kid, currentKid(t, behind, signingkey.EdDSA), "it has not reloaded, so it still signs")
				assert.Contains(t, storedKids(t, f.mem), replaced.Kid, "the key it signs with stays in the store")
				issued := signToken(t, behind, f.clk, lifetime-rotation)
				assert.NoError(t, verifyToken(t, f.restart(t, opts...), f.clk, issued), "and a replica restarted now verifies its token")

				both(time.Second) // its reload
				require.NotEqual(t, replaced.Kid, currentKid(t, behind, signingkey.EdDSA))
				assert.Contains(t, storedKids(t, f.mem), replaced.Kid, "a second short of its retire time")

				both(time.Second) // exactly its retire time
				assert.Contains(t, storedKids(t, f.mem), replaced.Kid, "a grace of zero waits for a retire time to pass")

				both(time.Second)
				assert.NotContains(t, storedKids(t, f.mem), replaced.Kid)
			},
		},
		{
			name: "A clock stepping back past a replaced key's successor loses nothing for good",
			assert: func(t *testing.T, f *retireFixture) {
				stepped := &steppedClock{FakeClock: f.clk}
				recs := f.seed(t, signingkey.EdDSA, -30*time.Hour, -2*time.Hour, -time.Hour)
				replaced := recs[0]
				km, err := signingkey.New(t.Context(), retireOptions(stepped, f.mem)...)
				require.NoError(t, err)
				shutdownAndVerify(t, km)
				require.NoError(t, km.Start(t.Context()))
				require.True(t, publishes(t, km, replaced.Kid))

				stepped.back.Store(int64(3 * time.Hour)) // neither newer key counts now
				f.run(t, time.Second)                    // housekeeping alone, before any reload

				assert.Len(t, storedKids(t, f.mem), 3, "nothing leaves the store")

				f.run(t, time.Minute) // the reload

				assert.Equal(t, replaced.Kid, currentKid(t, km, signingkey.EdDSA),
					"the only key not dated ahead is the one a reload picks")
				assert.True(t, publishes(t, km, replaced.Kid))
				assert.Len(t, storedKids(t, f.mem), 3, "and nothing leaves the store")

				stepped.back.Store(0)
				f.run(t, time.Minute)

				assert.Equal(t, recs[2].Kid, currentKid(t, km, signingkey.EdDSA))
				assert.True(t, publishes(t, km, replaced.Kid), "its successor counts again, and so does its window")
			},
		},
		{
			name: "Replica with a fast clock leaves keys in place",
			// The review's TestRepro_FastClockReplicaDeletesKeyStillSigningElsewhere.
			assert: func(t *testing.T, f *retireFixture) {
				fastClk := clockwork.NewFakeClockAt(f.clk.Now().Add(19 * time.Hour))
				correct, err := signingkey.New(t.Context(), retentionOptions(f.clk, f.mem)...)
				require.NoError(t, err)
				fast, err := signingkey.New(t.Context(), retentionOptions(fastClk, f.mem)...)
				require.NoError(t, err)
				startReplicas(t, correct, fast)

				advance(t, f.clk, 6*time.Hour, loopCount)
				advance(t, fastClk, 6*time.Hour, loopCount)
				signing := currentKid(t, correct, signingkey.EdDSA)
				advance(t, f.clk, 5*time.Hour+30*time.Minute, loopCount) // half an hour before the next rotation
				advance(t, fastClk, 5*time.Hour+30*time.Minute, loopCount)
				require.Equal(t, signing, currentKid(t, correct, signingkey.EdDSA), "it still signs")
				issued := signToken(t, correct, f.clk, 18*time.Hour)

				assert.Contains(t, storedKids(t, f.mem), signing, "the key it signs with stays in the store")
				restarted, err := signingkey.New(t.Context(),
					retentionOptions(clockwork.NewFakeClockAt(f.clk.Now()), f.mem)...)
				require.NoError(t, err)
				assert.True(t, publishes(t, restarted, signing), "a restarted replica publishes it")
				assert.NoError(t, verifyToken(t, restarted, f.clk, issued))
			},
		},
		{
			name: "Replica with a fast clock leaves a key with live tokens in place",
			assert: func(t *testing.T, f *retireFixture) {
				// Created 23 hours ago, replaced on time, a token signed just
				// before that lives another hour less a second.
				recs := f.seed(t, signingkey.EdDSA, -23*time.Hour, -22*time.Hour, -time.Hour)
				issued := signedBy(t, recs[0], epoch.Add(-22*time.Hour-time.Second), retireWindow)
				fastClk := clockwork.NewFakeClockAt(epoch.Add(19 * time.Hour))
				fast, err := signingkey.New(t.Context(), retireOptions(fastClk, f.mem)...)
				require.NoError(t, err)
				startReplicas(t, fast)

				advance(t, fastClk, time.Second, loopCount)

				assert.Contains(t, storedKids(t, f.mem), recs[0].Kid)
				restarted := f.restart(t)
				assert.True(t, publishes(t, restarted, recs[0].Kid))
				assert.NoError(t, verifyToken(t, restarted, f.clk, issued))
			},
		},
		{
			name: "Replica with a slow clock leaves its key in place",
			// The review's TestRepro_SlowClockReplicasSigningKeyDeleted.
			assert: func(t *testing.T, f *retireFixture) {
				slowClk := clockwork.NewFakeClockAt(f.clk.Now().Add(-19 * time.Hour))
				correct, err := signingkey.New(t.Context(), retentionOptions(f.clk, f.mem)...)
				require.NoError(t, err)
				slow, err := signingkey.New(t.Context(), retentionOptions(slowClk, f.mem)...)
				require.NoError(t, err)
				signing := currentKid(t, slow, signingkey.EdDSA)
				require.NotEqual(t, signing, currentKid(t, correct, signingkey.EdDSA))
				startReplicas(t, correct, slow)

				advance(t, f.clk, 5*time.Hour+30*time.Minute, loopCount)
				advance(t, slowClk, 5*time.Hour+30*time.Minute, loopCount)

				require.Equal(t, signing, currentKid(t, slow, signingkey.EdDSA), "it still signs")
				assert.Contains(t, storedKids(t, f.mem), signing, "the key it signs with stays in the store")
				restarted, err := signingkey.New(t.Context(),
					retentionOptions(clockwork.NewFakeClockAt(f.clk.Now()), f.mem)...)
				require.NoError(t, err)
				assert.True(t, publishes(t, restarted, signing), "and a replica restarted afterwards can load it")
			},
		},
		{
			name: "Replica with a shorter lifetime",
			assert: func(t *testing.T, f *retireFixture) {
				recs := f.seed(t, signingkey.EdDSA, -40*time.Hour, -34*time.Hour, -28*time.Hour)
				short, err := signingkey.New(t.Context(), retentionOptions(f.clk, f.mem)...)
				require.NoError(t, err)
				startReplicas(t, short)

				f.run(t, time.Second)

				assert.False(t, publishes(t, short, recs[0].Kid), "unpublished here")
				assert.Contains(t, storedKids(t, f.mem), recs[0].Kid, "and still in the key store")
				longer, err := signingkey.New(t.Context(), append(
					retentionOptions(clockwork.NewFakeClockAt(f.clk.Now()), f.mem),
					signingkey.WithKeyLifetime(72*time.Hour))...)
				require.NoError(t, err)
				assert.True(t, publishes(t, longer, recs[0].Kid), "so the longer replica finds it after a restart")
			},
		},
		{
			name: "Replica with a shorter lifetime, through its own rotation",
			// The review's TestRepro_ShorterLifetimeReplicaDeletesLongerLifetimeReplicasKey.
			assert: func(t *testing.T, f *retireFixture) {
				long, err := signingkey.New(t.Context(), append(retentionOptions(f.clk, f.mem),
					signingkey.WithKeyLifetime(72*time.Hour))...)
				require.NoError(t, err)
				first := currentKid(t, long, signingkey.EdDSA)
				short, err := signingkey.New(t.Context(), retentionOptions(f.clk, f.mem)...)
				require.NoError(t, err)
				startReplicas(t, long, short)

				advance(t, f.clk, 25*time.Hour, 2*loopCount)
				advance(t, f.clk, time.Second, 2*loopCount)

				restarted, err := signingkey.New(t.Context(), append(
					retentionOptions(clockwork.NewFakeClockAt(f.clk.Now()), f.mem),
					signingkey.WithKeyLifetime(72*time.Hour))...)
				require.NoError(t, err)
				assert.True(t, publishes(t, restarted, first), "within the longer lifetime, it survives that replica's restart")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, &retireFixture{clk: newClock(), mem: signingkey.NewMemoryKeyStore()})
		})
	}
}

// TestRetireTime_RefusedConfiguration is construction's half of the grace option:
// a wiring mistake is an error from New, in whichever order the options come.
func TestRetireTime_RefusedConfiguration(t *testing.T) {
	type testCase struct {
		name   string
		opts   []signingkey.Option
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, signingkey.ErrConfig)
	}

	cases := []testCase{
		{
			name:   "Negative grace",
			opts:   []signingkey.Option{signingkey.WithRetiredKeyGrace(-time.Second)},
			assert: refused,
		},
		{
			name:   "A grace of zero, then kept keys",
			opts:   []signingkey.Option{signingkey.WithRetiredKeyGrace(0), signingkey.WithRetiredKeysKept()},
			assert: refused,
		},
		{
			name:   "Kept keys, then a grace of zero",
			opts:   []signingkey.Option{signingkey.WithRetiredKeysKept(), signingkey.WithRetiredKeyGrace(0)},
			assert: refused,
		},
		{
			name:   "A grace of an hour, then kept keys",
			opts:   []signingkey.Option{signingkey.WithRetiredKeyGrace(time.Hour), signingkey.WithRetiredKeysKept()},
			assert: refused,
		},
		{
			name:   "Kept keys, then a grace of an hour",
			opts:   []signingkey.Option{signingkey.WithRetiredKeysKept(), signingkey.WithRetiredKeyGrace(time.Hour)},
			assert: refused,
		},
		{
			name: "A grace of zero alone is accepted",
			opts: []signingkey.Option{signingkey.WithRetiredKeyGrace(0)},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := signingkey.New(t.Context(),
				append(retireOptions(newClock(), signingkey.NewMemoryKeyStore()), tc.opts...)...)
			tc.assert(t, err)
		})
	}
}

// TestRetireTime_SkewNeededToDeleteASigningKey measures decision 4's figure: with
// the default lifetime, rotation, reload and grace, a key still signing on a correct
// replica is deleted by a replica whose clock is fast by more than 47 hours and a
// minute, that being lifetime + reload + grace - rotation. The key is an hour old
// less a second, so a successor on the fast replica's calendar puts it at its latest
// moment of signing.
func TestRetireTime_SkewNeededToDeleteASigningKey(t *testing.T) {
	type testCase struct {
		name   string
		skew   time.Duration
		assert func(t *testing.T, stored []string, signing string)
	}

	const signedFor = retireRotation - time.Second

	cases := []testCase{
		{
			name: "A second under the figure",
			skew: retireLifetime + retireReload + retireLifetime - retireRotation,
			assert: func(t *testing.T, stored []string, signing string) {
				assert.Contains(t, stored, signing)
			},
		},
		{
			name: "A second over the figure",
			skew: retireLifetime + retireReload + retireLifetime - retireRotation + 2*time.Second,
			assert: func(t *testing.T, stored []string, signing string) {
				assert.NotContains(t, stored, signing)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mem := signingkey.NewMemoryKeyStore()
			f := &retireFixture{clk: newClock(), mem: mem}
			// The first key signs on a correct replica whose clock reads the epoch;
			// the second is what a replica fast by the skew minted an hour after it
			// by the store's calendar.
			recs := f.seed(t, signingkey.EdDSA, -signedFor, -signedFor+retireRotation, tc.skew)

			fastClk := clockwork.NewFakeClockAt(epoch.Add(tc.skew - time.Second))
			fast, err := signingkey.New(t.Context(), retireOptions(fastClk, mem)...)
			require.NoError(t, err)
			startReplicas(t, fast)
			advance(t, fastClk, time.Second, loopCount)

			tc.assert(t, storedKids(t, mem), recs[0].Kid)
		})
	}
}

// mustLoad returns what store holds of alg.
func mustLoad(t *testing.T, store signingkey.KeyStore, alg signingkey.Alg) []signingkey.Record {
	t.Helper()

	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)

	return slices.DeleteFunc(recs, func(rec signingkey.Record) bool { return rec.Alg != alg })
}
