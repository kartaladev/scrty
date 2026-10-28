package signingkey

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/logsample"
)

// Default configuration, each replaceable by the Option of the same name.
const (
	defaultLifetime       = 24 * time.Hour
	defaultRotateEvery    = time.Hour
	defaultHousekeepEvery = time.Hour
	defaultReloadEvery    = time.Minute
	defaultSampleWindow   = 5 * time.Minute
)

// Keys owns the signing keys: it generates them, persists them before
// using them, reloads them, rotates them and publishes them.
type Keys struct {
	mu      sync.RWMutex
	keys    map[string]*keyEntry // by kid
	order   []string             // kids, in the order they were held
	current map[Alg]string       // alg -> kid

	// lifecycle guards the background work. No loop ever takes it, which is
	// what lets Stop hold it across the wait for the loops to end.
	lifecycle sync.Mutex
	// cancel ends the run last launched, and is nil when there is none left to
	// reap; runDone is that run's context's Done channel, so Start can tell a
	// live run from one whose context has been cancelled. stopped is the only
	// state Stop leaves behind, because it is the one a later Start honours.
	cancel  context.CancelFunc
	runDone <-chan struct{}
	stopped bool
	wg      sync.WaitGroup

	algs           []Alg
	lifetime       time.Duration
	rotateEvery    time.Duration
	housekeepEvery time.Duration
	reloadEvery    time.Duration
	sampleWindow   time.Duration
	store          KeyStore
	clock          clock.Timed
	logger         *slog.Logger
	errorHook      func(error)
	sampler        *logsample.Sampler
}

// New returns a manager holding a current key for every configured
// algorithm, generating and storing one where the store has none. A stored key
// is adopted rather than replaced, so a restart invalidates no token signed
// within the key lifetime.
//
// Construction publishes what reload and housekeeping would: every stored key
// within the key lifetime, and the newest key of each configured algorithm
// whatever its age, which becomes current. A key past the lifetime that is not
// the newest of its algorithm is not published, so a manager that is never
// started still stops verifying it. The newest key is chosen among those dated
// no later than the present plus the reload interval, so an algorithm whose
// stored keys are all dated later than that gets a fresh key; a key dated more
// than one lifetime ahead is not published at all.
//
// It starts no goroutine.
//
// The context is the caller's own, and it is propagated to the key store for
// the load and for any key minted and written here. A store that honours
// cancellation therefore lets a construction blocked on a database or a key
// service be abandoned, rather than holding up start-up until the dependency
// answers or its own client gives up. The manager does not itself inspect the
// context: it neither shortens it nor refuses a context that is already done,
// because the store is the only part of construction that can block, and what
// a deadline means to it is the store's contract, not this one's. The default
// in-memory store performs no I/O at all, so a default construction has
// nothing to cancel — a limit of that store, stated here so it is not
// discovered as a surprise.
//
// Defaults, each replaced by the Option named after it: RS256 only
// (WithAlgs); a 24h key lifetime (WithLifetime); rotation every 1h
// (WithRotateInterval); housekeeping every 1h (WithHousekeepingInterval);
// reload every 1m (WithReloadInterval); a 5m failure-log sampling window
// (WithLogSampleWindow); an in-memory store that does not survive a restart
// (WithKeyStore); clock.System(), the system clock (WithClock); slog.Default() (WithLogger);
// and no error hook (WithErrorHook).
//
// A configuration that cannot work — an unsupported algorithm, a non-positive
// interval, a lifetime no longer than the rotation interval, or a reload
// interval no shorter than it — is an error here, not a surprise at the first
// rotation.
//
// A record of a failed rotation or reload carries a fixed reason and the
// error's Go type, never the store's own text; a consumer who wants that
// detail logs it inside their own implementation of KeyStore. The algorithm
// the failure belongs to is kept.
func New(ctx context.Context, opts ...Option) (*Keys, error) {
	km := &Keys{
		keys:           make(map[string]*keyEntry),
		current:        make(map[Alg]string),
		algs:           []Alg{RS256},
		lifetime:       defaultLifetime,
		rotateEvery:    defaultRotateEvery,
		housekeepEvery: defaultHousekeepEvery,
		reloadEvery:    defaultReloadEvery,
		sampleWindow:   defaultSampleWindow,
		store:          NewMemoryKeyStore(),
		clock:          clock.System(),
		logger:         slog.Default(),
	}
	for _, opt := range opts {
		// A nil option is skipped, so a caller building the slice
		// conditionally need not filter it first. password and identity
		// already promise this.
		if opt != nil {
			opt(km)
		}
	}
	if err := km.validate(); err != nil {
		return nil, err
	}
	// See WithLogSampleWindow for what the sampler is for; the reporter is
	// what keeps a count from being dropped rather than written.
	km.sampler = logsample.New(km.sampleWindow, logsample.WithReporter(km.reportSuppressed))

	if err := km.loadFromStore(ctx); err != nil {
		return nil, err
	}
	if err := km.mintMissing(ctx); err != nil {
		return nil, err
	}
	return km, nil
}

// loadFromStore holds every stored record the publishing rule admits, and makes
// the newest key of each configured algorithm current. A record that cannot be
// decoded fails the load, whether or not it would have been published: it is
// never skipped, and never replaced by a fresh key.
//
// A key past the lifetime is dropped here rather than left for housekeeping,
// because a manager that only verifies may never be started, and would
// otherwise publish it for as long as the process lived.
func (km *Keys) loadFromStore(ctx context.Context) error {
	recs, err := km.store.LoadAll(ctx)
	if err != nil {
		return diag.Wrap(err, "signingkey: load keys")
	}

	entries := make([]*keyEntry, 0, len(recs))
	keys := make([]storedKey, 0, len(recs))
	for _, rec := range recs {
		entry, err := entryFromRecord(rec)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
		keys = append(keys, entry.stored())
	}

	now := km.clock.Now()
	current := km.pickCurrent(keys, now)

	km.mu.Lock()
	defer km.mu.Unlock()

	for _, entry := range entries {
		if km.publishable(entry.stored(), current[entry.alg] == entry.kid, now) {
			km.holdLocked(entry)
		}
	}
	km.current = current
	return nil
}

// storedKey is what the publishing rule and the choice of current key read of
// a key, whether the manager holds it or the store has only listed it.
type storedKey struct {
	kid       string
	alg       Alg
	createdAt time.Time
}

func (e *keyEntry) stored() storedKey {
	return storedKey{kid: e.kid, alg: e.alg, createdAt: e.createdAt}
}

// publishable is the one rule for which keys are published, shared by
// construction, reload and housekeeping: a key is published while it is within
// the key lifetime, or while it is the newest key of a configured algorithm,
// which is the one that signs and is kept however old it is.
//
// There is no option over the rule itself, because it is what makes a retired
// key stop verifying; WithLifetime moves the line it draws.
func (km *Keys) publishable(k storedKey, newestOfAlg bool, now time.Time) bool {
	return newestOfAlg || !km.pastLifetime(k.createdAt, now)
}

// repickCurrentLocked re-chooses the current key per configured algorithm from
// the keys held, as pickCurrent describes, breaking a tie by the order
// listedOrderLocked gives them over recs, the records the reload listed. The
// order is taken here, under the lock, so a key rotation held after the reload
// read the store is a candidate too. A listed record the manager does not hold
// is passed over. A reload never leaves a configured algorithm without a
// current key: where no held key qualifies, as after the clock steps back past
// the reload interval, the previous current key stays current while it is still
// held. Callers hold km.mu.
func (km *Keys) repickCurrentLocked(recs []Record, now time.Time) {
	keys := slices.DeleteFunc(km.listedOrderLocked(recs), func(k storedKey) bool {
		return km.keys[k.kid] == nil
	})
	picked := km.pickCurrent(keys, now)
	for alg, kid := range km.current {
		if _, ok := picked[alg]; !ok && km.keys[kid] != nil {
			picked[alg] = kid
		}
	}
	km.current = picked
}

// pickCurrent chooses, per configured algorithm, the key in keys created most
// recently, whatever order they are listed in, among those created no later
// than now plus the reload interval. An exact tie goes to the key listed later,
// which for a store's own ordering is the one it listed last.
//
// The bound is what keeps a key dated far ahead from signing: it would
// otherwise be the newest key at every reload, and take signing back from each
// key rotation makes current. The allowance of one reload interval absorbs the
// usual skew between replicas, so a key a slightly fast replica has just minted
// is adopted at the next reload. WithReloadInterval moves it; the bound itself
// has no option, because without it a stored date decides who signs.
//
// An algorithm with no key that qualifies gets no entry from pickCurrent; a
// reload keeps its previous current key instead (see repickCurrentLocked), so
// signing never stops, while construction mints a new key.
//
// Only configured algorithms get a current key. A store is shared, and the
// replica on the other side of it may be configured differently, so it holds
// keys for algorithms this manager was never asked about. Such a key stays
// published while it is within the lifetime — that is what lets this replica
// verify the other's tokens — but making it current would hand it to Signer
// for an algorithm SupportedAlgs denies, and would exempt it from housekeeping
// for as long as the process lived, because the current key of an algorithm is
// never expired.
func (km *Keys) pickCurrent(keys []storedKey, now time.Time) map[Alg]string {
	current := make(map[Alg]string, len(km.algs))
	newest := make(map[Alg]time.Time, len(km.algs))
	latest := now.Add(km.reloadEvery)

	for _, k := range keys {
		if !slices.Contains(km.algs, k.alg) || k.createdAt.After(latest) {
			continue
		}
		if best, seen := newest[k.alg]; seen && k.createdAt.Before(best) {
			continue
		}
		newest[k.alg] = k.createdAt
		current[k.alg] = k.kid
	}
	return current
}

// mintMissing generates and stores a key for every configured algorithm that
// has no current key.
func (km *Keys) mintMissing(ctx context.Context) error {
	for _, alg := range km.algs {
		km.mu.RLock()
		_, have := km.current[alg]
		km.mu.RUnlock()
		if have {
			continue
		}
		if _, f := km.mintAndStore(ctx, alg); f != nil {
			return f.err
		}
	}
	return nil
}

// mintAndStore generates a key, writes it to the store, and only then holds it
// and makes it current. A key the store rejected is never used, so a failed
// write leaves the previous current key signing.
//
// A failure comes back as a *failure, whose err is what construction returns
// and the error hook receives, and whose cause is the store's own error, so a
// record names the store's error type rather than this package's wrapping.
func (km *Keys) mintAndStore(ctx context.Context, alg Alg) (string, *failure) {
	entry, rec, err := generateKey(alg, km.clock.Now())
	if err != nil {
		return "", &failure{err: err, reason: reasonGenerate, cause: err}
	}
	if err := km.store.Store(ctx, rec); err != nil {
		return "", &failure{
			err:    diag.Wrap(err, fmt.Sprintf("signingkey: store %s key", alg)),
			reason: reasonStore,
			cause:  err,
		}
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	km.holdLocked(entry)
	km.current[alg] = entry.kid
	return entry.kid, nil
}

// pastLifetime reports whether a key created at createdAt is more than one key
// lifetime away from now, in either direction: it has outlived the lifetime, or
// it is dated more than one lifetime ahead. A key that far ahead is a clock
// gone wrong or an edited row, and would otherwise never age out at all; one
// dated a little ahead by the skew between replicas stays within it, so the
// tokens that replica signs still verify.
func (km *Keys) pastLifetime(createdAt, now time.Time) bool {
	age := now.Sub(createdAt)
	return age > km.lifetime || age < -km.lifetime
}

// holdLocked holds entry, remembering the order keys were held in. Callers hold
// km.mu.
func (km *Keys) holdLocked(entry *keyEntry) {
	if _, held := km.keys[entry.kid]; !held {
		km.order = append(km.order, entry.kid)
	}
	km.keys[entry.kid] = entry
}

// SupportedAlgs reports the configured algorithms.
//
// The slice returned is the caller's own: sorting, filtering or rewriting it
// changes nothing here.
func (km *Keys) SupportedAlgs() []Alg {
	return slices.Clone(km.algs)
}

// Signer returns the kid and signer currently signing for alg, and whether
// there is one.
//
// It answers only for the configured algorithms, so what SupportedAlgs reports
// and what this hands out are the same set. A shared store may hold keys for
// other algorithms, written by a replica configured differently; those stay
// published, and none of them ever signs here.
func (km *Keys) Signer(alg Alg) (string, crypto.Signer, bool) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	kid, ok := km.current[alg]
	if !ok {
		return "", nil, false
	}
	entry, held := km.keys[kid]
	if !held {
		return "", nil, false
	}
	return kid, entry.signer, true
}

// VerificationKeys returns the public half of every key held, each carrying
// its kid and its algorithm, in the order the keys were held.
//
// Every key held is published, a key stored for an algorithm this manager was
// not configured with included: a replica sharing the store may have written
// it, and publishing it is what verifies the tokens it signed. Publishing a
// key is not signing with it — Signer hands out none of them — and such a
// key stops being published once it is past the key lifetime, like any other.
//
// The error is never non-nil here, because a manager already holds its keys
// and has nothing left to fail at. It is part of the KeySource contract for
// the sources that do: one backed by a key service answers a request per call
// and has an outage to report.
func (km *Keys) VerificationKeys() ([]PublicKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keys := make([]PublicKey, 0, len(km.order))
	for _, kid := range km.order {
		entry := km.keys[kid]
		// A copy, not the manager's own key: see clonePublicKey. The
		// verification path asks for these on every request, so what is handed
		// out here is exactly what that path relies on.
		public, err := clonePublicKey(entry.public)
		if err != nil {
			return nil, fmt.Errorf("signingkey: publish key %q: %w", kid, err)
		}

		keys = append(keys, PublicKey{
			Kid: kid,
			Alg: entry.alg,
			Key: public,
		})
	}

	return keys, nil
}
