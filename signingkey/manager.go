package signingkey

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

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

// KeyManager owns the signing keys: it generates them, persists them before
// using them, reloads them, rotates them and publishes them.
type KeyManager struct {
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
	clock          Clock
	logger         *slog.Logger
	errorHook      func(error)
	sampler        *logsample.Sampler
}

// NewKeyManager returns a manager holding a current key for every configured
// algorithm, generating and storing one where the store has none. A stored key
// is always adopted rather than replaced, so a restart invalidates no token.
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
// (WithKeyStore); the system clock (WithClock); slog.Default() (WithLogger);
// and no error hook (WithErrorHook).
//
// A configuration that cannot work — an unsupported algorithm, a non-positive
// interval, a lifetime no longer than the rotation interval, or a reload
// interval no shorter than it — is an error here, not a surprise at the first
// rotation.
func NewKeyManager(ctx context.Context, opts ...Option) (*KeyManager, error) {
	km := &KeyManager{
		keys:           make(map[string]*keyEntry),
		current:        make(map[Alg]string),
		algs:           []Alg{RS256},
		lifetime:       defaultLifetime,
		rotateEvery:    defaultRotateEvery,
		housekeepEvery: defaultHousekeepEvery,
		reloadEvery:    defaultReloadEvery,
		sampleWindow:   defaultSampleWindow,
		store:          NewInMemoryKeyStore(),
		clock:          systemClock{},
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

// loadFromStore holds every stored record. A record that cannot be decoded
// fails the load: it is never skipped, and never replaced by a fresh key.
func (km *KeyManager) loadFromStore(ctx context.Context) error {
	recs, err := km.store.LoadAll(ctx)
	if err != nil {
		return fmt.Errorf("signingkey: load keys: %w", err)
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	for _, rec := range recs {
		entry, err := entryFromRecord(rec)
		if err != nil {
			return err
		}
		km.holdLocked(entry)
	}
	km.repickCurrentLocked()
	return nil
}

// repickCurrentLocked chooses, per configured algorithm, the held key created
// most recently, whatever order the store returned the records in. An exact tie
// goes to the record seen later, which for a store's own ordering is the one it
// listed last. Callers hold km.mu.
//
// Only configured algorithms get a current key. A store is shared, and the
// replica on the other side of it may be configured differently, so it holds
// keys for algorithms this manager was never asked about. Such a key stays
// published — that is what lets this replica verify the other's tokens — but
// making it current would hand it to GetSigner for an algorithm SupportedAlgs
// denies, and would exempt it from housekeeping for as long as the process
// lived, because the current key of an algorithm is never expired.
func (km *KeyManager) repickCurrentLocked() {
	current := make(map[Alg]string, len(km.algs))
	newest := make(map[Alg]time.Time, len(km.algs))

	for _, kid := range km.order {
		entry := km.keys[kid]
		if !slices.Contains(km.algs, entry.alg) {
			continue
		}
		if best, seen := newest[entry.alg]; seen && entry.createdAt.Before(best) {
			continue
		}
		newest[entry.alg] = entry.createdAt
		current[entry.alg] = kid
	}
	km.current = current
}

// mintMissing generates and stores a key for every configured algorithm that
// has no current key.
func (km *KeyManager) mintMissing(ctx context.Context) error {
	for _, alg := range km.algs {
		km.mu.RLock()
		_, have := km.current[alg]
		km.mu.RUnlock()
		if have {
			continue
		}
		if _, err := km.mintAndStore(ctx, alg); err != nil {
			return err
		}
	}
	return nil
}

// mintAndStore generates a key, writes it to the store, and only then holds it
// and makes it current. A key the store rejected is never used, so a failed
// write leaves the previous current key signing.
func (km *KeyManager) mintAndStore(ctx context.Context, alg Alg) (string, error) {
	entry, rec, err := generateKey(alg, km.clock.Now())
	if err != nil {
		return "", err
	}
	if err := km.store.Store(ctx, rec); err != nil {
		return "", fmt.Errorf("signingkey: store %s key: %w", alg, err)
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	km.holdLocked(entry)
	km.current[alg] = entry.kid
	return entry.kid, nil
}

// pastLifetime reports whether a key created at createdAt has outlived the key
// lifetime by now. It is the whole question on the reload path, where a record
// the manager does not already hold cannot be anyone's current key.
func (km *KeyManager) pastLifetime(createdAt, now time.Time) bool {
	return now.Sub(createdAt) > km.lifetime
}

// expired reports whether the key identified by kid, created at createdAt for
// alg, has outlived the key lifetime and may stop being published. The current
// key of an algorithm is never expired however old it is: dropping it would
// leave that algorithm with nothing to sign with.
//
// Only housekeeping asks this, because only housekeeping drops a key it holds.
// The current key per algorithm is passed in rather than read from the manager,
// so a caller may ask outside the keyring lock from a snapshot.
func (km *KeyManager) expired(current map[Alg]string, alg, kid string, createdAt, now time.Time) bool {
	return current[alg] != kid && km.pastLifetime(createdAt, now)
}

// holdLocked holds entry, remembering the order keys were held in. Callers hold
// km.mu.
func (km *KeyManager) holdLocked(entry *keyEntry) {
	if _, held := km.keys[entry.kid]; !held {
		km.order = append(km.order, entry.kid)
	}
	km.keys[entry.kid] = entry
}

// SupportedAlgs reports the configured algorithms.
//
// The slice returned is the caller's own: sorting, filtering or rewriting it
// changes nothing here.
func (km *KeyManager) SupportedAlgs() []Alg {
	return slices.Clone(km.algs)
}

// GetSigner returns the kid and signer currently signing for alg, and whether
// there is one.
//
// It answers only for the configured algorithms, so what SupportedAlgs reports
// and what this hands out are the same set. A shared store may hold keys for
// other algorithms, written by a replica configured differently; those stay
// published, and none of them ever signs here.
func (km *KeyManager) GetSigner(alg Alg) (string, crypto.Signer, bool) {
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
// key is not signing with it — GetSigner hands out none of them — and such a
// key stops being published once it is past the key lifetime, like any other.
//
// The error is never non-nil here, because a manager already holds its keys
// and has nothing left to fail at. It is part of the KeySource contract for
// the sources that do: one backed by a key service answers a request per call
// and has an outage to report.
func (km *KeyManager) VerificationKeys() ([]PublicKey, error) {
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
