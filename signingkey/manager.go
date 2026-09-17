package signingkey

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"

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
	started   bool
	stopped   bool
	cancel    context.CancelFunc
	wg        sync.WaitGroup

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
func NewKeyManager(opts ...Option) (*KeyManager, error) {
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

	ctx := context.Background()
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

// repickCurrentLocked chooses, per algorithm, the held key created most
// recently, whatever order the store returned the records in. An exact tie goes
// to the record seen later, which for a store's own ordering is the one it
// listed last. Callers hold km.mu.
func (km *KeyManager) repickCurrentLocked() {
	current := make(map[Alg]string, len(km.algs))
	newest := make(map[Alg]time.Time, len(km.algs))

	for _, kid := range km.order {
		entry := km.keys[kid]
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

// expired reports whether the key identified by kid, created at createdAt for
// alg, has outlived the key lifetime. The current key of an algorithm is never
// expired however old it is: dropping it would leave that algorithm with
// nothing to sign with.
//
// Reload and housekeeping both ask this, so the rule lives in one place. The
// current key per algorithm is passed in rather than read from the manager, so
// a caller may ask outside the keyring lock from a snapshot.
func (km *KeyManager) expired(current map[Alg]string, alg, kid string, createdAt, now time.Time) bool {
	return current[alg] != kid && now.Sub(createdAt) > km.lifetime
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
func (km *KeyManager) SupportedAlgs() []Alg {
	return append([]Alg(nil), km.algs...)
}

// GetSigner returns the kid and signer currently signing for alg, and whether
// there is one.
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

// JWKS returns the public part of every key held, each carrying its kid, its
// algorithm and use "sig". No entry carries private key material.
func (km *KeyManager) JWKS() (jwk.Set, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	set := jwk.NewSet()
	for _, kid := range km.order {
		// A clone, not the manager's own key. A jwk.Key is mutable, and a caller
		// that tags or edits a key it was handed would otherwise rewrite the
		// manager's published identifier under it, leaving jws.WithKeySet — which
		// matches on kid — unable to find the key its own current signer uses.
		// The verification path calls this on every request, so the keys handed
		// out are the same objects that path relies on.
		clone, err := km.keys[kid].publicJWK.Clone()
		if err != nil {
			return nil, fmt.Errorf("signingkey: clone key %q: %w", kid, err)
		}

		if err := set.AddKey(clone); err != nil {
			return nil, fmt.Errorf("signingkey: build jwks: %w", err)
		}
	}

	return set, nil
}
