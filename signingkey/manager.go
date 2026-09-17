package signingkey

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// Default configuration, each replaceable by the Option of the same name.
const (
	defaultLifetime       = 24 * time.Hour
	defaultRotateEvery    = time.Hour
	defaultHousekeepEvery = time.Hour
	defaultReloadEvery    = time.Minute
)

// KeyManager owns the signing keys: it generates them, persists them before
// using them, reloads them, rotates them and publishes them.
type KeyManager struct {
	mu      sync.RWMutex
	keys    map[string]*keyEntry // by kid
	order   []string             // kids, in the order they were held
	current map[Alg]string       // alg -> kid

	algs           []Alg
	lifetime       time.Duration
	rotateEvery    time.Duration
	housekeepEvery time.Duration
	reloadEvery    time.Duration
	store          KeyStore
	clock          Clock
	logger         *slog.Logger
	errorHook      func(error)
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
// reload every 1m (WithReloadInterval); an in-memory store that does not
// survive a restart (WithKeyStore); the system clock (WithClock);
// slog.Default() (WithLogger); and no error hook (WithErrorHook).
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
		store:          NewInMemoryKeyStore(),
		clock:          systemClock{},
		logger:         slog.Default(),
	}
	for _, opt := range opts {
		opt(km)
	}
	if err := km.validate(); err != nil {
		return nil, err
	}

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
	current := make(map[Alg]string, len(km.keys))
	newest := make(map[Alg]time.Time, len(km.keys))

	for _, kid := range km.orderLocked() {
		entry := km.keys[kid]
		if best, seen := newest[entry.alg]; seen && entry.createdAt.Before(best) {
			continue
		}
		newest[entry.alg] = entry.createdAt
		current[entry.alg] = kid
	}
	km.current = current
}

// orderLocked returns the held kids in the order they were held, so a tie in
// createdAt resolves the way the store listed the records. Callers hold km.mu.
func (km *KeyManager) orderLocked() []string {
	return append([]string(nil), km.order...)
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
	for _, kid := range km.orderLocked() {
		if err := set.AddKey(km.keys[kid].publicJWK); err != nil {
			return nil, fmt.Errorf("signingkey: build jwks: %w", err)
		}
	}
	return set, nil
}
