package signingkey

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
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

// JWKS returns the keys the manager holds as the RFC 7517 JSON document a JWKS
// endpoint serves: an object with a "keys" array, one entry per key, each
// carrying its kid, the algorithm it verifies and use "sig".
//
// It answers in bytes rather than in a key-set type so serving the endpoint is
// a w.Write away and a consumer needs no JOSE library to publish what this
// process signs with — the same promise KeySource makes, kept here too, since
// a document that obliged its caller to import a JOSE library to hand it over
// would have kept none of it.
//
// Every key held is published, one stored for an algorithm this manager was
// not configured with included, exactly as VerificationKeys reports them and
// in the same order: a replica sharing the store may have written that key,
// and publishing it is what verifies the tokens it signed. Publishing a key is
// not signing with it — Signer hands out none of them — and a key stops
// being published once it is past the key lifetime, like any other. Nothing
// private is rendered: each entry is built from the public half alone, so the
// document is safe to serve to anyone who asks for it.
//
// This is the opinionated document, and it is the only one this package
// produces. A consumer whose infrastructure wants something else — a filtered
// set, another order, extra parameters such as x5c, or the whole thing wrapped
// in an object of its own — builds it from VerificationKeys, which hands over
// each key's identifier, algorithm and public half as standard-library types
// for exactly that purpose.
//
// Nothing is cached: every call renders the document afresh, under the same
// read lock the other read methods take, which for a handful of keys is a JSON
// encode and some base64. An endpoint served on every request by a fleet of
// verifiers should cache the bytes — as an HTTP cache header, typically — and
// keep that cache well inside the key lifetime, which is what keeps a replaced
// key published.
func (km *Keys) JWKS() ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	set := jwk.NewSet()
	for _, kid := range km.order {
		// PublicKey both copies the held key and strips whatever a public key
		// may not carry. The copy is what matters here: a jwk.Key is mutable,
		// and adding the manager's own to a set would let anything that
		// touched that set rewrite the key this process publishes. The
		// stripping costs nothing and means no future path that puts a
		// private key in an entry can reach this document.
		public, err := km.keys[kid].publicJWK.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("signingkey: publish key %q: %w", kid, err)
		}
		if err := set.AddKey(public); err != nil {
			return nil, fmt.Errorf("signingkey: publish key %q: %w", kid, err)
		}
	}

	doc, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("signingkey: marshal jwks: %w", err)
	}

	return doc, nil
}

// ErrConfig is wrapped by every error New returns for a wiring
// mistake, so a consumer can tell a contradictory configuration from a store
// failure without matching on message text.
var ErrConfig = errors.New("signingkey: invalid configuration")

// Option configures the Keys. Every default New applies has an
// Option here that replaces it.
type Option func(*Keys)

// WithAlgs sets the algorithms a current key is kept for. Default: RS256 only.
// Supported: RS256, ES256 and EdDSA; anything else fails construction.
//
// The list is copied, so a caller may sort, filter or reuse the slice it passed
// afterwards. Without the copy a consumer reusing that slice would rewrite the
// configuration after construction validated it, and rotation would go on
// minting for whatever it had become.
func WithAlgs(algs ...Alg) Option {
	return func(km *Keys) { km.algs = slices.Clone(algs) }
}

// WithLifetime sets how long a key stays published after it was created.
// Default: 24h. It must be longer than the rotation interval, or a key would
// stop being published while tokens it signed are still valid.
func WithLifetime(d time.Duration) Option {
	return func(km *Keys) { km.lifetime = d }
}

// WithRotateInterval sets how often a new key is minted for every configured
// algorithm. Default: 1h.
func WithRotateInterval(d time.Duration) Option {
	return func(km *Keys) { km.rotateEvery = d }
}

// WithHousekeepingInterval sets how often keys past their lifetime stop being
// published. Default: 1h.
func WithHousekeepingInterval(d time.Duration) Option {
	return func(km *Keys) { km.housekeepEvery = d }
}

// WithReloadInterval sets how often the store is reloaded, which is how
// replicas sharing a store see each other's keys. Default: 1m. It must be
// shorter than the rotation interval, or a replica would miss a rotation.
func WithReloadInterval(d time.Duration) Option {
	return func(km *Keys) { km.reloadEvery = d }
}

// WithLogSampleWindow sets how long one written record about a rotation or
// reload failure suppresses further records for the same operation and
// algorithm. Default: 5m.
//
// A store outage fails every interval for as long as it lasts, which without
// sampling is one record per interval. At most one record per window is
// written, and every record states how many failures were suppressed before it,
// so no failure goes unaccounted for. A window of zero or less writes every
// failure, for a consumer whose own handler samples.
//
// The error hook is never sampled: every failure reaches it.
func WithLogSampleWindow(d time.Duration) Option {
	return func(km *Keys) { km.sampleWindow = d }
}

// WithKeyStore sets where keys are persisted. Default: NewMemoryKeyStore,
// which does not survive a restart.
func WithKeyStore(store KeyStore) Option {
	return func(km *Keys) { km.store = store }
}

// WithClock sets the time source. Default: clock.System().
//
// The clock stamps key creation times and paces the rotation, reload and
// housekeeping loops: each waits on the clock's After, and runs again one
// interval after its previous run finished. A controlled clock, such as
// clockwork's fake, therefore drives every one of them without real waiting.
//
// Each loop calls After from its own goroutine, after Start has returned, and
// again only once its previous run has finished. A caller driving a controlled
// clock must therefore wait until the loops are waiting on it before advancing
// it, both after Start and after each advance that triggers a run: with
// clockwork's fake, BlockUntilContext(ctx, 3) waits for all three loops. An
// advance made earlier is not seen by a loop that has not yet called After,
// and that loop waits a full interval from wherever the clock then stands.
//
// A nil clock, typed nil included, is a configuration error from
// New.
func WithClock(clk clock.Timed) Option {
	return func(km *Keys) { km.clock = clk }
}

// WithLogger sets where rotation and reload failures are logged. Default:
// slog.Default().
//
// Records are written from the background loops, under the rules
// WithErrorHook describes: a handler that blocks holds up the loop that is
// writing, and one that calls Start or Stop deadlocks the manager. A handler
// that panics takes the loop down with it.
func WithLogger(logger *slog.Logger) Option {
	return func(km *Keys) { km.logger = logger }
}

// WithErrorHook sets a function called with every rotation and reload failure.
// Default: none. Use it to surface a store outage that would otherwise leave
// one key signing indefinitely.
//
// The error the hook receives carries fixed library text naming the failed
// stage, never the store's own text; the store's error stays reachable
// through errors.Is and errors.As, so a consumer who wants its full detail
// inspects it deliberately or logs it inside their own implementation of
// KeyStore.
//
// The hook runs synchronously on the background loop that failed, which fixes
// what it may do:
//
//   - It must be fast. The loop's next interval begins only once the hook has
//     returned, so a hook that blocks delays every later run of that loop by
//     as long as it blocks, and one that never returns stops it.
//   - It must not panic. There is no recover between the hook and the loop, so
//     a panic ends that loop and takes the process with it.
//   - It must not call Start or Stop. Stop waits for the loop the hook is
//     running on, and Start waits for the same lock Stop holds while it waits,
//     so either one called from the hook wedges the manager: the loops stop
//     running, every later Stop blocks, and the process goes on serving with a
//     key that never rotates. To shut down from a hook, hand the error to a
//     goroutine or a channel of the consumer's own and call Stop from there.
//
// Everything that reads the manager is safe from the hook, which is what a
// hook needs in order to decide how bad an outage has become: Signer,
// VerificationKeys, SupportedAlgs, KeyLifetime and RotateInterval. The manager
// never holds the keyring lock across the hook.
func WithErrorHook(hook func(error)) Option {
	return func(km *Keys) { km.errorHook = hook }
}

// validate reports a configuration that cannot work, so a wiring mistake fails
// at construction rather than at the first rotation.
func (km *Keys) validate() error {
	// A nil port is caught here rather than at first use: a nil store or
	// clock would panic during construction, and a nil logger would panic in
	// a background loop at the first failure it tried to report.
	//
	// isNilPort, not == nil, because the shape a real wiring mistake produces is
	// a typed nil — `var s *myStore; WithKeyStore(s)` — and an interface holding
	// a nil pointer is not equal to nil. Comparing against nil alone accepts it
	// and panics on the first call instead.
	if isNilPort(km.store) {
		return fmt.Errorf("%w: key store must not be nil", ErrConfig)
	}

	if nilcheck.IsNil(km.clock) {
		return fmt.Errorf("%w: clock must not be nil", ErrConfig)
	}

	if isNilPort(km.logger) {
		return fmt.Errorf("%w: logger must not be nil", ErrConfig)
	}

	if len(km.algs) == 0 {
		return fmt.Errorf("%w: at least one algorithm is required", ErrConfig)
	}
	seen := make(map[Alg]struct{}, len(km.algs))

	for _, alg := range km.algs {
		if !supportedAlg(alg) {
			return fmt.Errorf(
				"%w: unsupported algorithm %q, want one of %q, %q or %q",
				ErrConfig, alg, RS256, ES256, EdDSA)
		}

		// One algorithm named twice is still one algorithm. Construction hides a
		// duplicate, because minting skips an algorithm that already has a key,
		// but rotation walks this list directly and would mint, marshal and store
		// one key per mention at every interval, growing the published set each
		// time. A concatenated config list is all it takes.
		if _, dup := seen[alg]; dup {
			return fmt.Errorf("%w: algorithm %q is named more than once", ErrConfig, alg)
		}

		seen[alg] = struct{}{}
	}

	for _, interval := range []struct {
		name  string
		value time.Duration
	}{
		{"lifetime", km.lifetime},
		{"rotate interval", km.rotateEvery},
		{"housekeeping interval", km.housekeepEvery},
		{"reload interval", km.reloadEvery},
	} {
		if interval.value <= 0 {
			return fmt.Errorf("%w: %s must be positive, got %s",
				ErrConfig, interval.name, interval.value)
		}
	}

	if km.lifetime <= km.rotateEvery {
		return fmt.Errorf(
			"%w: lifetime %s must be longer than the rotate interval %s, "+
				"or a key would stop being published while tokens it signed are still valid",
			ErrConfig, km.lifetime, km.rotateEvery)
	}
	if km.reloadEvery >= km.rotateEvery {
		return fmt.Errorf(
			"%w: reload interval %s must be shorter than the rotate interval %s, "+
				"or a replica would miss another replica's rotation",
			ErrConfig, km.reloadEvery, km.rotateEvery)
	}

	// Housekeeping is the only thing that stops publishing an expired key:
	// reload declines to re-add one, but never drops a key already held. So the
	// lifetime is only honoured to within one housekeeping interval, and an
	// interval longer than the lifetime turns the guarantee into a suggestion —
	// a 2-hour lifetime swept every 1000 hours publishes keys for hundreds of
	// times their stated life. Refused rather than quietly relaxed.
	if km.housekeepEvery > km.lifetime {
		return fmt.Errorf(
			"%w: housekeeping interval %s must not exceed the lifetime %s, "+
				"or a key would stay published long past the lifetime it was given",
			ErrConfig, km.housekeepEvery, km.lifetime)
	}

	return nil
}

// isNilPort reports whether v is nil, or a non-nil interface holding a nil
// pointer, map, slice, channel or function.
//
// A consumer's wiring mistake almost always produces the second shape, which
// == nil does not catch.
func isNilPort(v any) bool {
	if v == nil {
		return true
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.Interface:
		return rv.IsNil()
	default:
		return false
	}
}
