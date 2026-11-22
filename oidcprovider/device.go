package oidcprovider

import (
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/origin"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

// DeviceOption customises WithDeviceAuthorization.
type DeviceOption func(*deviceConfig)

// deviceConfig is what the device authorization grant is configured with. A provider
// that did not enable the grant has none.
type deviceConfig struct {
	// entryRaw is the URL as the consumer gave it, until New checks it against the
	// issuer.
	entryRaw string
	// entryURL is the page where the user types the code, parsed and checked.
	entryURL *url.URL

	// formatAlphabet and formatLength are what WithUserCodeFormat was given, until New
	// checks them, and formatSet says it was given.
	formatAlphabet string
	formatLength   int
	formatSet      bool
	// format is the user-code format New resolved: the default, or the one given.
	format userCodeFormat

	// userCodeKey is what user codes are digested under: a copy of the key given to
	// WithUserCodeKey, or one New draws. userCodeKeySet says the consumer gave one, which a
	// durable store requires.
	userCodeKey    *digestKey
	userCodeKeySet bool

	// lifetime and interval are what WithDeviceLifetime and WithDevicePollInterval gave,
	// and lifetimeSet and intervalSet say they were given. Once New has resolved them they
	// are the lifetime and interval the provider uses.
	lifetime, interval       time.Duration
	lifetimeSet, intervalSet bool

	// store is what WithDeviceAuthorizationStore gave, and storeSet says it was given.
	// Once New has resolved it, store is the store the provider keeps device
	// authorizations in: the one given, or a MemoryDeviceAuthorizationStore.
	store    DeviceAuthorizationStore
	storeSet bool

	// entryLimiter is what WithUserCodeEntryLimiter gave, and entryLimiterSet says it was
	// given.
	entryLimiter    ratelimit.Limiter
	entryLimiterSet bool
	// entry holds the throttle user-code entry is checked against, which New builds and
	// UseUserCodeEntryLimiter may replace once. It is behind a pointer, so that the
	// configuration can be copied without copying its lock.
	entry *entryState
}

// WithDeviceAuthorizationStore replaces where device authorizations are kept. The default
// is a MemoryDeviceAuthorizationStore of the provider's own, which is lost with the
// process and not shared between instances. A nil store, typed nil included, fails New
// with an error matching ErrConfig naming this option. Given twice, the last one wins.
//
// Any store given here other than a *MemoryDeviceAuthorizationStore is taken to outlive
// the process and to be shared by replicas, even with one replica today, so it also needs
// WithUserCodeKey, the same key on every replica: a key drawn at start would differ after a
// restart and between replicas, and none would find the codes another issued. Without
// one, New fails with an error matching ErrConfig naming WithUserCodeKey.
func WithDeviceAuthorizationStore(store DeviceAuthorizationStore) DeviceOption {
	return func(d *deviceConfig) { d.store, d.storeSet = store, true }
}

// WithUserCodeFormat replaces the user-code format: the characters a code is drawn
// from, and how many it has. The default is DefaultUserCodeAlphabet, 8 long
// (DefaultUserCodeLength), shown as XXXX-XXXX. Codes are drawn uniformly from the
// provider's random source (WithRandom).
//
// A code is shown in dash-joined groups of 4 when its length divides by 4, otherwise in
// groups of 3 when it divides by 3, and otherwise ungrouped, so 9 digits show as
// 123-456-789. An entered code is read with whitespace and dashes dropped, and is
// upper-cased only when the alphabet has no lower-case letter.
//
// New fails with an error matching ErrConfig, naming this option, when the format
// allows fewer than 2^29 distinct codes (so 6 digits are refused, and 9 are accepted),
// when the length is outside 1 to 32, or when the alphabet holds fewer than 2
// characters, repeats one, or holds anything but printable ASCII. The space and '-' are
// refused too, as reading an entered code drops them, and a code holding one could
// never be typed. Given twice, the last one wins.
func WithUserCodeFormat(alphabet string, length int) DeviceOption {
	return func(d *deviceConfig) {
		d.formatAlphabet, d.formatLength, d.formatSet = alphabet, length, true
	}
}

// WithUserCodeKey sets the key user codes are digested under, as HMAC-SHA-256(key,
// code), so that a copy of the store cannot be reversed by trying every possible code.
// The key is a secret, and is copied when the option is made: changing the slice
// afterwards changes nothing. It serves this purpose alone: do not reuse it for any
// other secret of the application's or of scrty's, such as WithRefreshSuccessorKey's
// key, and give each purpose a key of its own.
// It must be at least MinUserCodeKeyBytes (32) bytes, or New fails with an error
// matching ErrConfig naming this option. Given twice, the last one wins.
//
// The default is 32 random bytes drawn once in New from the provider's random source
// (WithRandom), which fits a provider alone over the in-memory device store: codes in
// flight are lost with a restart, as the store's records are. A source that cannot
// supply them fails New with an error matching ErrConfig. A durable device store, which
// outlives a restart and which replicas share, requires this key, the same on every
// replica, or no replica finds the codes another issued.
func WithUserCodeKey(key []byte) DeviceOption {
	given := slices.Clone(key)

	return func(d *deviceConfig) {
		d.userCodeKey, d.userCodeKeySet = &digestKey{key: slices.Clone(given)}, true
	}
}

// The lifetime and poll interval of a device authorization, and the bounds options keep
// them within.
const (
	// DefaultDeviceLifetime is how long a device code and its user code last unless
	// WithDeviceLifetime says otherwise.
	DefaultDeviceLifetime = 600 * time.Second
	// DefaultDevicePollInterval is how long a device must wait between polls unless
	// WithDevicePollInterval says otherwise.
	DefaultDevicePollInterval = 5 * time.Second

	// minDeviceLifetime and maxDeviceLifetime bound WithDeviceLifetime.
	minDeviceLifetime = time.Minute
	maxDeviceLifetime = 30 * time.Minute
	// minDevicePollInterval and maxDevicePollInterval bound WithDevicePollInterval.
	minDevicePollInterval = time.Second
	maxDevicePollInterval = time.Minute
)

// WithDeviceLifetime replaces how long a device authorization lasts, from the moment it
// is issued: the time the user has to enter the code and answer, and the device to
// collect its tokens. The default is DefaultDeviceLifetime, 600 seconds. It is answered
// as expires_in in whole seconds, so a lifetime that is no whole number of seconds is
// answered rounded down.
//
// New fails with an error matching ErrConfig, naming this option, for a lifetime under a
// minute or over 30 minutes, zero included: zero is no way to ask for the default. Given
// twice, the last one wins.
func WithDeviceLifetime(d time.Duration) DeviceOption {
	return func(c *deviceConfig) { c.lifetime, c.lifetimeSet = d, true }
}

// WithDevicePollInterval replaces how long a device must wait between polls of the token
// endpoint, which is answered as interval in whole seconds. The default is
// DefaultDevicePollInterval, 5 seconds.
//
// New fails with an error matching ErrConfig, naming this option, for an interval under a
// second or over a minute, zero included, and for one that is not strictly below the
// lifetime. Given twice, the last one wins.
func WithDevicePollInterval(d time.Duration) DeviceOption {
	return func(c *deviceConfig) { c.interval, c.intervalSet = d, true }
}

// WithDeviceAuthorization enables the device authorization grant (RFC 8628). The
// default is off: with no option, no client may list GrantDeviceCode, and
// Provider.DeviceEnabled is false.
//
// entryURL is the page where a user types the code shown on the device. It must be
// absolute, on the issuer's origin (so https, unless the issuer is the loopback http
// one WithLoopbackHTTPIssuer permits), and carry no fragment or user information. A
// query is allowed. Anything else fails construction with ErrConfig. A nil DeviceOption
// is skipped. Given twice, the last one wins.
func WithDeviceAuthorization(entryURL string, opts ...DeviceOption) Option {
	return func(c *config) {
		d := &deviceConfig{entryRaw: entryURL}
		for _, opt := range opts {
			if opt != nil {
				opt(d)
			}
		}
		c.device = d
	}
}

// DeviceEnabled says whether the provider was built with WithDeviceAuthorization. The
// chain registers the device endpoints only when it is true.
func (p *Provider) DeviceEnabled() bool { return p.cfg.device != nil }

// validate checks the configuration, resolves the user-code format, the store and the entry
// throttle, and draws the user-code key from random when none was given. The throttle logs
// through logger and reads clk, the provider's own.
func (d *deviceConfig) validate(issuer string, random io.Reader, clk clock.Clock, logger *slog.Logger) error {
	if err := d.validateEntryURL(issuer); err != nil {
		return err
	}
	if err := d.resolveFormat(); err != nil {
		return err
	}
	if err := d.resolveTiming(); err != nil {
		return err
	}
	if err := d.resolveStore(); err != nil {
		return err
	}
	if err := d.resolveEntry(clk, logger); err != nil {
		return err
	}

	return d.resolveKey(random)
}

// resolveTiming checks the lifetime and interval given, or takes the defaults. A value
// given is never read as unset, so a zero is out of bounds and refused.
func (d *deviceConfig) resolveTiming() error {
	if !d.lifetimeSet {
		d.lifetime = DefaultDeviceLifetime
	}
	if !d.intervalSet {
		d.interval = DefaultDevicePollInterval
	}
	if d.lifetime < minDeviceLifetime || d.lifetime > maxDeviceLifetime {
		return fmt.Errorf("%w: WithDeviceLifetime: must be between %s and %s", ErrConfig, minDeviceLifetime, maxDeviceLifetime)
	}
	if d.interval < minDevicePollInterval || d.interval > maxDevicePollInterval {
		return fmt.Errorf("%w: WithDevicePollInterval: must be between %s and %s", ErrConfig, minDevicePollInterval, maxDevicePollInterval)
	}
	if d.interval >= d.lifetime {
		return fmt.Errorf("%w: WithDevicePollInterval: must be shorter than the lifetime (WithDeviceLifetime)", ErrConfig)
	}

	return nil
}

// resolveStore checks the store WithDeviceAuthorizationStore gave, or takes the default.
// A store other than the in-memory one is durable, and needs a key that outlives the
// process, so it is refused without WithUserCodeKey before resolveKey would draw one.
func (d *deviceConfig) resolveStore() error {
	if !d.storeSet {
		d.store = NewMemoryDeviceAuthorizationStore()

		return nil
	}
	if nilcheck.IsNil(d.store) {
		return fmt.Errorf("%w: WithDeviceAuthorizationStore: must not be nil", ErrConfig)
	}
	if _, inMemory := d.store.(*MemoryDeviceAuthorizationStore); !inMemory && !d.userCodeKeySet {
		return fmt.Errorf("%w: WithUserCodeKey: a durable device authorization store (WithDeviceAuthorizationStore) outlives a drawn key, as a restart or another replica digests user codes differently: give the same key on every replica", ErrConfig)
	}

	return nil
}

// resolveFormat checks the format WithUserCodeFormat gave, or takes the default.
func (d *deviceConfig) resolveFormat() error {
	alphabet, length := DefaultUserCodeAlphabet, DefaultUserCodeLength
	if d.formatSet {
		alphabet, length = d.formatAlphabet, d.formatLength
	}
	f, err := newUserCodeFormat(alphabet, length)
	if err != nil {
		return err
	}
	d.format = f

	return nil
}

// resolveKey checks the key WithUserCodeKey gave, or draws the default from random.
// Its messages never repeat the key.
func (d *deviceConfig) resolveKey(random io.Reader) error {
	if d.userCodeKeySet {
		if len(d.userCodeKey.key) < MinUserCodeKeyBytes {
			return fmt.Errorf("%w: WithUserCodeKey: must be at least %d bytes", ErrConfig, MinUserCodeKeyBytes)
		}

		return nil
	}
	key := make([]byte, defaultUserCodeKeyBytes)
	if _, err := io.ReadFull(random, key); err != nil {
		return fmt.Errorf("%w: WithRandom: could not supply a user-code key; give WithUserCodeKey or a source that works", ErrConfig)
	}
	d.userCodeKey = &digestKey{key: key}

	return nil
}

// validateEntryURL checks the entry URL against the issuer, which only Deps knows, and
// keeps it parsed. Its messages never repeat the value, which could hold a credential.
func (d *deviceConfig) validateEntryURL(issuer string) error {
	if !utf8.ValidString(d.entryRaw) || strings.IndexFunc(d.entryRaw, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return fmt.Errorf("%w: WithDeviceAuthorization: the entry URL must hold no whitespace, control character or invalid UTF-8", ErrConfig)
	}
	u, err := url.Parse(d.entryRaw)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("%w: WithDeviceAuthorization: the entry URL must be absolute", ErrConfig)
	}
	if u.User != nil || strings.Contains(d.entryRaw, "#") {
		return fmt.Errorf("%w: WithDeviceAuthorization: the entry URL must have no fragment or user information", ErrConfig)
	}
	if !origin.Same(d.entryRaw, issuer) {
		return fmt.Errorf("%w: WithDeviceAuthorization: the entry URL must be on the issuer's origin", ErrConfig)
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("%w: WithDeviceAuthorization: the entry URL's query is malformed", ErrConfig)
	}
	if _, found := query["user_code"]; found {
		return fmt.Errorf("%w: WithDeviceAuthorization: the entry URL's query must not carry user_code", ErrConfig)
	}
	d.entryURL = u

	return nil
}

// The default throttle of user-code entry: how many failed entries a source may make, and
// in what window, before Provider.EnterUserCode refuses it. They are exported so that a
// consumer building its own limiter, or asking a factory for one, can ask for the same
// rate.
const (
	DefaultUserCodeEntryLimit  = 5
	DefaultUserCodeEntryWindow = 10 * time.Minute
)

// WithUserCodeEntryLimiter replaces the limiter that throttles failed user-code entries per
// source. The default is a ratelimit.MemoryLimiter of the provider's own allowing
// DefaultUserCodeEntryLimit (5) failures per source in DefaultUserCodeEntryWindow (10
// minutes), which is per process and not shared by replicas. A limiter carries its own
// rate, so the consumer sets the rate by building it.
//
// A limiter given here is never replaced, not even by UseUserCodeEntryLimiter. A nil
// limiter, typed nil included, fails New with an error matching ErrConfig naming this
// option. Given twice, the last one wins.
func WithUserCodeEntryLimiter(limiter ratelimit.Limiter) DeviceOption {
	return func(d *deviceConfig) { d.entryLimiter, d.entryLimiterSet = limiter, true }
}

// UseUserCodeEntryLimiter hands the provider a limiter for user-code entry after New, the
// way the chain shares its rate-limiter factory with the provider it was built after. It is
// meant to be called before any traffic.
//
// It answers nil and changes nothing when the consumer gave WithUserCodeEntryLimiter,
// whose limiter is never replaced. Otherwise the first call replaces the default limiter,
// and a later call with the same limiter answers nil and changes nothing. A later call with
// a different limiter is refused with an error matching ErrConfig, so that two callers
// cannot silently split the counts between them. A nil limiter, typed nil included, and a
// provider without the device grant (WithDeviceAuthorization) are refused with an error
// matching ErrConfig. It is safe for concurrent use, with itself and with EnterUserCode.
func (p *Provider) UseUserCodeEntryLimiter(limiter ratelimit.Limiter) error {
	cfg := p.cfg.device
	if cfg == nil {
		return fmt.Errorf("%w: UseUserCodeEntryLimiter: the device grant is off; enable it with WithDeviceAuthorization", ErrConfig)
	}
	if nilcheck.IsNil(limiter) {
		return fmt.Errorf("%w: UseUserCodeEntryLimiter: must not be nil", ErrConfig)
	}

	cfg.entry.mu.Lock()
	defer cfg.entry.mu.Unlock()

	current := cfg.entry.current.Load()
	switch {
	case current.consumer:
		return nil
	case current.handedOver && sameLimiter(current.limiter, limiter):
		return nil
	case current.handedOver:
		return fmt.Errorf("%w: UseUserCodeEntryLimiter: a different limiter was already handed over, and two would split the counts", ErrConfig)
	}

	throttle, err := newEntryThrottle(limiter, p.cfg.clock, p.cfg.logger)
	if err != nil {
		return fmt.Errorf("%w: UseUserCodeEntryLimiter: %w", ErrConfig, err)
	}
	throttle.handedOver = true
	cfg.entry.current.Store(throttle)

	return nil
}
