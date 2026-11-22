package oidcprovider

import (
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kartaladev/scrty/internal/origin"
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

// validate checks the configuration, resolves the user-code format, and draws the
// user-code key from random when none was given.
func (d *deviceConfig) validate(issuer string, random io.Reader) error {
	if err := d.validateEntryURL(issuer); err != nil {
		return err
	}
	if err := d.resolveFormat(); err != nil {
		return err
	}

	return d.resolveKey(random)
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
