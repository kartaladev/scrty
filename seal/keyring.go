package seal

import (
	"bytes"
	"crypto/subtle"
	"fmt"
)

// KeySize is the only key length a keyring accepts: 32 bytes, an AES-256 key.
const KeySize = 32

// maxKeyIDLen is the longest key id a keyring accepts. The envelope stores the
// id's length in one byte, and 64 leaves room for dates, versions and a KMS
// alias while keeping every sealed value short.
const maxKeyIDLen = 64

// Keyring hands a cipher its keys: one active key that seals, and every key,
// active or retired, that opens.
//
// NewKeyring returns the default, an in-memory ring built from options. A
// consumer who keeps keys elsewhere implements this interface instead; the
// cipher asks it for a key on every seal and open, so a ring that reloads keys
// takes effect at once. An implementation must be safe for concurrent use, and
// must return key bytes the caller may keep and alter without changing the
// ring.
//
//go:generate mockgen -source=keyring.go -package=seal_test -destination=keyring_mock_test.go -typed
type Keyring interface {
	// Active returns the id and bytes of the key new values are sealed under.
	Active() (id string, key []byte, err error)

	// ByID returns the key named id, active or retired, or an error that
	// matches ErrUnknownKeyID when the ring holds no such key.
	ByID(id string) ([]byte, error)
}

// namedKey is one configured key, before validation.
type namedKey struct {
	id  string
	key []byte
}

// keyringConfig collects what the options configure. The active and the
// retired keys are kept apart, never told apart by position, so the key that
// seals is the one the consumer named as active and no other.
type keyringConfig struct {
	active  []namedKey
	retired []namedKey
}

// KeyringOption configures NewKeyring.
type KeyringOption func(*keyringConfig)

// WithEncryptionKey names the active key: the one new values are sealed under,
// which also opens them. A keyring has exactly one. There is no default active
// key: a keyring without one is a configuration error, because a key the
// library chose would be a key the consumer cannot recover.
//
// key is copied, so changing the caller's slice afterwards does not change the
// ring.
func WithEncryptionKey(id string, key []byte) KeyringOption {
	k := namedKey{id: id, key: bytes.Clone(key)}

	return func(c *keyringConfig) { c.active = append(c.active, k) }
}

// WithRetiredEncryptionKey adds a retired key, which only opens: values sealed
// under it before a rotation still read, and nothing new is sealed under it.
// A keyring has zero retired keys unless this option adds them, and may have
// any number.
//
// key is copied, so changing the caller's slice afterwards does not change the
// ring.
func WithRetiredEncryptionKey(id string, key []byte) KeyringOption {
	k := namedKey{id: id, key: bytes.Clone(key)}

	return func(c *keyringConfig) { c.retired = append(c.retired, k) }
}

// keyring is the default Keyring: fixed at construction and read-only after,
// so it needs no lock.
type keyring struct {
	activeID string
	keys     map[string][]byte
}

// NewKeyring builds the default in-memory keyring from one
// WithEncryptionKey and any number of WithRetiredEncryptionKey options.
//
// It returns an error matching ErrInvalidConfiguration when there is no active
// key or more than one, when a key is not exactly 32 bytes, when a key id is
// empty, used twice, longer than 64 characters or contains anything but ASCII
// letters, digits, '.', '_' and '-', when two ids name identical key bytes, or
// when an option is nil. Identical bytes under two ids are refused because a
// retired key equal to the active key records a rotation that never happened.
// The error names the offending key by its role and, when the id itself is
// well formed, by its id; it never contains key bytes.
func NewKeyring(opts ...KeyringOption) (Keyring, error) {
	var cfg keyringConfig
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: a keyring option is nil", ErrInvalidConfiguration)
		}
		opt(&cfg)
	}

	if len(cfg.active) != 1 {
		return nil, fmt.Errorf("%w: a keyring needs exactly one active key, got %d",
			ErrInvalidConfiguration, len(cfg.active))
	}

	kr := &keyring{activeID: cfg.active[0].id, keys: make(map[string][]byte, 1+len(cfg.retired))}
	if err := kr.add("the active key", cfg.active[0]); err != nil {
		return nil, err
	}
	for i, k := range cfg.retired {
		if err := kr.add(fmt.Sprintf("retired key %d", i+1), k); err != nil {
			return nil, err
		}
	}

	return kr, nil
}

// add validates k, which role names in an error, against the rules and the
// keys already added, and adds it.
func (r *keyring) add(role string, k namedKey) error {
	if !validKeyID(k.id) {
		return fmt.Errorf("%w: the id of %s must be 1 to %d of A-Z, a-z, 0-9, '.', '_' or '-'",
			ErrInvalidConfiguration, role, maxKeyIDLen)
	}
	if len(k.key) != KeySize {
		return fmt.Errorf("%w: key %q must be %d bytes, got %d",
			ErrInvalidConfiguration, k.id, KeySize, len(k.key))
	}
	if _, dup := r.keys[k.id]; dup {
		return fmt.Errorf("%w: key id %q is used more than once", ErrInvalidConfiguration, k.id)
	}
	for id, other := range r.keys {
		if subtle.ConstantTimeCompare(k.key, other) == 1 {
			return fmt.Errorf("%w: keys %q and %q have identical bytes", ErrInvalidConfiguration, id, k.id)
		}
	}

	r.keys[k.id] = k.key

	return nil
}

// Active returns the active key's id and a copy of its bytes.
func (r *keyring) Active() (string, []byte, error) {
	return r.activeID, bytes.Clone(r.keys[r.activeID]), nil
}

// ByID returns a copy of the bytes of the key named id, or ErrUnknownKeyID.
// The error does not repeat id, which comes from a stored value.
func (r *keyring) ByID(id string) ([]byte, error) {
	key, ok := r.keys[id]
	if !ok {
		return nil, ErrUnknownKeyID
	}

	return bytes.Clone(key), nil
}

// validKeyID reports whether id is 1 to maxKeyIDLen bytes of
// [A-Za-z0-9._-].
func validKeyID(id string) bool {
	if id == "" || len(id) > maxKeyIDLen {
		return false
	}

	for i := range len(id) {
		switch c := id[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}

	return true
}
