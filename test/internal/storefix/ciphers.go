package storefix

import (
	"crypto/rand"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/seal"
)

// SealKey returns a fresh random key of the size the default cipher takes.
func SealKey(t *testing.T) []byte {
	t.Helper()

	key := make([]byte, seal.KeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	return key
}

// Keys is a pair of keys: K1, retired, and K2, active.
type Keys struct{ K1, K2 []byte }

// NewKeys returns a pair of fresh random keys.
func NewKeys(t *testing.T) Keys {
	t.Helper()

	return Keys{K1: SealKey(t), K2: SealKey(t)}
}

// CipherOf returns the default cipher over a keyring built from opts.
func CipherOf(t *testing.T, opts ...seal.KeyringOption) seal.Cipher {
	t.Helper()

	kr, err := seal.NewKeyring(opts...)
	require.NoError(t, err)
	c, err := seal.NewAEADCipher(kr)
	require.NoError(t, err)

	return c
}

// UnderK1 seals under K1 alone.
func (k Keys) UnderK1(t *testing.T) seal.Cipher {
	t.Helper()
	return CipherOf(t, seal.WithEncryptionKey("k1", k.K1))
}

// Rotated seals under K2 and still opens what K1 sealed.
func (k Keys) Rotated(t *testing.T) seal.Cipher {
	t.Helper()
	return CipherOf(t, seal.WithEncryptionKey("k2", k.K2), seal.WithRetiredEncryptionKey("k1", k.K1))
}

// OnlyK2 seals and opens under K2 alone: what K1 sealed does not open.
func (k Keys) OnlyK2(t *testing.T) seal.Cipher {
	t.Helper()
	return CipherOf(t, seal.WithEncryptionKey("k2", k.K2))
}

// TestCipher is the cipher a test uses when the keys do not matter: k2
// active, k1 retired.
func TestCipher(t *testing.T) seal.Cipher {
	t.Helper()
	return NewKeys(t).Rotated(t)
}

// IdentityCipher "seals" by returning its input: a store over it keeps the
// plaintext, which the sealed-column suite must catch.
type IdentityCipher struct{}

// ActiveKeyID reports k2.
func (IdentityCipher) ActiveKeyID() (string, error) { return "k2", nil }

// Seal returns a copy of plaintext.
func (IdentityCipher) Seal(plaintext, _ []byte) ([]byte, error) { return slices.Clone(plaintext), nil }

// Open returns a copy of sealed, under k2.
func (IdentityCipher) Open(sealed, _ []byte) ([]byte, string, error) {
	return slices.Clone(sealed), "k2", nil
}

// MissingAADCipher seals through the default cipher but drops the additional
// data, so a value opens in any record: the sealed-column suite must catch it.
type MissingAADCipher struct{ seal.Cipher }

// Seal seals plaintext with no additional data.
func (c MissingAADCipher) Seal(plaintext, _ []byte) ([]byte, error) {
	return c.Cipher.Seal(plaintext, nil)
}

// Open opens sealed with no additional data.
func (c MissingAADCipher) Open(sealed, _ []byte) ([]byte, string, error) {
	return c.Cipher.Open(sealed, nil)
}

// CountingCipher records the additional data every Seal and Open is given,
// and delegates to the embedded cipher. It is safe for concurrent use.
type CountingCipher struct {
	seal.Cipher

	mu    sync.Mutex
	seals []string
	opens []string
}

// Seal records aad and delegates.
func (c *CountingCipher) Seal(plaintext, aad []byte) ([]byte, error) {
	c.mu.Lock()
	c.seals = append(c.seals, string(aad))
	c.mu.Unlock()

	return c.Cipher.Seal(plaintext, aad)
}

// Open records aad and delegates.
func (c *CountingCipher) Open(sealed, aad []byte) ([]byte, string, error) {
	c.mu.Lock()
	c.opens = append(c.opens, string(aad))
	c.mu.Unlock()

	return c.Cipher.Open(sealed, aad)
}

// Seals is the additional data of every Seal so far, in order.
func (c *CountingCipher) Seals() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.seals)
}

// Opens is the additional data of every Open so far, in order.
func (c *CountingCipher) Opens() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.opens)
}

// GatedCipher holds its first Open until the test releases it, so the test
// can write between a read and the re-seal that read would make.
type GatedCipher struct {
	seal.Cipher

	once             sync.Once
	opening, release chan struct{}
}

// NewGatedCipher gates c.
func NewGatedCipher(c seal.Cipher) *GatedCipher {
	return &GatedCipher{Cipher: c, opening: make(chan struct{}), release: make(chan struct{})}
}

// Opening is closed once the first Open has begun.
func (c *GatedCipher) Opening() <-chan struct{} { return c.opening }

// Release lets the held Open go on. Call it once.
func (c *GatedCipher) Release() { close(c.release) }

// Open delegates, the first call only after signalling Opening and waiting
// for Release.
func (c *GatedCipher) Open(sealed, aad []byte) ([]byte, string, error) {
	c.once.Do(func() {
		close(c.opening)
		<-c.release
	})
	return c.Cipher.Open(sealed, aad)
}
