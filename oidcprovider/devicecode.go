package oidcprovider

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/bits"
	"strings"
	"unicode"
)

// The user-code format a provider uses unless WithUserCodeFormat replaces it, and the
// shortest key WithUserCodeKey accepts.
const (
	// DefaultUserCodeAlphabet is RFC 8628 §6.1's base-20 alphabet: upper-case consonants
	// with no vowels, so that a code spells no word and no letter is mistaken for another.
	DefaultUserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	// DefaultUserCodeLength is the number of characters in a default user code, shown in
	// two groups of four as XXXX-XXXX.
	DefaultUserCodeLength = 8
	// MinUserCodeKeyBytes is the shortest key WithUserCodeKey accepts.
	MinUserCodeKeyBytes = 32
)

const (
	// maxUserCodeLength bounds WithUserCodeFormat's length.
	maxUserCodeLength = 32
	// minUserCodeSpace is the fewest distinct codes a format may allow, 2^29.
	minUserCodeSpace = 1 << 29
	// defaultUserCodeKeyBytes is the size of the key New draws when none is given.
	defaultUserCodeKeyBytes = 32
	// deviceCodeBytes is a device code's size. It is the size of every other secret the
	// provider mints, so that digestEncoded reads a device code back as it reads them.
	deviceCodeBytes = flowSecretBytes
	// maxUserCodeDraw bounds the bytes one user code may draw from the random source,
	// rejected ones included. The widest rejection zone any accepted alphabet has is under
	// a third of the byte values, so even a 32-character code of the worst alphabet keeps
	// 32 of 256 draws with a chance of failing too small to compute in float64; only a
	// source that is broken, yielding byte values in the zone again and again, reaches it.
	maxUserCodeDraw = 256
)

// errUserCodeDrawExhausted stands for a random source whose bytes kept landing in the
// rejection zone until the draw's bound. It says nothing of the bytes.
var errUserCodeDrawExhausted = errors.New("oidcprovider: the random source yielded no usable bytes for a user code")

// userCodeFormat is how user codes are drawn, shown and read back.
type userCodeFormat struct {
	// alphabet is the characters a code is drawn from, each printable ASCII and distinct.
	alphabet string
	// length is the number of characters in a raw code.
	length int
	// group is the size of the dash-joined groups a code is shown in, and 0 shows it
	// ungrouped.
	group int
	// upper says the alphabet has no lower-case letter, so an entered code is upper-cased.
	upper bool
}

// newUserCodeFormat checks a format and works out how it is shown and read. Its
// messages never repeat the alphabet, whose bytes may not print.
func newUserCodeFormat(alphabet string, length int) (userCodeFormat, error) {
	if length < 1 || length > maxUserCodeLength {
		return userCodeFormat{}, fmt.Errorf("%w: WithUserCodeFormat: the length must be between 1 and %d", ErrConfig, maxUserCodeLength)
	}
	if len(alphabet) < 2 {
		return userCodeFormat{}, fmt.Errorf("%w: WithUserCodeFormat: the alphabet must hold at least 2 characters", ErrConfig)
	}
	var seen [128]bool
	upper := true
	for i := range len(alphabet) {
		c := alphabet[i]
		if c <= ' ' || c > '~' || c == '-' {
			return userCodeFormat{}, fmt.Errorf("%w: WithUserCodeFormat: the alphabet must hold only printable ASCII characters other than space and '-'", ErrConfig)
		}
		if seen[c] {
			return userCodeFormat{}, fmt.Errorf("%w: WithUserCodeFormat: the alphabet must not repeat a character", ErrConfig)
		}
		seen[c] = true
		if c >= 'a' && c <= 'z' {
			upper = false
		}
	}
	if !holdsAtLeast(len(alphabet), length, minUserCodeSpace) {
		return userCodeFormat{}, fmt.Errorf("%w: WithUserCodeFormat: the format must allow at least 2^29 distinct codes", ErrConfig)
	}

	f := userCodeFormat{alphabet: alphabet, length: length, upper: upper}
	switch {
	case length%4 == 0:
		f.group = 4
	case length%3 == 0:
		f.group = 3
	}

	return f, nil
}

// holdsAtLeast reports whether n^length >= floor. It multiplies in uint64 with bits.Mul64,
// whatever the size of int, and stops as soon as the floor is reached or the product
// carries past 64 bits, which is above any floor, so it never wraps.
func holdsAtLeast(n, length, floor int) bool {
	if n < 1 || floor < 0 {
		return false
	}
	un, uf := uint64(n), uint64(floor)
	hi, space := uint64(0), uint64(1)
	for range length {
		hi, space = bits.Mul64(space, un)
		if hi != 0 || space >= uf {
			return true
		}
	}

	return false
}

// digestKey holds the key user codes are digested under, behind a pointer so that fmt
// prints an address, not the bytes, when it reaches one inside a struct; it prints and
// logs redacted when formatted directly.
type digestKey struct {
	key []byte
}

// Format writes the redacted form under every verb.
func (*digestKey) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(redacted)) }

// LogValue is the redacted form.
func (*digestKey) LogValue() slog.Value { return slog.StringValue(redacted) }

// generate draws a raw code uniformly by rejection sampling: a byte b is kept when
// b < 256 - 256%n, as alphabet[b%n], and drawn again otherwise. It reads only as many
// bytes as it still needs, so it never reads past the last byte it keeps. A source that
// fails or runs short is an error, wrapped, and never a partial code; so is one whose
// bytes are rejected until maxUserCodeDraw bytes have been read.
func (f userCodeFormat) generate(r io.Reader) (string, error) {
	n := len(f.alphabet)
	limit := 256 - 256%n
	code := make([]byte, 0, f.length)
	buf := make([]byte, f.length)
	drawn := 0
	for len(code) < f.length {
		need := min(f.length-len(code), maxUserCodeDraw-drawn)
		if need == 0 {
			return "", errUserCodeDrawExhausted
		}
		if _, err := io.ReadFull(r, buf[:need]); err != nil {
			return "", fmt.Errorf("oidcprovider: draw a user code: %w", err)
		}
		drawn += need
		for _, b := range buf[:need] {
			if int(b) < limit {
				code = append(code, f.alphabet[int(b)%n])
			}
		}
	}

	return string(code), nil
}

// display shows a raw code in dash-joined groups, or as it is when the format has none.
func (f userCodeFormat) display(raw string) string {
	if f.group == 0 || len(raw) <= f.group {
		return raw
	}
	var b strings.Builder
	b.Grow(len(raw) + len(raw)/f.group)
	for i := 0; i < len(raw); i += f.group {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(raw[i:min(i+f.group, len(raw))])
	}

	return b.String()
}

// normalise reads an entered code back to its raw form: whitespace and dashes are
// dropped, and ASCII letters are upper-cased when the alphabet has no lower-case letter.
// Only ASCII is upper-cased, so no other character can fold into the alphabet. Any
// character outside the alphabet, or the wrong length, answers false, and no more than
// length characters are ever kept, whatever was entered.
func (f userCodeFormat) normalise(entered string) (string, bool) {
	raw := make([]byte, 0, f.length)
	for i, r := range entered {
		if r == '-' || unicode.IsSpace(r) {
			continue
		}
		// Invalid UTF-8 reads as U+FFFD, so a rune at most MaxASCII is the one byte at i.
		if r > unicode.MaxASCII || len(raw) == f.length {
			return "", false
		}
		c := entered[i]
		if f.upper && c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if strings.IndexByte(f.alphabet, c) < 0 {
			return "", false
		}
		raw = append(raw, c)
	}
	if len(raw) != f.length {
		return "", false
	}

	return string(raw), true
}

// mintDeviceCode draws a device code of deviceCodeBytes random bytes, encoded as every
// secret the provider mints is, and returns it with the SHA-256 digest of those bytes,
// which is what a store keeps. A source that fails or runs short is an error, wrapped,
// with no code and no digest.
func mintDeviceCode(r io.Reader) (string, []byte, error) {
	raw := make([]byte, deviceCodeBytes)
	if _, err := io.ReadFull(r, raw); err != nil {
		return "", nil, fmt.Errorf("oidcprovider: draw a device code: %w", err)
	}

	return secretEncoding.EncodeToString(raw), digestSecret(raw), nil
}

// userCodeDigest is HMAC-SHA-256 of a raw, normalised user code under the provider's
// key, so that a copy of the store cannot be reversed by trying every code. A digest
// read back is compared with hmac.Equal.
func (d *deviceConfig) userCodeDigest(raw string) []byte {
	mac := hmac.New(sha256.New, d.userCodeKey.key)
	mac.Write([]byte(raw))

	return mac.Sum(nil)
}
