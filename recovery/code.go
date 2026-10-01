package recovery

import (
	"crypto/sha256"
	"io"

	"github.com/kartaladev/scrty/internal/diag"
)

// codeBytes is how much entropy a saved code carries: 128 bits, far beyond
// guessing within any presentation limit. It is not an option, because the only
// direction anyone would move it is down, and the tests pin it so no later
// change can shorten the codes silently.
const codeBytes = 16

const (
	// codeAlphabet is Crockford's base32 alphabet. It omits I, L, O and U, so a
	// code read aloud or copied by hand has no look-alike characters.
	codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	// codeChars is how many alphabet characters a code has: 26 characters of 5
	// bits hold 130 bits, the smallest multiple of 5 that fits 128. The two
	// spare bits are the value's leading zeros, which is why the first
	// character is always 0–7.
	codeChars = 26

	// codeGroup is how many characters sit between two dashes.
	codeGroup = 4

	// maxFirstChar is the highest value the first character may carry: with
	// two leading zero bits its 5 bits hold at most 0b00111.
	maxFirstChar = 7
)

// newCode draws one saved code from random and returns it as grouped Crockford
// base32 text, with the SHA-256 hash of its 16 bytes that the store keeps.
//
// A random source that fails or runs short is an error, and no code is
// returned: a code built from fewer bytes than codeBytes would carry less
// entropy than the library promises.
func newCode(random io.Reader) (text string, hash [32]byte, err error) {
	var raw [codeBytes]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		// The reader's own text is not repeated: it belongs to a source the
		// library does not know. The cause stays reachable through errors.Is.
		return "", [32]byte{}, diag.Wrap(err, "recovery: random source failed")
	}

	return encodeCode(raw), sha256.Sum256(raw[:]), nil
}

// encodeCode writes raw as 26 Crockford base32 characters, most significant
// first, grouped in fours with dashes.
//
// The 128 bits are read as a 130-bit big-endian value with two leading zero
// bits, and taken 5 bits at a time. Package encoding/base32 is not used: its
// alphabet differs and it pads a partial group rather than widening the value.
func encodeCode(raw [codeBytes]byte) string {
	out := make([]byte, 0, codeChars+codeChars/codeGroup)

	for i := range codeChars {
		if i > 0 && i%codeGroup == 0 {
			out = append(out, '-')
		}

		out = append(out, codeAlphabet[fiveBits(raw, i)])
	}

	return string(out)
}

// fiveBits returns the i-th 5-bit group of raw read as a 130-bit value with two
// leading zero bits. Group i covers bits [5i-2, 5i+3) of raw, counting from its
// most significant bit; positions before bit 0 are the leading zeros.
func fiveBits(raw [codeBytes]byte, i int) byte {
	var v byte

	for b := 5*i - 2; b < 5*i+3; b++ {
		v <<= 1
		if b >= 0 && raw[b/8]&(0x80>>(b%8)) != 0 {
			v |= 1
		}
	}

	return v
}

// codeValues maps an ASCII byte to its 5-bit value, or to -1 for a byte that is
// not a code character. Lower case folds to upper case, and the look-alikes
// O, I and L read as 0, 1 and 1, as Crockford's decoding defines.
var codeValues = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}

	for v, c := range []byte(codeAlphabet) {
		t[c] = int8(v)
		t[c|0x20] = int8(v) // lower case; a no-op on digits, which have no case
	}

	for _, alias := range []struct{ from, to byte }{{'O', '0'}, {'I', '1'}, {'L', '1'}} {
		t[alias.from] = t[alias.to]
		t[alias.from|0x20] = t[alias.to]
	}

	return t
}()

// parseCode reads a presented saved code and returns the hash the store keeps
// it under.
//
// It ignores dashes wherever they fall and folds case, reads O as 0 and I or L
// as 1, and refuses anything else: another character outside the alphabet
// (spaces and U included), a length other than 26 characters, or a first
// character above 7, which would not fit in 16 bytes. Every refusal is
// ErrRefused, and its text never quotes the presented value.
//
// The hash is taken over the decoded bytes rather than the text, so every
// accepted spelling of one code hashes alike.
func parseCode(presented string) (hash [32]byte, err error) {
	var (
		raw [codeBytes]byte
		n   int
	)

	for i := range len(presented) {
		c := presented[i]
		if c == '-' {
			continue
		}

		v := codeValues[c]
		if v < 0 || n == codeChars || (n == 0 && v > maxFirstChar) {
			return [32]byte{}, ErrRefused
		}

		setFiveBits(&raw, n, byte(v))
		n++
	}

	if n != codeChars {
		return [32]byte{}, ErrRefused
	}

	return sha256.Sum256(raw[:]), nil
}

// setFiveBits writes v as the i-th 5-bit group of raw, read as fiveBits reads
// it. The bits of group 0 that fall before bit 0 are the leading zeros, which
// the caller has already checked are zero.
func setFiveBits(raw *[codeBytes]byte, i int, v byte) {
	for k := range 5 {
		b := 5*i - 2 + k
		if b >= 0 && v&(0x10>>k) != 0 {
			raw[b/8] |= 0x80 >> (b % 8)
		}
	}
}
