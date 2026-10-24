// Package ascii holds the string helpers that treat only the ASCII letters
// and whitespace specially.
//
// Security names (schemes, hosts, methods, paths, scopes) must compare the way
// their specifications say, which is ASCII case only. The standard library's
// strings.ToLower, strings.EqualFold and strings.TrimSpace apply Unicode
// rules: they fold U+212A (the Kelvin sign) to "k", U+017F (long s) to "s" and
// U+0130 to "i", and they trim U+00A0, so a look-alike spelling would equal a
// name that was never declared. Every helper here works on bytes and changes
// only 'A' to 'Z' and 'a' to 'z', or the six ASCII whitespace bytes.
//
// Working on bytes is safe on UTF-8 input: the bytes rewritten are all below
// 0x80, and those never occur inside a multi-byte sequence, so every
// non-ASCII character passes through intact.
package ascii

import "strings"

// space is the whitespace TrimSpace strips.
const space = " \t\n\v\f\r"

// ToLower returns s with the letters A-Z folded to a-z and every other byte
// unchanged. It returns s itself when there is nothing to fold.
func ToLower(s string) string {
	return flipCase(s, 'A', 'Z')
}

// ToUpper returns s with the letters a-z folded to A-Z and every other byte
// unchanged. It returns s itself when there is nothing to fold.
func ToUpper(s string) string {
	return flipCase(s, 'a', 'z')
}

// flipCase flips the case bit (0x20) of every byte in [lo, hi], an ASCII
// letter range, allocating only once a byte in range is found.
func flipCase(s string, lo, hi byte) string {
	for i := range len(s) {
		if s[i] < lo || s[i] > hi {
			continue
		}

		b := []byte(s)
		for j := i; j < len(b); j++ {
			if b[j] >= lo && b[j] <= hi {
				b[j] ^= 0x20
			}
		}

		return string(b)
	}

	return s
}

// EqualFold reports whether a and b are equal when only the letters A-Z are
// folded to a-z. Every other byte, including every byte of a multi-byte UTF-8
// sequence, must match exactly, so the Kelvin sign never equals "k" and the
// long s never equals "s", as they do under strings.EqualFold.
func EqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range len(a) {
		if lower(a[i]) != lower(b[i]) {
			return false
		}
	}

	return true
}

// TrimSpace strips leading and trailing ASCII whitespace (space, tab,
// newline, vertical tab, form feed, carriage return) from s. Unlike
// strings.TrimSpace it leaves U+00A0 and every other Unicode space in place.
func TrimSpace(s string) string {
	return strings.Trim(s, space)
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}

	return c
}
