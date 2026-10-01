package pgschema

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/kartaladev/scrty/recovery"
)

// The proven and reported columns of account_recoveries hold a record's
// authenticator references as text: each reference in its "kind:id" form
// (recovery.AuthenticatorRef.String), one per line, in order, and the empty
// text for none. Every adapter writes and reads them through the two
// functions below, so a record written by one reads back unchanged through
// another.

// ErrRecoveryRefUnstorable is wrapped by RecoveryRefsText's refusal of a
// reference that would not read back as itself: an empty kind or identifier,
// a newline anywhere, a colon in the kind, or text PostgreSQL cannot store (a
// NUL byte or invalid UTF-8). Its text carries no value.
var ErrRecoveryRefUnstorable = errors.New("an authenticator reference cannot be stored as a kind:id line")

// RecoveryRefsText is refs as a proven or reported column holds them.
func RecoveryRefsText(refs []recovery.AuthenticatorRef) (string, error) {
	lines := make([]string, len(refs))
	for i, ref := range refs {
		line := ref.String()
		back, err := recovery.ParseAuthenticatorRef(line)
		if err != nil || back != ref || strings.IndexByte(line, 0) >= 0 || !utf8.ValidString(line) {
			return "", ErrRecoveryRefUnstorable
		}
		lines[i] = line
	}

	return strings.Join(lines, "\n"), nil
}

// ParseRecoveryRefs reads a proven or reported column back: nil for the empty
// text. A line that is not a "kind:id" reference is an error that carries no
// stored value, never a line skipped, since a list read short would plan a
// different reset.
func ParseRecoveryRefs(text string) ([]recovery.AuthenticatorRef, error) {
	if text == "" {
		return nil, nil
	}

	lines := strings.Split(text, "\n")
	refs := make([]recovery.AuthenticatorRef, len(lines))
	for i, line := range lines {
		ref, err := recovery.ParseAuthenticatorRef(line)
		if err != nil {
			return nil, errors.New("a stored authenticator reference is not a kind:id line")
		}
		refs[i] = ref
	}

	return refs, nil
}
