package admin

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// invalid returns an error matching ErrInvalidInput that names what was wrong,
// never the value.
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, fmt.Sprintf(format, args...))
}

// text checks s is valid UTF-8, within limit bytes and free of control
// characters. what names the input for the error.
func text(what, s string, limit int) error {
	switch {
	case len(s) > limit:
		return invalid("%s is longer than %d bytes", what, limit)
	case !utf8.ValidString(s):
		return invalid("%s is not valid UTF-8", what)
	case strings.ContainsFunc(s, unicode.IsControl):
		return invalid("%s contains a control character", what)
	}

	return nil
}

// nonBlank is text that is also not empty or only white space.
func nonBlank(what, s string, limit int) error {
	if strings.TrimSpace(s) == "" {
		return invalid("%s is blank", what)
	}

	return text(what, s, limit)
}

// noNUL checks s is valid UTF-8, within limit bytes and has no NUL byte, the
// bytes a text column refuses.
func noNUL(what, s string, limit int) error {
	switch {
	case len(s) > limit:
		return invalid("%s is longer than %d bytes", what, limit)
	case !utf8.ValidString(s):
		return invalid("%s is not valid UTF-8", what)
	case strings.ContainsRune(s, 0):
		return invalid("%s contains a NUL byte", what)
	}

	return nil
}

// emailValid checks an email and its verification time: an email is empty
// (none) or not blank, within MaxTextBytes and free of control characters, and
// a verification time needs an email.
func emailValid(email string, verifiedAt time.Time) error {
	if email != "" {
		if err := nonBlank("email", email, MaxTextBytes); err != nil {
			return err
		}
	}

	if email == "" && !verifiedAt.IsZero() {
		return invalid("email verification time is set without an email")
	}

	return nil
}

// exactName is nonBlank for a name a store matches exactly: it also refuses
// leading or trailing white space, which would make two spellings of one name.
// Invisible format characters at a name's edge, such as U+200B ZERO WIDTH
// SPACE, are not white space and are not refused (design F41).
func exactName(what, s string, limit int) error {
	if err := nonBlank(what, s, limit); err != nil {
		return err
	}

	if strings.TrimSpace(s) != s {
		return invalid("%s has leading or trailing white space", what)
	}

	return nil
}
