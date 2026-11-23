package admin

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/kartaladev/scrty/identity"
)

// The cursor is base64url (no padding) of: one version byte, then the
// username as stored and the identifier of the last user of the page, each
// with a two-byte big-endian length. It is not signed (design D16): a changed
// cursor only moves the start of a list the caller may already read in full.
const (
	cursorVersion    = 1
	cursorFieldMax   = 1024
	cursorTextMax    = 4 * (1 + 2 + cursorFieldMax + 2 + cursorFieldMax + 2) / 3
	cursorHeaderSize = 2
)

var errCursor = errors.New("cursor does not decode")

// encodeCursor builds the cursor that continues a list after last.
func encodeCursor(last User) (string, error) {
	username := last.Username
	uid := string(last.ID)

	if !cursorField(username) || !cursorField(uid) {
		return "", errors.New("admin: the last user of the page does not fit a cursor")
	}

	b := make([]byte, 0, 1+2*cursorHeaderSize+len(username)+len(uid))
	b = append(b, cursorVersion)
	b = binary.BigEndian.AppendUint16(b, uint16(len(username))) //nolint:gosec // cursorField bounds it to 1024
	b = append(b, username...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(uid))) //nolint:gosec // cursorField bounds it to 1024
	b = append(b, uid...)

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// decodeCursor reads a cursor strictly: any deviation from the layout is
// errCursor.
func decodeCursor(text string) (username string, id identity.UserID, err error) {
	if len(text) > cursorTextMax {
		return "", "", errCursor
	}

	b, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || len(b) == 0 || b[0] != cursorVersion {
		return "", "", errCursor
	}

	b = b[1:]

	username, b, ok := cursorTake(b)
	if !ok {
		return "", "", errCursor
	}

	uid, b, ok := cursorTake(b)
	if !ok || len(b) != 0 {
		return "", "", errCursor
	}

	return username, identity.UserID(uid), nil
}

// cursorTake reads one length-prefixed field.
func cursorTake(b []byte) (field string, rest []byte, ok bool) {
	if len(b) < cursorHeaderSize {
		return "", nil, false
	}

	n := int(binary.BigEndian.Uint16(b))
	b = b[cursorHeaderSize:]

	if n == 0 || n > cursorFieldMax || n > len(b) {
		return "", nil, false
	}

	field = string(b[:n])
	if !cursorField(field) {
		return "", nil, false
	}

	return field, b[n:], true
}

// cursorField reports whether s can be a cursor field: not empty, within the
// bound, valid UTF-8 and free of NUL.
func cursorField(s string) bool {
	return s != "" && len(s) <= cursorFieldMax && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
