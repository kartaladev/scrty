package id

import (
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// ID is a 16-byte identifier for records scrty owns.
type ID [16]byte

// Nil is the zero ID. It means "no identifier", and no generator scrty ships returns it.
var Nil ID

// ErrInvalid is wrapped by every error returned for input that is not a canonical identifier.
var ErrInvalid = errors.New("id: invalid identifier")

// IsZero reports whether i is the zero ID.
func (i ID) IsZero() bool { return i == Nil }

// String formats i as a lowercase RFC 9562 string: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
func (i ID) String() string {
	buf := i.format()
	return string(buf[:])
}

// format renders the canonical lowercase text of i. It is the only description of
// the text layout; String, MarshalText and every caller go through it.
func (i ID) format() [36]byte {
	var buf [36]byte
	hex.Encode(buf[0:8], i[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], i[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], i[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], i[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], i[10:16])
	return buf
}

// Parse accepts exactly the 36-character hyphenated layout, in either letter case,
// and rejects everything else, the empty string included. It does not check the
// version field, so identifiers from a consumer's generator parse unchanged.
func Parse(s string) (ID, error) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return Nil, fmt.Errorf("%w: %s", ErrInvalid, describe(s))
	}

	// The hyphens sit at fixed positions, so the other 32 characters are the hex digits.
	var digits [32]byte
	n := copy(digits[:], s[0:8])
	n += copy(digits[n:], s[9:13])
	n += copy(digits[n:], s[14:18])
	n += copy(digits[n:], s[19:23])
	copy(digits[n:], s[24:36])

	var i ID
	if _, err := hex.Decode(i[:], digits[:]); err != nil {
		return Nil, fmt.Errorf("%w: %s", ErrInvalid, describe(s))
	}
	return i, nil
}

// MustParse is Parse for tests and constants; it panics on invalid input.
func MustParse(s string) ID {
	i, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return i
}

// describe quotes short input and summarises long input, so errors never echo unbounded data.
func describe(s string) string {
	const maxEcho = 64
	if len(s) > maxEcho {
		return strconv.Itoa(len(s)) + "-byte input"
	}
	return strconv.Quote(s)
}

// MarshalText returns the canonical lowercase text form. It also serves JSON encoding.
func (i ID) MarshalText() ([]byte, error) {
	buf := i.format()
	return buf[:], nil
}

// UnmarshalText parses b with Parse. On error, i is left unchanged.
func (i *ID) UnmarshalText(b []byte) error {
	parsed, err := Parse(string(b))
	if err != nil {
		return err
	}
	*i = parsed
	return nil
}

// UnmarshalJSON accepts only a JSON string holding a canonical identifier.
// JSON null decodes to the empty string, which Parse rejects like any other
// malformed value; numbers and other JSON values fail here. Use *ID or omitzero
// for optional fields.
func (i *ID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("%w: JSON value %s is not an identifier string", ErrInvalid, describe(string(data)))
	}
	return i.UnmarshalText([]byte(s))
}

// Scan implements sql.Scanner. It accepts canonical text (string or []byte) and
// 16-byte binary. SQL NULL and every other type fail; scan nullable columns with
// sql.Null[id.ID]. On error, i is left unchanged.
func (i *ID) Scan(src any) error {
	switch v := src.(type) {
	case string:
		return i.UnmarshalText([]byte(v))
	case []byte:
		if len(v) == len(ID{}) {
			copy(i[:], v)
			return nil
		}
		return i.UnmarshalText(v)
	case nil:
		return fmt.Errorf("%w: SQL NULL", ErrInvalid)
	default:
		return fmt.Errorf("%w: unsupported SQL type %T", ErrInvalid, src)
	}
}

// Value implements driver.Valuer and sends canonical text, which PostgreSQL accepts
// for uuid and text columns. For a BINARY(16) column, pass i[:] explicitly.
func (i ID) Value() (driver.Value, error) { return i.String(), nil }
