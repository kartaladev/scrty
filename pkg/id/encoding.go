package id

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

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
