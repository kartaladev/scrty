package id

import (
	"encoding/json"
	"fmt"
)

// MarshalText returns the canonical lowercase text form. It also serves JSON encoding.
func (i ID) MarshalText() ([]byte, error) { return []byte(i.String()), nil }

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
// JSON null, numbers and other values fail; use *ID or omitzero for optional fields.
func (i *ID) UnmarshalJSON(data []byte) error {
	var s string
	if string(data) == "null" || json.Unmarshal(data, &s) != nil {
		return fmt.Errorf("%w: JSON value %s is not an identifier string", ErrInvalid, describe(string(data)))
	}
	return i.UnmarshalText([]byte(s))
}
