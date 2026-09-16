package id

// ID is a 16-byte identifier for records scrty owns.
type ID [16]byte

// Nil is the zero ID. It means "no identifier", and no generator scrty ships returns it.
var Nil ID

// IsZero reports whether i is the zero ID.
func (i ID) IsZero() bool { return i == Nil }
