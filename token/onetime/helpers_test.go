package onetime_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/kartaladev/scrty/pkg/id"
)

// issuedAt is the instant every test clock starts from.
var issuedAt = time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)

// nilClock is a consumer's clock type; (*nilClock)(nil) is the typed nil an
// unchecked constructor error hands over.
type nilClock struct{}

func (*nilClock) Now() time.Time { return time.Time{} }

// fixedClock is a consumer's own clock with only Now.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

var (
	// checkTokenID and checkSecret stand for one issued token, spelled out so
	// that each row can vary exactly one thing about the record behind it.
	checkTokenID = id.MustParse("01999f00-0000-7000-8000-00000000abcd")
	checkSecret  = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xA5}, 32))
	checkBinding = "device-nonce-a"
)

// sha256Of is what the package stores for a secret or a binding.
func sha256Of(value string) []byte {
	sum := sha256.Sum256([]byte(value))

	return sum[:]
}
