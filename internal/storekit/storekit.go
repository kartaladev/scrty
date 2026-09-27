package storekit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
)

// Storable reports whether PostgreSQL text can hold every one of values: none
// holds a NUL byte, and each is valid UTF-8. A value that fails is refused by
// the writes, never altered; a lookup by one matches nothing, since no such
// value can have been stored.
func Storable(values ...string) bool {
	for _, v := range values {
		if strings.IndexByte(v, 0) >= 0 || !utf8.ValidString(v) {
			return false
		}
	}

	return true
}

// Field is one text value a write stores, and the name its refusal gives it.
// Text makes one.
type Field struct{ name, value string }

// Text is the field named name, holding value.
func Text(name, value string) Field { return Field{name: name, value: value} }

// CheckStorable refuses a write when one of fields holds text PostgreSQL
// cannot store, naming the first such field and never its value.
func CheckStorable(fields ...Field) error {
	for _, f := range fields {
		if !Storable(f.value) {
			return unstorable(f.name)
		}
	}

	return nil
}

// unstorable is the refusal of a write handed text PostgreSQL cannot hold. It
// names the field and never the value.
func unstorable(field string) error {
	return fmt.Errorf("the %s holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store", field)
}

// CheckID refuses the insert of a record, named record, whose own identifier
// v is zero: it is the row's primary key and the caller's to mint.
func CheckID(v id.ID, record string) error {
	if v.IsZero() {
		return fmt.Errorf("the %s id is zero", record)
	}

	return nil
}

// CheckSession refuses a session the stores cannot hold without altering it:
// one with text PostgreSQL cannot store in a column or in its data.
func CheckSession(sess *session.Session) error {
	if err := CheckStorable(
		Text("user reference", string(sess.UserID)),
		Text("first factor", string(sess.FirstFactor)),
		Text("external provider", sess.ExternalProvider),
		Text("external issuer", sess.ExternalIssuer),
		Text("external session identifier", sess.ExternalSessionID),
		Text("external ID token", sess.ExternalIDToken),
	); err != nil {
		return err
	}
	// json.Marshal would replace invalid UTF-8 with U+FFFD, and jsonb refuses
	// an escaped NUL, so the data is judged before it is marshalled.
	for k, v := range sess.Data {
		if !Storable(k, v) {
			return unstorable("session data")
		}
	}

	return nil
}

// RequireCipher is the construction check of a store with sealed columns: a
// nil cipher, typed nil included, is a configuration error wrapping
// errConfig, the adapter's configuration sentinel.
func RequireCipher(c seal.Cipher, errConfig error) error {
	if nilcheck.IsNil(c) {
		return fmt.Errorf("%w: the cipher is nil", errConfig)
	}

	return nil
}

// OrEmpty is b, or an empty value for nil: the byte columns are NOT NULL, a
// driver may send a nil slice as NULL, and a store persists what it is given
// rather than refusing an absent value.
func OrEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}

	return b
}

// OrNone is values, or an empty list for nil, so a JSON array column never
// holds null.
func OrNone(values []string) []string {
	if values == nil {
		return []string{}
	}

	return values
}

// Time is t as stored: UTC, truncated to the microsecond PostgreSQL keeps.
// Truncating here, rather than leaving it to the driver, makes the stored
// value the same whichever adapter wrote it and however its driver sends it
// (PostgreSQL rounds text input).
func Time(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}

// SecretText is how a sealed secret is stored in a text column: base64url
// without padding.
func SecretText(sealed []byte) string {
	return base64.RawURLEncoding.EncodeToString(sealed)
}

// SecretFromText is the sealed secret SecretText stored as text. A stored
// value that is not base64url is an error naming neither the value nor the
// decoder's complaint.
func SecretFromText(text string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return nil, errors.New("the stored secret is not base64url")
	}

	return sealed, nil
}

// flowHandleBytes is how many random bytes a flow handle carries.
const flowHandleBytes = 32

// NewFlowHandle mints the handle a login flow is found by: 32 bytes from
// crypto/rand, base64url without padding. The error is crypto/rand's.
func NewFlowHandle() (string, error) {
	var raw [flowHandleBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// SessionDigest is the key a session is stored and found under: the SHA-256
// of its identifier, so the table never holds the bearer value itself.
func SessionDigest(sessionID string) []byte {
	sum := sha256.Sum256([]byte(sessionID))

	return sum[:]
}
