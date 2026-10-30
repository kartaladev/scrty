package storekit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/seal"
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

// CheckAssurance refuses the asserted amr values and acr of a record when one
// holds text PostgreSQL cannot store. json.Marshal would silently replace
// invalid UTF-8 with U+FFFD, and jsonb refuses an escaped NUL, so the values
// are judged before they are marshalled. The refusal names the field, never
// the value. prefix leads the field names, "federated " for a session and ""
// for a handoff record.
func CheckAssurance(prefix string, amr []string, acr string) error {
	if !Storable(amr...) {
		return unstorable(prefix + "amr")
	}

	return CheckStorable(Text(prefix+"acr", acr))
}

// EncodeAMR is values as the JSON array text a jsonb column holds, "[]" for
// none, nil or empty; it never produces null. The values are stored as given,
// unsealed, and in order.
func EncodeAMR(values []string) (string, error) {
	b, err := json.Marshal(OrNone(values))
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// DecodeAMR is the values a jsonb column holds, in order. An empty array reads
// back as nil, the "none" every store returns, so a record never reports an
// empty non-nil list the in-memory stores would not.
func DecodeAMR(raw []byte) ([]string, error) {
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, errors.New("the stored amr is not a JSON array of strings")
	}
	if len(values) == 0 {
		return nil, nil
	}

	return values, nil
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
	if err := CheckAssurance("federated ", sess.FederatedAMR, sess.FederatedACR); err != nil {
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

// ErrIdentifierInUse is why a bounded insert (OneTimeStore.InsertWithin) of
// an identifier already stored fails. It carries no adapter prefix; the
// adapter wraps it with its own and the operation's name.
var ErrIdentifierInUse = errors.New("the identifier is already in use")

// ErrPasskeyHandleHeld is the refusal of an offered handle another user
// holds. With 64 random bytes it does not happen by chance; it names no part
// of the handle. It carries no adapter prefix; the adapter wraps it with its
// own and the operation's name.
var ErrPasskeyHandleHeld = errors.New("the offered user handle is held by another user")

// ErrStreakContended is AddStreakFailure's error when every run of the upsert
// lost a race to create the streak. It names no identifier, and carries no
// adapter prefix; the adapter wraps it with its own and the operation's name.
var ErrStreakContended = errors.New("the streak was created and deleted concurrently on every run")

// ParseUserID is ref as the identifier it names, or false when ref is not the
// canonical lowercase UUID string the identity stores hand out. pkg/id
// accepts either letter case; a reference is opaque and matched byte for
// byte, so another spelling of the same UUID names no user.
func ParseUserID(ref identity.UserID) (id.ID, bool) {
	uid, err := id.Parse(string(ref))
	if err != nil || uid.String() != string(ref) {
		return id.Nil, false
	}

	return uid, true
}

// CheckUser refuses text PostgreSQL cannot store, naming the field and never
// its value.
func CheckUser(username string, u *identity.UserChange) error {
	fields := []Field{Text("username", username), Text("name", u.Name)}
	for _, r := range u.Roles {
		fields = append(fields, Text("role", r))
	}

	return CheckStorable(fields...)
}

// SurvivingRoles applies the update's role rules: empty names are skipped and
// a repeated name collapses to its first occurrence. No survivor means the
// grants are left as stored.
func SurvivingRoles(names []string) []string {
	out := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}

	return out
}

// BestEffort runs f, recovering any panic it raises. It is only for cleanup
// that runs while another panic is already unwinding, where f's own panic
// would otherwise replace that one.
func BestEffort(f func()) {
	defer func() { _ = recover() }()
	f()
}

// SQLStater is the method PostgreSQL drivers' errors report their SQLSTATE
// through: pgconn.PgError and lib/pq's Error both provide it.
type SQLStater interface{ SQLState() string }

// DetachedError is a database failure cut from the driver's error: fixed
// text and the sentinels it matched, nothing else. DetachedText makes one.
type DetachedError struct {
	text string
	kept []error
}

func (e *DetachedError) Error() string   { return e.text }
func (e *DetachedError) Unwrap() []error { return e.kept }

// DetachedText is err with the driver's error value left out of its chain and
// text in place of err's own text. It stays matchable against each sentinel
// of kept that err matched, whatever text says, and against nothing else.
// kept is the adapter's own list of sentinels that carry no value: the
// context errors and its driver's closed-transaction and closed-connection
// errors.
func DetachedText(err error, text string, kept []error) error {
	var matched []error
	for _, s := range kept {
		if errors.Is(err, s) {
			matched = append(matched, s)
		}
	}

	return &DetachedError{text: text, kept: matched}
}

// Detached is err with the driver's error value left out of its chain and
// its text replaced with the library's own: "database failure", followed by
// the SQLSTATE when err is or wraps an error reporting one through a
// SQLState method and ValidSQLState accepts it. No other text of err's chain
// is kept, neither the driver's message, since a PostgreSQL primary message
// can quote a value, nor any text a library between the driver and the
// adapter adds. It stays matchable against each sentinel of kept that err
// matched, as DetachedText describes, so a caller still tells a
// cancellation from a failure.
func Detached(err error, kept []error) error {
	text := "database failure"

	var st SQLStater
	if errors.As(err, &st) {
		if code := st.SQLState(); ValidSQLState(code) {
			text += " (SQLSTATE " + code + ")"
		}
	}

	return DetachedText(err, text, kept)
}

// ValidSQLState reports whether code has the shape of a SQLSTATE: five digits
// or upper-case letters. A driver, or a consumer's error, reporting anything
// else through its SQLState method adds no text of its own.
func ValidSQLState(code string) bool {
	if len(code) != 5 {
		return false
	}
	for _, c := range []byte(code) {
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') {
			return false
		}
	}

	return true
}

// Column is one users column an update writes, and the value it binds. Its
// name is unexported: a Column comes only from UserColumns or RoleColumn, so
// the column names that reach the SQL text are the ones this package fixes.
type Column struct {
	name  string
	value any
}

// RoleColumn is the users column holding the primary role, bound to value.
func RoleColumn(value any) Column { return Column{name: "role", value: value} }

// UserColumns is the users columns an update writes for the fields u names,
// in a fixed order. Column names come only from this allow-list, never from
// input. A field is written when it was named, whatever its value, and left
// alone otherwise. The email has no column and writes nothing; the roles are
// written by the grant rebuild. The password-changed-at time is its own
// field: naming the password alone never writes it. org is the bound value
// of organization_id, and ts converts the password-changed-at time to the
// value the adapter's driver binds.
func UserColumns(u *identity.UserChange, org any, ts func(time.Time) any) []Column {
	var set []Column
	if u.IsSet(identity.FieldName) {
		set = append(set, Column{name: "name", value: u.Name})
	}
	if u.IsSet(identity.FieldPassword) {
		set = append(set, Column{name: "password", value: OrEmpty(u.Password)})
	}
	if u.IsSet(identity.FieldOrganization) {
		set = append(set, Column{name: "organization_id", value: org})
	}
	if u.IsSet(identity.FieldPasswordChangedAt) {
		set = append(set, Column{name: "password_changed_at", value: ts(u.PasswordChangedAt)})
	}

	return set
}

// UpdateUserQuery is the partial UPDATE of user userID writing set and
// updated_at, with its arguments. userID is bound as given, in the form the
// adapter's driver takes. Each column name is written into the SQL text as it
// is, and a Column carries only names this package fixes.
func UpdateUserQuery(set []Column, now time.Time, userID any) (string, []any) {
	var b strings.Builder
	args := make([]any, 0, len(set)+2)

	b.WriteString("UPDATE users SET ")
	for _, c := range set {
		args = append(args, c.value)
		b.WriteString(c.name + " = $" + strconv.Itoa(len(args)) + ", ")
	}
	args = append(args, now)
	b.WriteString("updated_at = $" + strconv.Itoa(len(args)))
	args = append(args, userID)
	b.WriteString(" WHERE id = $" + strconv.Itoa(len(args)))

	return b.String(), args
}
