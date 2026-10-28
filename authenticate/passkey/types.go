package passkey

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// State is a credential's lifecycle state. The zero value is not a state.
type State uint8

const (
	// StateActive is a credential that may log in and verify.
	StateActive State = iota + 1
	// StatePending is a credential awaiting at least one confirmation, named
	// by its PendingReason bits. It is not usable.
	StatePending
	// StateSuspended is a credential refused for good, for example after a
	// suspected clone. It is not usable, and it never becomes active again.
	StateSuspended
)

// PendingReason is the set of confirmations a pending credential awaits. A
// credential is pending while any bit is set; clearing the last one makes it
// active.
type PendingReason uint8

const (
	// AwaitingSavedCodes waits for the user to confirm saved recovery codes.
	AwaitingSavedCodes PendingReason = 1 << iota
	// AwaitingEmailCode waits for the user to enter a code emailed to them.
	AwaitingEmailCode
)

// UserVerification is the user-verification requirement of a ceremony.
type UserVerification uint8

const (
	// UVRequired requires the authenticator to verify the user. It is the
	// default.
	UVRequired UserVerification = iota + 1
	// UVPreferred asks for user verification but accepts its absence.
	UVPreferred
)

// ResidentKey is the discoverable-credential requirement of a registration.
type ResidentKey uint8

const (
	// ResidentKeyRequired requires a discoverable credential. It is the
	// default.
	ResidentKeyRequired ResidentKey = iota + 1
	// ResidentKeyPreferred asks for a discoverable credential but accepts a
	// non-discoverable one.
	ResidentKeyPreferred
)

// MaxEmailCodeAttempts is the number of attempts a CredentialStore charges
// against one emailed code before refusing every further one. The store
// contract fixes it at five and it is not configurable: the specification
// sets the limit, so a consumer cannot raise it and weaken the guarantee.
const MaxEmailCodeAttempts = 5

// EmailCode is the code emailed to confirm a pending credential, its expiry
// and the attempts charged against it. Durable stores seal Code at rest.
type EmailCode struct {
	Code      string
	ExpiresAt time.Time
	Attempts  int
}

// Credential is one registered passkey.
type Credential struct {
	// ID is the library's identifier, the only name logs and errors use.
	ID   id.ID
	User identity.UserID
	// CredentialID is the WebAuthn credential ID, unique across every user.
	CredentialID []byte
	// PublicKey is the COSE_Key the authenticator registered.
	PublicKey      []byte
	SignCount      uint32
	BackupEligible bool
	BackupState    bool
	Transports     []string
	// AAGUID identifies the authenticator model: 16 bytes, or nil.
	AAGUID []byte
	// AttestationFormat and AttestationStatement are kept only when
	// attestation is recorded.
	AttestationFormat    string
	AttestationStatement []byte
	Name                 string
	CreatedAt            time.Time
	LastUsedAt           time.Time
	State                State
	Pending              PendingReason
	// EmailCode is set while the credential awaits its emailed code.
	EmailCode *EmailCode
}

// Descriptor names a credential in creation or request options.
type Descriptor struct {
	ID         []byte
	Transports []string
}

// CreationInput is what a Verifier needs to render registration options.
type CreationInput struct {
	UserHandle  []byte
	UserName    string
	DisplayName string
	Challenge   string
	Timeout     time.Duration
	Exclude     []Descriptor
	UV          UserVerification
	ResidentKey ResidentKey
}

// RequestInput is what a Verifier needs to render assertion options. An empty
// Allow asks for a discoverable credential.
type RequestInput struct {
	Challenge string
	Timeout   time.Duration
	Allow     []Descriptor
	UV        UserVerification
}

// RegistrationExpectation is what a registration response must match.
type RegistrationExpectation struct {
	Challenge string
	UV        UserVerification
}

// AssertionExpectation is what an assertion response must match.
type AssertionExpectation struct {
	Challenge string
	UV        UserVerification
}

// NewCredential is a verified registration, before it is stored.
type NewCredential struct {
	CredentialID         []byte
	PublicKey            []byte
	SignCount            uint32
	UserVerified         bool
	BackupEligible       bool
	BackupState          bool
	Transports           []string
	AAGUID               []byte
	AttestationFormat    string
	AttestationStatement []byte
	// AttestationTrusted reports whether the attestation chained to a trusted
	// root under the verifier's attestation policy.
	AttestationTrusted bool
}

// AssertionResult is a verified assertion.
type AssertionResult struct {
	SignCount      uint32
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
}

// NormaliseName returns raw trimmed of surrounding white space, or the
// default name "Passkey <YYYY-MM-DD>" for created's date, in created's own
// location, when the trimmed name is empty, is not valid UTF-8, is longer
// than 64 characters, or holds a control character or a Unicode format
// character (category Cf, such as a bidirectional override or a zero-width
// character). A name is replaced, never truncated or refused.
func NormaliseName(raw string, created time.Time) string {
	name := strings.TrimSpace(raw)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > maxNameRunes ||
		strings.ContainsFunc(name, isUnsafeNameRune) {
		return "Passkey " + created.Format(time.DateOnly)
	}

	return name
}

// isUnsafeNameRune reports whether r is a control or format character, which
// could hide or reorder a name when it is displayed.
func isUnsafeNameRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}

// maxNameRunes is the longest name, in characters, a credential keeps.
const maxNameRunes = 64

// errChallengeEncoding is what DecodeChallenge returns for input that is not
// unpadded base64url. It names no part of the input.
var errChallengeEncoding = errors.New("passkey: challenge is not unpadded base64url")

// DecodeChallenge returns the token string a clientDataJSON challenge
// carries: its unpadded base64url (RawURLEncoding) decoding. Padded or
// standard-alphabet input is refused.
func DecodeChallenge(clientDataChallenge string) (string, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(clientDataChallenge)
	if err != nil || len(b) == 0 {
		return "", errChallengeEncoding
	}

	return string(b), nil
}
