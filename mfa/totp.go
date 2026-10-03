package mfa

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

//go:generate mockgen -destination=idgenerator_mock_test.go -package=mfa_test -typed github.com/kartaladev/scrty/pkg/id Generator

// TOTP is the built-in second-factor method: RFC 6238 time-based codes from an
// authenticator app.
//
// Codes are HMAC-SHA-1 with a tolerance of one step either side. The algorithm
// and the tolerance are fixed rather than configurable, because authenticator
// apps widely ignore any other algorithm parameter in a provisioning URI, so an
// option here would mostly produce enrolments that cannot be used.
//
// It satisfies Method, and is safe for concurrent use as long as its store is.
type TOTP struct {
	store  EnrolmentStore
	issuer string
	digits int
	period time.Duration
	clock  clock.Clock
	random io.Reader
	ids    id.Generator
	logger *slog.Logger

	// verifyLimit and verifyWindow bound the verification attempts charged
	// against one enrolment: at most verifyLimit per window of verifyWindow.
	verifyLimit  int
	verifyWindow time.Duration

	// proofs is the store as a DeviceProofStore, or nil when it does not
	// implement the port. It is decided once, at construction.
	proofs DeviceProofStore
}

// NewTOTP builds the method for issuer.
//
// issuer is required and appears in every provisioning URI, which is what an
// authenticator app shows beside the code. The library supplies no default: a
// name belongs to the consumer's product, not to scrty, and an issuer that was
// stored but never shown would be worse than none.
//
// Defaults: 6 digits (WithDigits, which also accepts 8), a 30-second step
// (WithPeriod), clock.System() (WithClock), crypto/rand.Reader (WithRandom) and
// id.NewV7Generator for enrolment generations (WithTOTPIDGenerator), and 5
// verification attempts per enrolment per 15 minutes (WithVerifyAttempts). store
// has no default — an enrolment store is the one thing this method cannot
// invent, and NewMemoryEnrolmentStore is the obvious argument for a test or a
// single process.
//
// Construction fails on an absent store, an empty issuer, an issuer containing
// ':' — the separator of the provisioning URI's label — a digit count that is
// neither 6 nor 8, a period of zero or less, a verification attempt limit or
// window of zero or less, and a nil clock, random source or identifier
// generator.
// Each of those is a wiring mistake whose symptom would otherwise appear at the
// first verification, a long way from its cause.
func NewTOTP(store EnrolmentStore, issuer string, opts ...TOTPOption) (*TOTP, error) {
	t := &TOTP{
		store:  store,
		issuer: issuer,
		digits: 6,
		period: 30 * time.Second,
		clock:  clock.System(),
		random: rand.Reader,
		ids:    id.NewV7Generator(),
		logger: slog.Default(),

		verifyLimit:  DefaultVerifyAttemptLimit,
		verifyWindow: DefaultVerifyAttemptWindow,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(t)
		}
	}

	if nilcheck.IsNil(t.store) {
		return nil, errors.New("mfa: totp requires an enrolment store")
	}

	if t.issuer == "" {
		return nil, errors.New("mfa: totp requires an issuer, which the library does not default")
	}

	if strings.Contains(t.issuer, ":") {
		return nil, fmt.Errorf("mfa: totp issuer must not contain ':', got %q", t.issuer)
	}

	if t.digits != 6 && t.digits != 8 {
		return nil, fmt.Errorf("mfa: totp digits must be 6 or 8, got %d", t.digits)
	}

	if t.period <= 0 {
		return nil, fmt.Errorf("mfa: totp period must be positive, got %s", t.period)
	}

	if t.verifyLimit <= 0 {
		return nil, fmt.Errorf("%w: totp verification attempt limit must be positive, got %d", ErrConfig, t.verifyLimit)
	}

	if t.verifyWindow <= 0 {
		return nil, fmt.Errorf("%w: totp verification attempt window must be positive, got %s", ErrConfig, t.verifyWindow)
	}

	if nilcheck.IsNil(t.clock) {
		return nil, fmt.Errorf("%w: totp clock must not be nil", ErrConfig)
	}

	if nilcheck.IsNil(t.random) {
		return nil, fmt.Errorf("%w: totp random source must not be nil", ErrConfig)
	}

	if t.logger == nil {
		return nil, errors.New("mfa: totp logger must not be nil")
	}

	if nilcheck.IsNil(t.ids) {
		return nil, errors.New("mfa: totp identifier generator must not be nil")
	}

	t.proofs, _ = t.store.(DeviceProofStore)

	return t, nil
}

// Name reports "totp".
func (t *TOTP) Name() string { return "totp" }

// Channel reports factor.AuthenticatorApp, the channel of no first-factor kind
// the library names — which is exactly why an authenticator code is a second
// factor after any of them.
func (t *TOTP) Channel() factor.Channel { return factor.AuthenticatorApp }

// Response reports FormField("code", 4<<10): the code is the "code" field of a
// URL-encoded body of at most 4 KiB, so a plain HTML form verifies a code.
func (t *TOTP) Response() ResponseFormat { return FormField(totpResponseField, totpResponseLimit) }

const (
	// totpResponseField is the form field TOTP's code is read from.
	totpResponseField = "code"

	// totpResponseLimit bounds the verify body; a code is a handful of digits.
	totpResponseLimit = 4 << 10
)

// Digits reports the configured code length. Default: 6.
func (t *TOTP) Digits() int { return t.digits }

// Period reports the configured time step. Default: 30s.
func (t *TOTP) Period() time.Duration { return t.period }

// Verify checks the code in response for user. The response is the value of
// the "code" form field, as the verify endpoint read it.
//
// The order is: read the enrolment, charge the attempt against it, match the
// code against the accepted steps, then ask the store to accept the matched
// step.
//
// The charge comes before the compare, and every presented code is charged,
// a malformed one included: it is one conditional write to the store, so of
// any number of verifications arriving at once, on any number of replicas, at
// most the limit of [WithVerifyAttempts] are compared per window. A refused
// charge returns [ErrVerifyAttemptsExhausted], which matches [ErrVerifyThrottled],
// and the code is not compared at all. An unknown user or an unconfirmed
// enrolment is refused before the charge, and charges nothing.
//
// A code the store accepts gives its charge back, in the window it was charged
// in, so a user who proves the factor spends nothing; a replayed step, which
// the store does not accept, keeps its charge. The give-back runs whether or
// not the caller is still waiting. If it fails it is logged at WARN and the
// verification still succeeds: the user is out one attempt, nothing more.
//
// The accepting store call is last and is the only thing that decides
// acceptance, because it is the one operation that is atomic: a code matched
// by two concurrent verifications reaches AcceptStep twice, and exactly one of
// those calls changes anything. RFC 6238 requires that a verifier not accept a
// code a second time after a successful validation, and this is where that is
// decided.
//
// Every other refusal is ErrInvalidCode — an unknown user, an unconfirmed
// enrolment, a wrong code, a code from outside the window, and a replay. They
// are deliberately indistinguishable: telling them apart would say whether a
// user exists and whether they have enrolled.
//
// A store failure is returned as an error, never as ErrInvalidCode, so a caller
// can tell a refusal from an outage. It is also never reported as "not
// enrolled". Its text is the package's own, never the store's, and the store's
// error still matches through errors.Is and errors.As.
func (t *TOTP) Verify(ctx context.Context, user identity.UserID, response []byte) error {
	code := string(response)

	e, ok, err := t.store.Get(ctx, user)
	if err != nil {
		return enrolmentStoreFailed(err, msgReadFailed)
	}

	if !ok || e.ConfirmedAt.IsZero() {
		t.record(ctx, slog.LevelDebug, msgCodeRefused, user, slog.String("reason", "no-enrolment"))

		return ErrInvalidCode
	}

	until, charged, err := t.store.ChargeVerifyAttempt(ctx, user, t.clock.Now(), t.verifyLimit, t.verifyWindow)
	if err != nil {
		return enrolmentStoreFailed(err, "mfa: totp could not charge the verification attempt")
	}

	if !charged {
		t.record(ctx, slog.LevelDebug, msgCodeRefused, user, slog.String("reason", "attempts-spent"))

		return ErrVerifyAttemptsExhausted
	}

	step, matched := t.match(e.Secret, code, t.clock.Now())
	if !matched {
		t.record(ctx, slog.LevelDebug, msgCodeRefused, user, slog.String("reason", "no-match"))

		return ErrInvalidCode
	}

	accepted, err := t.store.AcceptStep(ctx, user, step)
	if err != nil {
		return enrolmentStoreFailed(err, "mfa: totp could not record the accepted step")
	}

	if !accepted {
		t.record(ctx, slog.LevelDebug, msgCodeRefused, user, slog.String("reason", "step-spent"))

		return ErrInvalidCode
	}

	// A success gives back its own charge, in the window it was charged in,
	// so a user who proves the factor spends nothing. A caller hanging up
	// after the code was accepted must not cost them an attempt, so the
	// give-back does not inherit the request's cancellation. Failing to give
	// it back costs the user one attempt and refuses nothing.
	if _, err := t.store.RefundVerifyAttempt(context.WithoutCancel(ctx), user, until); err != nil {
		t.record(ctx, slog.LevelWarn, msgGiveBackFailed, user, diag.Failure("enrolment-store", err)...)
	}

	t.record(ctx, slog.LevelDebug, msgCodeAccepted, user)

	return nil
}

// Enrolled reports whether user has a confirmed, readable enrolment.
//
// A store failure is an error, never a false: a false is read as "this user has
// no second factor" and completes the login on its first factor. A pending
// enrolment is also false — it was begun and never proved. The error's text is
// the package's own; the store's error still matches by identity.
func (t *TOTP) Enrolled(ctx context.Context, user identity.UserID) (bool, error) {
	e, ok, err := t.store.Get(ctx, user)
	if err != nil {
		return false, enrolmentStoreFailed(err, msgReadFailed)
	}

	return ok && !e.ConfirmedAt.IsZero(), nil
}

// match finds the time step whose code equals the presented one.
//
// The shape matters. The code is rejected on its form first, so a malformed
// code never reaches the store. Then every candidate step is computed and
// compared in constant time — every one of them, without an early return —
// because returning as soon as one matches leaks, through timing, which step
// the code belonged to.
//
// The window is one step either side. A verifier with no tolerance refuses
// codes from a phone whose clock drifted by seconds; a wider one multiplies the
// codes an attacker may guess at.
func (t *TOTP) match(secret []byte, code string, at time.Time) (int64, bool) {
	if len(code) != t.digits || !isASCIIDigits(code) {
		return 0, false
	}

	seconds := int64(t.period.Seconds())
	step := at.Unix() / seconds

	// The secret's base32 form and the presented code's bytes are the same for
	// every candidate, so they are prepared once. Every candidate is still
	// computed and still compared, which is what the constant-time property
	// rests on; what is hoisted is identical work, not a branch.
	encoded := encodeSecret(secret)
	presented := []byte(code)

	var (
		matched int64
		found   bool
	)

	for _, candidate := range []int64{step - 1, step, step + 1} {
		expected, err := t.codeForStep(encoded, candidate)
		if err != nil {
			continue
		}

		if subtle.ConstantTimeCompare([]byte(expected), presented) == 1 {
			matched, found = candidate, true
		}
	}

	return matched, found
}

// codeForStep computes the code for one time step, HMAC-SHA-1 over the step
// counter as RFC 6238 specifies. secret is already in the base32 form
// encodeSecret produces.
func (t *TOTP) codeForStep(secret string, step int64) (string, error) {
	at := time.Unix(step*int64(t.period.Seconds()), 0)

	return totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
		Period:    uint(t.period.Seconds()),
		Digits:    otp.Digits(t.digits),
		Algorithm: otp.AlgorithmSHA1,
	})
}

// encodeSecret renders a raw secret in the base32 form both authenticators and
// the code generator read it in.
func encodeSecret(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// isASCIIDigits reports whether s is entirely ASCII 0-9.
//
// strconv.Atoi would accept a leading sign, and unicode.IsDigit would accept
// digits from other scripts that no authenticator produces. Neither is what a
// six-character numeric code means.
func isASCIIDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return len(s) > 0
}

// Provisioning is what a user needs to add the enrolment to an authenticator.
type Provisioning struct {
	// Secret is the shared secret in base32, for a user typing it in.
	Secret string

	// URI is the otpauth:// URI, which an authenticator reads from a QR code
	// the consumer renders. The library renders no image.
	URI string
}

// BeginEnrolment starts an enrolment for user and returns what to show them.
//
// accountLabel is what the authenticator app displays beside the issuer,
// typically the user's email address. It belongs to the consumer and is never
// derived from the user reference, which may be an internal identifier the user
// has never seen and should not be shown. An empty label, or one containing
// ':', is refused: ':' separates the issuer from the label in the provisioning
// URI.
//
// The enrolment is pending until ConfirmEnrolment accepts a code from it. A
// pending enrolment does not count as enrolled and satisfies no challenge, so a
// user who begins and abandons enrolment is exactly where they started.
//
// Beginning again while an enrolment is pending replaces the pending secret.
// Beginning for a user with a confirmed enrolment fails with ErrAlreadyEnrolled
// — the store's own, returned as itself when the store returns it bare — and
// changes nothing: replacing a working second factor silently is how a user is
// locked out of their own account. RemoveEnrolment is the explicit way. Any
// other store failure comes back with the package's own text, the store's
// error still matching by identity.
//
// The secret is read before anything is written, so a random source that fails
// leaves no half-made enrolment behind.
func (t *TOTP) BeginEnrolment(
	ctx context.Context, user identity.UserID, accountLabel string,
) (Provisioning, error) {
	p, _, err := t.BeginEnrolmentGeneration(ctx, user, accountLabel)

	return p, err
}

// BeginEnrolmentGeneration is BeginEnrolment, also returning the generation
// the new pending enrolment was stored on.
//
// Every call draws a new generation from the method's identifier generator
// before anything is written, so a generator that fails, like a random source
// that fails, stores nothing; so does a generator that returns the nil
// identifier, which no device proof could ever match. The enrolment path
// records the generation on the session that began, and proves and completes
// only that generation.
func (t *TOTP) BeginEnrolmentGeneration(
	ctx context.Context, user identity.UserID, accountLabel string,
) (Provisioning, id.ID, error) {
	if accountLabel == "" {
		return Provisioning{}, id.Nil, errors.New("mfa: totp enrolment requires an account label")
	}

	if strings.Contains(accountLabel, ":") {
		return Provisioning{}, id.Nil, fmt.Errorf(
			"mfa: totp account label must not contain ':', got %q", accountLabel)
	}

	secret := make([]byte, secretBytes)
	if _, err := io.ReadFull(t.random, secret); err != nil {
		return Provisioning{}, id.Nil, fmt.Errorf("mfa: totp could not read a secret: %w", err)
	}

	gen, err := t.ids.NewID()
	if err != nil {
		return Provisioning{}, id.Nil, fmt.Errorf("mfa: totp could not draw an enrolment generation: %w", err)
	}

	// The nil generation matches nothing on the device-proof port, so an
	// enrolment stored on it could never be proven or completed.
	if gen == id.Nil {
		return Provisioning{}, id.Nil, errors.New("mfa: totp identifier generator returned the nil identifier")
	}

	encoded := encodeSecret(secret)

	if err := t.store.PutPending(ctx, Enrolment{
		User:       user,
		Secret:     secret,
		CreatedAt:  t.clock.Now(),
		Generation: gen,
	}); err != nil {
		return Provisioning{}, id.Nil, enrolmentStoreFailed(err, "mfa: totp could not store the pending enrolment")
	}

	t.record(ctx, slog.LevelInfo, msgEnrolmentBegun, user)

	return Provisioning{Secret: encoded, URI: t.provisioningURI(accountLabel, encoded)}, gen, nil
}

// secretBytes is the length of a TOTP shared secret. RFC 4226 requires at least
// 128 bits and recommends 160, which is also the output length of the SHA-1
// these codes are computed with.
const secretBytes = 20

// provisioningURI builds the otpauth URI. The label is escaped as a path
// segment, so an address with a '+' or a space survives it.
func (t *TOTP) provisioningURI(label, secret string) string {
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   "/" + t.issuer + ":" + label,
	}

	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", t.issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(t.digits))
	q.Set("period", strconv.Itoa(int(t.period.Seconds())))
	u.RawQuery = q.Encode()

	return u.String()
}

// ConfirmEnrolment turns a pending enrolment into a usable one.
//
// It requires a code computed from the pending secret, which is what proves the
// user actually added it to an authenticator: confirming without one would
// enrol users into a second factor they cannot present. The matched step is
// recorded with the enrolment, so the code that confirmed cannot then be
// presented again as a verification.
//
// A wrong, malformed or out-of-window code, a user with nothing pending, and an
// enrolment that is already confirmed all return ErrInvalidCode and change
// nothing. So does any enrolment whose device was proven on the enrolment
// path, whatever the state of its emailed code: such an enrolment completes
// only through the path, by Enroller.CompleteEnrolment or
// Enroller.RedeemEmailCode. A store failure is returned with the package's own
// text, the store's error still matching by identity.
//
// Known limit: it reads the enrolment, then calls the store's Confirm, which
// conditions on neither the generation nor the device proof. A device proof
// landing between that read and that write, or not yet visible to a store
// whose reads may lag its writes, is not seen, and the enrolment is
// confirmed with it. This call serves out-of-band enrolment through a
// consumer's own route, which a session confined to the enrolment path cannot
// reach; a consumer exposing both to one session should not offer this call
// while an enrolment-path proof may be in flight.
func (t *TOTP) ConfirmEnrolment(ctx context.Context, user identity.UserID, code string) error {
	e, ok, err := t.store.Get(ctx, user)
	if err != nil {
		return enrolmentStoreFailed(err, msgReadFailed)
	}

	if !ok || !e.ConfirmedAt.IsZero() || !e.DeviceProvenAt.IsZero() || !e.EmailCodeUntil.IsZero() {
		return ErrInvalidCode
	}

	step, matched := t.match(e.Secret, code, t.clock.Now())
	if !matched {
		return ErrInvalidCode
	}

	confirmed, err := t.store.Confirm(ctx, user, step, t.clock.Now())
	if err != nil {
		return enrolmentStoreFailed(err, "mfa: totp could not confirm the enrolment")
	}

	if !confirmed {
		return ErrInvalidCode
	}

	t.record(ctx, slog.LevelInfo, msgEnrolmentConfirmed, user)

	return nil
}

// RemoveEnrolment deletes the user's enrolment record, pending or confirmed.
//
// It removes the enrolment and nothing else. Whether the user is required to
// use a second factor lives with the user, in the consumer's own requirement
// lookup, and this call cannot reach it — which is what makes a removed
// enrolment refuse a required user's next login rather than complete it on the
// first factor.
//
// Removing an enrolment the store does not hold is not an error: the caller
// wanted it gone and it is gone. Afterwards the user may enrol again. A store
// failure is returned with the package's own text, the store's error still
// matching by identity.
func (t *TOTP) RemoveEnrolment(ctx context.Context, user identity.UserID) error {
	if err := t.store.Delete(ctx, user); err != nil {
		return enrolmentStoreFailed(err, "mfa: totp could not remove the enrolment")
	}

	t.record(ctx, slog.LevelInfo, msgEnrolmentRemoved, user)

	return nil
}

// The messages this method writes. They are constants because a consumer may
// route on them and a test asserts on what they do not carry.
const (
	msgCodeRefused        = "mfa: totp code refused"
	msgCodeAccepted       = "mfa: totp code accepted"
	msgGiveBackFailed     = "mfa: totp could not give back the verification attempt"
	msgEnrolmentBegun     = "mfa: totp enrolment begun"
	msgEnrolmentConfirmed = "mfa: totp enrolment confirmed"
	msgEnrolmentRemoved   = "mfa: totp enrolment removed"

	msgEnrolmentDeviceProven = "mfa: totp enrolment device proven"
	msgDeviceRefused         = "mfa: totp enrolment device code refused"
	msgCompletionRefused     = "mfa: totp enrolment completion refused"
	msgEmailCodeRefused      = "mfa: totp enrolment emailed code refused"
)

// record writes one event about a user.
//
// Every record carries the method and the user reference, and a refusal carries
// why. The user reference is kept on purpose: it is the consumer's opaque
// identifier, and without it an operator could not tell whose factor changed.
// None of them is ever given the presented code, the emailed code, the
// enrolment secret or the provisioning URI: those are what an attacker who
// reaches the logs would come for, and a record that named one would hand over
// the second factor itself. Verification records are written at debug, because
// they are ordinary traffic an attacker can drive; enrolment changes are
// written at info, because they change what the account is protected by.
func (t *TOTP) record(
	ctx context.Context, level slog.Level, msg string, user identity.UserID, attrs ...slog.Attr,
) {
	t.logger.LogAttrs(ctx, level, msg,
		append([]slog.Attr{
			slog.String("method", t.Name()),
			slog.String("user", string(user)),
		}, attrs...)...)
}

// msgReadFailed is the text of an enrolment the store could not read.
const msgReadFailed = "mfa: totp could not read the enrolment"

// enrolmentStoreBare are the sentinels EnrolmentStore's contract lets a store
// return bare: PutPending's ErrAlreadyEnrolled.
var enrolmentStoreBare = []error{ErrAlreadyEnrolled}

// enrolmentStoreFailed returns an EnrolmentStore failure with text of the
// package's own in place of the store's, the store's error still reachable
// through errors.Is and errors.As. A sentinel the contract lets the store
// return bare comes back as itself, text included.
//
// The bare sentinels are not given to diag.Wrap as kinds: a kind is what every
// failure is answered as, and a store outage is not ErrAlreadyEnrolled. A
// store's own error that wraps a sentinel still matches it, through its cause.
func enrolmentStoreFailed(err error, text string) error {
	return storeFailed(err, text, enrolmentStoreBare)
}

// deviceProofStoreFailed is enrolmentStoreFailed for a DeviceProofStore, whose
// contract names no sentinel a store returns bare.
func deviceProofStoreFailed(err error, text string) error {
	return storeFailed(err, text, nil)
}

// storeFailed returns err itself when it is exactly one of bare, and otherwise
// err behind text.
func storeFailed(err error, text string, bare []error) error {
	for _, sentinel := range bare {
		if err == sentinel { //nolint:errorlint // identity: only a bare sentinel passes through
			return err
		}
	}

	return diag.Wrap(err, text)
}
