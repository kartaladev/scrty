package mfa

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// Enroller is a Method a user can enrol in through the enrolment path: from a
// confined session, by beginning an enrolment, proving the device with a code
// from it, and completing it, by default only after an emailed code has proven
// the mailbox too.
//
// Every step after the begin names the generation the begin returned, and acts
// only while it is the enrolment's current generation. So a device proven, or
// a code emailed, against one provisioned secret can never confirm a secret a
// later begin provisioned in another session.
//
// The built-in TOTP method implements it. A consumer's own method may too, and
// is then held to the same order.
//
// An implementation is expected to be safe for concurrent use.
type Enroller interface {
	Method

	// BeginEnrolmentGeneration begins a pending enrolment for user, replacing
	// a pending one, and returns what the user needs to add it to their
	// authenticator and the new generation. A user with a confirmed enrolment is
	// refused with ErrAlreadyEnrolled, and it is left unchanged.
	BeginEnrolmentGeneration(ctx context.Context, user identity.UserID, accountLabel string) (Provisioning, id.ID, error)

	// ProveDevice proves code against the pending secret of generation gen.
	// A wrong code, or a generation that is not current, is ErrInvalidCode and
	// proves nothing. With emailCode true it returns a fresh code for the user's
	// mailbox, accepted for emailCodeTTL; otherwise it returns "". A proven
	// device does not make the enrolment confirmed.
	ProveDevice(
		ctx context.Context, user identity.UserID, gen id.ID,
		code string, emailCode bool, emailCodeTTL time.Duration,
	) (string, error)

	// CompleteEnrolment confirms the enrolment on generation gen, where its
	// device is proven and it is not yet confirmed. It is how the path
	// completes when email confirmation is off.
	//
	// It must complete only when the device proof on gen issued no emailed
	// code: a proof that issued one completes only through RedeemEmailCode,
	// whether the code is outstanding, expired or out of attempts. An
	// implementation over a DeviceProofStore reads the enrolment and goes on
	// only when the read shows the device already proven on gen with
	// EmailCodeUntil zero, then completes with the store's conditional
	// Complete; a read showing the device not yet proven is refused, so a
	// proof landing between the read and the write cannot slip through.
	// Every refusal is ErrInvalidCode and writes nothing.
	CompleteEnrolment(ctx context.Context, user identity.UserID, gen id.ID) error

	// RedeemEmailCode charges one attempt against the emailed code of
	// generation gen, compares code with it in constant time, and completes
	// the enrolment last. It charges before it reads or compares, so a
	// malformed code is charged too, and once MaxEmailCodeFailures attempts
	// have been charged against one code it refuses every later attempt,
	// correct or not: the cap is fixed, not the method's to raise.
	// VoidEmailCode relies on both. Every refusal is ErrEmailCodeInvalid and
	// completes nothing.
	RedeemEmailCode(ctx context.Context, user identity.UserID, gen id.ID, code string) error

	// SupportsEnrolmentPath reports whether the method's store implements
	// DeviceProofStore. A method whose store does not cannot serve the path,
	// and the path refuses it at construction.
	SupportsEnrolmentPath() bool
}

var _ Enroller = (*TOTP)(nil)

// emailCodeDigits is the length of an emailed enrolment code, and
// emailCodeSpace the number of codes of that length.
const (
	emailCodeDigits = 6
	emailCodeSpace  = 1_000_000
)

// msgCompleteFailed is the text of a completion the store could not write.
const msgCompleteFailed = "mfa: totp could not complete the enrolment"

// errNoDeviceProofStore refuses an enrolment-path step on a method whose store
// does not implement DeviceProofStore. It is a wiring mistake, not a wrong
// code, so it is not ErrInvalidCode.
var errNoDeviceProofStore = errors.New("mfa: totp store does not implement DeviceProofStore")

// SupportsEnrolmentPath reports whether the store this method was built with
// implements DeviceProofStore. It is decided once, at construction.
func (t *TOTP) SupportsEnrolmentPath() bool { return t.proofs != nil }

// ProveDevice proves the device on the enrolment path: code must be a valid
// code, within the window, from the pending secret of generation gen.
//
// The order is: read the pending enrolment, match the code, draw the emailed
// code when email confirmation applies, then record the proof in one
// conditional write that decides. Everything that can fail on its own — the
// match, the random source — happens before that write, so a failure leaves
// the device unproven. The write records the matched step, so the code that
// proved the device cannot later be presented again as a verification.
//
// The emailed code is 6 digits drawn uniformly from the method's random
// source, crypto/rand.Reader by default. It is handed to the caller to send,
// and kept on the enrolment (sealed at rest by a durable store). It is
// accepted until emailCodeTTL has passed or its attempts run out, and kept
// until the enrolment completes or a begin replaces it: an expired or
// exhausted code still records that this proof issued one, so the enrolment
// can then complete only by beginning again. It is never written to a log.
//
// A wrong, malformed or out-of-window code, a generation that is not the
// current pending one, and a device already proven are ErrInvalidCode. A store
// failure, a random-source failure, an emailCodeTTL of zero or less with
// emailCode true, and a store without DeviceProofStore are errors that are not.
// A store failure carries the package's own text, never the store's, and the
// store's error still matches by identity.
func (t *TOTP) ProveDevice(
	ctx context.Context, user identity.UserID, gen id.ID,
	code string, emailCode bool, emailCodeTTL time.Duration,
) (string, error) {
	if t.proofs == nil {
		return "", errNoDeviceProofStore
	}

	if emailCode && emailCodeTTL <= 0 {
		return "", fmt.Errorf("mfa: totp emailed code lifetime must be positive, got %s", emailCodeTTL)
	}

	e, ok, err := t.store.Get(ctx, user)
	if err != nil {
		return "", enrolmentStoreFailed(err, msgReadFailed)
	}

	if !ok || !onPendingGeneration(e, gen) {
		t.record(ctx, slog.LevelDebug, msgDeviceRefused, user, slog.String("reason", "not-pending"))

		return "", ErrInvalidCode
	}

	now := t.now()

	step, matched := t.match(e.Secret, code, now)
	if !matched {
		t.record(ctx, slog.LevelDebug, msgDeviceRefused, user, slog.String("reason", "no-match"))

		return "", ErrInvalidCode
	}

	var (
		emailed   string
		codeBytes []byte
		codeUntil time.Time
	)

	if emailCode {
		emailed, err = t.drawEmailCode()
		if err != nil {
			return "", err
		}

		codeBytes, codeUntil = []byte(emailed), now.Add(emailCodeTTL)
	}

	proven, err := t.proofs.ProveDevice(ctx, user, gen, step, codeBytes, codeUntil, now)
	if err != nil {
		return "", deviceProofStoreFailed(err, "mfa: totp could not record the device proof")
	}

	if !proven {
		t.record(ctx, slog.LevelDebug, msgDeviceRefused, user, slog.String("reason", "proof-refused"))

		return "", ErrInvalidCode
	}

	t.record(ctx, slog.LevelInfo, msgEnrolmentDeviceProven, user,
		slog.Bool("email_confirmation", emailCode))

	return emailed, nil
}

// drawEmailCode draws a uniform 6-digit code from the method's random source.
func (t *TOTP) drawEmailCode() (string, error) {
	n, err := rand.Int(t.random, big.NewInt(emailCodeSpace))
	if err != nil {
		return "", fmt.Errorf("mfa: totp could not draw an emailed code: %w", err)
	}

	return fmt.Sprintf("%0*d", emailCodeDigits, n.Int64()), nil
}

// CompleteEnrolment confirms the enrolment on generation gen, where its
// device is proven and no emailed code was issued for that proof: the path's
// completion when email confirmation is off.
//
// It reads the enrolment first and goes on only when the read shows it on
// generation gen, with its device already proven and EmailCodeUntil zero.
// Anything else is ErrInvalidCode, and nothing is written. Then it confirms in
// one conditional write, which succeeds only where the device is proven and
// the enrolment is not yet confirmed, so of concurrent completions of one
// generation exactly one succeeds. A store failure is returned with the
// package's own text, the store's error still matching by identity.
//
// So a proof that issued a code completes only through RedeemEmailCode,
// whether the code is outstanding, expired or out of attempts, and email
// confirmation does not rest on the caller choosing the right step. The read
// cannot go stale before the write: a proof is made once per generation and
// its fields do not change within it, a store clears EmailCodeUntil only on a
// begin, and a begin changes the generation the write checks. A read that shows
// the device not yet proven is refused, which also refuses a proof landing
// between the read and the write.
func (t *TOTP) CompleteEnrolment(ctx context.Context, user identity.UserID, gen id.ID) error {
	if t.proofs == nil {
		return errNoDeviceProofStore
	}

	e, ok, err := t.store.Get(ctx, user)
	if err != nil {
		return enrolmentStoreFailed(err, msgReadFailed)
	}

	switch {
	case !ok || e.Generation != gen || e.DeviceProvenAt.IsZero():
		t.record(ctx, slog.LevelDebug, msgCompletionRefused, user, slog.String("reason", "not-proven"))

		return ErrInvalidCode
	case !e.EmailCodeUntil.IsZero():
		t.record(ctx, slog.LevelDebug, msgCompletionRefused, user, slog.String("reason", "email-code-issued"))

		return ErrInvalidCode
	}

	completed, err := t.proofs.Complete(ctx, user, gen, t.now())
	if err != nil {
		return deviceProofStoreFailed(err, msgCompleteFailed)
	}

	if !completed {
		t.record(ctx, slog.LevelDebug, msgCompletionRefused, user)

		return ErrInvalidCode
	}

	t.record(ctx, slog.LevelInfo, msgEnrolmentConfirmed, user)

	return nil
}

// RedeemEmailCode redeems the code emailed when the device of generation gen
// was proven, in the order that bounds guessing:
//
//  1. charge one attempt, in a conditional write that succeeds only while the
//     enrolment is pending on gen, its device is proven, its code is
//     outstanding and unexpired, and fewer than MaxEmailCodeFailures attempts
//     have been charged;
//  2. read the enrolment, and refuse a presented code that is not exactly six
//     ASCII digits — it is never trimmed or normalised into a match;
//  3. compare it with the emailed code in constant time;
//  4. complete the enrolment, in one conditional write, last.
//
// Charging first, in the write that decides, is what caps the comparisons
// against one code at MaxEmailCodeFailures however many requests race: a
// failure counted after the comparison would let every request that read the
// count before the fifth failure landed compare too. A correct code charged
// as the last allowed attempt still completes.
//
// Every refusal is ErrEmailCodeInvalid, and none completes anything. A store
// failure is returned with the package's own text, the store's error still
// matching by identity.
func (t *TOTP) RedeemEmailCode(ctx context.Context, user identity.UserID, gen id.ID, code string) error {
	if t.proofs == nil {
		return errNoDeviceProofStore
	}

	attempt, charged, err := t.proofs.ChargeEmailCode(ctx, user, gen, t.now())
	if err != nil {
		return deviceProofStoreFailed(err, "mfa: totp could not charge an attempt against the emailed code")
	}

	if !charged {
		t.record(ctx, slog.LevelDebug, msgEmailCodeRefused, user, slog.String("reason", "not-chargeable"))

		return ErrEmailCodeInvalid
	}

	e, ok, err := t.store.Get(ctx, user)
	if err != nil {
		return enrolmentStoreFailed(err, msgReadFailed)
	}

	if !ok || e.Generation != gen || len(code) != emailCodeDigits || !isASCIIDigits(code) {
		t.record(ctx, slog.LevelDebug, msgEmailCodeRefused, user,
			slog.String("reason", "malformed"), slog.Int("attempt", attempt))

		return ErrEmailCodeInvalid
	}

	if subtle.ConstantTimeCompare(e.EmailCode, []byte(code)) != 1 {
		t.record(ctx, slog.LevelDebug, msgEmailCodeRefused, user,
			slog.String("reason", "no-match"), slog.Int("attempt", attempt))

		return ErrEmailCodeInvalid
	}

	completed, err := t.proofs.Complete(ctx, user, gen, t.now())
	if err != nil {
		return deviceProofStoreFailed(err, msgCompleteFailed)
	}

	if !completed {
		t.record(ctx, slog.LevelDebug, msgEmailCodeRefused, user, slog.String("reason", "completion-refused"))

		return ErrEmailCodeInvalid
	}

	t.record(ctx, slog.LevelInfo, msgEnrolmentConfirmed, user)

	return nil
}

// voidingCode is what VoidEmailCode presents: never six digits, so it is
// charged and can never match.
const voidingCode = ""

// VoidEmailCode voids the emailed code of generation gen, so that no later
// RedeemEmailCode can complete the proof that issued it: it charges every
// attempt the code has left by presenting a code that can never match, at most
// MaxEmailCodeFailures times.
//
// It is how a caller that could not deliver the code fails closed. A code
// nobody received must not stay redeemable, or whoever learned it some other
// way — a relay that accepted the mail before the sender reported failure, a
// store read — could still complete the enrolment. The user begins again.
//
// It works through the Enroller contract alone, which charges an attempt
// before it reads or compares the presented code and refuses every attempt
// once MaxEmailCodeFailures have been charged against one code, so
// MaxEmailCodeFailures refused attempts spend the code whatever it had left.
// It therefore holds for a consumer's method that honours that contract as
// for the built-in one; a method that charges late, or allows more attempts,
// may leave the code redeemable. A method that completes the enrolment on
// the never-matching code is broken, and that is returned as an error. Where
// no code is outstanding,
// or it has expired or run out, nothing is charged and it returns nil. An
// error other than ErrEmailCodeInvalid — a store failure — stops it and is
// returned; the code may then keep some attempts.
func VoidEmailCode(ctx context.Context, e Enroller, user identity.UserID, gen id.ID) error {
	for range MaxEmailCodeFailures {
		err := e.RedeemEmailCode(ctx, user, gen, voidingCode)

		switch {
		case err == nil:
			return errVoidCompleted
		case !errors.Is(err, ErrEmailCodeInvalid):
			return err
		}
	}

	return nil
}

// errVoidCompleted reports a method that completed an enrolment on a code that
// can never match: a broken Enroller, not a refusal.
var errVoidCompleted = errors.New("mfa: voiding the emailed code completed the enrolment")
