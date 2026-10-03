package mfa

//go:generate mockgen -source=store.go -destination=store_mock_test.go -package=mfa_test -typed

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// Enrolment is one user's registration on a method.
type Enrolment struct {
	// User is the consumer's own reference, matched byte-for-byte.
	User identity.UserID

	// Secret is the shared secret. A durable store seals it; an unreadable
	// secret is an error on the way out, never an absent enrolment.
	Secret []byte

	// ConfirmedAt is when a valid code proved the enrolment. Zero means
	// pending, and a pending enrolment is not an enrolment: it does not count
	// as enrolled and cannot satisfy a challenge.
	ConfirmedAt time.Time

	// LastStep is the most recent time step accepted for this user. It is what
	// makes a code single-use within its window.
	LastStep int64

	// CreatedAt is when the enrolment was begun.
	CreatedAt time.Time

	// Generation identifies one begin. Every begin gives the pending
	// enrolment a new one, and the enrolment path's device proof and completion
	// act only on the generation they name, so a proof made against one
	// provisioned secret can never confirm a secret provisioned by a later
	// begin. It is a pkg/id identifier, never derived from the secret or its
	// ciphertext, which a re-seal would change.
	Generation id.ID

	// DeviceProvenAt is when a code from the pending secret proved the device
	// on the enrolment path. Zero means not yet proven. A store clears it only
	// on PutPending, which starts a new generation.
	DeviceProvenAt time.Time

	// EmailCode is the code emailed to the user when the device was proven,
	// as the store was given it (sealed at rest by a durable store). Nil means
	// none was issued for this generation's proof, or the enrolment was
	// completed or confirmed, or a begin cleared it. A store clears it only on
	// Complete, Confirm or PutPending: never on expiry or when its attempts
	// run out. An expired or exhausted code stays, and ChargeEmailCode refuses
	// it.
	//
	// A reader may still see nil for a code the store keeps: a sealing store
	// (seal.NewEnrolmentStore) does not open a code whose EmailCodeUntil has
	// passed, and reads it back as nil with EmailCodeUntil kept. That the
	// proof issued a code is therefore recorded by EmailCodeUntil, never by
	// this field, and a caller deciding whether a code was issued reads that.
	EmailCode []byte

	// EmailCodeUntil is when EmailCode stops being accepted. Non-zero records
	// that the device proof of this generation issued a code, and that record
	// is what keeps such an enrolment from completing without the code. A store
	// clears it only on PutPending, which starts a new generation: never on
	// expiry, exhaustion, completion or confirmation.
	EmailCodeUntil time.Time

	// EmailCodeAttempts counts the attempts charged against EmailCode, each
	// before its comparison. A begin and a device proof reset it.
	EmailCodeAttempts int

	// VerifyAttempts counts the TOTP verification attempts charged in the
	// window ending at VerifyWindowUntil. ChargeVerifyAttempt raises it and
	// RefundVerifyAttempt lowers it; PutPending clears it.
	VerifyAttempts int

	// VerifyWindowUntil is when the current charging window ends. Zero means
	// no window is open. A durable store keeps it to the microsecond.
	// PutPending clears it.
	VerifyWindowUntil time.Time
}

// EnrolmentStore holds enrolments.
//
// Four of its operations decide an outcome by the write rather than by a
// preceding read, and an implementation that reads first and then writes is
// wrong however careful the read is:
//
//   - PutPending must refuse when a confirmed enrolment exists, decided by the
//     write, so two concurrent begins cannot both replace one confirmed
//     enrolment.
//   - AcceptStep must be one conditional update — set the last step to this one
//     only where the enrolment is confirmed and the recorded step is strictly
//     lower — and report whether it changed anything. On a SQL backend that is a
//     single UPDATE with the condition in its WHERE clause. It is what makes
//     each time step usable once per user, so of concurrent verifications of one
//     code, exactly one succeeds.
//   - ChargeVerifyAttempt must be one conditional update that opens a new
//     window or counts one more below the limit, and RefundVerifyAttempt one
//     that lowers a positive count only in the window it names. On a SQL
//     backend each is a single UPDATE with its condition in its WHERE
//     clause. They are what bound the TOTP codes compared against one
//     enrolment per window, however many verifications race.
//
// A store failure, or a secret that cannot be read, is returned as an error.
// Never as an absent enrolment: a caller reads absence as "this user has no
// second factor" and lets the login through on its first factor.
//
// There is no default: NewTOTP takes a store as an argument and refuses a nil
// one, because a method cannot invent somewhere to keep enrolments and a
// silent fallback to memory would leave a fleet's second factors in one
// process. NewMemoryEnrolmentStore is what a test or a single process passes,
// and it keeps enrolments in this process only.
//
// An implementation is expected to be safe for concurrent use.
type EnrolmentStore interface {
	// Get returns the user's enrolment. The bool is false only when the store
	// definitively holds none.
	Get(ctx context.Context, user identity.UserID) (Enrolment, bool, error)

	// PutPending stores e as a pending enrolment, replacing an existing pending
	// one. It returns ErrAlreadyEnrolled when a confirmed enrolment exists,
	// decided by the write.
	//
	// The stored enrolment is pending with no accepted time step: its
	// confirmation time and last accepted step are cleared whatever e holds,
	// so a replaced pending enrolment keeps no step spent against its secret.
	//
	// It starts the generation e carries: the stored enrolment takes
	// e.Generation, and its device proof, emailed code, code expiry and attempt
	// count are cleared whatever e holds, so nothing proven against an earlier
	// begin survives a later one.
	PutPending(ctx context.Context, e Enrolment) error

	// Confirm marks the user's pending enrolment confirmed at the given time
	// and records step, never moving the recorded step backwards, and clears
	// any outstanding emailed code. It reports false when there was no pending
	// enrolment to confirm.
	Confirm(ctx context.Context, user identity.UserID, step int64, at time.Time) (bool, error)

	// AcceptStep records step for user in the same operation that decides
	// whether it may be accepted. It reports false when the enrolment is not
	// confirmed, or when the recorded step is already at or past step.
	AcceptStep(ctx context.Context, user identity.UserID, step int64) (bool, error)

	// Delete removes the user's enrolment. Deleting an absent enrolment is not
	// an error: the caller wanted it gone and it is gone.
	Delete(ctx context.Context, user identity.UserID) error

	// ChargeVerifyAttempt charges one TOTP verification attempt at at against
	// the user's confirmed enrolment, in one operation that decides and
	// writes. When the window has ended (none is open, or its end is at or
	// before at) it opens one ending at at+window, truncated to the
	// microsecond, counting one; otherwise it counts one more while fewer
	// than limit are charged. It returns the end of the window charged in,
	// which is what RefundVerifyAttempt must be given back. ok is false, with
	// nothing changed, for an absent or pending enrolment or a full window.
	//
	// Of any number of concurrent charges against one enrolment within one
	// window, at most limit succeed. The limit must be at least 1; the caller
	// validates it, the store does not.
	ChargeVerifyAttempt(
		ctx context.Context, user identity.UserID, at time.Time, limit int, window time.Duration,
	) (until time.Time, ok bool, err error)

	// RefundVerifyAttempt gives back one attempt charged in the window ending
	// at until, in one operation that decides and writes. It reports false,
	// with nothing changed, when the enrolment is absent, its window end is
	// not until, or no attempt is charged. A give-back naming a window that a
	// later charge replaced therefore never lowers the later window's count.
	// until is meant to be the value a charge returned; a durable store
	// compares it at microsecond precision, so an until in the same
	// microsecond as that value is treated as the same window end.
	RefundVerifyAttempt(ctx context.Context, user identity.UserID, until time.Time) (bool, error)
}

// DeviceProofStore is what the enrolment path needs from a store beyond
// EnrolmentStore: proving the device and completing the enrolment as two
// separate writes, each bound to one generation.
//
// It is a port of its own, beside EnrolmentStore rather than on it, so a store
// written against EnrolmentStore alone keeps compiling and keeps serving the
// single-call confirmation of out-of-band enrolment. The enrolment path is
// refused at construction when the method's store does not implement it.
//
// Every method decides its outcome by its write, never by a preceding read: on
// a SQL backend each is a single UPDATE with every condition in its WHERE
// clause, reporting whether a row changed. A read-then-write implementation is
// wrong however careful the read is, because a begin, a proof or a completion
// in another session can land between the two.
//
// The nil generation matches nothing: an enrolment that was never given a
// generation cannot be proven or completed on this port, and a caller that
// passes none proves and completes nothing.
//
// Within one generation, the fields a device proof writes are written once:
// an implementation clears EmailCodeUntil only in PutPending, and EmailCode
// only in Complete, Confirm or PutPending — never when the code expires or
// runs out of attempts. A method reads them before completing to decide
// whether a proof issued a code, so a store that clears either one early
// lets an enrolment complete without the mailbox proof.
//
// An implementation is expected to be safe for concurrent use.
type DeviceProofStore interface {
	// ProveDevice records step as the last accepted step, at as the
	// device-proof time, and code with its expiry codeUntil, only where the
	// user's enrolment is pending on generation gen, its device is not yet
	// proven, and step is later than its recorded step. code is nil when email
	// confirmation is off; a durable store seals it at rest. It reports false
	// when any condition does not hold, and changes nothing then.
	ProveDevice(
		ctx context.Context, user identity.UserID, gen id.ID,
		step int64, code []byte, codeUntil, at time.Time,
	) (bool, error)

	// Complete marks the user's enrolment confirmed at at, and clears its
	// emailed code, only where it is on generation gen, its device is proven
	// and it is not yet confirmed. It reports false otherwise, and changes
	// nothing then. Of concurrent completions of one generation, exactly one
	// reports true.
	Complete(ctx context.Context, user identity.UserID, gen id.ID, at time.Time) (bool, error)

	// ChargeEmailCode charges one attempt against the emailed code of the
	// user's enrolment on generation gen, at time at, and reports the attempt
	// count after the write. It charges only where the enrolment is pending on
	// gen, its device is proven, its code is outstanding and not expired at at,
	// and fewer than MaxEmailCodeFailures attempts have been charged. Otherwise
	// it reports false with a count of 0, and changes nothing.
	//
	// The charge comes before the presented code is compared, and it is the
	// write that decides, so however many requests race on one code, no more
	// than MaxEmailCodeFailures of them ever reach a comparison. A correct code
	// charged as the last allowed attempt still completes; the attempt after it
	// is refused whatever it presents.
	ChargeEmailCode(ctx context.Context, user identity.UserID, gen id.ID, at time.Time) (int, bool, error)
}

// MaxEmailCodeFailures is how many attempts may be charged against one
// emailed code. Every attempt is charged before it is compared, so the fifth
// wrong code leaves no attempt for the right one, which is then refused and the
// user begins again.
const MaxEmailCodeFailures = 5
