package mfa

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/identity"
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
}

// EnrolmentStore holds enrolments.
//
// Two of its operations decide an outcome by the write rather than by a
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
	PutPending(ctx context.Context, e Enrolment) error

	// Confirm marks the user's pending enrolment confirmed at the given time
	// and records step. It reports false when there was no pending enrolment to
	// confirm.
	Confirm(ctx context.Context, user identity.UserID, step int64, at time.Time) (bool, error)

	// AcceptStep records step for user in the same operation that decides
	// whether it may be accepted. It reports false when the enrolment is not
	// confirmed, or when the recorded step is already at or past step.
	AcceptStep(ctx context.Context, user identity.UserID, step int64) (bool, error)

	// Delete removes the user's enrolment. Deleting an absent enrolment is not
	// an error: the caller wanted it gone and it is gone.
	Delete(ctx context.Context, user identity.UserID) error
}
