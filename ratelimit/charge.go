package ratelimit

import (
	"context"
	"time"
)

// Charger counts a failure before the guarded work rather than after it, for a
// flow whose limit must hold under concurrent attempts.
//
// A guard that checks with Exceeded and records with RecordFailure lets a
// burst through: every attempt in it may read the count before any has
// recorded. A flow that cannot accept that charges first instead, does the
// guarded work only when the charge was accepted, and refunds the charge when
// the attempt succeeds, so only failed attempts spend the allowance.
//
// Limiter embeds it, so every limiter charges and refunds. The limiters scrty
// ships do it in one step: MemoryLimiter under the same lock that guards its
// counts, and the limiters of redisstore, sqlstore and pgxstore each in one
// step on its store. A consumer's own limiter must meet the same line the
// guarantee needs: Charge is one indivisible step. Reading the count and
// recording the failure in two steps, even under a lock released in between
// or with two round trips to a store, is not an implementation of Charge. The
// conformance suite in the test module's ratelimittest package proves it, with
// a case that releases concurrent charges against one key together and fails
// a two-step charge.
//
// An implementation must be safe for concurrent use.
type Charger interface {
	// Charge records one failure for key and reports exceeded=false, or
	// reports exceeded=true and records nothing, in one indivisible step.
	// The receipt of an accepted charge names the failure it recorded; a
	// refused charge returns the zero Receipt.
	//
	// An error means the charge could not be decided, and comes with
	// exceeded=true, so a caller reading only the bool still refuses, as
	// with Exceeded. A context that has already ended is such an error, and
	// nothing is recorded.
	Charge(ctx context.Context, key string) (r Receipt, exceeded bool, err error)

	// Refund removes the failure r recorded, if it is still in the window,
	// and no other: a refund for a failure that has left the window removes
	// nothing, and refunding the zero Receipt does nothing.
	//
	// A receipt belongs to the limiter that issued it. It carries the key
	// and the stamp but not the namespace, so a receipt refunded on another
	// limiter can remove that limiter's failure of the same key and stamp.
	//
	// A caller refunds each receipt once. Two charges of one key at the same
	// instant record equal stamps, and their receipts are equal too, so a
	// receipt refunded a second time may remove the other charge's failure.
	//
	// The context may have had its cancellation stripped, as with
	// RecordFailure, so an implementation that reaches a remote store bounds
	// its own I/O. An error is an outage: the failure may still be counted.
	Refund(ctx context.Context, r Receipt) error
}

// Receipt names the one failure a Charge recorded: the key it was charged to,
// and the stamp it was recorded with. A Refund removes that failure and no
// other, so two charges of one key at the same instant are refunded one at a
// time.
//
// A Receipt whose stamp is the zero time, the zero Receipt among them, names no
// failure, and refunding it does nothing. A Receipt is a comparable value,
// safe to copy.
type Receipt struct {
	key   string
	stamp time.Time
}

// NewReceipt returns the receipt of a failure recorded for key at stamp. A
// limiter calls it from Charge, with the stamp exactly as it stored it, so
// that its Refund can find that stamp again; a limiter that stores stamps at
// a coarser resolution than time.Time passes the stored value.
func NewReceipt(key string, stamp time.Time) Receipt {
	return Receipt{key: key, stamp: stamp}
}

// Key returns the key the failure was charged to.
func (r Receipt) Key() string { return r.key }

// Stamp returns the time the failure was recorded with, as the limiter stored
// it. A limiter compares it with time.Time.Equal, never with ==.
func (r Receipt) Stamp() time.Time { return r.stamp }
