package ratelimit

import (
	"errors"
	"strconv"
)

// UnavailableMode is what a shared limiter does while the store it counts in
// cannot be reached: an error, a timeout or an exhausted pool while the
// caller's context is still live.
//
// The in-memory limiter has no outage and ignores it. A limiter over shared
// storage takes it through its own constructor's options; each of scrty's
// backend modules does, and a consumer's own Limiter may honour it the same way.
//
// Whatever the mode, a check whose caller context has already ended returns
// true and an error: a hung-up caller is not an outage, and is never answered
// from a degraded mode.
//
// The zero value is UnavailableRefuse, so a consumer who chooses nothing fails
// closed. Any value other than the three declared here is a configuration
// error wherever a mode is accepted.
type UnavailableMode int

const (
	// UnavailableRefuse is the default. While the backend is unavailable a
	// check reports the key as exceeded, with an error wrapping
	// ErrBackendUnavailable, so a guard refuses the attempt as throttled; a
	// record returns that error, and the key it could not record is refused on
	// this instance for one window, even once checks reach the backend again.
	//
	// What it costs, stated: during an outage every flow guarded by the
	// limiter refuses, including second-factor verification, so a user who
	// needs a second factor cannot complete sign-in until the backend returns.
	// It is the default because a limiter that fails open is one an attacker
	// disables by causing the outage.
	UnavailableRefuse UnavailableMode = iota

	// UnavailableFallBackToLocal counts in an in-memory limiter with the same
	// limit and window while the backend is unavailable, and a record that
	// cannot reach the backend is counted there instead. Once the backend is
	// back, a key is exceeded when either the shared count or the local one is.
	//
	// What it gives up, stated: during the outage each replica counts only its
	// own failures, so behind N replicas the effective limit is N times the
	// configured one — the in-memory limiter's own documented bound. Entering
	// and leaving this state is logged at ERROR and WARN. It suits
	// second-factor flows, which keep a per-replica bound without locking
	// users out of sign-in during an outage.
	UnavailableFallBackToLocal

	// UnavailableAllow reports every key as not exceeded and drops every
	// record while the backend is unavailable, logging an ERROR sampled per
	// namespace, and a WARN when the backend is back.
	//
	// What it gives up, stated: there is no limit at all during the outage.
	// It is for a flow whose consumer has another bound in front of it, such as
	// an edge rate limiter.
	UnavailableAllow
)

// ErrBackendUnavailable is wrapped by the error a shared limiter returns,
// in UnavailableRefuse mode, when it could not reach its backend or is not
// trying to because a recent attempt failed. A guard already refuses on any
// limiter error; a caller matches on this one to tell an outage from a check
// its own context abandoned.
var ErrBackendUnavailable = errors.New("ratelimit: backend unavailable")

// String names the mode in lower case, as a log record or an error message
// prints it: "refuse", "fall-back" or "allow". A value that names no mode
// prints as UnavailableMode(n) rather than passing itself off as one of them.
func (m UnavailableMode) String() string {
	switch m {
	case UnavailableRefuse:
		return "refuse"
	case UnavailableFallBackToLocal:
		return "fall-back"
	case UnavailableAllow:
		return "allow"
	default:
		return "UnavailableMode(" + strconv.Itoa(int(m)) + ")"
	}
}
