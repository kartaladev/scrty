package mfa

import (
	"io"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

// TOTPOption configures the method NewTOTP returns. Every default that
// constructor applies has an option here that replaces it.
//
// A nil option is ignored, so a consumer may build a slice with conditional
// entries without guarding each one.
type TOTPOption func(*TOTP)

// WithDigits sets how many digits a code has, replacing the default of 6.
//
// The only other value is 8; anything else is a construction error. RFC 6238
// admits other lengths, but authenticator apps generate 6 or 8, so a third
// value would produce enrolments whose codes no app can show.
func WithDigits(n int) TOTPOption {
	return func(t *TOTP) { t.digits = n }
}

// WithPeriod sets the length of one time step, replacing the default of 30
// seconds. A period of zero or less is a construction error.
//
// 30 seconds is what authenticator apps assume when a provisioning URI omits
// the period. A deployment that changes it is relying on the app reading the
// period parameter, which not every app does.
func WithPeriod(d time.Duration) TOTPOption {
	return func(t *TOTP) { t.period = d }
}

// WithClock replaces the source of the instant codes are matched against. The
// default is clock.System(). A nil clock, typed nil included, fails NewTOTP
// with ErrConfig.
//
// It exists for tests, which must pin the time step a code belongs to, and for
// a deployment whose notion of now comes from somewhere other than the process
// clock.
//
// This clock also sets an emailed enrolment code's expiry and the instant each
// attempt is charged at. A sealing enrolment store decides by its own clock
// whether that code has expired and is no longer opened (seal.WithClock, and
// WithClock on the durable stores): give it the same clock, or a store clock
// running ahead reads a live code as none and a correct code is refused.
func WithClock(clk clock.Clock) TOTPOption {
	return func(t *TOTP) { t.clock = clk }
}

// WithRandom replaces crypto/rand.Reader as the source of enrolment secrets. A
// nil reader, typed nil included, fails NewTOTP with ErrConfig.
//
// The default is the operating system's cryptographically secure source, which
// is what a shared secret must come from. This option is for tests that need a
// fixed secret or a failing source; a consumer who replaces it in production
// owns the consequences of whatever they supply.
func WithRandom(r io.Reader) TOTPOption {
	return func(t *TOTP) { t.random = r }
}

// WithTOTPLogger replaces slog.Default as the destination for the records this
// method writes: a verification refused or accepted, and an enrolment begun,
// confirmed or removed.
//
// No record carries a presented code, an enrolment secret or a provisioning
// URI, whatever logger is given. Every record names the method and, on purpose,
// the user by the opaque identity.UserID reference the consumer supplied, so an
// operator can tell whose second factor was used or changed; the reference is
// the consumer's own identifier, not an address or a name. A failed store's
// error text is never written; a consumer who wants it logs it inside their own
// EnrolmentStore. A nil logger is a configuration error; a
// consumer who wants silence supplies one with a discarding handler, which says
// so at the wiring.
func WithTOTPLogger(l *slog.Logger) TOTPOption {
	return func(t *TOTP) { t.logger = l }
}

// WithTOTPIDGenerator replaces id.NewV7Generator as the source of enrolment
// generations, the identifier every begin gives its pending enrolment. A nil
// generator is a construction error.
//
// A generation is not a secret: it binds a device proof and a completion to
// one begin, and only needs to differ from every earlier one for the user.
func WithTOTPIDGenerator(g id.Generator) TOTPOption {
	return func(t *TOTP) { t.ids = g }
}

// WithVerifyAttempts replaces how many verification attempts may be charged
// against one enrolment within a window, and the window's length. The default
// is DefaultVerifyAttemptLimit attempts per DefaultVerifyAttemptWindow: 5 per
// 15 minutes. A limit or a window of zero or less fails NewTOTP with
// ErrConfig.
//
// Every presented code is charged against the enrolment, in one conditional
// store write, before it is compared, so at most limit codes are compared per
// window however many requests arrive at once and however many replicas serve
// them. A code the store accepts gives its charge back, so successes spend
// nothing. A charge the window refuses fails the verification with
// ErrVerifyAttemptsExhausted, without comparing the code.
//
// The window is fixed, not sliding: it opens at the first charge after the
// previous one ended and lasts window. Around a window's end, up to twice
// limit codes can therefore be compared within one window's length — limit at
// the end of one window and limit at the start of the next.
//
// There is no way to turn the charge off. It is what bounds the codes compared
// when concurrent requests all pass a VerifyThrottle check before any of their
// failures is recorded; a consumer wanting a looser bound raises the limit.
func WithVerifyAttempts(limit int, window time.Duration) TOTPOption {
	return func(t *TOTP) {
		t.verifyLimit = limit
		t.verifyWindow = window
	}
}
