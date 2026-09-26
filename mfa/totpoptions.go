package mfa

import (
	"io"
	"log/slog"
	"time"

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

// WithClock replaces time.Now as the source of the instant codes are matched
// against. A nil clock is a construction error.
//
// It exists for tests, which must pin the time step a code belongs to, and for
// a deployment whose notion of now comes from somewhere other than the process
// clock.
func WithClock(now func() time.Time) TOTPOption {
	return func(t *TOTP) { t.now = now }
}

// WithRandom replaces crypto/rand.Reader as the source of enrolment secrets. A
// nil reader is a construction error.
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
