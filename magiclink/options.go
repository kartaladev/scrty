package magiclink

import (
	"io"
	"log/slog"
)

// Option customises a Manager at construction.
//
// Every option replaces a default that already works, so a consumer who passes
// none gets a manager that behaves safely. A nil option is ignored.
type Option func(*Manager)

// WithConfirmPath sets the path on the link base URL that the emailed link
// points at — the page that posts the token back.
//
// The default is "/login/magic/confirm". The path must be host-relative:
// anything absolute or protocol-relative would send the recipient of a live
// sign-in link somewhere other than the consumer's own application, so it
// fails construction with ErrConfig.
func WithConfirmPath(path string) Option {
	return func(m *Manager) { m.confirmPath = path }
}

// WithIssuanceLimit sets how many links one user may be issued within the
// token manager's issuance window.
//
// The default is 5. A limit below 1 fails construction with ErrConfig: it
// would refuse every request, which is a wiring mistake rather than a policy.
//
// The window itself belongs to the token manager, configured there with
// onetime.WithIssuanceWindow, so a one-time credential's timing is set in one
// place.
func WithIssuanceLimit(n int) Option {
	return func(m *Manager) { m.issuanceLimit = n }
}

// WithAddressResolver replaces how a submitted address becomes a user.
//
// The default passes the address to the user loader as a username, exactly as
// submitted — never trimmed, never case-folded. A consumer whose addresses are
// not usernames supplies a resolver, which then becomes the only path: the
// default lookup no longer runs at all.
//
// A nil resolver is ignored and the default is kept.
func WithAddressResolver(r AddressResolver) Option {
	return func(m *Manager) {
		if r != nil {
			m.resolver = r
		}
	}
}

// WithRenderer replaces the message the library sends.
//
// The default is a neutral plain-text message that contains the link, says it
// expires shortly and can be used once, and names no product, brand or
// organisation. A nil renderer fails construction with ErrConfig rather than
// silently restoring the default: a consumer who passed one meant to replace
// the wording, and sending the library's own instead is not what they asked
// for.
//
// Whatever a renderer returns, the recipient is forced to the submitted
// address.
func WithRenderer(r Renderer) Option {
	return func(m *Manager) { m.renderer = r }
}

// WithSameDeviceBinding turns same-device binding on or off.
//
// The default is on: a link is issued bound to a value returned in
// RequestResult, and redemption requires that value back, so a link read out
// of a mailbox on another device does not sign anyone in. A consumer who needs
// a link to be followable from any device turns it off, and redemption then
// ignores any binding presented.
func WithSameDeviceBinding(enabled bool) Option {
	return func(m *Manager) { m.binding = enabled }
}

// WithSynchronousDelivery accepts a sender that waits for delivery.
//
// The default is to refuse one. A sender that waits puts the mail server's
// response time into the caller's response time, and a request for an address
// that has an account then takes measurably longer than one for an address
// that does not — which reveals exactly what the uniform result of Request
// exists to hide. Passing this option accepts that channel: response time then
// reveals which addresses have accounts.
//
// The alternative is to wrap the sender in notify.NewQueuedSender, which
// declares itself non-blocking and needs no option here.
func WithSynchronousDelivery() Option {
	return func(m *Manager) { m.acceptSyncDelivery = true }
}

// WithLogger replaces the logger. The default is slog.Default().
//
// Everything Request refuses and everything Redeem refuses is reported here
// and nowhere else, so a manager with no usable logger reports nothing at all.
// A nil logger is ignored rather than refused: "do not configure this" is a
// reading a nil logger plainly has.
//
// No record written by this package carries the token, the binding value or
// the submitted address. A dependency failure — the token store's count or
// issue, the sender, the address resolver or the redemption user loader — is
// recorded by a fixed reason and the error's Go type, never by the error's own
// text; a consumer who wants that detail logs it inside their own
// implementation of the port.
func WithLogger(l *slog.Logger) Option {
	return func(m *Manager) {
		if l != nil {
			m.logger = l
		}
	}
}

// WithRandom replaces the source the binding value is drawn from. The default
// is crypto/rand.Reader.
//
// It exists so a test can make the source fail and watch the request refuse
// without sending anything. A nil source fails construction with ErrConfig.
func WithRandom(r io.Reader) Option {
	return func(m *Manager) { m.random = r }
}
