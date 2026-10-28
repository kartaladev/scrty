package magiclink

import (
	"context"
	"errors"
	"time"

	"github.com/kartaladev/scrty/identity"
)

// ErrConfig is wrapped by every error NewManager returns for a wiring mistake.
// A magic-link manager that cannot be built is a fault the consumer sees from
// the constructor, never a surprise on the first request that needs it.
var ErrConfig = errors.New("magiclink: invalid configuration")

// ErrInvalidLink is the single error every refused redemption returns.
//
// A malformed, unknown, expired, consumed or wrong-purpose token, a wrong
// secret, a wrong binding, a user who is gone, disabled or does not match the
// link, and a failure of the token store or the user loader are all this one
// error. A caller cannot tell them apart, and neither can whoever is holding
// the link. The cause is logged server-side instead.
//
// Only two redemption errors are not this one: a consumer refusal check's own
// error, which is returned unchanged, and a policy denial the consumer's check
// reports.
var ErrInvalidLink = errors.New("magiclink: invalid link")

// BindingNonceLength is the length of RequestResult.BindingNonce whenever
// same-device binding is on.
//
// It is fixed, and the same whether a link was issued or not, so that a caller
// showing the client something derived from the nonce — a cookie set on every
// response, say — shows a value of one shape whatever happened. A caller that
// has to produce its own stand-in, for a manager with binding disabled or for
// a request it refused before reaching the manager, builds one of this length.
const BindingNonceLength = 22

// RequestResult is everything Request tells its caller.
//
// There is deliberately almost nothing in it, and there is no error beside it.
// A caller that cannot see which branch a request took cannot leak it to the
// client, even by accident.
type RequestResult struct {
	// BindingNonce is the same-device binding value, to be handed back to
	// Redeem by the device that asked for the link.
	//
	// With binding on it is always BindingNonceLength long, on every branch:
	// when a link went out it is what the link is bound to, and when none did
	// it is a decoy that binds nothing, so the two cannot be told apart. It is
	// empty only when WithSameDeviceBinding(false) was given, or when the
	// random source itself failed — an outage in which nothing was issued for
	// anybody, and which therefore still says nothing about the address.
	BindingNonce string
}

// Redemption is who a spent link authenticates.
//
// Its zero value is what every refused redemption returns, so a caller that
// ignores the error still establishes nothing.
type Redemption struct {
	// Principal is the user the link was minted for, loaded by the reference
	// recorded on the link rather than by any address or username.
	Principal identity.Principal

	// PasswordChangedAt is the loaded user's password-change time, carried so
	// that a consumer's refusal check can apply a password-age policy without
	// loading the user a second time.
	PasswordChangedAt time.Time
}

// Check is a consumer's refusal check, run against the resolved principal
// before the link is spent.
//
// A check must have no side effects. Several racing redemptions of one link
// each run every check, and only one of them goes on to consume, so a check
// that wrote something would write it once per racing attempt rather than once
// per sign-in.
//
// The first check that returns an error stops the redemption, later checks do
// not run, and the error is returned to the caller unchanged — it is the
// consumer's contract with their own caller, and the library has no business
// rewriting it.
type Check func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error

// AddressResolver turns a submitted address into the user it belongs to.
//
// With none supplied, the library passes the address to the user loader as a
// username, exactly as it was submitted. A resolver that reports
// identity.ErrUserNotFound says there is no such account; any other error says
// the lookup failed. Neither reaches the caller of Request.
type AddressResolver func(ctx context.Context, address string) (*identity.Details, error)
