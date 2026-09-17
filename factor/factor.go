// Package factor names the first-factor kinds a login can use and the channels
// they travel over.
//
// It is the sole owner of this vocabulary. Multi-factor authentication,
// security policy and every other capability reference these values and define
// no kinds or channels of their own, so there is one place to read what scrty
// recognises. The package imports nothing, so any of them can use it without an
// import cycle.
//
// Unknown kinds fail closed: they report no channel and are never exempt from a
// second-factor requirement. A caller that forgets to set the kind is therefore
// enforced rather than waved through, and never matches an enrolled method's
// channel.
package factor

// Kind is the kind of first factor a caller authenticated with.
//
// A consumer may use a kind of their own. It flows through as enforced, with no
// channel.
type Kind string

// The first-factor kinds scrty names.
//
// Go cannot enumerate a string-const type, so a kind added here must also be
// added to AllKinds in export_test.go, which every test that walks the
// vocabulary iterates. Without that, a new kind is simply untested.
const (
	Password  Kind = "password"
	MagicLink Kind = "magic-link"
	OIDC      Kind = "oidc"
	Basic     Kind = "basic"
	APIKey    Kind = "api-key"
)

// Channel is the medium a factor travels over.
//
// Two channels belong to second factors rather than first: AuthenticatorApp is
// the channel of authenticator-app second factors such as TOTP, and Email is
// the channel of email-delivered second factors as well as of a magic-link
// login. Comparing a first factor's channel with an enrolled second factor's is
// how a policy detects that both would arrive the same way.
type Channel string

// The channels scrty names.
const (
	Knowledge        Channel = "knowledge"
	Email            Channel = "email"
	AuthenticatorApp Channel = "authenticator-app"
	Federated        Channel = "federated"
	Machine          Channel = "machine"
)

// Channel reports the channel k travels over.
//
// A kind the library does not name, including the empty kind, reports the empty
// channel, which matches no enrolled method.
func (k Kind) Channel() Channel {
	switch k {
	case Password, Basic:
		return Knowledge
	case MagicLink:
		return Email
	case OIDC:
		return Federated
	case APIKey:
		return Machine
	default:
		return ""
	}
}

// MFAExempt reports whether a login with this kind is exempt from a
// second-factor requirement.
//
// Only OIDC and APIKey are exempt: the first has already authenticated at the
// provider, and the second is a machine caller with no one to prompt. Every
// other kind is enforced, including the empty kind and kinds the library does
// not name.
//
// The exemption is data, not a decision. Whether an exempt login is accepted
// for a user who requires a second factor belongs to the security-policy
// capability, with its own options.
func (k Kind) MFAExempt() bool {
	return k == OIDC || k == APIKey
}
