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

	// Recovery is the kind of the session an account recovery produces. The
	// recovery rested on two proofs of different kinds rather than on one
	// channel, so it reports no channel, and it is not exempt from MFA.
	Recovery Kind = "recovery"

	// Passkey is the kind of a passwordless login with a WebAuthn passkey. It
	// travels on the PublicKey channel and is not exempt from MFA: whether a
	// user-verified passkey login also met the second factor is recorded by the
	// library as a separate proof, never inferred from the kind.
	Passkey Kind = "passkey"
)

// Channel is the medium a factor travels over.
//
// Two channels belong to second factors rather than first: AuthenticatorApp is
// the channel of authenticator-app second factors such as TOTP, and Email is
// the channel of email-delivered second factors as well as of a magic-link
// login. PublicKey is shared by a passkey login and the passkey second factor,
// so a passkey never serves as the second factor of a passkey login. Comparing a first factor's channel with an enrolled second factor's is
// how a policy detects that both would arrive the same way.
type Channel string

// The channels scrty names.
const (
	Knowledge        Channel = "knowledge"
	Email            Channel = "email"
	AuthenticatorApp Channel = "authenticator-app"
	Federated        Channel = "federated"
	Machine          Channel = "machine"

	// PublicKey is the channel of credentials an authenticator holds as a key
	// pair and proves by signing a challenge; also the channel of the passkey
	// second factor. The name follows WebAuthn's credential type "public-key".
	PublicKey Channel = "public-key"
)

// Channel reports the channel k travels over.
//
// Recovery, the empty kind and any kind the library does not name all report
// the empty channel, which matches no enrolled method.
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
	case Passkey:
		return PublicKey
	default:
		return ""
	}
}

// MFAExempt reports whether a login with this kind is exempt from a
// second-factor requirement.
//
// Only APIKey is exempt: a machine caller has no one to prompt. Every other
// kind is enforced, including OIDC, Recovery, Passkey, the empty kind and kinds
// the library does not name.
//
// OIDC is not exempt by its kind. A login on the Federated channel meets a
// second-factor requirement only as the federated-assurance rules of the
// security-policy capability decide: by the assurance its provider verifiably
// asserted, or by a mode the consumer chooses (see policy.WithFederatedAssurance).
//
// The exemption is data, not a decision. Whether an exempt login is accepted
// for a user who requires a second factor belongs to the security-policy
// capability, with its own options.
func (k Kind) MFAExempt() bool {
	return k == APIKey
}
