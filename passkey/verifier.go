package passkey

import (
	"context"
	"encoding/json"
)

// Verifier is the only seam to WebAuthn parsing and verification.
//
// The core package supplies no default: the library's implementation is
// github.com/kartaladev/scrty/passkey/webauthn. A replacement is trusted
// exactly as the library's own. In particular, its AssertionResult's
// UserVerified decides whether a passkey login meets the second factor.
type Verifier interface {
	// RelyingParty returns the relying party the verifier checks against.
	RelyingParty() RelyingParty
	// CreationOptions renders the registration options for the browser.
	CreationOptions(ctx context.Context, in CreationInput) (json.RawMessage, error)
	// RequestOptions renders the assertion options for the browser.
	RequestOptions(ctx context.Context, in RequestInput) (json.RawMessage, error)
	// ParseRegistration reads a registration response body without verifying it.
	ParseRegistration(body []byte) (ParsedRegistration, error)
	// VerifyRegistration verifies a parsed registration against exp.
	VerifyRegistration(ctx context.Context, p ParsedRegistration, exp RegistrationExpectation) (*NewCredential, error)
	// ParseAssertion reads an assertion response body without verifying it.
	ParseAssertion(body []byte) (ParsedAssertion, error)
	// VerifyAssertion verifies a parsed assertion against the stored
	// credential c and exp.
	VerifyAssertion(ctx context.Context, p ParsedAssertion, c *Credential, exp AssertionExpectation) (*AssertionResult, error)
}

// ParsedRegistration is a registration response read but not yet verified.
type ParsedRegistration interface {
	// Challenge is clientDataJSON's challenge as sent, still base64url.
	Challenge() string
	CredentialID() []byte
	// Name is the name the client proposed, unnormalised.
	Name() string
}

// ParsedAssertion is an assertion response read but not yet verified.
type ParsedAssertion interface {
	// Challenge is clientDataJSON's challenge as sent, still base64url.
	Challenge() string
	CredentialID() []byte
	UserHandle() []byte
}
