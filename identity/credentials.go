package identity

// CredentialsType names a kind of credential a caller can present.
type CredentialsType string

// The credential types scrty names. Later authentication methods add their own;
// this package owns only the two that exist from the start.
const (
	CredentialsUsernamePassword CredentialsType = "username-password"
	CredentialsJWT              CredentialsType = "jwt"
)

// Credentials is a credential presented by a caller.
//
// An authentication provider declares which type it handles, so a manager can
// offer presented credentials to the provider that understands them.
type Credentials interface {
	// Type reports which kind of credential this is.
	Type() CredentialsType

	// Cleanup wipes the sensitive material the credential holds and reports any
	// failure. Callers invoke it once the credential has been used, successfully
	// or not.
	Cleanup() error
}

// UsernamePassword is a username and password presented together.
type UsernamePassword struct {
	Username string
	Password []byte

	// presented is the buffer the credential was built over.
	//
	// Cleanup wipes it as well as whatever Password points at, so the secret is
	// wiped rather than merely the field's current target: any use of the
	// exported field that reallocates — normalising, padding, appending a
	// terminator — leaves Password pointing at a new array while the secret
	// stays resident in the old one, where nothing would ever overwrite it.
	presented []byte
}

// NewUsernamePassword returns credentials over the caller's password buffer.
//
// The buffer is not copied: Cleanup wipes it in place, so the caller must not
// reuse it afterwards. Sharing one buffer between two credentials means wiping
// either one wipes both.
//
// The credential remembers the buffer, so Cleanup still wipes the secret when
// the caller has since reassigned or grown the Password field. That record is
// made here: a credential built as a struct literal instead has none, and its
// Cleanup wipes only what Password points at when it is called.
func NewUsernamePassword(username string, password []byte) *UsernamePassword {
	return &UsernamePassword{Username: username, Password: password, presented: password}
}

// Type reports CredentialsUsernamePassword.
func (c *UsernamePassword) Type() CredentialsType { return CredentialsUsernamePassword }

// Cleanup overwrites the password bytes with zeroes.
//
// It overwrites in place rather than dropping the reference: releasing the slice
// would leave the secret resident in the caller's own buffer, where it would sit
// until the memory happened to be reused. It wipes both the buffer the
// credential was built over and whatever Password points at now, so reassigning
// or growing that field cannot orphan the array holding the secret.
//
// Cleaning up an absent credential does nothing and reports no error. A
// provider that produced no credential still runs its deferred cleanup, and a
// nil *UsernamePassword inside a Credentials interface is not a nil interface,
// so the caller has no way to guard against it.
func (c *UsernamePassword) Cleanup() error {
	if c == nil {
		return nil
	}

	clear(c.Password)
	clear(c.presented)

	return nil
}

var _ Credentials = (*UsernamePassword)(nil)
