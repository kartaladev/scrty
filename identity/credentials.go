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
}

// NewUsernamePassword returns credentials over the caller's password buffer.
//
// The buffer is not copied: Cleanup wipes it in place, so the caller must not
// reuse it afterwards. Sharing one buffer between two credentials means wiping
// either one wipes both.
func NewUsernamePassword(username string, password []byte) *UsernamePassword {
	return &UsernamePassword{Username: username, Password: password}
}

// Type reports CredentialsUsernamePassword.
func (c *UsernamePassword) Type() CredentialsType { return CredentialsUsernamePassword }

// Cleanup overwrites the password bytes with zeroes.
//
// It overwrites in place rather than dropping the reference: releasing the slice
// would leave the secret resident in the caller's own buffer, where it would sit
// until the memory happened to be reused.
func (c *UsernamePassword) Cleanup() error {
	clear(c.Password)

	return nil
}

var _ Credentials = (*UsernamePassword)(nil)
