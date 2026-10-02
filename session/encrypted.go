package session

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// Cipher seals and opens the one session field that is a credential in its own
// right, binding each value to the session it belongs to.
//
// It is declared here, in the package that consumes it, rather than imported
// from a package that owns encryption. A cipher shipped by another capability
// satisfies this interface structurally, so neither package imports the other,
// and a consumer wires one implementation into every place that seals. A later
// capability needing to seal something else declares the narrow port it needs
// rather than inheriting this one.
//
// An implementation must be safe for concurrent use, and must bind the
// additional authenticated data to the ciphertext: Open has to fail when it is
// given the same ciphertext with different additional data. That is what stops
// a sealed value being moved from one session to another.
//
//go:generate mockgen -source=encrypted.go -package=session_test -destination=cipher_mock_test.go -typed
type Cipher interface {
	// Seal encrypts plaintext, authenticating additionalData alongside it
	// without storing it.
	Seal(plaintext, additionalData []byte) ([]byte, error)

	// Open decrypts ciphertext, and fails unless additionalData is exactly
	// what Seal was given.
	Open(ciphertext, additionalData []byte) ([]byte, error)
}

// aadPrefix prefixes the additional authenticated data every sealed provider
// ID token is bound to. The session identifier follows it, so an envelope
// lifted from one row and written into another will not open: the additional
// data names the session it was sealed for.
//
// It is a documented constant rather than an option. Changing it makes every
// stored envelope unreadable, which is a key rotation with none of a key
// rotation's machinery, so it is not something a consumer configures.
const aadPrefix = "scrty/session:external-id-token:"

// textSessionUnreadableIDTokenNotOpened is ErrSessionUnreadable's own words,
// kept as a constant (never ErrSessionUnreadable.Error(), which forbidigo
// forbids outside a stated exception) so this fixed text is never a
// dependency's error rendered at runtime. It must read exactly as
// ErrSessionUnreadable.Error() does, followed by what additionally failed.
const textSessionUnreadableIDTokenNotOpened = "session: session cannot be read: the provider ID token would not open"

// encryptedStore seals Session.ExternalIDToken on the way to inner and opens
// it on the way back.
type encryptedStore struct {
	inner  Store
	cipher Cipher
}

// NewEncryptedStore wraps inner so a session's provider ID token is sealed
// before it reaches storage and opened when it is loaded.
//
// Only ExternalIDToken is sealed: it is the one field of the record that is a
// credential in its own right, and a store that sealed more would hand back
// rows no query could filter. Every other field, and every other operation,
// passes straight through.
//
// A failure of inner or of the cipher is returned behind fixed text of this
// package — never naming the session identifier, which is the bearer
// credential — and still matches the original error through errors.Is and
// errors.As; a cipher that will not open a value is also
// ErrSessionUnreadable. A sentinel of this package that inner returns bare
// comes back as itself.
//
// The sealed value is bound to the session identifier, so an envelope moved to
// another session's row will not open. An empty token is stored unsealed,
// because there is nothing to hide and an envelope over nothing still says a
// federated session was here.
//
// A nil inner store or a nil cipher is a configuration error. Falling back to
// storing tokens in the clear, or to no store at all, would be a security
// decision made on the consumer's behalf at the moment they most clearly asked
// for the opposite.
func NewEncryptedStore(inner Store, c Cipher) (Store, error) {
	if nilcheck.IsNil(inner) {
		return nil, fmt.Errorf("%w: the inner store must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(c) {
		return nil, fmt.Errorf("%w: the cipher must not be nil", ErrConfig)
	}

	return &encryptedStore{inner: inner, cipher: c}, nil
}

// additionalData is what a session's ID token is sealed against.
func additionalData(id string) []byte {
	return []byte(aadPrefix + id)
}

// sealed returns a copy of sess whose ID token is an envelope, leaving the
// caller's own record holding plaintext.
//
// Sealing a copy is what keeps a create or a save from reaching back into the
// caller's struct. A caller that handed over a session and then read its token
// would otherwise find ciphertext there, and a retry of the same write would
// seal the envelope a second time.
func (s *encryptedStore) sealed(sess *Session) (*Session, error) {
	if sess.ExternalIDToken == "" {
		return sess, nil
	}

	envelope, err := s.cipher.Seal([]byte(sess.ExternalIDToken), additionalData(sess.ID))
	if err != nil {
		return nil, diag.Wrap(err, "session: the provider ID token of the session could not be sealed")
	}

	out := sess.clone()
	out.ExternalIDToken = base64.RawURLEncoding.EncodeToString(envelope)

	return out, nil
}

func (s *encryptedStore) Create(ctx context.Context, sess *Session) error {
	out, err := s.sealed(sess)
	if err != nil {
		return err
	}

	return storeFailed(s.inner.Create(ctx, out), "session: the inner store could not create the session")
}

func (s *encryptedStore) Save(ctx context.Context, sess *Session) error {
	out, err := s.sealed(sess)
	if err != nil {
		return err
	}

	return storeFailed(s.inner.Save(ctx, out), "session: the inner store could not save the session")
}

// Load opens the stored ID token and returns the session with plaintext in it.
//
// A value that will not open is ErrSessionUnreadable, and the session is not
// returned at all. Returning it with the token blanked would turn a retired
// key — an operational mistake affecting every federated session at once —
// into a session that works until something reaches for the token, and by then
// nothing points at the key.
//
// Nothing is written here. Re-sealing what was just opened would make every
// read a write, and a write on read is how a session another request has just
// revoked comes back.
func (s *encryptedStore) Load(ctx context.Context, id string) (*Session, error) {
	sess, err := s.inner.Load(ctx, id)
	if err != nil {
		return nil, storeFailed(err, "session: the inner store could not load the session")
	}
	if sess.ExternalIDToken == "" {
		return sess, nil
	}

	envelope, err := base64.RawURLEncoding.DecodeString(sess.ExternalIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: the stored provider ID token is not a valid envelope: %w",
			ErrSessionUnreadable, err)
	}

	plaintext, err := s.cipher.Open(envelope, additionalData(sess.ID))
	if err != nil {
		return nil, diag.Wrap(err, textSessionUnreadableIDTokenNotOpened,
			ErrSessionUnreadable)
	}

	sess.ExternalIDToken = string(plaintext)

	return sess, nil
}

func (s *encryptedStore) Delete(ctx context.Context, id string) error {
	return storeFailed(s.inner.Delete(ctx, id), "session: the inner store could not delete the session")
}

func (s *encryptedStore) DeleteByUser(ctx context.Context, user identity.UserID) error {
	return storeFailed(s.inner.DeleteByUser(ctx, user), "session: the inner store could not delete the user's sessions")
}

func (s *encryptedStore) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	n, err := s.inner.DeleteByUserExcept(ctx, user, keep)

	return n, storeFailed(err, "session: the inner store could not delete the user's other sessions")
}

func (s *encryptedStore) CountActiveByUser(ctx context.Context, user identity.UserID) (int, error) {
	n, err := s.inner.CountActiveByUser(ctx, user)

	return n, storeFailed(err, "session: the inner store could not count the user's active sessions")
}

func (s *encryptedStore) DeleteExpired(ctx context.Context) (int, error) {
	n, err := s.inner.DeleteExpired(ctx)

	return n, storeFailed(err, "session: the inner store could not delete expired sessions")
}

func (s *encryptedStore) DeleteByExternalSession(ctx context.Context, issuer, sessionID string) (int, error) {
	n, err := s.inner.DeleteByExternalSession(ctx, issuer, sessionID)

	return n, storeFailed(err, "session: the inner store could not delete the provider session's sessions")
}

func (s *encryptedStore) DeleteByUserAndExternalIssuer(ctx context.Context, user identity.UserID, issuer string) (int, error) {
	n, err := s.inner.DeleteByUserAndExternalIssuer(ctx, user, issuer)

	return n, storeFailed(err, "session: the inner store could not delete the user's sessions from the issuer")
}

var _ Store = (*encryptedStore)(nil)
