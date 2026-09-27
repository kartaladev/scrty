package seal

import (
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/session"
)

// sessionCipher adapts a Cipher to session.Cipher, which has no use for the
// id of the key that opened a value: sessions are never re-sealed on read.
type sessionCipher struct {
	c Cipher
}

// SessionCipher adapts c to the session.Cipher port, so a durable session
// store seals the provider ID token through session.NewEncryptedStore:
//
//	store, err := session.NewEncryptedStore(inner, seal.SessionCipher(c))
//
// The sealing rule for sessions, including the additional data each token is
// bound to, stays in package session; this adapter only drops the key id Open
// reports. c's errors are returned unchanged, and the session store answers a
// token that will not open as session.ErrSessionUnreadable.
//
// A nil c, typed nil included, gives a nil session.Cipher, so
// session.NewEncryptedStore refuses it with session.ErrConfig instead of the
// first seal panicking.
func SessionCipher(c Cipher) session.Cipher {
	if nilcheck.IsNil(c) {
		return nil
	}

	return sessionCipher{c: c}
}

// Seal seals plaintext through the wrapped Cipher.
func (s sessionCipher) Seal(plaintext, additionalData []byte) ([]byte, error) {
	return s.c.Seal(plaintext, additionalData)
}

// Open opens ciphertext through the wrapped Cipher, dropping the key id.
func (s sessionCipher) Open(ciphertext, additionalData []byte) ([]byte, error) {
	plaintext, _, err := s.c.Open(ciphertext, additionalData)

	return plaintext, err
}
