package apikey

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// ErrVerificationFailed is the single answer Verify gives to every presented
// key it will not accept.
//
// A malformed key, a wrong prefix, an unknown identifier, a wrong secret, an
// expired key, a revoked key and a store that cannot be reached are all this
// error. They are one error on purpose: a caller able to tell them apart could
// enumerate which identifiers were ever issued, and an outage that looked
// different from a refusal would announce when the store was down.
var ErrVerificationFailed = errors.New("apikey: verification failed")

// ErrKeyNotFound is what a store reports when there was no record to act on,
// and what Revoke returns for an identifier that was never issued.
//
// Verify never returns it. A caller presenting a key learns only
// ErrVerificationFailed; ErrKeyNotFound is for the management operations, whose
// caller already holds the identifier and is entitled to know it is unknown.
var ErrKeyNotFound = errors.New("apikey: key not found")

// Key is the stored record of one API key.
//
// It never holds the secret. The secret exists once, in the string Issue
// returned, and what is stored is a one-way digest of it, so a store that leaks
// yields nothing that authenticates.
type Key struct {
	// ID identifies the record and appears in the presented key. It is not a
	// secret: it is a library-owned identifier, so it is a pkg/id.ID.
	ID id.ID

	// Principal is the consumer's own reference for the machine caller this
	// key authenticates. Stored and returned unchanged, never parsed.
	Principal identity.UserID

	// Name is the consumer's label for the key, shown to whoever manages it.
	Name string

	// Scopes are the consumer's own scope strings, stored and returned exactly
	// as given. The library assigns them no meaning; enforcing them is the
	// authorization capability's job.
	Scopes []string

	// SecretDigest is the one-way digest of the secret. The secret itself is
	// never stored, so a leaked store yields nothing that authenticates.
	SecretDigest []byte

	// ExpiresAt is when the key stops being accepted. Nil means it never
	// expires.
	ExpiresAt *time.Time

	// RevokedAt is when the key was revoked. Nil means it is live.
	RevokedAt *time.Time

	// LastUsedAt is when a verification last succeeded, written best effort.
	// Nil means it has never been used.
	LastUsedAt *time.Time

	// CreatedAt is when the key was issued.
	CreatedAt time.Time
}

// parsePresented splits a presented key into its record identifier and its
// secret.
//
// It is strict on purpose, and it runs before any store call: a key whose shape
// is wrong is refused without a lookup, so a scanner firing malformed strings
// at an endpoint costs one string comparison rather than a query. Decoding the
// secret here rather than after the lookup is part of that: a secret that is
// not base64url is a wrong shape, not a wrong secret.
//
// The prefix is matched with its separator attached, so a configured prefix of
// "s" does not accept a key issued under "sk".
func (m *Manager) parsePresented(presented string) (id.ID, []byte, bool) {
	// A presented key is a prefix, a separator, a 36-character identifier,
	// another separator and a 43-character secret. The bound above that is
	// slack, not licence: it keeps an arbitrarily long string from reaching
	// the decoder at all.
	if len(presented) > maxPresentedSize {
		return id.Nil, nil, false
	}

	rest, ok := strings.CutPrefix(presented, m.opening)
	if !ok {
		return id.Nil, nil, false
	}

	idPart, secretPart, ok := strings.Cut(rest, secretSeparator)
	if !ok || secretPart == "" {
		return id.Nil, nil, false
	}

	parsed, err := id.Parse(idPart)
	if err != nil {
		return id.Nil, nil, false
	}

	secret, err := base64.RawURLEncoding.DecodeString(secretPart)
	if err != nil {
		return id.Nil, nil, false
	}

	return parsed, secret, true
}
