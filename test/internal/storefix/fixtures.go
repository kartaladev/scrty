package storefix

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
)

// NewID mints a fresh identifier, failing t when the generator fails.
func NewID(t *testing.T) id.ID {
	t.Helper()

	v, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	return v
}

// GeneratorFunc is a consumer's id generator.
type GeneratorFunc func() (id.ID, error)

// NewID calls g.
func (g GeneratorFunc) NewID() (id.ID, error) { return g() }

// Clock is a clock a test advances by hand. It is safe for concurrent use.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock returns a clock reading start.
func NewClock(start time.Time) *Clock { return &Clock{now: start} }

// Now reads the clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock on by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// APIKey is the API key numbered n, issued to principal.
func APIKey(n int, principal identity.UserID) apikey.Key {
	digest := sha256.Sum256(fmt.Appendf(nil, "api-key-%d", n))

	return apikey.Key{
		ID:           id.MustParse(fmt.Sprintf("01926a4e-0000-7000-8000-%012x", 0x300000+n)),
		Principal:    principal,
		Name:         fmt.Sprintf("key %d", n),
		Scopes:       []string{"read"},
		SecretDigest: digest[:],
		CreatedAt:    time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC),
	}
}

// RaceToken is the i-th one-time token a race seeds, unspent and valid for an
// hour.
func RaceToken(i int) onetime.Token {
	secret := sha256.Sum256(fmt.Appendf(nil, "secret-%d", i))
	issued := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

	return onetime.Token{
		ID:         id.MustParse(fmt.Sprintf("01926a4e-0000-7000-8000-%012x", 0x100000+i)),
		Purpose:    "race",
		Subject:    fmt.Sprintf("subject-%d", i),
		SecretHash: secret[:],
		IssuedAt:   issued,
		ExpiresAt:  issued.Add(time.Hour),
	}
}

// SessionAAD is the additional data package session binds a provider ID
// token to, followed by the session identifier.
const SessionAAD = "scrty/session:external-id-token:"

// Digest is the key a session is stored under.
func Digest(sid string) []byte {
	sum := sha256.Sum256([]byte(sid))
	return sum[:]
}

// DurableSession returns a federated session with identifier sid, holding a
// provider ID token, valid from now for an hour.
func DurableSession(sid string, now time.Time) *session.Session {
	return &session.Session{
		ID:                sid,
		UserID:            identity.UserID("u-" + sid),
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(5 * time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
		ExternalProvider:  "corp",
		ExternalIssuer:    "https://idp.example",
		ExternalSessionID: "sid-" + sid,
		ExternalIDToken:   "ID-TOKEN-" + sid,
		Data:              map[string]string{"tenant": "t-9"},
	}
}

// SaveUpsertsStore creates a session its Save does not find, so a save racing
// a logout writes the revoked session back.
type SaveUpsertsStore struct{ session.Store }

// Save saves sess, creating it when the store does not find it.
func (s SaveUpsertsStore) Save(ctx context.Context, sess *session.Session) error {
	err := s.Store.Save(ctx, sess)
	if errors.Is(err, session.ErrSessionNotFound) {
		return s.Create(ctx, sess)
	}
	return err
}

// EnrolmentBegun is when every MFA enrolment here was begun.
var EnrolmentBegun = time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

// Pending is a pending enrolment of user carrying secret.
func Pending(user identity.UserID, secret string) mfa.Enrolment {
	return mfa.Enrolment{User: user, Secret: []byte(secret), CreatedAt: EnrolmentBegun}
}

// KeyCreated is when every signing key here was generated; kids break the
// tie.
var KeyCreated = time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

// SigningKey is a record for kid holding private material private.
func SigningKey(kid string, private []byte) signingkey.Record {
	return signingkey.Record{
		Kid:       kid,
		Alg:       "ES256",
		Private:   private,
		PublicJWK: []byte(`{"kty":"EC","kid":"` + kid + `"}`),
		CreatedAt: KeyCreated,
	}
}

// OIDCStart is when every OIDC record here was made.
var OIDCStart = time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

// Flow is a flow for provider and state, expiring ten minutes after
// OIDCStart.
func Flow(provider, state string) oidc.Flow {
	return oidc.Flow{
		Provider: provider, State: state, Nonce: "nonce-" + state, Verifier: "verifier-" + state,
		Next: "/next?of=" + state, ExpiresAt: OIDCStart.Add(10 * time.Minute),
	}
}

// Handoff is a record for tokenID under a fresh id, issued at OIDCStart and
// expiring a minute later.
func Handoff(t *testing.T, tokenID string) oidc.HandoffRecord {
	t.Helper()

	sum := sha256.Sum256([]byte("secret-of-" + tokenID))

	return oidc.HandoffRecord{
		ID: NewID(t), TokenID: tokenID, SecretHash: sum[:], UserID: "u-" + identity.UserID(tokenID),
		Provider: "corp", Issuer: "https://corp.example", SessionID: "sid-" + tokenID,
		IDToken: "header.payload.signature", Next: "/home",
		CreatedAt: OIDCStart, ExpiresAt: OIDCStart.Add(time.Minute),
	}
}

// Link is a link of provider's subject at issuer to user, under a fresh id.
func Link(t *testing.T, provider, issuer, subject string, user identity.UserID) oidc.Link {
	t.Helper()

	return oidc.Link{
		ID: NewID(t), Provider: provider, Issuer: issuer, Subject: subject,
		UserID: user, Username: "user-of-" + subject, Email: subject + "@example.com", CreatedAt: OIDCStart,
	}
}
