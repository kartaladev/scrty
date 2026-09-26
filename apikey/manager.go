package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/id"
)

// Manager issues, verifies, revokes and rotates API keys.
//
// Every default is replaceable. With no options a manager keeps its records in
// process memory, mints secrets from crypto/rand, stores them under SHA-256 and
// prefixes presented keys with "sk". A consumer supplies a durable store
// through WithStore, their own prefix through WithPrefix, their own digest
// through WithDigest, and a test moves time through WithClock without waiting
// for it.
//
// A Manager is safe for concurrent use as far as its store is: it holds no
// mutable state of its own after construction.
type Manager struct {
	store  Store
	prefix string
	digest func([]byte) []byte
	ids    id.Generator
	now    func() time.Time
	logger *slog.Logger
	random io.Reader

	// opening is the prefix with its separator already attached, settled once
	// the prefix has been validated. Issuing and parsing both want it, and
	// parsing wants it on every presented key, so it is joined here rather
	// than on each request.
	opening string
}

// NewManager returns a manager with every default in place.
//
// A prefix that is not 1 to 16 lowercase ASCII letters or digits is refused
// here rather than left to produce keys nothing can split, and every port and
// function is refused when nil, with one exception: a nil logger is ignored,
// because "do not log from this component" is a reading a nil logger plainly
// has, while a nil clock has no reading other than a mistake.
//
// A record of a failed store read or write carries a fixed reason and the
// error's Go type, never the store's own text; a consumer who wants that
// detail logs it inside their own implementation of Store. The key
// identifier, a library-owned value rather than a secret, is kept.
func NewManager(opts ...Option) (*Manager, error) {
	m := &Manager{
		store:  NewMemoryStore(),
		prefix: defaultPrefix,
		digest: sha256Digest,
		ids:    id.NewV7Generator(),
		now:    time.Now,
		logger: slog.Default(),
		random: rand.Reader,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}

	if !validPrefix(m.prefix) {
		return nil, fmt.Errorf(
			"%w: prefix must be 1 to %d lowercase letters or digits, got %q",
			ErrConfig, maxPrefixLen, m.prefix)
	}
	if nilcheck.IsNil(m.store) {
		return nil, fmt.Errorf("%w: store must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(m.digest) {
		return nil, fmt.Errorf("%w: digest must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(m.ids) {
		return nil, fmt.Errorf("%w: identifier generator must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(m.now) {
		return nil, fmt.Errorf("%w: clock must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(m.random) {
		return nil, fmt.Errorf("%w: random source must not be nil", ErrConfig)
	}

	m.opening = m.prefix + prefixSeparator

	return m, nil
}

// Prefix reports the prefix every key this manager issues carries, which is
// what WithPrefix configured.
func (m *Manager) Prefix() string { return m.prefix }

// sha256Digest is the default digest. It is a fast hash on purpose: see
// WithDigest for why a password hash would buy nothing here.
func sha256Digest(b []byte) []byte {
	sum := sha256.Sum256(b)

	return sum[:]
}

// Issue mints a key for principal and returns it once.
//
// The returned string is the only time the secret exists outside the caller's
// hands: the store receives a digest, and no read of the record ever produces
// the secret again. A caller who loses it issues a new key.
//
// Its shape is "<prefix>_<record identifier>.<base64url secret>". The prefix is
// there so that a scanner, a log redactor or a person reading a paste can
// recognise the string as a key before anything parses it.
//
// A lifetime of zero or less means the key never expires. That is deliberate —
// a machine credential with no rotation schedule is common — and the tradeoff
// is that revocation, not expiry, is what ends such a key. LastUsedAt is what
// finds the ones nobody is using any more.
//
// principal must not be empty: a key bound to no one would authenticate a
// caller the consumer cannot name. name and scopes are the consumer's own
// strings, stored and returned unchanged; the library assigns them no meaning.
//
// Nothing is stored unless everything before the write succeeded. A random
// source that cannot answer and a generator that cannot mint an identifier are
// each reported, and neither leaves a record behind.
func (m *Manager) Issue(
	ctx context.Context,
	principal identity.UserID,
	name string,
	scopes []string,
	lifetime time.Duration,
) (string, Key, error) {
	if principal == "" {
		return "", Key{}, fmt.Errorf("%w: a key requires a principal reference", ErrConfig)
	}

	// Everything that can fail without touching the store happens first, so a
	// failure here leaves nothing behind.
	secret := make([]byte, secretBytes)
	if _, err := io.ReadFull(m.random, secret); err != nil {
		return "", Key{}, fmt.Errorf("apikey: could not read a secret: %w", err)
	}

	keyID, err := m.ids.NewID()
	if err != nil {
		return "", Key{}, fmt.Errorf("apikey: could not mint an identifier: %w", err)
	}

	now := m.now()

	rec := Key{
		ID:           keyID,
		Principal:    principal,
		Name:         name,
		Scopes:       slices.Clone(scopes),
		SecretDigest: m.digest(secret),
		CreatedAt:    now,
	}

	if lifetime > 0 {
		expires := now.Add(lifetime)
		rec.ExpiresAt = &expires
	}

	if err := m.store.Put(ctx, rec); err != nil {
		return "", Key{}, diag.Wrap(err, "apikey: could not store the issued key")
	}

	presented := m.opening + keyID.String() +
		secretSeparator + base64.RawURLEncoding.EncodeToString(secret)

	return presented, rec, nil
}

// List returns every key belonging to principal, revoked and expired ones
// included, so whoever manages a principal's keys sees all of them.
//
// No listed record carries a secret; there is no read of any record that does.
//
// A store failure comes back wrapped, with fixed text; a consumer who wants
// its own detail logs it inside their own implementation of Store.
func (m *Manager) List(ctx context.Context, principal identity.UserID) ([]Key, error) {
	keys, err := m.store.List(ctx, principal)
	if err != nil {
		return nil, diag.Wrap(err, "apikey: could not list the principal's keys")
	}

	return keys, nil
}

// Verify checks a presented key and returns the principal it authenticates.
//
// Every failure is ErrVerificationFailed: a wrong shape, a wrong prefix, an
// unknown identifier, a wrong secret, an expired key, a revoked key and a store
// that could not answer. They are one error on purpose. A caller who could tell
// them apart could enumerate which identifiers were ever issued, and an outage
// that looked different from a refusal would say when the store was down.
//
// The digest comparison is constant time, so the length of a shared prefix
// between a guess and the stored digest cannot be measured.
//
// A key is accepted while now is not after its expiry, so one verified on the
// instant it expires still works. A key issued with a lifetime of zero or less
// has no expiry at all and is ended only by revocation.
//
// On success the last-use time is recorded best effort: a key that works must
// not stop working because the store could not note when it was used. The
// returned record carries that time whether or not the write landed.
//
// No error this returns and no log record it writes contains the presented key
// or its secret.
func (m *Manager) Verify(ctx context.Context, presented string) (identity.Principal, Key, error) {
	keyID, secret, ok := m.parsePresented(presented)
	if !ok {
		return identity.Principal{}, Key{}, ErrVerificationFailed
	}

	rec, err := m.store.Get(ctx, keyID)
	if err != nil {
		// ErrKeyNotFound included: an unknown key and an unreachable store are
		// the same answer to whoever asked. Only the log tells them apart, and
		// only for the operator reading it.
		m.log(ctx, levelFor(err), "apikey: verification failed",
			append([]slog.Attr{slog.String("key_id", keyID.String())}, diag.Failure("key-store", err)...)...)

		return identity.Principal{}, Key{}, ErrVerificationFailed
	}

	if subtle.ConstantTimeCompare(m.digest(secret), rec.SecretDigest) != 1 {
		return identity.Principal{}, Key{}, ErrVerificationFailed
	}

	now := m.now()

	if rec.RevokedAt != nil || (rec.ExpiresAt != nil && now.After(*rec.ExpiresAt)) {
		return identity.Principal{}, Key{}, ErrVerificationFailed
	}

	// Best effort: a key that works must not stop working because the store
	// could not record when it was last used.
	if err := m.store.TouchLastUsed(ctx, rec.ID, now); err != nil {
		m.log(ctx, slog.LevelWarn, "apikey: could not record last use",
			append([]slog.Attr{slog.String("key_id", rec.ID.String())}, diag.Failure("key-store", err)...)...)
	}

	rec.LastUsedAt = &now

	return identity.Principal{
		ID:     rec.Principal,
		Kind:   identity.KindService,
		Name:   rec.Name,
		Scopes: slices.Clone(rec.Scopes),
	}, rec, nil
}

// log writes through the configured logger, and writes nothing when the
// consumer supplied none.
func (m *Manager) log(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	if m.logger == nil {
		return
	}

	m.logger.LogAttrs(ctx, level, msg, attrs...)
}

// levelFor separates the traffic an endpoint sees all day from the failure an
// operator has to act on. A key nobody ever issued is expected traffic; a store
// that cannot answer is not.
func levelFor(err error) slog.Level {
	if errors.Is(err, ErrKeyNotFound) {
		return slog.LevelDebug
	}

	return slog.LevelError
}

// Revoke ends a key, so that every later verification of it fails.
//
// An identifier that was never issued is ErrKeyNotFound. Unlike Verify, this
// distinguishes: whoever calls Revoke already holds the identifier, and telling
// them it is unknown reveals nothing they could not have learned by listing the
// principal's keys.
//
// Revoking a key already revoked is not an error and does not move the time
// first recorded. The first revocation is the one that happened.
//
// ErrKeyNotFound comes back exactly as the store returned it — the identity a
// caller already matches on — and any other store failure comes back
// wrapped, with fixed text; a consumer who wants its own detail logs it
// inside their own implementation of Store.
func (m *Manager) Revoke(ctx context.Context, keyID id.ID) error {
	return keyStoreFailed(m.store.Revoke(ctx, keyID, m.now()), "apikey: could not revoke the key")
}

// keyStoreFailed returns a Store's error as the manager returns it: nil as
// nil; ErrKeyNotFound, the sentinel the Store contract names, exactly as the
// store returned it, since a bare sentinel carries no dependency text; and any
// other error wrapped with text and no sentinel, so an outage never reads as
// not-found. A store error that itself wraps ErrKeyNotFound still matches it,
// through the cause.
func keyStoreFailed(err error, text string) error {
	if err == ErrKeyNotFound { //nolint:errorlint // identity: a bare sentinel carries no dependency text
		return err
	}

	return diag.Wrap(err, text)
}

// Rotate issues a replacement for the key with this identifier and revokes the
// old one.
//
// The replacement carries the same principal reference, name and scopes, with
// whatever lifetime the caller gives — rotation replaces a secret, it does not
// change what a key may do. An identifier that was never issued is
// ErrKeyNotFound, and nothing is issued for it.
//
// The new key is returned only when both steps succeed, so a caller acting on
// the returned string is acting on a completed rotation.
//
// # Atomicity
//
// These are two separate writes. Outside a transaction the caller has attached
// to the store, a failure between them leaves the new key issued and the old
// one still live; the error says so and names both identifiers, because an
// operator reading it needs to know which key to revoke by hand. Neither
// identifier is a secret. Inside a transaction the store carries, a rollback
// undoes both, and whether that is available is the store implementation's to
// say — this package neither opens nor requires one.
func (m *Manager) Rotate(ctx context.Context, keyID id.ID, lifetime time.Duration) (string, Key, error) {
	existing, err := m.store.Get(ctx, keyID)
	if err != nil {
		return "", Key{}, keyStoreFailed(err, "apikey: could not read the key to rotate")
	}

	presented, rec, err := m.Issue(ctx, existing.Principal, existing.Name, existing.Scopes, lifetime)
	if err != nil {
		return "", Key{}, err
	}

	if err := m.store.Revoke(ctx, keyID, m.now()); err != nil {
		return "", Key{}, diag.Wrap(err, fmt.Sprintf(
			"apikey: rotated key %s was issued but %s could not be revoked", rec.ID, keyID))
	}

	return presented, rec, nil
}
