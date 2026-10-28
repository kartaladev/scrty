package apikey

import (
	"bytes"
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
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

// compensatingRevokeTimeout bounds the revoke of a replacement that a lost
// rotation undoes, which runs detached from the caller's cancellation.
const compensatingRevokeTimeout = 5 * time.Second

// Keys issues, verifies, revokes and rotates API keys.
//
// Every default is replaceable. With no options a manager keeps its records in
// process memory, mints secrets from crypto/rand, stores them under SHA-256 and
// prefixes presented keys with "sk". A consumer supplies a durable store
// through WithStore, their own prefix through WithPrefix, their own digest
// through WithDigest, and a test moves time through WithClock without waiting
// for it.
//
// A Keys value is safe for concurrent use as far as its store is: it holds no
// mutable state of its own after construction.
type Keys struct {
	store  Store
	prefix string
	digest func([]byte) []byte
	ids    id.Generator
	clock  clock.Clock
	logger *slog.Logger
	random io.Reader

	// opening is the prefix with its separator already attached, settled once
	// the prefix has been validated. Issuing and parsing both want it, and
	// parsing wants it on every presented key, so it is joined here rather
	// than on each request.
	opening string
}

// New returns a manager with every default in place.
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
func New(opts ...Option) (*Keys, error) {
	m := &Keys{
		store:  NewMemoryStore(),
		prefix: defaultPrefix,
		digest: sha256Digest,
		ids:    id.NewV7Generator(),
		clock:  clock.System(),
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
	if nilcheck.IsNil(m.clock) {
		return nil, fmt.Errorf("%w: clock must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(m.random) {
		return nil, fmt.Errorf("%w: random source must not be nil", ErrConfig)
	}
	if err := probeDigest(m.digest); err != nil {
		return nil, err
	}

	m.opening = m.prefix + prefixSeparator

	return m, nil
}

// Prefix reports the prefix every key this manager issues carries, which is
// what WithPrefix configured.
func (m *Keys) Prefix() string { return m.prefix }

// digestProbes are the two inputs New hands the digest once, each the
// size of a real secret. Neither starts with a zero byte, and they differ in
// every byte.
var digestProbes = [2][secretBytes]byte{
	[secretBytes]byte(bytes.Repeat([]byte{0xa5}, secretBytes)),
	[secretBytes]byte(bytes.Repeat([]byte{0x5a}, secretBytes)),
}

// probeDigest calls digest once on each of two different inputs and refuses
// it when either digest is empty or the two are equal.
//
// It catches the digest that cannot work, not every weak one. A digest that
// returns nothing would store keys under no digest, and every secret would
// then match; one that returns the same value for everything would let any
// secret verify against any key. Neither is a policy a consumer could mean.
func probeDigest(digest func([]byte) []byte) error {
	first, second := digest(digestProbes[0][:]), digest(digestProbes[1][:])
	if len(first) == 0 || len(second) == 0 {
		return fmt.Errorf("%w: digest must not return an empty value", ErrConfig)
	}
	if bytes.Equal(first, second) {
		return fmt.Errorf("%w: digest must return different values for different inputs", ErrConfig)
	}

	return nil
}

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
// each reported, and neither leaves a record behind. A digest that returns an
// empty value for the secret is refused with ErrConfig, and stores nothing:
// New's probe refuses a digest that always does, and this refuses one
// that does only for some inputs.
func (m *Keys) Issue(
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

	digest := m.digest(secret)
	if len(digest) == 0 {
		// A key stored under no digest would match every secret a broken
		// digest also returns nothing for.
		return "", Key{}, fmt.Errorf("%w: the digest returned an empty value", ErrConfig)
	}

	now := m.clock.Now()

	rec := Key{
		ID:           keyID,
		Principal:    principal,
		Name:         name,
		Scopes:       slices.Clone(scopes),
		SecretDigest: digest,
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
func (m *Keys) List(ctx context.Context, principal identity.UserID) ([]Key, error) {
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
// between a guess and the stored digest cannot be measured. An empty digest,
// stored or computed from the presented secret, never verifies: it is logged
// at error, since it means a record or a digest function is broken.
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
func (m *Keys) Verify(ctx context.Context, presented string) (identity.Principal, Key, error) {
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

	digest := m.digest(secret)
	if len(digest) == 0 || len(rec.SecretDigest) == 0 {
		// Two empty digests compare equal, so without this a record stored
		// under no digest would accept every secret a broken digest drops.
		m.log(ctx, slog.LevelError, "apikey: verification refused an empty digest",
			slog.String("key_id", keyID.String()))

		return identity.Principal{}, Key{}, ErrVerificationFailed
	}

	if subtle.ConstantTimeCompare(digest, rec.SecretDigest) != 1 {
		return identity.Principal{}, Key{}, ErrVerificationFailed
	}

	now := m.clock.Now()

	if !rec.liveAt(now) {
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
func (m *Keys) log(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
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
func (m *Keys) Revoke(ctx context.Context, keyID id.ID) error {
	_, err := m.store.Revoke(ctx, keyID, m.clock.Now())

	return keyStoreFailed(err, "apikey: could not revoke the key")
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
// Only a live key rotates. A key already revoked, or past its expiry, is
// ErrRotationRefused, and nothing is issued for it: renewing it would hand a
// working credential to whoever holds one that was ended, on purpose or by
// its lifetime. A key on the instant it expires is still live, as Verify
// judges it.
//
// The new key is returned only when both steps succeed, so a caller acting on
// the returned string is acting on a completed rotation.
//
// # Concurrent rotations
//
// The replacement is issued first and the old key revoked second, through
// Store.Revoke, a conditional write that reports whether this call was the
// one that ended the key. When it was not — a concurrent rotation or
// revocation got there first — the replacement just issued is revoked too, and
// the rotation is ErrRotationRefused. So of any number of concurrent rotations
// of one key, at most one leaves a live replacement, and that one is the
// rotation that returned it. Should revoking the replacement fail as well, the
// error still matches ErrRotationRefused, and names the replacement, which an
// operator then revokes by hand. A key that expires while the replacement is
// being issued loses the same way, since it is no longer live to be rotated.
// Revoking the replacement does not depend on the caller's context: it runs
// detached from its cancellation, bounded by a few seconds, so a caller that
// hangs up mid-rotation cannot leave the replacement live.
//
// The same holds when revoking the old key fails outright, whether the store
// errored or the caller's context ended at that write: the replacement is
// revoked, and the error wraps the failure of the old key's revoke. The old key
// may still be live: the failure says the revoke was not confirmed, not that it
// did not happen, since a store can commit it and then report an error, as a
// timeout after commit does. Check the old key rather than assume it. Should
// revoking the replacement fail too, the error wraps both failures and names
// the replacement, which an operator then revokes by hand, the replacement
// being live until then.
//
// # Atomicity
//
// These are separate writes. Outside a transaction the caller has attached
// to the store, a failure between them leaves the old key live; the
// replacement is revoked on the way out, and stays issued only when that
// revoke fails too. The error says which, and names both identifiers, because
// an operator reading it needs to know which key to revoke by hand. Neither
// identifier is a secret. Inside a transaction the store carries, a rollback
// undoes both, and whether that is available is the store implementation's to
// say — this package neither opens nor requires one.
func (m *Keys) Rotate(ctx context.Context, keyID id.ID, lifetime time.Duration) (string, Key, error) {
	existing, err := m.store.Get(ctx, keyID)
	if err != nil {
		return "", Key{}, keyStoreFailed(err, "apikey: could not read the key to rotate")
	}

	if !existing.liveAt(m.clock.Now()) {
		return "", Key{}, ErrRotationRefused
	}

	presented, rec, err := m.Issue(ctx, existing.Principal, existing.Name, existing.Scopes, lifetime)
	if err != nil {
		return "", Key{}, err
	}

	// One reading of the clock judges the old key and dates its revocation: a
	// key that expired while the replacement was being issued is one this
	// rotation must not end as though it were live.
	at := m.clock.Now()

	revoked := false
	if existing.liveAt(at) {
		revoked, err = m.store.Revoke(ctx, keyID, at)
		if err != nil {
			// The old key may still be live (the failed revoke may even have
			// committed, then errored), and the replacement was handed to
			// nobody: end it, detached from the caller, which may be the
			// very reason the revoke failed.
			if undoErr := m.revokeReplacement(ctx, rec.ID); undoErr != nil {
				return "", Key{}, diag.Wrap(errors.Join(err, undoErr), fmt.Sprintf(
					"apikey: rotated key %s was issued but %s could not be revoked, and the replacement could not be revoked either",
					rec.ID, keyID))
			}

			return "", Key{}, diag.Wrap(err, fmt.Sprintf(
				"apikey: rotated key %s was issued but %s could not be revoked; the replacement was revoked, and the old key may still be live",
				rec.ID, keyID))
		}
	}

	if !revoked {
		// The old key was ended by someone else, or ran out, between the read
		// and this write, so this rotation lost: its replacement must not
		// stay live. The caller may be gone by now, and a replacement left
		// live for it would be a credential nobody was handed, so this write
		// outlives the caller's cancellation, within a bound.
		if err := m.revokeReplacement(ctx, rec.ID); err != nil {
			return "", Key{}, diag.Wrap(err, fmt.Sprintf(
				"apikey: rotation of %s was refused, but its replacement %s could not be revoked", keyID, rec.ID),
				ErrRotationRefused)
		}

		return "", Key{}, ErrRotationRefused
	}

	return presented, rec, nil
}

// revokeReplacement ends a replacement key that a failed or lost rotation must
// not leave live. It runs detached from ctx's cancellation, within
// compensatingRevokeTimeout, so a caller that has hung up cannot prevent it.
func (m *Keys) revokeReplacement(ctx context.Context, replacement id.ID) error {
	undoCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), compensatingRevokeTimeout)
	defer cancel()

	_, err := m.store.Revoke(undoCtx, replacement, m.clock.Now())

	return err
}
