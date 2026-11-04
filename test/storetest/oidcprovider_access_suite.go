package storetest

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// accessRecord returns a token with every field set: identifier n, digest n, expiring
// five minutes after suiteStart.
func accessRecord(n byte) *oidcprovider.AccessTokenRecord {
	return &oidcprovider.AccessTokenRecord{
		ID:           suiteID(int(n)),
		Digest:       opDigest(n),
		GrantFamily:  suiteID(100),
		ClientID:     opClient,
		User:         "u-1",
		Scopes:       []string{"openid", "profile"},
		Audience:     []string{"https://api.example.com"},
		Confirmation: map[string]string{"jkt": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"},
		IssuedAt:     suiteStart,
		ExpiresAt:    suiteStart.Add(5 * time.Minute),
	}
}

// normalAccess returns r with its times in UTC, for an exact comparison.
func normalAccess(r *oidcprovider.AccessTokenRecord) oidcprovider.AccessTokenRecord {
	out := *r
	out.IssuedAt, out.ExpiresAt = utc(r.IssuedAt), utc(r.ExpiresAt)

	return out
}

// loadAccess loads token n, which must exist.
func loadAccess(ctx context.Context, t *testing.T, s oidcprovider.AccessTokenStore, n int) *oidcprovider.AccessTokenRecord {
	t.Helper()

	got, err := s.Load(ctx, suiteID(n))
	require.NoError(t, err)
	require.NotNil(t, got)

	return got
}

// assertNoSecretField requires typ to hold its one byte slice as digestField, and no
// field whose name offers a place for a secret: the record's shape is what keeps a store
// from being handed one.
func assertNoSecretField(t *testing.T, typ reflect.Type, digestField string) {
	t.Helper()

	for i := range typ.NumField() {
		field := typ.Field(i)
		if field.Type == reflect.TypeFor[[]byte]() {
			assert.Equal(t, digestField, field.Name, "a byte field other than the digest")
		}
		name := strings.ToLower(field.Name)
		assert.False(t, strings.Contains(name, "secret") || strings.Contains(name, "token"),
			"%s offers a place for a secret", field.Name)
	}
}

// AccessTokenSuite holds an opaque access-token store to the contract
// oidcprovider.AccessTokenStore documents. newStore returns an empty store of its own
// for each case.
func AccessTokenSuite(t *testing.T, newStore func(t *testing.T) oidcprovider.AccessTokenStore) {
	t.Helper()

	runSuite(t, accessCases(), withoutClock(newStore))
}

func accessCases() []suiteCase[oidcprovider.AccessTokenStore] {
	type store = oidcprovider.AccessTokenStore

	return []suiteCase[store]{
		{
			name: "create and load return every field",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, accessRecord(1)))

				assert.Equal(t, normalAccess(accessRecord(1)), normalAccess(loadAccess(ctx, t, s, 1)))
			},
		},
		{
			name: "a missing token is not found, for a load and for a revocation, which inserts nothing",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				_, err := s.Load(ctx, suiteID(1))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)

				require.ErrorIs(t, s.Revoke(ctx, suiteID(1)), oidcprovider.ErrNotFound)
				_, err = s.Load(ctx, suiteID(1))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "a revocation must not insert")
			},
		},
		{
			name: "an identifier already held is refused, the record stays, and the error carries no digest",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, accessRecord(1)))

				other := accessRecord(1)
				other.Digest, other.ClientID = opDigest(9), opOtherClient
				err := s.Create(ctx, other)
				require.Error(t, err)
				assertNoDigest(t, err, opDigest(9))
				assertNoDigest(t, err, opDigest(1))

				assert.Equal(t, normalAccess(accessRecord(1)), normalAccess(loadAccess(ctx, t, s, 1)))
			},
		},
		{
			name: "a record holds only the digest it was given, unchanged",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				assertNoSecretField(t, reflect.TypeFor[oidcprovider.AccessTokenRecord](), "Digest")

				require.NoError(t, s.Create(ctx, accessRecord(1)))
				assert.Equal(t, opDigest(1), loadAccess(ctx, t, s, 1).Digest)
			},
		},
		{
			name: "revoking a token marks it, and no other of its grant",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, accessRecord(1)))
				require.NoError(t, s.Create(ctx, accessRecord(2)))

				require.NoError(t, s.Revoke(ctx, suiteID(1)))

				revoked := loadAccess(ctx, t, s, 1)
				assert.True(t, revoked.Revoked)
				want := normalAccess(accessRecord(1))
				want.Revoked = true
				assert.Equal(t, want, normalAccess(revoked), "nothing but the mark changes")
				assert.False(t, loadAccess(ctx, t, s, 2).Revoked, "another token of the grant stays live")
			},
		},
		{
			name: "revoking twice changes nothing",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, accessRecord(1)))

				require.NoError(t, s.Revoke(ctx, suiteID(1)))
				require.NoError(t, s.Revoke(ctx, suiteID(1)))

				assert.True(t, loadAccess(ctx, t, s, 1).Revoked)
			},
		},
		{
			name: "an expired or revoked token is still returned, because the provider judges it",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				expired := accessRecord(1)
				expired.IssuedAt, expired.ExpiresAt = longAgo, longAgo.Add(time.Minute)
				require.NoError(t, s.Create(ctx, expired))
				require.NoError(t, s.Create(ctx, accessRecord(2)))
				require.NoError(t, s.Revoke(ctx, suiteID(2)))

				assert.NotNil(t, loadAccess(ctx, t, s, 1))
				assert.True(t, loadAccess(ctx, t, s, 2).Revoked)
			},
		},
		{
			name: "delete expired removes what is strictly before the time given, revoked or not, by that time alone",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				expiresAt := suiteStart.Add(5 * time.Minute)
				for n := range byte(3) {
					r := accessRecord(n + 1)
					r.ExpiresAt = expiresAt.Add(time.Duration(n) * time.Minute)
					require.NoError(t, s.Create(ctx, r))
				}
				require.NoError(t, s.Revoke(ctx, suiteID(1)))
				require.NoError(t, s.Revoke(ctx, suiteID(3)))

				removed, err := s.DeleteExpired(ctx, expiresAt)
				require.NoError(t, err)
				assert.Equal(t, 0, removed, "a token expiring at the time given is not strictly before it")

				removed, err = s.DeleteExpired(ctx, expiresAt.Add(time.Minute))
				require.NoError(t, err)
				assert.Equal(t, 1, removed)

				_, err = s.Load(ctx, suiteID(1))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "the expired token, though revoked")
				assert.NotNil(t, loadAccess(ctx, t, s, 2))
				assert.True(t, loadAccess(ctx, t, s, 3).Revoked, "a revoked token stays until it expires")
			},
		},
		{
			name: "delete expired keeps what has not expired at the time given, however long ago that time is",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				for n, lifetime := range map[byte]time.Duration{1: time.Minute, 2: time.Hour} {
					r := accessRecord(n)
					r.IssuedAt, r.ExpiresAt = longAgo, longAgo.Add(lifetime)
					require.NoError(t, s.Create(ctx, r))
				}

				removed, err := s.DeleteExpired(ctx, longAgo.Add(10*time.Minute))
				require.NoError(t, err)
				assert.Equal(t, 1, removed, "the wall clock has long passed both, and the time given only one")

				_, err = s.Load(ctx, suiteID(1))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
				assert.NotNil(t, loadAccess(ctx, t, s, 2), "the other stays")
			},
		},
		{
			name: "a record stored or loaded is the caller's own copy",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				given := accessRecord(1)
				require.NoError(t, s.Create(ctx, given))
				given.Digest[0] ^= 0xff
				given.Scopes[0] = "changed"
				given.Audience[0] = "changed"
				given.Confirmation["jkt"] = "changed"

				got := loadAccess(ctx, t, s, 1)
				assert.Equal(t, normalAccess(accessRecord(1)), normalAccess(got), "writing to what was given changes nothing")

				got.Digest[0] ^= 0xff
				got.Scopes[0] = "changed"
				got.Audience[0] = "changed"
				got.Confirmation["jkt"] = "changed"
				assert.Equal(t, normalAccess(accessRecord(1)), normalAccess(loadAccess(ctx, t, s, 1)),
					"writing to what was loaded changes nothing")
			},
		},
	}
}
