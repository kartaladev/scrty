package storetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// keyPrincipal is the principal most API key cases issue keys to. Its case
// and trailing space catch a store that folds or trims the reference.
const keyPrincipal identity.UserID = "Svc-Billing "

// apiKeyRecord returns the suite's n-th key, issued to principal, live and
// never used, expiring a day after issue.
func apiKeyRecord(n int, principal identity.UserID) apikey.Key {
	digest := sha256.Sum256(fmt.Appendf(nil, "key-%d", n))
	expires := suiteStart.Add(24 * time.Hour)

	return apikey.Key{
		ID:           suiteID(0x200 + n),
		Principal:    principal,
		Name:         "deploy key ключ",
		Scopes:       []string{"write:invoices", "read:invoices", "admin"},
		SecretDigest: digest[:],
		ExpiresAt:    &expires,
		CreatedAt:    suiteStart,
	}
}

// assertAPIKey compares a stored key with want, field by field.
func assertAPIKey(t *testing.T, want, got apikey.Key) {
	t.Helper()

	assert.Equal(t, want.ID, got.ID)
	assert.Equal(t, want.Principal, got.Principal, "the principal must round-trip byte for byte")
	assert.Equal(t, want.Name, got.Name)
	assert.Equal(t, want.Scopes, got.Scopes, "scopes must round-trip in the order given")
	assert.Equal(t, want.SecretDigest, got.SecretDigest)
	assertTimePtrEqual(t, want.ExpiresAt, got.ExpiresAt, "ExpiresAt")
	assertTimePtrEqual(t, want.RevokedAt, got.RevokedAt, "RevokedAt")
	assertTimePtrEqual(t, want.LastUsedAt, got.LastUsedAt, "LastUsedAt")
	assertTimeEqual(t, want.CreatedAt, got.CreatedAt, "CreatedAt")
}

// assertAPIKeyStored requires the key with want's identifier to be stored as
// want.
func assertAPIKeyStored(ctx context.Context, t *testing.T, s apikey.Store, want apikey.Key) {
	t.Helper()

	got, err := s.Get(ctx, want.ID)
	require.NoError(t, err, "key %s must be found", want.ID)
	assertAPIKey(t, want, got)
}

// putAPIKeys stores every key, failing the case at the first error.
func putAPIKeys(ctx context.Context, t *testing.T, s apikey.Store, keys ...apikey.Key) {
	t.Helper()

	for _, k := range keys {
		require.NoError(t, s.Put(ctx, k), "put %s", k.ID)
	}
}

// apiKeyTextCase puts the key apiKeyRecord returns, changed by with to carry
// text a PostgreSQL text column cannot hold, marked by canary. The store
// either refuses it, with an error that does not echo it, and stores
// nothing; or stores it and loads it byte for byte. Anything else altered
// the consumer's value.
func apiKeyTextCase(name, canary string, with func(*apikey.Key)) suiteCase[apikey.Store] {
	return suiteCase[apikey.Store]{
		name: name,
		assert: func(t *testing.T, ctx context.Context, s apikey.Store, _ *clockwork.FakeClock) {
			want := apiKeyRecord(1, keyPrincipal)
			with(&want)

			if err := s.Put(ctx, want); err != nil {
				assert.NotContains(t, err.Error(), canary, "the refusal must not echo the value")
				_, getErr := s.Get(ctx, want.ID)
				assert.ErrorIs(t, getErr, apikey.ErrKeyNotFound, "a refused key must not be found")
				return
			}
			assertAPIKeyStored(ctx, t, s, want)
		},
	}
}

// RunAPIKeyStoreSuite checks an apikey.Store against the contract the API key
// manager relies on: a key round-trips every field, its scopes in order, and
// a key with no scopes, nil or empty, is stored and loads with none; an
// unknown identifier is ErrKeyNotFound for Get, Revoke and TouchLastUsed;
// revoking keeps the first revocation time; touching records the latest use;
// the scopes and digest put, read and listed are the caller's own copies;
// Get and List judge no expiry; stored times keep microsecond precision; List
// returns exactly one principal's keys, revoked and expired ones included,
// matching the principal byte for byte; and text a PostgreSQL text column
// cannot hold (a NUL byte, invalid UTF-8) in a scope, the name or the
// principal is either refused, with an error that does not echo it, or
// round-trips unchanged, and is never altered.
//
// newStore is called once per case and must return an empty store. The store
// takes every instant from its caller, so it needs no clock.
func RunAPIKeyStoreSuite(t *testing.T, newStore func(t *testing.T) apikey.Store) {
	t.Helper()

	cases := []suiteCase[apikey.Store]{
		{
			name: "a stored key is found with every field unchanged",
			assert: func(t *testing.T, ctx context.Context, s apikey.Store, _ *clockwork.FakeClock) {
				expiring := apiKeyRecord(1, keyPrincipal)
				never := apiKeyRecord(2, keyPrincipal)
				never.ExpiresAt = nil
				// Put stores the record as given, so a key put already revoked
				// and used keeps both.
				used := apiKeyRecord(3, keyPrincipal)
				revokedAt, lastUsedAt := suiteStart.Add(2*time.Hour), suiteStart.Add(time.Hour)
				used.RevokedAt, used.LastUsedAt = &revokedAt, &lastUsedAt
				putAPIKeys(ctx, t, s, expiring, never, used)

				assertAPIKeyStored(ctx, t, s, expiring)
				assertAPIKeyStored(ctx, t, s, never)
				assertAPIKeyStored(ctx, t, s, used)
			},
		},
		{
			// Scopes are the consumer's, so a key may carry none. Whether none
			// loads as nil or as empty is left to the store.
			name: "a key with nil or empty scopes is stored and found with none",
			assert: func(t *testing.T, ctx context.Context, s apikey.Store, _ *clockwork.FakeClock) {
				nilScopes := apiKeyRecord(1, keyPrincipal)
				nilScopes.Scopes = nil
				emptyScopes := apiKeyRecord(2, keyPrincipal)
				emptyScopes.Scopes = []string{}

				for _, want := range []apikey.Key{nilScopes, emptyScopes} {
					require.NoError(t, s.Put(ctx, want), "a key with scopes %#v must be stored", want.Scopes)

					got, err := s.Get(ctx, want.ID)
					require.NoError(t, err, "key %s must be found", want.ID)
					assert.Empty(t, got.Scopes, "a key stored with scopes %#v must load with none", want.Scopes)
					got.Scopes = want.Scopes
					assertAPIKey(t, want, got)
				}
			},
		},
		{
			name: "an unknown key is not found by get, revoke or touch",
			assert: func(t *testing.T, ctx context.Context, s apikey.Store, _ *clockwork.FakeClock) {
				putAPIKeys(ctx, t, s, apiKeyRecord(1, keyPrincipal))

				for _, unknown := range []id.ID{suiteID(0x2ff), id.Nil} {
					_, err := s.Get(ctx, unknown)
					require.ErrorIs(t, err, apikey.ErrKeyNotFound, "get %s", unknown)
					require.ErrorIs(t, s.Revoke(ctx, unknown, suiteStart), apikey.ErrKeyNotFound, "revoke %s", unknown)
					require.ErrorIs(t, s.TouchLastUsed(ctx, unknown, suiteStart), apikey.ErrKeyNotFound,
						"touch %s", unknown)
				}
				assertAPIKeyStored(ctx, t, s, apiKeyRecord(1, keyPrincipal))
			},
		},
		{
			name: "revoking records when, and a second revoke keeps the first time",
			assert: func(t *testing.T, ctx context.Context, s apikey.Store, _ *clockwork.FakeClock) {
				putAPIKeys(ctx, t, s, apiKeyRecord(1, keyPrincipal), apiKeyRecord(2, keyPrincipal))

				first := suiteStart.Add(time.Hour)
				require.NoError(t, s.Revoke(ctx, suiteID(0x201), first))
				require.NoError(t, s.Revoke(ctx, suiteID(0x201), first.Add(time.Hour)))

				want := apiKeyRecord(1, keyPrincipal)
				want.RevokedAt = &first
				assertAPIKeyStored(ctx, t, s, want)
				assertAPIKeyStored(ctx, t, s, apiKeyRecord(2, keyPrincipal))
			},
		},
		{
			name: "touching records the latest use and changes nothing else",
			assert: func(t *testing.T, ctx context.Context, s apikey.Store, _ *clockwork.FakeClock) {
				putAPIKeys(ctx, t, s, apiKeyRecord(1, keyPrincipal))

				first, latest := suiteStart.Add(time.Hour), suiteStart.Add(2*time.Hour)
				require.NoError(t, s.TouchLastUsed(ctx, suiteID(0x201), first))
				require.NoError(t, s.TouchLastUsed(ctx, suiteID(0x201), latest))

				want := apiKeyRecord(1, keyPrincipal)
				want.LastUsedAt = &latest
				assertAPIKeyStored(ctx, t, s, want)
			},
		},
		{
			name: "a stored key is not changed by the caller writing to what it put",
			assert: func(t *testing.T, ctx context.Context, s apikey.Store, _ *clockwork.FakeClock) {
				put := apiKeyRecord(1, keyPrincipal)
				putAPIKeys(ctx, t, s, put)
				put.Scopes[0] = "written after put"
				clear(put.SecretDigest)

				assertAPIKeyStored(ctx, t, s, apiKeyRecord(1, keyPrincipal))
			},
		},
		{
			name: "a stored key is not changed by the caller writing to what it read",
			assert: func(t *testing.T, ctx context.Context, s apikey.Store, _ *clockwork.FakeClock) {
				putAPIKeys(ctx, t, s, apiKeyRecord(1, keyPrincipal))

				got, err := s.Get(ctx, suiteID(0x201))
				require.NoError(t, err)
				got.Scopes[0] = "written after get"
				clear(got.SecretDigest)

				assertAPIKeyStored(ctx, t, s, apiKeyRecord(1, keyPrincipal))
			},
		},
		{
			name: "a stored key is not changed by the caller writing to what it listed",
			assert: func(t *testing.T, ctx context.Context, s apikey.Store, _ *clockwork.FakeClock) {
				putAPIKeys(ctx, t, s, apiKeyRecord(1, keyPrincipal))

				listed, err := s.List(ctx, keyPrincipal)
				require.NoError(t, err)
				require.Len(t, listed, 1)
				listed[0].Scopes[0] = "written after list"
				clear(listed[0].SecretDigest)

				assertAPIKeyStored(ctx, t, s, apiKeyRecord(1, keyPrincipal))
				again, err := s.List(ctx, keyPrincipal)
				require.NoError(t, err)
				require.Len(t, again, 1)
				assertAPIKey(t, apiKeyRecord(1, keyPrincipal), again[0])
			},
		},
		{
			// Expiry is the manager's to judge: a key long expired by the
			// system clock is still found and listed, so whoever manages the
			// principal's keys sees it.
			name: "expired keys are still found and listed",
			assert: func(t *testing.T, ctx context.Context, s apikey.Store, _ *clockwork.FakeClock) {
				expired := apiKeyRecord(1, keyPrincipal)
				longAgo := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
				expired.CreatedAt, expired.ExpiresAt = longAgo.Add(-time.Hour), &longAgo
				live := apiKeyRecord(2, keyPrincipal)
				putAPIKeys(ctx, t, s, expired, live)

				assertAPIKeyStored(ctx, t, s, expired)
				got, err := s.List(ctx, keyPrincipal)
				require.NoError(t, err)
				slices.SortFunc(got, func(a, b apikey.Key) int { return bytes.Compare(a.ID[:], b.ID[:]) })
				require.Len(t, got, 2, "an expired key is listed with the live one")
				assertAPIKey(t, expired, got[0])
				assertAPIKey(t, live, got[1])
			},
		},
		{
			name: "key times keep at least microsecond precision",
			assert: func(t *testing.T, ctx context.Context, s apikey.Store, _ *clockwork.FakeClock) {
				rec := apiKeyRecord(1, keyPrincipal)
				expires := preciseStart.Add(24 * time.Hour)
				rec.CreatedAt, rec.ExpiresAt = preciseStart, &expires
				putAPIKeys(ctx, t, s, rec)
				revoked, used := preciseStart.Add(2*time.Hour), preciseStart.Add(time.Hour)
				require.NoError(t, s.TouchLastUsed(ctx, rec.ID, used))
				require.NoError(t, s.Revoke(ctx, rec.ID, revoked))

				got, err := s.Get(ctx, rec.ID)
				require.NoError(t, err)
				assertTimeMicro(t, rec.CreatedAt, got.CreatedAt, "CreatedAt")
				for _, at := range []struct {
					field     string
					want, got *time.Time
				}{
					{"ExpiresAt", &expires, got.ExpiresAt},
					{"RevokedAt", &revoked, got.RevokedAt},
					{"LastUsedAt", &used, got.LastUsedAt},
				} {
					if assert.NotNil(t, at.got, "%s must be present", at.field) {
						assertTimeMicro(t, *at.want, *at.got, at.field)
					}
				}
			},
		},
		{
			name: "listing returns exactly the principal's keys, revoked ones included",
			assert: func(t *testing.T, ctx context.Context, s apikey.Store, _ *clockwork.FakeClock) {
				mine := []apikey.Key{apiKeyRecord(1, keyPrincipal), apiKeyRecord(2, keyPrincipal)}
				putAPIKeys(ctx, t, s, mine...)
				putAPIKeys(ctx, t, s, apiKeyRecord(3, "svc-billing "), apiKeyRecord(4, "Svc-Billing"),
					apiKeyRecord(5, "svc-other"))
				revoked := suiteStart.Add(time.Hour)
				require.NoError(t, s.Revoke(ctx, mine[1].ID, revoked))
				mine[1].RevokedAt = &revoked

				got, err := s.List(ctx, keyPrincipal)
				require.NoError(t, err)
				slices.SortFunc(got, func(a, b apikey.Key) int { return bytes.Compare(a.ID[:], b.ID[:]) })
				require.Len(t, got, len(mine), "only this principal's keys, matched byte for byte")
				for i := range mine {
					assertAPIKey(t, mine[i], got[i])
				}
			},
		},
		{
			name: "listing a principal with no keys is empty, without an error",
			assert: func(t *testing.T, ctx context.Context, s apikey.Store, _ *clockwork.FakeClock) {
				putAPIKeys(ctx, t, s, apiKeyRecord(1, keyPrincipal))

				got, err := s.List(ctx, "svc-nobody")
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
		apiKeyTextCase("a scope holding invalid UTF-8 is refused or round-trips, never altered",
			"canary-4f1a", func(k *apikey.Key) { k.Scopes[0] = "caf\xe9 canary-4f1a" }),
		apiKeyTextCase("a scope holding a NUL byte is refused or round-trips, never altered",
			"canary-c02d", func(k *apikey.Key) { k.Scopes[0] = "before\x00canary-c02d" }),
		apiKeyTextCase("a name holding invalid UTF-8 is refused or round-trips, never altered",
			"canary-77b3", func(k *apikey.Key) { k.Name = "caf\xe9 canary-77b3" }),
		apiKeyTextCase("a name holding a NUL byte is refused or round-trips, never altered",
			"canary-9dfa", func(k *apikey.Key) { k.Name = "before\x00canary-9dfa" }),
		apiKeyTextCase("a principal holding a NUL byte is refused or round-trips, never altered",
			"canary-1e6c", func(k *apikey.Key) { k.Principal = identity.UserID("svc\x00canary-1e6c") }),
	}

	runSuite(t, cases, withoutClock(newStore))
}
