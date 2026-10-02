package oidc_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/pkg/id"
)

// handoffStoreT0 is when every record in the memory store table was issued.
var handoffStoreT0 = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

// handoffStoreRecord is one record as Insert would receive it, issued at
// handoffStoreT0 and expiring a minute later.
func handoffStoreRecord(tokenID string) oidc.HandoffRecord {
	sum := sha256.Sum256([]byte("secret-of-" + tokenID))

	return oidc.HandoffRecord{
		ID:         id.MustParse("01926a4e-0000-7000-8000-000000000001"),
		TokenID:    tokenID,
		SecretHash: sum[:],
		UserID:     "u-1",
		Provider:   "corp",
		Issuer:     "https://idp.example.com",
		SessionID:  "sid-1",
		IDToken:    "id-token",
		Next:       "/home",
		AMR:        []string{"pwd", "mfa"},
		ACR:        "urn:corp:loa:2",
		CreatedAt:  handoffStoreT0,
		ExpiresAt:  handoffStoreT0.Add(time.Minute),
	}
}

func TestMemoryHandoffStore(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		seed   []oidc.HandoffRecord
		assert func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore)
	}

	cases := []testCase{
		{
			name: "insert then find returns what was stored",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, handoffStoreRecord("tok-a"), *got)
			},
		},
		{
			name: "find returns a copy the caller cannot write through",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				first, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				clear(first.SecretHash)
				first.AMR[1] = "x"
				first.UserID = "u-2"
				spent := handoffStoreT0
				first.ConsumedAt = &spent

				again, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assert.Equal(t, handoffStoreRecord("tok-a"), *again, "the store aliased its own record on read")
			},
		},
		{
			name: "insert copies the caller's buffers",
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				rec := handoffStoreRecord("tok-a")
				require.NoError(t, s.Insert(ctx, rec))
				clear(rec.SecretHash)
				rec.AMR[1] = "x"

				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assert.Equal(t, handoffStoreRecord("tok-a").SecretHash, got.SecretHash,
					"the store aliased the caller's buffer on write")
				assert.Equal(t, handoffStoreRecord("tok-a").AMR, got.AMR,
					"the store aliased the caller's amr on write")
			},
		},
		{
			name: "a second insert of one token id is refused and the first record survives",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				other := handoffStoreRecord("tok-a")
				other.UserID = "u-2"
				require.Error(t, s.Insert(ctx, other))

				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assert.Equal(t, handoffStoreRecord("tok-a"), *got)
			},
		},
		{
			name: "find of a missing id is not-found, and a present one is still found",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				got, err := s.FindByTokenID(ctx, "tok-missing")
				require.ErrorIs(t, err, oidc.ErrHandoffNotFound)
				assert.Nil(t, got)

				_, err = s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
			},
		},
		{
			name: "consume of an unconsumed record succeeds and records when",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				at := handoffStoreT0.Add(10 * time.Second)
				require.NoError(t, s.Consume(ctx, "tok-a", at))

				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				require.NotNil(t, got.ConsumedAt)
				assert.Equal(t, at, *got.ConsumedAt)
			},
		},
		{
			name: "a second consume is not-found and keeps the first consume time",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				first := handoffStoreT0.Add(10 * time.Second)
				require.NoError(t, s.Consume(ctx, "tok-a", first))
				require.ErrorIs(t, s.Consume(ctx, "tok-a", first.Add(time.Second)), oidc.ErrHandoffNotFound)

				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				require.NotNil(t, got.ConsumedAt)
				assert.Equal(t, first, *got.ConsumedAt)
			},
		},
		{
			name: "consume of a missing id is not-found, and another record still consumes",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				require.ErrorIs(t, s.Consume(ctx, "tok-missing", handoffStoreT0), oidc.ErrHandoffNotFound)

				_, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				require.NoError(t, s.Consume(ctx, "tok-a", handoffStoreT0))
			},
		},
		{
			name: "delete-expired removes only records expired before the cutoff and counts them",
			seed: func() []oidc.HandoffRecord {
				early := handoffStoreRecord("tok-early") // expires T0+1m
				late := handoffStoreRecord("tok-late")
				late.ExpiresAt = handoffStoreT0.Add(5 * time.Minute)
				live := handoffStoreRecord("tok-live")
				live.ExpiresAt = handoffStoreT0.Add(time.Hour)
				return []oidc.HandoffRecord{early, late, live}
			}(),
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				n, err := s.DeleteExpired(ctx, handoffStoreT0.Add(2*time.Minute))
				require.NoError(t, err)
				assert.Equal(t, 1, n)

				_, err = s.FindByTokenID(ctx, "tok-early")
				require.ErrorIs(t, err, oidc.ErrHandoffNotFound)
				_, err = s.FindByTokenID(ctx, "tok-late")
				require.NoError(t, err, "a record that expired after the cutoff must survive")
				_, err = s.FindByTokenID(ctx, "tok-live")
				require.NoError(t, err)
			},
		},
		{
			name: "a cutoff after a record's expiry deletes it even if the store clock has not reached it",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")}, // expires T0+1m; store clock stays T0
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				n, err := s.DeleteExpired(ctx, handoffStoreT0.Add(time.Hour))
				require.NoError(t, err)
				assert.Equal(t, 1, n,
					"the port contract judges expiry against the cutoff alone, not the store's own clock")

				_, err = s.FindByTokenID(ctx, "tok-a")
				require.ErrorIs(t, err, oidc.ErrHandoffNotFound)
			},
		},
		{
			name: "a zero cutoff is refused, every record survives, and a real cutoff then works",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a"), handoffStoreRecord("tok-b")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				n, err := s.DeleteExpired(ctx, time.Time{})
				require.ErrorIs(t, err, oidc.ErrRetainSinceRequired)
				assert.Zero(t, n)

				for _, tok := range []string{"tok-a", "tok-b"} {
					_, err := s.FindByTokenID(ctx, tok)
					require.NoError(t, err, "a refused purge must delete nothing")
				}

				n, err = s.DeleteExpired(ctx, handoffStoreT0.Add(5*time.Minute))
				require.NoError(t, err)
				assert.Equal(t, 2, n)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := oidc.NewMemoryHandoffStore()
			for _, rec := range tc.seed {
				require.NoError(t, s.Insert(t.Context(), rec))
			}

			tc.assert(t, t.Context(), s)
		})
	}
}
