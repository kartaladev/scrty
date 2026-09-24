package apikey_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

func TestManagerRotate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  func(inner apikey.Store) apikey.Store
		target func(t *testing.T, rec apikey.Key) id.ID
		assert func(t *testing.T, m *apikey.Manager, old string, fresh string, rec apikey.Key, err error)
	}

	sameKey := func(_ *testing.T, rec apikey.Key) id.ID { return rec.ID }

	cases := []testCase{
		{
			name:   "the new key works and the old one does not",
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Manager, old, fresh string, _ apikey.Key, err error) {
				require.NoError(t, err)

				p, _, verifyErr := m.Verify(t.Context(), fresh)
				require.NoError(t, verifyErr)
				assert.Equal(t, identity.UserID("svc-billing"), p.ID)
				assert.Equal(t, "nightly export", p.Name)
				assert.Equal(t, []string{"invoices:read"}, p.Scopes)

				_, _, oldErr := m.Verify(t.Context(), old)
				assert.ErrorIs(t, oldErr, apikey.ErrVerificationFailed)
			},
		},
		{
			name:   "the replacement is a different record",
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Manager, old, fresh string, _ apikey.Key, err error) {
				require.NoError(t, err)
				assert.NotEqual(t, old, fresh)

				keys, listErr := m.List(t.Context(), "svc-billing")
				require.NoError(t, listErr)
				assert.Len(t, keys, 2, "the old record stays, revoked, for whoever audits it")
			},
		},
		{
			name:   "the caller's lifetime is used, not the old key's",
			target: sameKey,
			assert: func(t *testing.T, _ *apikey.Manager, _, _ string, rec apikey.Key, err error) {
				require.NoError(t, err)
				assert.Nil(t, rec.ExpiresAt, "rotated here with a lifetime of zero")
			},
		},
		{
			name: "an unknown key issues nothing",
			target: func(t *testing.T, _ apikey.Key) id.ID {
				other, err := newID()
				require.NoError(t, err)

				return other
			},
			assert: func(t *testing.T, m *apikey.Manager, _, fresh string, _ apikey.Key, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, apikey.ErrKeyNotFound)
				assert.Empty(t, fresh)

				keys, listErr := m.List(t.Context(), "svc-billing")
				require.NoError(t, listErr)
				assert.Len(t, keys, 1, "nothing new may be issued for an unknown key")
			},
		},
		{
			name:   "a failed revoke is an error rather than a silently split credential",
			store:  func(inner apikey.Store) apikey.Store { return revokeFailsStore{Store: inner} },
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Manager, old, fresh string, _ apikey.Key, err error) {
				require.Error(t, err)
				assert.Empty(t, fresh, "the new key is returned only when both steps succeed")

				_, _, oldErr := m.Verify(t.Context(), old)
				assert.NoError(t, oldErr,
					"outside a transaction these are two writes: the old key is still live, and the error says so")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			inner := apikey.NewMemoryStore()

			store := apikey.Store(inner)
			if tc.store != nil {
				store = tc.store(inner)
			}

			m, err := apikey.NewManager(apikey.WithStore(store))
			require.NoError(t, err)

			old, issued, err := m.Issue(ctx, "svc-billing", "nightly export", []string{"invoices:read"}, 0)
			require.NoError(t, err)

			fresh, rec, rotateErr := m.Rotate(ctx, tc.target(t, issued), 0)
			tc.assert(t, m, old, fresh, rec, rotateErr)
		})
	}
}

func TestManagerLastUsed(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		store  func(inner apikey.Store) apikey.Store
		assert func(t *testing.T, inner apikey.Store, rec apikey.Key, err error)
	}

	cases := []testCase{
		{
			name: "a successful verification records the time",
			assert: func(t *testing.T, inner apikey.Store, rec apikey.Key, err error) {
				require.NoError(t, err)

				stored, getErr := inner.Get(t.Context(), rec.ID)
				require.NoError(t, getErr)
				require.NotNil(t, stored.LastUsedAt)
				assert.True(t, stored.LastUsedAt.Equal(at))
			},
		},
		{
			name:  "a failure to record does not fail verification",
			store: func(inner apikey.Store) apikey.Store { return touchFailsStore{Store: inner} },
			assert: func(t *testing.T, inner apikey.Store, rec apikey.Key, err error) {
				assert.NoError(t, err, "a best-effort write may not refuse a valid key")

				stored, getErr := inner.Get(t.Context(), rec.ID)
				require.NoError(t, getErr)
				assert.Nil(t, stored.LastUsedAt, "nothing was recorded, and nothing pretended otherwise")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			inner := apikey.NewMemoryStore()

			store := apikey.Store(inner)
			if tc.store != nil {
				store = tc.store(inner)
			}

			m, err := apikey.NewManager(
				apikey.WithStore(store),
				apikey.WithClock(func() time.Time { return at }),
				// The best-effort case logs a warning by design; this keeps it
				// out of the test output without silencing the behaviour.
				apikey.WithLogger(slog.New(slog.DiscardHandler)),
			)
			require.NoError(t, err)

			presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
			require.NoError(t, err)

			_, verified, verifyErr := m.Verify(ctx, presented)
			if verifyErr == nil {
				require.NotNil(t, verified.LastUsedAt)
				assert.True(t, verified.LastUsedAt.Equal(at),
					"the returned record carries the time whether or not the write landed")
			}

			tc.assert(t, inner, rec, verifyErr)
		})
	}
}
