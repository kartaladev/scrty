package apikey_test

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

func TestManagerRotate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// lifetime is how long the key rotated lives; zero is no expiry.
		lifetime time.Duration
		// advance moves the manager's clock once the key is issued.
		advance time.Duration
		// store wraps the inner store; clk is the manager's clock and cancel
		// ends the context Rotate is called with.
		store  func(inner apikey.Store, clk *clockwork.FakeClock, cancel context.CancelFunc) apikey.Store
		target func(t *testing.T, rec apikey.Key) id.ID
		assert func(t *testing.T, m *apikey.Manager, old string, fresh string, rec apikey.Key, err error)
	}

	// noLiveReplacement fails when a key without an expiry, which is what a
	// replacement rotated with a zero lifetime is, is still live.
	noLiveReplacement := func(t *testing.T, m *apikey.Manager) {
		t.Helper()

		keys, err := m.List(t.Context(), "svc-billing")
		require.NoError(t, err)

		for _, k := range keys {
			if k.ExpiresAt == nil {
				assert.NotNil(t, k.RevokedAt, "replacement %s was left live", k.ID)
			}
		}
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
			name: "a failed revoke is an error rather than a silently split credential",
			store: func(inner apikey.Store, _ *clockwork.FakeClock, _ context.CancelFunc) apikey.Store {
				return revokeFailsStore{Store: inner}
			},
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Manager, old, fresh string, _ apikey.Key, err error) {
				require.Error(t, err)
				assert.Empty(t, fresh, "the new key is returned only when both steps succeed")

				_, _, oldErr := m.Verify(t.Context(), old)
				assert.NoError(t, oldErr,
					"outside a transaction these are two writes: the old key is still live, and the error says so")
			},
		},
		{
			name:     "a key that expires while the replacement is issued is refused and nothing stays live",
			lifetime: time.Hour,
			advance:  time.Hour, // on the instant it expires: still live at the first check
			store: func(inner apikey.Store, clk *clockwork.FakeClock, _ context.CancelFunc) apikey.Store {
				return advanceOnPutStore{Store: inner, clk: clk, by: time.Second, puts: new(atomic.Int32)}
			},
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Manager, _, fresh string, _ apikey.Key, err error) {
				assert.ErrorIs(t, err, apikey.ErrRotationRefused)
				assert.Empty(t, fresh)
				noLiveReplacement(t, m)
			},
		},
		{
			name: "a cancelled caller still ends the replacement of a rotation that lost",
			store: func(inner apikey.Store, _ *clockwork.FakeClock, cancel context.CancelFunc) apikey.Store {
				return &loseThenCancelStore{Store: inner, cancel: cancel}
			},
			target: sameKey,
			assert: func(t *testing.T, m *apikey.Manager, _, fresh string, _ apikey.Key, err error) {
				assert.ErrorIs(t, err, apikey.ErrRotationRefused)
				assert.Empty(t, fresh)
				noLiveReplacement(t, m)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			clk := clockwork.NewFakeClockAt(time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC))
			inner := apikey.NewMemoryStore()

			store := apikey.Store(inner)
			if tc.store != nil {
				store = tc.store(inner, clk, cancel)
			}

			m, err := apikey.NewManager(apikey.WithStore(store), apikey.WithClock(clk))
			require.NoError(t, err)

			old, issued, err := m.Issue(ctx, "svc-billing", "nightly export", []string{"invoices:read"}, tc.lifetime)
			require.NoError(t, err)

			clk.Advance(tc.advance)

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
				apikey.WithClock(clockwork.NewFakeClockAt(at)),
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

func TestRotate_RefusesRevokedOrExpiredKey(t *testing.T) {
	t.Parallel()

	issuedAt := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name     string
		lifetime time.Duration
		// end makes the issued key one Rotate must refuse.
		end    func(t *testing.T, m *apikey.Manager, clk *clockwork.FakeClock, rec apikey.Key)
		assert func(t *testing.T, m *apikey.Manager, store *countingKeyStore, fresh string, err error)
	}

	refusedIssuingNothing := func(t *testing.T, m *apikey.Manager, store *countingKeyStore, fresh string, err error) {
		require.ErrorIs(t, err, apikey.ErrRotationRefused)
		assert.Empty(t, fresh)
		assert.Zero(t, store.Writes(), "a refused rotation writes nothing")

		keys, listErr := m.List(t.Context(), "svc-admin")
		require.NoError(t, listErr)
		assert.Len(t, keys, 1, "nothing new may be issued for a key that is no longer accepted")
	}

	cases := []testCase{
		{
			name: "a revoked admin-scoped key",
			end: func(t *testing.T, m *apikey.Manager, _ *clockwork.FakeClock, rec apikey.Key) {
				require.NoError(t, m.Revoke(t.Context(), rec.ID))
			},
			assert: refusedIssuingNothing,
		},
		{
			name:     "a key past its lifetime",
			lifetime: time.Hour,
			end: func(_ *testing.T, _ *apikey.Manager, clk *clockwork.FakeClock, _ apikey.Key) {
				clk.Advance(time.Hour + time.Second)
			},
			assert: refusedIssuingNothing,
		},
		{
			name:     "a key on the instant it expires is still live, and rotates",
			lifetime: time.Hour,
			end: func(_ *testing.T, _ *apikey.Manager, clk *clockwork.FakeClock, _ apikey.Key) {
				clk.Advance(time.Hour)
			},
			assert: func(t *testing.T, m *apikey.Manager, _ *countingKeyStore, fresh string, err error) {
				require.NoError(t, err)

				_, _, verifyErr := m.Verify(t.Context(), fresh)
				assert.NoError(t, verifyErr)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			clk := clockwork.NewFakeClockAt(issuedAt)
			inner := apikey.NewMemoryStore()

			m, err := apikey.NewManager(apikey.WithStore(inner), apikey.WithClock(clk))
			require.NoError(t, err)

			_, rec, err := m.Issue(ctx, "svc-admin", "break glass", []string{"admin"}, tc.lifetime)
			require.NoError(t, err)

			tc.end(t, m, clk, rec)

			// Counting starts here, so only the rotation's own writes count.
			store := &countingKeyStore{Store: inner}
			rotator, err := apikey.NewManager(apikey.WithStore(store), apikey.WithClock(clk))
			require.NoError(t, err)

			fresh, _, rotateErr := rotator.Rotate(ctx, rec.ID, 0)
			tc.assert(t, m, store, fresh, rotateErr)
		})
	}
}

func TestRotate_ConcurrentRotationsLeaveOneLiveReplacement(t *testing.T) {
	t.Parallel()

	const rotations = 8

	ctx := t.Context()

	inner := apikey.NewMemoryStore()
	m, err := apikey.NewManager(apikey.WithStore(inner))
	require.NoError(t, err)

	old, rec, err := m.Issue(ctx, "svc-billing", "nightly export", []string{"invoices:read"}, 0)
	require.NoError(t, err)

	// Every rotation reads the key live and issues its replacement before any
	// of them revokes it.
	rotator, err := apikey.NewManager(apikey.WithStore(newRevokeBarrierStore(inner, rec.ID, rotations)))
	require.NoError(t, err)

	type outcome struct {
		presented string
		rec       apikey.Key
		err       error
	}

	outcomes := make([]outcome, rotations)

	var wg sync.WaitGroup
	for i := range rotations {
		wg.Go(func() {
			presented, fresh, rotateErr := rotator.Rotate(ctx, rec.ID, 0)
			outcomes[i] = outcome{presented: presented, rec: fresh, err: rotateErr}
		})
	}
	wg.Wait()

	var winners []outcome
	for _, o := range outcomes {
		if o.err == nil {
			winners = append(winners, o)
			continue
		}
		require.ErrorIs(t, o.err, apikey.ErrRotationRefused, "a rotation that lost the race is refused")
		assert.Empty(t, o.presented, "a refused rotation returns no key")
	}
	require.Equal(t, 1, len(winners), "exactly one concurrent rotation returns a new key") //nolint:testifylint // Len would print every presented key

	keys, err := m.List(ctx, "svc-billing")
	require.NoError(t, err)
	require.Len(t, keys, rotations+1, "every replacement issued is kept, revoked, for whoever audits it")

	var live []id.ID
	for _, k := range keys {
		if k.RevokedAt == nil {
			live = append(live, k.ID)
		}
	}
	assert.Equal(t, []id.ID{winners[0].rec.ID}, live, "exactly one key derived from the old one is live")

	_, _, err = m.Verify(ctx, winners[0].presented)
	require.NoError(t, err, "the returned replacement verifies")
	_, _, err = m.Verify(ctx, old)
	assert.ErrorIs(t, err, apikey.ErrVerificationFailed, "the old key is revoked")
}
