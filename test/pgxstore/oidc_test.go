package pgxstore_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/internal/storefix"
	oidctest "github.com/kartaladev/scrty/test/oidc"
	"github.com/kartaladev/scrty/test/storetest"
)

// newLinkStore builds the link store over db, failing t on a refusal.
func newLinkStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) *pgxstore.LinkStore {
	t.Helper()

	s, err := pgxstore.NewLinkStore(pool, opts...)
	require.NoError(t, err)

	return s
}

// newFlowStore builds the flow store over db, failing t on a refusal.
func newFlowStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) *pgxstore.FlowStore {
	t.Helper()

	s, err := pgxstore.NewFlowStore(pool, opts...)
	require.NoError(t, err)

	return s
}

// newHandoffStore builds the handoff store over db, failing t on a refusal.
func newHandoffStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) *pgxstore.HandoffStore {
	t.Helper()

	s, err := pgxstore.NewHandoffStore(pool, opts...)
	require.NoError(t, err)

	return s
}

func TestLinkStore(t *testing.T) {
	t.Parallel()

	db := migrated(t)

	t.Run("pgx", func(t *testing.T) {
		oidctest.RunLinkStoreSuite(t, func(t *testing.T) oidc.LinkStore {
			return newLinkStore(t, emptied(t, db, "oidc_links"))
		})
	})
}

func TestFlowStore(t *testing.T) {
	t.Parallel()

	db := migrated(t)

	t.Run("pgx", func(t *testing.T) {
		oidctest.RunFlowStoreSuite(t, func(t *testing.T, now func() time.Time) oidc.FlowStore {
			return newFlowStore(t, emptied(t, db, "oidc_flows"), pgxstore.WithClock(now))
		})
	})
}

func TestHandoffStore(t *testing.T) {
	t.Parallel()

	db := migrated(t)

	t.Run("pgx", func(t *testing.T) {
		oidctest.RunHandoffStoreSuite(t, func(t *testing.T, _ func() time.Time) oidc.HandoffStore {
			return newHandoffStore(t, emptied(t, db, "oidc_handoffs"))
		})
	})
}

func TestLinkStore_InsertRace(t *testing.T) {
	t.Parallel()

	h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) *pgxstore.LinkStore {
		return newLinkStore(t, pool, opts...)
	})

	t.Run("pgx", func(t *testing.T) {
		storetest.RunLinkInsertRace(t, h, storefix.LinkRace[*pgxstore.LinkStore]())
	})
}

func TestHandoffStore_ConsumeRace(t *testing.T) {
	t.Parallel()

	h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) *pgxstore.HandoffStore {
		return newHandoffStore(t, pool, opts...)
	})

	t.Run("pgx", func(t *testing.T) {
		storetest.RunConsumeRace(t, h, storefix.HandoffRace[*pgxstore.HandoffStore]())
	})
}

func TestNewOIDCStores(t *testing.T) {
	t.Parallel()

	pool := unreachablePool(t)

	type testCase struct {
		name   string
		build  func(pool *pgxpool.Pool, opts ...pgxstore.Option) (any, error)
		pool   *pgxpool.Pool
		opts   []pgxstore.Option
		assert func(t *testing.T, s any, err error)
	}

	links := func(pool *pgxpool.Pool, opts ...pgxstore.Option) (any, error) {
		return pgxstore.NewLinkStore(pool, opts...)
	}
	flows := func(pool *pgxpool.Pool, opts ...pgxstore.Option) (any, error) {
		return pgxstore.NewFlowStore(pool, opts...)
	}
	handoffs := func(pool *pgxpool.Pool, opts ...pgxstore.Option) (any, error) {
		return pgxstore.NewHandoffStore(pool, opts...)
	}
	refused := refusedConfig[any]
	accepted := storefix.AcceptedConfig[any]
	generator := pgxstore.WithIDGenerator(id.NewV7Generator())
	clock := pgxstore.WithClock(time.Now)

	cases := []testCase{
		{name: "links: a pool is all it needs", build: links, pool: pool, assert: accepted},
		{name: "links: a missing pool is refused", build: links, assert: refused("the pool is nil")},
		{
			name: "links: an id generator does not apply", build: links, pool: pool, opts: []pgxstore.Option{generator},
			assert: refused("WithIDGenerator does not apply to this store"),
		},
		{
			name: "links: a clock does not apply", build: links, pool: pool, opts: []pgxstore.Option{clock},
			assert: refused("WithClock does not apply to this store"),
		},
		{name: "flows: a pool is all it needs", build: flows, pool: pool, assert: accepted},
		{name: "flows: a missing pool is refused", build: flows, assert: refused("the pool is nil")},
		{
			name: "flows: it honours a clock and an id generator", build: flows, pool: pool,
			opts: []pgxstore.Option{clock, generator}, assert: accepted,
		},
		{
			name: "flows: re-sealing does not apply", build: flows, pool: pool,
			opts:   []pgxstore.Option{pgxstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
		{name: "handoffs: a pool is all it needs", build: handoffs, pool: pool, assert: accepted},
		{name: "handoffs: a missing pool is refused", build: handoffs, assert: refused("the pool is nil")},
		{
			name: "handoffs: a clock does not apply", build: handoffs, pool: pool, opts: []pgxstore.Option{clock},
			assert: refused("WithClock does not apply to this store"),
		},
		{
			name: "handoffs: an id generator does not apply", build: handoffs, pool: pool,
			opts: []pgxstore.Option{generator}, assert: refused("WithIDGenerator does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := tc.build(tc.pool, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestOIDCStores_Durable(t *testing.T) {
	t.Parallel()

	db := migrated(t)

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context, db database)
	}

	// clockedFlows is a flow store whose clock starts at oidcStart.
	clockedFlows := func(t *testing.T, pool *pgxpool.Pool) (*pgxstore.FlowStore, *storefix.Clock) {
		t.Helper()
		clock := storefix.NewClock(storefix.OIDCStart)
		return newFlowStore(t, pool, pgxstore.WithClock(clock.Now)), clock
	}
	// countLinks counts the links at issuer, out of band.
	countLinks := func(ctx context.Context, t *testing.T, db *sql.DB, issuer string) int {
		t.Helper()
		var n int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM oidc_links WHERE issuer = $1`, issuer).Scan(&n))
		return n
	}
	// countHandoffs counts the handoffs of tokenID, out of band.
	countHandoffs := func(ctx context.Context, t *testing.T, db *sql.DB, tokenID string) int {
		t.Helper()
		var n int
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT count(*) FROM oidc_handoffs WHERE token_id = $1`, tokenID).Scan(&n))
		return n
	}

	cases := []testCase{
		{
			name: "a refused link insert does not overwrite the stored link",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s := newLinkStore(t, db.Pool)
				require.NoError(t, s.Insert(ctx, storefix.Link(t, "corp", "https://overwrite.example", "s-1", "u1")))
				require.ErrorIs(t, s.Insert(ctx, storefix.Link(t, "corp", "https://overwrite.example", "s-1", "u2")), oidc.ErrLinkExists)

				got, err := s.FindByExternal(ctx, "corp", "https://overwrite.example", "s-1")
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u1"), got.UserID)
			},
		},
		{
			name: "a refused link insert's error text carries neither the subject nor the user",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s := newLinkStore(t, db.Pool)
				require.NoError(t, s.Insert(ctx, storefix.Link(t, "corp", "https://text.example", "subject-9f2c", "user-4d1e")))

				err := s.Insert(ctx, storefix.Link(t, "corp", "https://text.example", "subject-9f2c", "user-4d1e"))
				require.ErrorIs(t, err, oidc.ErrLinkExists)
				assert.NotContains(t, err.Error(), "subject-9f2c")
				assert.NotContains(t, err.Error(), "user-4d1e")
			},
		},
		{
			name: "deleting a user's links removes all of them, reports the count, and keeps another user's",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s := newLinkStore(t, db.Pool)
				require.NoError(t, s.Insert(ctx, storefix.Link(t, "corp", "https://delete.example", "s-1", "del-u1")))
				require.NoError(t, s.Insert(ctx, storefix.Link(t, "social", "https://delete.example", "s-9", "del-u1")))
				require.NoError(t, s.Insert(ctx, storefix.Link(t, "corp", "https://delete.example", "s-2", "del-u2")))

				n, err := s.DeleteByUser(ctx, "del-u1")
				require.NoError(t, err)
				assert.Equal(t, 2, n)

				kept, err := s.FindByExternal(ctx, "corp", "https://delete.example", "s-2")
				require.NoError(t, err, "another user's link still resolves")
				assert.Equal(t, identity.UserID("del-u2"), kept.UserID)
			},
		},
		{
			name: "deleting the links of an empty user reference removes nothing and reports 0",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s := newLinkStore(t, db.Pool)
				require.NoError(t, s.Insert(ctx, storefix.Link(t, "corp", "https://empty.example", "s-1", "")))
				require.NoError(t, s.Insert(ctx, storefix.Link(t, "corp", "https://empty.example", "s-2", "someone")))

				n, err := s.DeleteByUser(ctx, "")
				require.NoError(t, err)
				assert.Zero(t, n)
				assert.Equal(t, 2, countLinks(ctx, t, db.DB, "https://empty.example"), "no link is removed")
			},
		},
		{
			name: "a link holding text PostgreSQL cannot store is refused without echoing it",
			assert: func(t *testing.T, ctx context.Context, db database) {
				err := newLinkStore(t, db.Pool).Insert(ctx,
					storefix.Link(t, "corp", "https://nul.example", "sub\x00canary-81aa", "u1"))
				require.Error(t, err)
				assert.NotErrorIs(t, err, oidc.ErrLinkExists)
				assert.NotContains(t, err.Error(), "canary-81aa")
				assert.Zero(t, countLinks(ctx, t, db.DB, "https://nul.example"), "nothing is written")
			},
		},
		{
			name: "a zero-id link insert is refused before any statement, and nothing is written",
			assert: func(t *testing.T, ctx context.Context, db database) {
				l := storefix.Link(t, "corp", "https://zeroid.example", "s-zero", "u1")
				l.ID = id.Nil
				err := newLinkStore(t, db.Pool).Insert(ctx, l)
				require.Error(t, err)
				assert.Zero(t, countLinks(ctx, t, db.DB, "https://zeroid.example"), "nothing is written")
			},
		},
		{
			name: "a completion with a wrong state is refused and does not burn the flow",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s, _ := clockedFlows(t, db.Pool)
				f := storefix.Flow("p1", "s1")
				h, err := s.Begin(ctx, f)
				require.NoError(t, err)

				_, err = s.Complete(ctx, h, "p1", "attacker")
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				got, err := s.Complete(ctx, h, "p1", "s1")
				require.NoError(t, err, "the refused completion burned the flow")
				assert.Equal(t, f.Nonce, got.Nonce)
			},
		},
		{
			name: "a completion at a wrong provider is refused and does not burn the flow",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s, _ := clockedFlows(t, db.Pool)
				h, err := s.Begin(ctx, storefix.Flow("p1", "s1"))
				require.NoError(t, err)

				_, err = s.Complete(ctx, h, "p2", "s1")
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				_, err = s.Complete(ctx, h, "p1", "s1")
				require.NoError(t, err, "the refused completion burned the flow")
			},
		},
		{
			name: "an expired flow is refused as an unknown handle is, and stays uncompleted",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s, clock := clockedFlows(t, db.Pool)
				h, err := s.Begin(ctx, storefix.Flow("p1", "s-expired"))
				require.NoError(t, err)
				clock.Advance(10 * time.Minute)

				_, expired := s.Complete(ctx, h, "p1", "s-expired")
				_, unknown := s.Complete(ctx, "no-such-handle", "p1", "s-expired")
				require.ErrorIs(t, expired, oidc.ErrInvalidState)
				assert.Equal(t, unknown, expired, "an expired flow must be refused as an unknown handle is")

				var completed sql.NullTime
				require.NoError(t, db.DB.QueryRowContext(ctx,
					`SELECT completed_at FROM oidc_flows WHERE handle = $1`, h).Scan(&completed))
				assert.False(t, completed.Valid, "the refused completion wrote the flow")
			},
		},
		{
			name: "a completion with an empty handle or an empty state is refused without a statement error",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s, _ := clockedFlows(t, db.Pool)
				h, err := s.Begin(ctx, storefix.Flow("p1", "s-empty"))
				require.NoError(t, err)

				_, err = s.Complete(ctx, "", "p1", "s-empty")
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				_, err = s.Complete(ctx, h, "p1", "")
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				_, err = s.Complete(ctx, h, "p1", "s-empty")
				require.NoError(t, err, "a refused completion burned the flow")
			},
		},
		{
			name: "a flow begun with an empty state never completes, even with an empty state",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s, _ := clockedFlows(t, db.Pool)
				h, err := s.Begin(ctx, storefix.Flow("p1", ""))
				require.NoError(t, err)

				_, err = s.Complete(ctx, h, "p1", "")
				require.ErrorIs(t, err, oidc.ErrInvalidState)
			},
		},
		{
			name: "handles are minted from 32 random bytes, base64url, and differ",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s, _ := clockedFlows(t, db.Pool)
				h1, err := s.Begin(ctx, storefix.Flow("p1", "s-handle-1"))
				require.NoError(t, err)
				h2, err := s.Begin(ctx, storefix.Flow("p1", "s-handle-2"))
				require.NoError(t, err)

				assert.NotEqual(t, h1, h2)
				raw, err := base64.RawURLEncoding.DecodeString(h1)
				require.NoError(t, err)
				assert.Len(t, raw, 32)
			},
		},
		{
			name: "a flow row takes its id from the consumer's generator",
			assert: func(t *testing.T, ctx context.Context, db database) {
				fixed := id.MustParse("00000000-0000-4000-8000-00000000f10e")
				s := newFlowStore(t, db.Pool,
					pgxstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) { return fixed, nil })))
				h, err := s.Begin(ctx, storefix.Flow("p1", "s-generated"))
				require.NoError(t, err)

				var stored string
				require.NoError(t, db.DB.QueryRowContext(ctx,
					`SELECT id::text FROM oidc_flows WHERE handle = $1`, h).Scan(&stored))
				assert.Equal(t, fixed.String(), stored)
			},
		},
		{
			name: "a completion under a cancelled context fails with the cancellation, not a refusal",
			ctx:  storefix.Cancelled,
			assert: func(t *testing.T, ctx context.Context, db database) {
				s, _ := clockedFlows(t, db.Pool)
				_, err := s.Complete(ctx, "some-handle", "p1", "s1")
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, oidc.ErrInvalidState)
			},
		},
		{
			name: "a handoff's subject round-trips byte for byte",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s := newHandoffStore(t, db.Pool)
				rec := storefix.Handoff(t, "tok-round-trip")
				rec.UserID, rec.Provider, rec.Issuer = "Alice@Example.com", "Corp IdP", "https://Corp.example/"
				rec.SessionID, rec.Next = " sid-Ω ", "/after?x=1&y=ü"
				require.NoError(t, s.Insert(ctx, rec))

				got, err := s.FindByTokenID(ctx, "tok-round-trip")
				require.NoError(t, err)
				assert.Equal(t, rec.UserID, got.UserID)
				assert.Equal(t, rec.Provider, got.Provider)
				assert.Equal(t, rec.Issuer, got.Issuer)
				assert.Equal(t, rec.SessionID, got.SessionID)
				assert.Equal(t, rec.Next, got.Next)
			},
		},
		{
			name: "a second consumption is refused and the first consumption time is kept",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s := newHandoffStore(t, db.Pool)
				require.NoError(t, s.Insert(ctx, storefix.Handoff(t, "tok-twice")))
				t1 := storefix.OIDCStart.Add(10 * time.Second)
				require.NoError(t, s.Consume(ctx, "tok-twice", t1))

				require.ErrorIs(t, s.Consume(ctx, "tok-twice", t1.Add(time.Second)), oidc.ErrHandoffNotFound)
				got, err := s.FindByTokenID(ctx, "tok-twice")
				require.NoError(t, err)
				require.NotNil(t, got.ConsumedAt)
				assert.True(t, t1.Equal(*got.ConsumedAt), "consumed at %v, want %v", *got.ConsumedAt, t1)
			},
		},
		{
			name: "a handoff whose consumption time is infinite is an error, never unconsumed",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s := newHandoffStore(t, db.Pool)
				require.NoError(t, s.Insert(ctx, storefix.Handoff(t, "tok-infinite")))
				_, err := db.DB.ExecContext(ctx,
					`UPDATE oidc_handoffs SET consumed_at = 'infinity' WHERE token_id = 'tok-infinite'`)
				require.NoError(t, err)

				got, err := s.FindByTokenID(ctx, "tok-infinite")
				require.Error(t, err)
				assert.NotErrorIs(t, err, oidc.ErrHandoffNotFound)
				assert.Nil(t, got)
			},
		},
		{
			name: "an empty token id is refused as unknown, even when a record holds one",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s := newHandoffStore(t, db.Pool)
				require.NoError(t, s.Insert(ctx, storefix.Handoff(t, "")))

				require.ErrorIs(t, s.Consume(ctx, "", storefix.OIDCStart), oidc.ErrHandoffNotFound)
				_, err := s.FindByTokenID(ctx, "")
				require.ErrorIs(t, err, oidc.ErrHandoffNotFound)

				var consumed sql.NullTime
				require.NoError(t, db.DB.QueryRowContext(ctx,
					`SELECT consumed_at FROM oidc_handoffs WHERE token_id = ''`).Scan(&consumed))
				assert.False(t, consumed.Valid, "the empty token id consumed a record")
			},
		},
		{
			name: "a zero-id handoff insert is refused before any statement, and nothing is written",
			assert: func(t *testing.T, ctx context.Context, db database) {
				rec := storefix.Handoff(t, "tok-zero-id")
				rec.ID = id.Nil
				err := newHandoffStore(t, db.Pool).Insert(ctx, rec)
				require.Error(t, err)
				assert.Zero(t, countHandoffs(ctx, t, db.DB, "tok-zero-id"), "nothing is written")
			},
		},
		{
			name: "a consumption under a cancelled context fails with the cancellation, not a refusal",
			ctx:  storefix.Cancelled,
			assert: func(t *testing.T, ctx context.Context, db database) {
				err := newHandoffStore(t, db.Pool).Consume(ctx, "tok-cancelled", storefix.OIDCStart)
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, oidc.ErrHandoffNotFound)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			tc.assert(t, ctx, db)
		})
	}
}
