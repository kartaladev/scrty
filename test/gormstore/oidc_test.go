package gormstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/pkg/id"
	oidctest "github.com/kartaladev/scrty/test/oidc"
	"github.com/kartaladev/scrty/test/storetest"
)

// newLinkStore builds the link store over db, failing t on a refusal.
func newLinkStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.LinkStore {
	t.Helper()

	s, err := gormstore.NewLinkStore(db, opts...)
	require.NoError(t, err)

	return s
}

// newFlowStore builds the flow store over db, failing t on a refusal.
func newFlowStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.FlowStore {
	t.Helper()

	s, err := gormstore.NewFlowStore(db, opts...)
	require.NoError(t, err)

	return s
}

// newHandoffStore builds the handoff store over db, failing t on a refusal.
func newHandoffStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.HandoffStore {
	t.Helper()

	s, err := gormstore.NewHandoffStore(db, opts...)
	require.NoError(t, err)

	return s
}

// oidcStart is when every OIDC record here was made.
var oidcStart = time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

// link is a link of provider's subject at issuer to user, under a fresh id.
func link(t *testing.T, provider, issuer, subject string, user identity.UserID) oidc.Link {
	t.Helper()

	return oidc.Link{
		ID: newID(t), Provider: provider, Issuer: issuer, Subject: subject,
		UserID: user, Username: "user-of-" + subject, Email: subject + "@example.com", CreatedAt: oidcStart,
	}
}

// flow is a flow for provider and state, expiring ten minutes after
// oidcStart.
func flow(provider, state string) oidc.Flow {
	return oidc.Flow{
		Provider: provider, State: state, Nonce: "nonce-" + state, Verifier: "verifier-" + state,
		Next: "/next?of=" + state, ExpiresAt: oidcStart.Add(10 * time.Minute),
	}
}

// handoff is a record for tokenID under a fresh id, issued at oidcStart and
// expiring a minute later.
func handoff(t *testing.T, tokenID string) oidc.HandoffRecord {
	t.Helper()

	sum := sha256.Sum256([]byte("secret-of-" + tokenID))

	return oidc.HandoffRecord{
		ID: newID(t), TokenID: tokenID, SecretHash: sum[:], UserID: "u-" + identity.UserID(tokenID),
		Provider: "corp", Issuer: "https://corp.example", SessionID: "sid-" + tokenID,
		IDToken: "header.payload.signature", Next: "/home",
		CreatedAt: oidcStart, ExpiresAt: oidcStart.Add(time.Minute),
	}
}

// testClock is a clock a test advances by hand. It is safe for concurrent
// use.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// linkRace is the race over link inserts: record i is the subject
// race-subject-i, which Seed does not insert, and every racer inserts it for
// a user of its own, the refusal mapped to (false, nil).
func linkRace[S oidc.LinkStore]() storetest.Race[S] {
	gen := id.NewV7Generator()
	return storetest.Race[S]{
		Seed: func(_ context.Context, _ *testing.T, _ S, i int) string {
			return fmt.Sprintf("race-subject-%d", i)
		},
		Attempt: func(ctx context.Context, s S, key string, racer int) (bool, error) {
			linkID, err := gen.NewID()
			if err != nil {
				return false, err
			}
			err = s.Insert(ctx, oidc.Link{
				ID: linkID, Provider: "corp", Issuer: "https://race.example", Subject: key,
				UserID: identity.UserID(fmt.Sprintf("u-%d", racer)), CreatedAt: oidcStart,
			})
			if errors.Is(err, oidc.ErrLinkExists) {
				return false, nil
			}
			return err == nil, err
		},
	}
}

// handoffRace is the race over handoff consumption: Seed inserts the record
// race-token-i, and every racer consumes it, the refusal mapped to
// (false, nil).
func handoffRace[S oidc.HandoffStore]() storetest.Race[S] {
	return storetest.Race[S]{
		Seed: func(ctx context.Context, t *testing.T, s S, i int) string {
			rec := handoff(t, fmt.Sprintf("race-token-%d", i))
			require.NoError(t, s.Insert(ctx, rec))
			return rec.TokenID
		},
		Attempt: func(ctx context.Context, s S, key string, _ int) (bool, error) {
			err := s.Consume(ctx, key, time.Now())
			if errors.Is(err, oidc.ErrHandoffNotFound) {
				return false, nil
			}
			return err == nil, err
		},
	}
}

func TestLinkStore(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)

	t.Run("gorm", func(t *testing.T) {
		oidctest.RunLinkStoreSuite(t, func(t *testing.T) oidc.LinkStore {
			return newLinkStore(t, emptied(t, d, "oidc_links"))
		})
	})
}

func TestFlowStore(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)

	t.Run("gorm", func(t *testing.T) {
		oidctest.RunFlowStoreSuite(t, func(t *testing.T, now func() time.Time) oidc.FlowStore {
			return newFlowStore(t, emptied(t, d, "oidc_flows"), gormstore.WithClock(now))
		})
	})
}

func TestHandoffStore(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)

	t.Run("gorm", func(t *testing.T) {
		oidctest.RunHandoffStoreSuite(t, func(t *testing.T, _ func() time.Time) oidc.HandoffStore {
			return newHandoffStore(t, emptied(t, d, "oidc_handoffs"))
		})
	})
}

func TestLinkStore_InsertRace(t *testing.T) {
	t.Parallel()

	h := durableHarness(migratedDB(t), func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.LinkStore {
		return newLinkStore(t, db, opts...)
	})

	t.Run("gorm", func(t *testing.T) {
		storetest.RunLinkInsertRace(t, h, linkRace[*gormstore.LinkStore]())
	})
}

func TestHandoffStore_ConsumeRace(t *testing.T) {
	t.Parallel()

	h := durableHarness(migratedDB(t), func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.HandoffStore {
		return newHandoffStore(t, db, opts...)
	})

	t.Run("gorm", func(t *testing.T) {
		storetest.RunConsumeRace(t, h, handoffRace[*gormstore.HandoffStore]())
	})
}

func TestNewOIDCStores(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)

	type testCase struct {
		name   string
		build  func(db *gormdb.DB, opts ...gormstore.Option) (any, error)
		db     *gormdb.DB
		opts   []gormstore.Option
		assert func(t *testing.T, s any, err error)
	}

	links := func(db *gormdb.DB, opts ...gormstore.Option) (any, error) { return gormstore.NewLinkStore(db, opts...) }
	flows := func(db *gormdb.DB, opts ...gormstore.Option) (any, error) { return gormstore.NewFlowStore(db, opts...) }
	handoffs := func(db *gormdb.DB, opts ...gormstore.Option) (any, error) {
		return gormstore.NewHandoffStore(db, opts...)
	}
	refused := refusedConfig[any]
	accepted := acceptedConfig[any]
	generator := gormstore.WithIDGenerator(id.NewV7Generator())
	clock := gormstore.WithClock(time.Now)

	cases := []testCase{
		{name: "links: a handle is all it needs", build: links, db: db, assert: accepted},
		{name: "links: a missing handle is refused", build: links, assert: refused("the database handle is nil")},
		{
			name: "links: an id generator does not apply", build: links, db: db, opts: []gormstore.Option{generator},
			assert: refused("WithIDGenerator does not apply to this store"),
		},
		{
			name: "links: a clock does not apply", build: links, db: db, opts: []gormstore.Option{clock},
			assert: refused("WithClock does not apply to this store"),
		},
		{name: "flows: a handle is all it needs", build: flows, db: db, assert: accepted},
		{name: "flows: a missing handle is refused", build: flows, assert: refused("the database handle is nil")},
		{
			name: "flows: it honours a clock and an id generator", build: flows, db: db,
			opts: []gormstore.Option{clock, generator}, assert: accepted,
		},
		{
			name: "flows: re-sealing does not apply", build: flows, db: db,
			opts:   []gormstore.Option{gormstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
		{name: "handoffs: a handle is all it needs", build: handoffs, db: db, assert: accepted},
		{name: "handoffs: a missing handle is refused", build: handoffs, assert: refused("the database handle is nil")},
		{
			name: "handoffs: a clock does not apply", build: handoffs, db: db, opts: []gormstore.Option{clock},
			assert: refused("WithClock does not apply to this store"),
		},
		{
			name: "handoffs: an id generator does not apply", build: handoffs, db: db,
			opts: []gormstore.Option{generator}, assert: refused("WithIDGenerator does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := tc.build(tc.db, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestOIDCStores_Durable(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context, d database)
	}

	// clockedFlows is a flow store whose clock starts at oidcStart.
	clockedFlows := func(t *testing.T, db *gormdb.DB) (*gormstore.FlowStore, *testClock) {
		t.Helper()
		clock := &testClock{now: oidcStart}
		return newFlowStore(t, db, gormstore.WithClock(clock.Now)), clock
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
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newLinkStore(t, d.db)
				require.NoError(t, s.Insert(ctx, link(t, "corp", "https://overwrite.example", "s-1", "u1")))
				require.ErrorIs(t, s.Insert(ctx, link(t, "corp", "https://overwrite.example", "s-1", "u2")), oidc.ErrLinkExists)

				got, err := s.FindByExternal(ctx, "corp", "https://overwrite.example", "s-1")
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u1"), got.UserID)
			},
		},
		{
			name: "a refused link insert's error text carries neither the subject nor the user",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newLinkStore(t, d.db)
				require.NoError(t, s.Insert(ctx, link(t, "corp", "https://text.example", "subject-9f2c", "user-4d1e")))

				err := s.Insert(ctx, link(t, "corp", "https://text.example", "subject-9f2c", "user-4d1e"))
				require.ErrorIs(t, err, oidc.ErrLinkExists)
				assert.NotContains(t, err.Error(), "subject-9f2c")
				assert.NotContains(t, err.Error(), "user-4d1e")
			},
		},
		{
			name: "deleting a user's links removes all of them, reports the count, and keeps another user's",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newLinkStore(t, d.db)
				require.NoError(t, s.Insert(ctx, link(t, "corp", "https://delete.example", "s-1", "del-u1")))
				require.NoError(t, s.Insert(ctx, link(t, "social", "https://delete.example", "s-9", "del-u1")))
				require.NoError(t, s.Insert(ctx, link(t, "corp", "https://delete.example", "s-2", "del-u2")))

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
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newLinkStore(t, d.db)
				require.NoError(t, s.Insert(ctx, link(t, "corp", "https://empty.example", "s-1", "")))
				require.NoError(t, s.Insert(ctx, link(t, "corp", "https://empty.example", "s-2", "someone")))

				n, err := s.DeleteByUser(ctx, "")
				require.NoError(t, err)
				assert.Zero(t, n)
				assert.Equal(t, 2, countLinks(ctx, t, d.conn.DB, "https://empty.example"), "no link is removed")
			},
		},
		{
			name: "a link holding text PostgreSQL cannot store is refused without echoing it",
			assert: func(t *testing.T, ctx context.Context, d database) {
				err := newLinkStore(t, d.db).Insert(ctx,
					link(t, "corp", "https://nul.example", "sub\x00canary-81aa", "u1"))
				require.Error(t, err)
				assert.NotErrorIs(t, err, oidc.ErrLinkExists)
				assert.NotContains(t, err.Error(), "canary-81aa")
				assert.Zero(t, countLinks(ctx, t, d.conn.DB, "https://nul.example"), "nothing is written")
			},
		},
		{
			name: "a zero-id link insert is refused before any statement, and nothing is written",
			assert: func(t *testing.T, ctx context.Context, d database) {
				l := link(t, "corp", "https://zeroid.example", "s-zero", "u1")
				l.ID = id.Nil
				err := newLinkStore(t, d.db).Insert(ctx, l)
				require.Error(t, err)
				assert.Zero(t, countLinks(ctx, t, d.conn.DB, "https://zeroid.example"), "nothing is written")
			},
		},
		{
			name: "a completion with a wrong state is refused and does not burn the flow",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s, _ := clockedFlows(t, d.db)
				f := flow("p1", "s1")
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
			assert: func(t *testing.T, ctx context.Context, d database) {
				s, _ := clockedFlows(t, d.db)
				h, err := s.Begin(ctx, flow("p1", "s1"))
				require.NoError(t, err)

				_, err = s.Complete(ctx, h, "p2", "s1")
				require.ErrorIs(t, err, oidc.ErrInvalidState)
				_, err = s.Complete(ctx, h, "p1", "s1")
				require.NoError(t, err, "the refused completion burned the flow")
			},
		},
		{
			name: "an expired flow is refused as an unknown handle is, and stays uncompleted",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s, clock := clockedFlows(t, d.db)
				h, err := s.Begin(ctx, flow("p1", "s-expired"))
				require.NoError(t, err)
				clock.Advance(10 * time.Minute)

				_, expired := s.Complete(ctx, h, "p1", "s-expired")
				_, unknown := s.Complete(ctx, "no-such-handle", "p1", "s-expired")
				require.ErrorIs(t, expired, oidc.ErrInvalidState)
				assert.Equal(t, unknown, expired, "an expired flow must be refused as an unknown handle is")

				var completed sql.NullTime
				require.NoError(t, d.conn.DB.QueryRowContext(ctx,
					`SELECT completed_at FROM oidc_flows WHERE handle = $1`, h).Scan(&completed))
				assert.False(t, completed.Valid, "the refused completion wrote the flow")
			},
		},
		{
			name: "a completion with an empty handle or an empty state is refused without a statement error",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s, _ := clockedFlows(t, d.db)
				h, err := s.Begin(ctx, flow("p1", "s-empty"))
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
			assert: func(t *testing.T, ctx context.Context, d database) {
				s, _ := clockedFlows(t, d.db)
				h, err := s.Begin(ctx, flow("p1", ""))
				require.NoError(t, err)

				_, err = s.Complete(ctx, h, "p1", "")
				require.ErrorIs(t, err, oidc.ErrInvalidState)
			},
		},
		{
			name: "handles are minted from 32 random bytes, base64url, and differ",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s, _ := clockedFlows(t, d.db)
				h1, err := s.Begin(ctx, flow("p1", "s-handle-1"))
				require.NoError(t, err)
				h2, err := s.Begin(ctx, flow("p1", "s-handle-2"))
				require.NoError(t, err)

				assert.NotEqual(t, h1, h2)
				raw, err := base64.RawURLEncoding.DecodeString(h1)
				require.NoError(t, err)
				assert.Len(t, raw, 32)
			},
		},
		{
			name: "a flow row takes its id from the consumer's generator",
			assert: func(t *testing.T, ctx context.Context, d database) {
				fixed := id.MustParse("00000000-0000-4000-8000-00000000f10e")
				s := newFlowStore(t, d.db,
					gormstore.WithIDGenerator(generatorFunc(func() (id.ID, error) { return fixed, nil })))
				h, err := s.Begin(ctx, flow("p1", "s-generated"))
				require.NoError(t, err)

				var stored string
				require.NoError(t, d.conn.DB.QueryRowContext(ctx,
					`SELECT id::text FROM oidc_flows WHERE handle = $1`, h).Scan(&stored))
				assert.Equal(t, fixed.String(), stored)
			},
		},
		{
			name: "a completion under a cancelled context fails with the cancellation, not a refusal",
			ctx:  cancelled,
			assert: func(t *testing.T, ctx context.Context, d database) {
				s, _ := clockedFlows(t, d.db)
				_, err := s.Complete(ctx, "some-handle", "p1", "s1")
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, oidc.ErrInvalidState)
			},
		},
		{
			name: "a handoff's subject round-trips byte for byte",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newHandoffStore(t, d.db)
				rec := handoff(t, "tok-round-trip")
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
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newHandoffStore(t, d.db)
				require.NoError(t, s.Insert(ctx, handoff(t, "tok-twice")))
				t1 := oidcStart.Add(10 * time.Second)
				require.NoError(t, s.Consume(ctx, "tok-twice", t1))

				require.ErrorIs(t, s.Consume(ctx, "tok-twice", t1.Add(time.Second)), oidc.ErrHandoffNotFound)
				got, err := s.FindByTokenID(ctx, "tok-twice")
				require.NoError(t, err)
				require.NotNil(t, got.ConsumedAt)
				assert.True(t, t1.Equal(*got.ConsumedAt), "consumed at %v, want %v", *got.ConsumedAt, t1)
			},
		},
		{
			name: "an empty token id is refused as unknown, even when a record holds one",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newHandoffStore(t, d.db)
				require.NoError(t, s.Insert(ctx, handoff(t, "")))

				require.ErrorIs(t, s.Consume(ctx, "", oidcStart), oidc.ErrHandoffNotFound)
				_, err := s.FindByTokenID(ctx, "")
				require.ErrorIs(t, err, oidc.ErrHandoffNotFound)

				var consumed sql.NullTime
				require.NoError(t, d.conn.DB.QueryRowContext(ctx,
					`SELECT consumed_at FROM oidc_handoffs WHERE token_id = ''`).Scan(&consumed))
				assert.False(t, consumed.Valid, "the empty token id consumed a record")
			},
		},
		{
			name: "a zero-id handoff insert is refused before any statement, and nothing is written",
			assert: func(t *testing.T, ctx context.Context, d database) {
				rec := handoff(t, "tok-zero-id")
				rec.ID = id.Nil
				err := newHandoffStore(t, d.db).Insert(ctx, rec)
				require.Error(t, err)
				assert.Zero(t, countHandoffs(ctx, t, d.conn.DB, "tok-zero-id"), "nothing is written")
			},
		},
		{
			name: "a consumption under a cancelled context fails with the cancellation, not a refusal",
			ctx:  cancelled,
			assert: func(t *testing.T, ctx context.Context, d database) {
				err := newHandoffStore(t, d.db).Consume(ctx, "tok-cancelled", oidcStart)
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
			tc.assert(t, ctx, d)
		})
	}
}
