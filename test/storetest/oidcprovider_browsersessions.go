package storetest

import (
	"context"
	"database/sql"
	"reflect"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

var (
	// browserIdle and browserAbsolute are a suite session's deadlines.
	browserIdle     = suiteStart.Add(30 * time.Minute)
	browserAbsolute = suiteStart.Add(8 * time.Hour)
)

// browserRecord returns a session with every field set, keyed by digest n, of signIn.
func browserRecord(n byte, signIn oidcprovider.SignIn) *oidcprovider.BrowserSession {
	return &oidcprovider.BrowserSession{
		Digest:            opDigest(n),
		SignIn:            signIn,
		IdleExpiresAt:     browserIdle,
		AbsoluteExpiresAt: browserAbsolute,
	}
}

// normalBrowser returns s with its times in UTC, for an exact comparison.
func normalBrowser(s *oidcprovider.BrowserSession) oidcprovider.BrowserSession {
	out := *s
	out.SignIn = normalSignIn(s.SignIn)
	out.IdleExpiresAt, out.AbsoluteExpiresAt = utc(s.IdleExpiresAt), utc(s.AbsoluteExpiresAt)

	return out
}

// loadBrowser loads the session for digest n at suiteStart, which must be live.
func loadBrowser(ctx context.Context, t *testing.T, s oidcprovider.BrowserSessionStore, n byte) *oidcprovider.BrowserSession {
	t.Helper()

	got, err := s.Load(ctx, opDigest(n), suiteStart)
	require.NoError(t, err)
	require.NotNil(t, got)

	return got
}

// assertBrowserGone requires the session for digest n to be gone, live or not at suiteStart.
func assertBrowserGone(ctx context.Context, t *testing.T, s oidcprovider.BrowserSessionStore, n byte) {
	t.Helper()

	_, err := s.Load(ctx, opDigest(n), suiteStart)
	assert.ErrorIs(t, err, oidcprovider.ErrNotFound)
}

// BrowserSessionSuite holds a browser-session store to the contract
// oidcprovider.BrowserSessionStore documents, RunTouchRace's race included, as a touch
// deciding by a read and a separate write passes everything else. newStore returns an
// empty store of its own for each case.
//
// The race runs on the one store newStore returns, as the suite knows no other instance,
// so its store must take two calls at once: a pool one connection wide would pass without
// the race having met. A store that may be serialised under a lock of its own instance
// needs RunTouchRace as well, with a harness giving it a second one.
func BrowserSessionSuite(t *testing.T, newStore func(t *testing.T) oidcprovider.BrowserSessionStore) {
	t.Helper()

	runSuite(t, browserCases(), withoutClock(newStore))
	runSuite(t, browserTouchCases(), withoutClock(newStore))
	runSuite(t, browserDeleteCases(), withoutClock(newStore))
	RunTouchRace(t, oneInstanceHarness(newStore))
}

// oneInstanceHarness is what a portable suite can give a race that reaches a store only
// through its methods: one store, from one call of newStore, as both instances, and two
// connections declared for the two racers. The race never reaches the rest of a
// DurableHarness, and a call to any of it fails the test, naming it.
func oneInstanceHarness[S any](newStore func(t *testing.T) S) DurableHarness[S] {
	var store S

	return DurableHarness[S]{
		Harness: Harness[S]{New: func(t *testing.T) S {
			t.Helper()
			store = newStore(t)

			return store
		}},
		NewReplica: func(*testing.T) S { return store },
		Raw:        new(sql.DB),
		Begin: func(t *testing.T) (context.Context, func() error, func() error) {
			t.Helper()
			t.Fatal("storetest: a one-instance harness has no Begin")

			return nil, nil, nil
		},
		BeginResolved: func(t *testing.T) (S, context.Context, func() error, func() error) {
			t.Helper()
			t.Fatal("storetest: a one-instance harness has no BeginResolved")

			return store, nil, nil, nil
		},
		BeginForeign: func(t *testing.T) (context.Context, func() error) {
			t.Helper()
			t.Fatal("storetest: a one-instance harness has no BeginForeign")

			return nil, nil
		},
		PoolSize: 2,
	}
}

func browserCases() []suiteCase[oidcprovider.BrowserSessionStore] {
	type store = oidcprovider.BrowserSessionStore

	signIn := opSignIn("u-1", 1)

	return []suiteCase[store]{
		{
			name: "put and load return every field",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))

				assert.Equal(t, normalBrowser(browserRecord(1, signIn)), normalBrowser(loadBrowser(ctx, t, s, 1)))
			},
		},
		{
			name: "a session holds only the digest it was given, and no secret",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				assertNoSecretField(t, reflect.TypeFor[oidcprovider.BrowserSession](), "Digest")

				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))
				assert.Equal(t, opDigest(1), loadBrowser(ctx, t, s, 1).Digest)
			},
		},
		{
			name: "a load by another digest is not found, and its error carries no digest",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))

				_, err := s.Load(ctx, opDigest(2), suiteStart)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
				assertNoDigest(t, err, opDigest(2))
			},
		},
		{
			name: "a digest already held is refused, the session stays, and the error carries no digest",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))

				err := s.Put(ctx, browserRecord(1, opSignIn("u-2", 2)))
				require.Error(t, err)
				assertNoDigest(t, err, opDigest(1))

				assert.Equal(t, userID("u-1"), loadBrowser(ctx, t, s, 1).SignIn.User)
			},
		},
		{
			name: "an empty digest is neither stored nor found",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := browserRecord(1, signIn)
				r.Digest = nil
				require.ErrorIs(t, s.Put(ctx, r), oidcprovider.ErrConfig)

				_, err := s.Load(ctx, nil, suiteStart)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
				_, err = s.Load(ctx, []byte{}, suiteStart)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "a session with a zero deadline is refused, as no load could judge it",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				idle := browserRecord(1, signIn)
				idle.IdleExpiresAt = time.Time{}
				require.ErrorIs(t, s.Put(ctx, idle), oidcprovider.ErrConfig)

				absolute := browserRecord(1, signIn)
				absolute.AbsoluteExpiresAt = time.Time{}
				require.ErrorIs(t, s.Put(ctx, absolute), oidcprovider.ErrConfig)

				assertBrowserGone(ctx, t, s, 1)
			},
		},
		{
			name: "a session put with an idle deadline past its absolute one holds the absolute one",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := browserRecord(1, signIn)
				r.IdleExpiresAt = browserAbsolute.Add(time.Hour)
				require.NoError(t, s.Put(ctx, r))

				assertTimeEqual(t, browserAbsolute, loadBrowser(ctx, t, s, 1).IdleExpiresAt, "IdleExpiresAt")
			},
		},
		{
			name: "a load is judged at the caller's time, against both deadlines",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))
				early := browserRecord(2, signIn)
				early.IdleExpiresAt, early.AbsoluteExpiresAt = browserAbsolute, browserIdle
				require.NoError(t, s.Put(ctx, early))

				load := func(n byte, now time.Time) error {
					_, err := s.Load(ctx, opDigest(n), now)
					return err
				}
				require.NoError(t, load(1, browserIdle.Add(-time.Nanosecond)), "just before the idle deadline")
				require.ErrorIs(t, load(1, browserIdle), oidcprovider.ErrNotFound, "at the idle deadline")
				require.ErrorIs(t, load(1, browserAbsolute.Add(time.Hour)), oidcprovider.ErrNotFound, "past both")

				require.NoError(t, load(2, browserIdle.Add(-time.Nanosecond)), "just before the absolute deadline")
				require.ErrorIs(t, load(2, browserIdle), oidcprovider.ErrNotFound, "at the absolute deadline")
			},
		},
		{
			name: "a load never reads a clock of its own: a session the wall clock has long passed is live at a time before its end",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := browserRecord(1, signIn)
				r.IdleExpiresAt, r.AbsoluteExpiresAt = longAgo.Add(time.Minute), longAgo.Add(time.Hour)
				require.NoError(t, s.Put(ctx, r))

				_, err := s.Load(ctx, opDigest(1), longAgo)
				require.NoError(t, err)
			},
		},
		{
			name: "a zero time is refused, as it would keep every session alive",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))

				_, err := s.Load(ctx, opDigest(1), time.Time{})
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
			},
		},
		{
			name: "a session stored or loaded is the caller's own copy",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				given := browserRecord(1, signIn)
				given.SignIn.AMR = []string{"pwd", "otp"}
				require.NoError(t, s.Put(ctx, given))
				given.Digest[1] ^= 0xff
				given.SignIn.AMR[0] = "changed"

				got := loadBrowser(ctx, t, s, 1)
				assert.Equal(t, normalBrowser(browserRecord(1, signIn)), normalBrowser(got), "writing to what was given changes nothing")

				got.Digest[1] ^= 0xff
				got.SignIn.AMR[0] = "changed"
				assert.Equal(t, normalBrowser(browserRecord(1, signIn)), normalBrowser(loadBrowser(ctx, t, s, 1)),
					"writing to what was loaded changes nothing")
			},
		},
	}
}

func browserTouchCases() []suiteCase[oidcprovider.BrowserSessionStore] {
	type store = oidcprovider.BrowserSessionStore

	signIn := opSignIn("u-1", 1)

	return []suiteCase[store]{
		{
			name: "touch extends the idle deadline, and changes nothing else",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))
				later := browserIdle.Add(time.Minute)

				require.NoError(t, s.Touch(ctx, opDigest(1), later))

				want := browserRecord(1, signIn)
				want.IdleExpiresAt = later
				assert.Equal(t, normalBrowser(want), normalBrowser(loadBrowser(ctx, t, s, 1)))
			},
		},
		{
			name: "touch never moves the idle deadline past the absolute one",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))

				require.NoError(t, s.Touch(ctx, opDigest(1), browserAbsolute.Add(time.Hour)))

				got := loadBrowser(ctx, t, s, 1)
				assertTimeEqual(t, browserAbsolute, got.IdleExpiresAt, "IdleExpiresAt")
				assertTimeEqual(t, browserAbsolute, got.AbsoluteExpiresAt, "AbsoluteExpiresAt")

				_, err := s.Load(ctx, opDigest(1), browserAbsolute)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "the session still ends at the absolute deadline")
			},
		},
		{
			name: "touch never shortens the idle deadline, so a slower request cannot undo a later one",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))

				require.NoError(t, s.Touch(ctx, opDigest(1), browserIdle.Add(-time.Minute)))

				assertTimeEqual(t, browserIdle, loadBrowser(ctx, t, s, 1).IdleExpiresAt, "IdleExpiresAt")
			},
		},
		{
			name: "touching what is not held is not found, and inserts nothing",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				err := s.Touch(ctx, opDigest(1), browserIdle)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
				assertNoDigest(t, err, opDigest(1))

				assertBrowserGone(ctx, t, s, 1)
			},
		},
		{
			name: "touching with a zero time is refused, and writes nothing",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))

				require.ErrorIs(t, s.Touch(ctx, opDigest(1), time.Time{}), oidcprovider.ErrConfig)

				assertTimeEqual(t, browserIdle, loadBrowser(ctx, t, s, 1).IdleExpiresAt, "IdleExpiresAt")
			},
		},
		{
			name: "a put under a new digest and a delete of the old replace a session",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))

				require.NoError(t, s.Put(ctx, browserRecord(2, signIn)))
				require.NoError(t, s.Delete(ctx, opDigest(1)))

				assertBrowserGone(ctx, t, s, 1)
				assert.Equal(t, normalBrowser(browserRecord(2, signIn)), normalBrowser(loadBrowser(ctx, t, s, 2)))
			},
		},
		{
			name: "deleting what is not held is not an error, and touches nothing else",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))

				require.NoError(t, s.Delete(ctx, opDigest(2)))

				assert.NotNil(t, loadBrowser(ctx, t, s, 1))
			},
		},
	}
}

func browserDeleteCases() []suiteCase[oidcprovider.BrowserSessionStore] {
	type store = oidcprovider.BrowserSessionStore

	signIn := opSignIn("u-1", 1)

	cases := []suiteCase[store]{
		{
			name: "delete by sign-in also removes a session already expired",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := browserRecord(1, signIn)
				r.IdleExpiresAt, r.AbsoluteExpiresAt = longAgo, longAgo
				require.NoError(t, s.Put(ctx, r))

				removed, err := s.DeleteBySignIn(ctx, oidcprovider.SignInSelector{User: "u-1"})
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name: "delete expired keeps what has not expired at the time given, however long ago that time is",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				gone := browserRecord(1, signIn)
				gone.IdleExpiresAt, gone.AbsoluteExpiresAt = longAgo.Add(time.Minute), longAgo.Add(2*time.Minute)
				require.NoError(t, s.Put(ctx, gone))
				kept := browserRecord(2, signIn)
				kept.IdleExpiresAt, kept.AbsoluteExpiresAt = longAgo.Add(time.Hour), longAgo.Add(2*time.Hour)
				require.NoError(t, s.Put(ctx, kept))

				removed, err := s.DeleteExpired(ctx, longAgo.Add(10*time.Minute))
				require.NoError(t, err)
				assert.Equal(t, 1, removed, "the wall clock has long passed both, and the time given only one")

				_, err = s.Load(ctx, opDigest(2), longAgo.Add(10*time.Minute))
				require.NoError(t, err, "the other stays")
			},
		},
		{
			name: "delete expired removes what is past either deadline, by the time given alone",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))
				early := browserRecord(2, signIn)
				early.IdleExpiresAt, early.AbsoluteExpiresAt = browserAbsolute, browserIdle
				require.NoError(t, s.Put(ctx, early))
				live := browserRecord(3, signIn)
				live.IdleExpiresAt, live.AbsoluteExpiresAt = browserAbsolute, browserAbsolute
				require.NoError(t, s.Put(ctx, live))

				removed, err := s.DeleteExpired(ctx, longAgo)
				require.NoError(t, err)
				assert.Equal(t, 0, removed, "a time long before every deadline removes nothing")

				removed, err = s.DeleteExpired(ctx, browserIdle)
				require.NoError(t, err)
				assert.Equal(t, 0, removed, "a deadline at the time given is not strictly before it")

				removed, err = s.DeleteExpired(ctx, browserIdle.Add(time.Second))
				require.NoError(t, err)
				assert.Equal(t, 2, removed, "past the idle deadline of one, and the absolute deadline of another")

				_, err = s.Load(ctx, opDigest(3), browserIdle)
				require.NoError(t, err, "a session past neither deadline stays")
				assertBrowserGone(ctx, t, s, 1)
				assertBrowserGone(ctx, t, s, 2)
			},
		},
	}

	for _, shape := range selectorShapes() {
		cases = append(cases, suiteCase[store]{
			name: "delete by sign-in by " + shape.name + " removes what it selects, and nothing else",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, shape.in)))
				require.NoError(t, s.Put(ctx, browserRecord(2, shape.out)))

				removed, err := s.DeleteBySignIn(ctx, shape.sel)
				require.NoError(t, err)
				assert.Equal(t, 1, removed)

				assertBrowserGone(ctx, t, s, 1)
				assert.NotNil(t, loadBrowser(ctx, t, s, 2))
			},
		})
	}
	for name, sel := range selectorsWithinUser() {
		cases = append(cases, suiteCase[store]{
			name: "delete by sign-in by " + name + " stays within that user",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				other := opSignIn("u-2", 1)
				other.ExternalIssuer, other.ExternalSessionID = opIssuer, opUpstream
				require.NoError(t, s.Put(ctx, browserRecord(1, other)))

				removed, err := s.DeleteBySignIn(ctx, sel)
				require.NoError(t, err)
				assert.Equal(t, 0, removed)
				assert.NotNil(t, loadBrowser(ctx, t, s, 1))
			},
		})
	}
	for name, sel := range invalidSelectors() {
		cases = append(cases, suiteCase[store]{
			name: "delete by sign-in refuses a selector of no valid shape: " + name,
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, browserRecord(1, signIn)))

				_, err := s.DeleteBySignIn(ctx, sel)
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.NotNil(t, loadBrowser(ctx, t, s, 1), "a refused call deletes nothing")
			},
		})
	}

	return cases
}
