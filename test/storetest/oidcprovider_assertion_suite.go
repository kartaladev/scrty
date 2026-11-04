package storetest

import (
	"context"
	"testing"
	"time"
	"unicode"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// assertionUntil is when the suite's assertion identifiers expire.
var assertionUntil = suiteStart.Add(5 * time.Minute)

// recorded records jti for client, and returns whether the store called it new.
func recorded(
	ctx context.Context, t *testing.T, s oidcprovider.AssertionIDStore, client, jti string, until time.Time,
) bool {
	t.Helper()

	fresh, err := s.Record(ctx, client, jti, until)
	require.NoError(t, err)

	return fresh
}

// joinedKeyPairs returns client and identifier pairs of which some collide in a store
// keeping each pair under one string, however it joins them: by any ASCII punctuation or
// symbol, by nothing at all, and with either the client or the identifier first.
func joinedKeyPairs() [][2]string {
	seps := []string{""}
	for c := rune('!'); c <= '~'; c++ {
		if unicode.IsPunct(c) || unicode.IsSymbol(c) {
			seps = append(seps, string(c))
		}
	}

	pairs := make([][2]string, 0, 3*len(seps))
	for _, sep := range seps {
		pairs = append(pairs,
			[2]string{"a" + sep + "b", "c"}, // client first, it collides with the next
			[2]string{"a", "b" + sep + "c"},
			[2]string{"b", "c" + sep + "a"}, // identifier first, it collides with the first
		)
	}

	return pairs
}

// AssertionIDSuite holds an assertion-identifier store to the contract
// oidcprovider.AssertionIDStore documents. newStore returns an empty store of its own
// for each case.
func AssertionIDSuite(t *testing.T, newStore func(t *testing.T) oidcprovider.AssertionIDStore) {
	t.Helper()

	runSuite(t, assertionCases(), withoutClock(newStore))
}

func assertionCases() []suiteCase[oidcprovider.AssertionIDStore] {
	type store = oidcprovider.AssertionIDStore

	return []suiteCase[store]{
		{
			name: "an identifier is new once",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				assert.True(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil))
				assert.False(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil))
			},
		},
		{
			name: "an identifier belongs to its client alone, whatever the text of either",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				assert.True(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil))
				assert.True(t, recorded(ctx, t, s, opOtherClient, "jti-1", assertionUntil), "another client")
				assert.True(t, recorded(ctx, t, s, opClient, "jti-2", assertionUntil), "another identifier")

				// Each pair is told apart from the others by the text alone, so no separator
				// or collation in the store's key can join them.
				pairs := append(joinedKeyPairs(), [][2]string{
					{"client", "jti"}, {"Client", "jti"}, {"client", "JTI"},
					{"client ", "jti"}, {"client", "jti "},
				}...)
				for _, pair := range pairs {
					assert.True(t, recorded(ctx, t, s, pair[0], pair[1], assertionUntil), "%q and %q", pair[0], pair[1])
				}
			},
		},
		{
			name: "a refused record keeps a later first expiry, and is not shortened",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.True(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil))
				require.False(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil.Add(-time.Minute)))

				removed, err := s.DeleteExpired(ctx, assertionUntil)
				require.NoError(t, err)
				assert.Equal(t, 0, removed, "the first expiry is the one kept")
				assert.False(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil))
			},
		},
		{
			name: "a refused record does not extend the first expiry",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.True(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil))
				require.False(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil.Add(time.Hour)))

				removed, err := s.DeleteExpired(ctx, assertionUntil.Add(time.Second))
				require.NoError(t, err)
				assert.Equal(t, 1, removed, "the first expiry is the one kept")
				assert.True(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil.Add(time.Hour)))
			},
		},
		{
			name: "delete expired forgets what is strictly before the time given, and that alone",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.True(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil))
				require.True(t, recorded(ctx, t, s, opClient, "jti-2", assertionUntil.Add(time.Hour)))

				removed, err := s.DeleteExpired(ctx, assertionUntil)
				require.NoError(t, err)
				assert.Equal(t, 0, removed, "an identifier expiring at the time given is not strictly before it")
				assert.False(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil), "it is still held")

				removed, err = s.DeleteExpired(ctx, assertionUntil.Add(time.Second))
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
				assert.True(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil.Add(time.Hour)), "the expired pair is gone")
				assert.False(t, recorded(ctx, t, s, opClient, "jti-2", assertionUntil.Add(time.Hour)), "the other stays")
			},
		},
		{
			name: "delete expired judges by the time given, never by a clock of its own",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.True(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil))

				removed, err := s.DeleteExpired(ctx, longAgo)
				require.NoError(t, err)
				assert.Equal(t, 0, removed)
				assert.False(t, recorded(ctx, t, s, opClient, "jti-1", assertionUntil))
			},
		},
		{
			name: "delete expired keeps what has not expired at the time given, however long ago that time is",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.True(t, recorded(ctx, t, s, opClient, "jti-1", longAgo.Add(time.Minute)))
				require.True(t, recorded(ctx, t, s, opClient, "jti-2", longAgo.Add(time.Hour)))

				removed, err := s.DeleteExpired(ctx, longAgo.Add(10*time.Minute))
				require.NoError(t, err)
				assert.Equal(t, 1, removed, "the wall clock has long passed both, and the time given only one")
				assert.False(t, recorded(ctx, t, s, opClient, "jti-2", longAgo.Add(time.Hour)), "the other stays")
			},
		},
		{
			name: "a pair is held until delete expired removes it, whatever any clock says of its expiry",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				until := longAgo.Add(time.Minute)
				require.True(t, recorded(ctx, t, s, opClient, "jti-1", until))
				assert.False(t, recorded(ctx, t, s, opClient, "jti-1", until), "the wall clock has long passed it, and it is held")

				removed, err := s.DeleteExpired(ctx, until.Add(time.Second))
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
				assert.True(t, recorded(ctx, t, s, opClient, "jti-1", until), "removed, it is new again")
			},
		},
	}
}
