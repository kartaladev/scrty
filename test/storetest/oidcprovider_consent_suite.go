package storetest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// ConsentSuite holds a consent store to the contract oidcprovider.ConsentStore
// documents. newStore returns an empty store of its own for each case.
func ConsentSuite(t *testing.T, newStore func(t *testing.T) oidcprovider.ConsentStore) {
	t.Helper()

	runSuite(t, consentCases(), withoutClock(newStore))
}

func consentCases() []suiteCase[oidcprovider.ConsentStore] {
	type store = oidcprovider.ConsentStore

	load := func(ctx context.Context, t *testing.T, s store, user, client string) *oidcprovider.Consent {
		t.Helper()

		got, err := s.Load(ctx, userID(user), client)
		require.NoError(t, err)
		require.NotNil(t, got)

		return got
	}

	return []suiteCase[store]{
		{
			name: "consent nobody gave is not found",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				_, err := s.Load(ctx, "u-1", opClient)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "scopes accumulate in the order given, once each",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Give(ctx, "u-1", opClient, []string{"openid", "profile"}, false, suiteStart))
				require.NoError(t, s.Give(ctx, "u-1", opClient, []string{"openid", "email"}, false, suiteStart))

				got := load(ctx, t, s, "u-1", opClient)
				assert.Equal(t, []string{"openid", "profile", "email"}, got.Scopes)
				assert.Equal(t, opClient, got.ClientID)
				assert.Equal(t, userID("u-1"), got.User)
			},
		},
		{
			name: "offline stays true once given, and later scopes do not clear it",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Give(ctx, "u-1", opClient, []string{"openid"}, true, suiteStart))
				require.NoError(t, s.Give(ctx, "u-1", opClient, []string{"email"}, false, suiteStart))

				assert.True(t, load(ctx, t, s, "u-1", opClient).Offline)
			},
		},
		{
			name: "offline is recorded only when given explicitly, whatever the scopes say",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Give(ctx, "u-1", opClient, []string{"openid", "offline_access"}, false, suiteStart))

				assert.False(t, load(ctx, t, s, "u-1", opClient).Offline)
			},
		},
		{
			name: "the time consent was last given moves",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				later := suiteStart.Add(time.Hour)
				require.NoError(t, s.Give(ctx, "u-1", opClient, []string{"openid"}, false, suiteStart))
				assertTimeEqual(t, suiteStart, load(ctx, t, s, "u-1", opClient).LastGivenAt, "LastGivenAt")

				require.NoError(t, s.Give(ctx, "u-1", opClient, []string{"openid"}, false, later))
				assertTimeEqual(t, later, load(ctx, t, s, "u-1", opClient).LastGivenAt, "LastGivenAt")
			},
		},
		{
			name: "revoke answers true, then false, and giving again starts from nothing",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Give(ctx, "u-1", opClient, []string{"openid", "profile"}, true, suiteStart))

				revoked, err := s.Revoke(ctx, "u-1", opClient)
				require.NoError(t, err)
				assert.True(t, revoked)

				revoked, err = s.Revoke(ctx, "u-1", opClient)
				require.NoError(t, err)
				assert.False(t, revoked)

				_, err = s.Load(ctx, "u-1", opClient)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)

				require.NoError(t, s.Give(ctx, "u-1", opClient, []string{"email"}, false, suiteStart))
				got := load(ctx, t, s, "u-1", opClient)
				assert.Equal(t, []string{"email"}, got.Scopes)
				assert.False(t, got.Offline)
			},
		},
		{
			name: "revoke reaches that user and client alone",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Give(ctx, "u-1", opClient, []string{"openid"}, false, suiteStart))
				require.NoError(t, s.Give(ctx, "u-1", opOtherClient, []string{"openid"}, false, suiteStart))
				require.NoError(t, s.Give(ctx, "u-2", opClient, []string{"openid"}, false, suiteStart))

				_, err := s.Revoke(ctx, "u-1", opClient)
				require.NoError(t, err)

				load(ctx, t, s, "u-1", opOtherClient)
				load(ctx, t, s, "u-2", opClient)
			},
		},
		{
			name: "user and client are kept apart, whatever their text",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Give(ctx, "ab", "c", []string{"openid"}, false, suiteStart))

				_, err := s.Load(ctx, "a", "bc")
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "a listing holds the user's consents and never another's",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Give(ctx, "u-1", opClient, []string{"openid"}, true, suiteStart))
				require.NoError(t, s.Give(ctx, "u-1", opOtherClient, []string{"profile"}, false, suiteStart))
				require.NoError(t, s.Give(ctx, "u-2", opClient, []string{"email"}, false, suiteStart))

				got, err := s.ListByUser(ctx, "u-1")
				require.NoError(t, err)
				require.Len(t, got, 2)
				byClient := map[string]oidcprovider.Consent{}
				for _, c := range got {
					assert.Equal(t, userID("u-1"), c.User)
					byClient[c.ClientID] = c
				}
				assert.Equal(t, []string{"openid"}, byClient[opClient].Scopes)
				assert.True(t, byClient[opClient].Offline)
				assert.Equal(t, []string{"profile"}, byClient[opOtherClient].Scopes)
				assertTimeEqual(t, suiteStart, byClient[opClient].LastGivenAt, "LastGivenAt")

				none, err := s.ListByUser(ctx, "u-3")
				require.NoError(t, err)
				assert.Empty(t, none)
			},
		},
		{
			name: "what the caller gave, loaded and listed are copies",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				given := []string{"openid", "profile"}
				require.NoError(t, s.Give(ctx, "u-1", opClient, given, false, suiteStart))
				given[0] = "scribbled"

				loaded := load(ctx, t, s, "u-1", opClient)
				loaded.Scopes[0] = "scribbled"

				listed, err := s.ListByUser(ctx, "u-1")
				require.NoError(t, err)
				require.Len(t, listed, 1)
				listed[0].Scopes[0] = "scribbled"

				assert.Equal(t, []string{"openid", "profile"}, load(ctx, t, s, "u-1", opClient).Scopes)
			},
		},
		{
			name: "concurrent gifts all accumulate",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				var (
					start = make(chan struct{})
					wg    sync.WaitGroup
					want  []string
				)
				for i := range 16 {
					scope := fmt.Sprintf("scope-%d", i)
					want = append(want, scope)
					wg.Go(func() {
						<-start
						assert.NoError(t, s.Give(ctx, "u-1", opClient, []string{scope}, i == 0, suiteStart))
					})
				}
				close(start)
				wg.Wait()

				got := load(ctx, t, s, "u-1", opClient)
				assert.ElementsMatch(t, want, got.Scopes, "a read-then-write store loses a gift")
				assert.True(t, got.Offline, "a read-then-write store loses the offline gift")
			},
		},
	}
}
