package storetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

// grantRecord returns a live grant with every field set: family n, from signIn, for
// the suite's client, holding a lineage and expiring in 90 days.
func grantRecord(n int, signIn oidcprovider.SignIn) *oidcprovider.Grant {
	return &oidcprovider.Grant{
		Family:            suiteID(n),
		User:              signIn.User,
		ClientID:          opClient,
		Scopes:            []string{"openid", "profile"},
		Resources:         []string{"https://api.example.com"},
		AuthTime:          signIn.AuthenticatedAt,
		AMR:               slices.Clone(signIn.AMR),
		ACR:               signIn.ACR,
		KeyBinding:        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
		CertBinding:       "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg4",
		CodeID:            suiteID(500 + n),
		SignInFamily:      signIn.Family,
		ExternalIssuer:    signIn.ExternalIssuer,
		ExternalSessionID: signIn.ExternalSessionID,
		HoldsLineage:      true,
		CreatedAt:         suiteStart,
		ExpiresAt:         suiteStart.Add(90 * 24 * time.Hour),
	}
}

// normalGrant returns g with its times in UTC, for an exact comparison.
func normalGrant(g *oidcprovider.Grant) oidcprovider.Grant {
	out := *g
	out.AuthTime, out.CreatedAt, out.ExpiresAt = utc(g.AuthTime), utc(g.CreatedAt), utc(g.ExpiresAt)
	out.RevokedAt, out.SignInEndedAt = utc(g.RevokedAt), utc(g.SignInEndedAt)

	return out
}

// createGrants stores each grant.
func createGrants(ctx context.Context, t *testing.T, s oidcprovider.GrantStore, grants ...*oidcprovider.Grant) {
	t.Helper()

	for _, g := range grants {
		require.NoError(t, s.Create(ctx, g))
	}
}

// loadGrant loads family n, which must exist.
func loadGrant(ctx context.Context, t *testing.T, s oidcprovider.GrantStore, n int) *oidcprovider.Grant {
	t.Helper()

	got, err := s.Load(ctx, suiteID(n))
	require.NoError(t, err)
	require.NotNil(t, got)

	return got
}

// familiesOf returns the family of each grant.
func familiesOf(grants []oidcprovider.Grant) []id.ID {
	out := make([]id.ID, 0, len(grants))
	for _, g := range grants {
		out = append(out, g.Family)
	}

	return out
}

// grantWorld is one case's grant store, with the code store it reads outstanding codes
// from. The suite uses the in-memory code store whatever the grant store under test is,
// as the two meet only through the port.
type grantWorld struct {
	oidcprovider.GrantStore
	codes *oidcprovider.MemoryCodeStore
	// source is what the store was joined to: codes, unless the case takes it down.
	source *switchableCodes
}

// outstanding stores an unspent code naming family n's grant.
func (w grantWorld) outstanding(ctx context.Context, t *testing.T, n int, signIn oidcprovider.SignIn, mutate ...func(*oidcprovider.CodeRecord)) {
	t.Helper()

	r := codeRecord(n, signIn)
	r.GrantFamily = suiteID(n)
	for _, m := range mutate {
		m(r)
	}
	require.NoError(t, w.codes.Create(ctx, r))
}

// offlineCode marks a code as holding offline_access.
func offlineCode(r *oidcprovider.CodeRecord) { r.Offline = true }

// tiedOfflineCode marks a code as holding offline_access, of a client tied to its sign-in.
func tiedOfflineCode(r *oidcprovider.CodeRecord) { r.Offline, r.EndsWithSignIn = true, true }

// switchableCodes is one code source a store is joined to once, which a case can take
// down and bring back, as a store refuses to be joined to another.
type switchableCodes struct {
	oidcprovider.UnspentCodes
	down error
}

func (s *switchableCodes) UnspentBySignIn(ctx context.Context, sel oidcprovider.SignInSelector, includeOffline bool) ([]id.ID, error) {
	if s.down != nil {
		return nil, s.down
	}

	return s.UnspentCodes.UnspentBySignIn(ctx, sel, includeOffline)
}

func (s *switchableCodes) UnspentByClient(ctx context.Context, user identity.UserID, clientID string) ([]id.ID, error) {
	if s.down != nil {
		return nil, s.down
	}

	return s.UnspentCodes.UnspentByClient(ctx, user, clientID)
}

// GrantSuite holds a grant store to the contract oidcprovider.GrantStore documents.
// newStore returns an empty store of its own for each case, and the suite gives it
// its code source through UseCodes, as oidcprovider.New does.
func GrantSuite(t *testing.T, newStore func(t *testing.T) oidcprovider.GrantStore) {
	t.Helper()

	cases := slices.Concat(grantCases(), grantEndCases(), grantShapeCases(), grantSweepCases())
	runSuite(t, cases, func(t *testing.T, _ clock.Clock) grantWorld {
		t.Helper()

		codes, err := oidcprovider.NewMemoryCodeStore()
		require.NoError(t, err)
		source := &switchableCodes{UnspentCodes: codes}
		s := newStore(t)
		require.NoError(t, s.UseCodes(source))

		return grantWorld{GrantStore: s, codes: codes, source: source}
	})

	grantJoinCases(t, newStore)

	t.Run("a store given no code source refuses what would miss a code", func(t *testing.T) {
		s := newStore(t)
		ctx := t.Context()
		createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)))

		_, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1"}, suiteStart)
		require.ErrorIs(t, err, oidcprovider.ErrConfig, "EndSignIns")
		_, err = s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, suiteStart)
		require.ErrorIs(t, err, oidcprovider.ErrConfig, "RevokeByUser")
		_, err = s.RevokeByUserAndClient(ctx, "u-1", opClient, oidcprovider.CauseConsentRevoked, suiteStart)
		require.ErrorIs(t, err, oidcprovider.ErrConfig, "RevokeByUserAndClient")

		assert.False(t, loadGrant(ctx, t, s, 1).Revoked, "a refused call writes nothing")
	})
}

// incomparableCodes is a code source that == cannot compare with its own kind.
type incomparableCodes struct {
	oidcprovider.UnspentCodes

	_ []string
}

// wrappedCodes is a code source whose type compares, and whose value may not.
type wrappedCodes struct{ oidcprovider.UnspentCodes }

// grantJoinCases holds a store to what UseCodes promises about a second call: joining
// another code source would silently break what the first provider relies on.
func grantJoinCases(t *testing.T, newStore func(t *testing.T) oidcprovider.GrantStore) {
	t.Helper()

	// Each row joins first, then second. first holds family 1's code, and second family 2's.
	cases := []struct {
		name          string
		first, second func(codes *oidcprovider.MemoryCodeStore, other *oidcprovider.MemoryCodeStore) oidcprovider.UnspentCodes
		assert        func(t *testing.T, err error)
	}{
		{
			name: "joining the same code source again is accepted",
			first: func(codes, _ *oidcprovider.MemoryCodeStore) oidcprovider.UnspentCodes {
				return codes
			},
			second: func(codes, _ *oidcprovider.MemoryCodeStore) oidcprovider.UnspentCodes {
				return codes
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		{
			name: "joining another code source is refused, and the first stays",
			first: func(codes, _ *oidcprovider.MemoryCodeStore) oidcprovider.UnspentCodes {
				return codes
			},
			second: func(_, other *oidcprovider.MemoryCodeStore) oidcprovider.UnspentCodes {
				return other
			},
			assert: refusedAsConfig,
		},
		{
			name: "two sources that cannot be compared are refused, without a panic",
			first: func(codes, _ *oidcprovider.MemoryCodeStore) oidcprovider.UnspentCodes {
				return incomparableCodes{UnspentCodes: codes}
			},
			second: func(codes, _ *oidcprovider.MemoryCodeStore) oidcprovider.UnspentCodes {
				return incomparableCodes{UnspentCodes: codes}
			},
			assert: refusedAsConfig,
		},
		{
			name: "two sources holding what cannot be compared are refused, without a panic",
			first: func(codes, _ *oidcprovider.MemoryCodeStore) oidcprovider.UnspentCodes {
				return wrappedCodes{incomparableCodes{UnspentCodes: codes}}
			},
			second: func(codes, _ *oidcprovider.MemoryCodeStore) oidcprovider.UnspentCodes {
				return wrappedCodes{incomparableCodes{UnspentCodes: codes}}
			},
			assert: refusedAsConfig,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			codes, err := oidcprovider.NewMemoryCodeStore()
			require.NoError(t, err)
			other, err := oidcprovider.NewMemoryCodeStore()
			require.NoError(t, err)
			for n, held := range map[int]*oidcprovider.MemoryCodeStore{1: codes, 2: other} {
				r := codeRecord(n, opSignIn("u-1", 1))
				r.GrantFamily = suiteID(n)
				require.NoError(t, held.Create(ctx, r))
			}

			s := newStore(t)
			require.NoError(t, s.UseCodes(tc.first(codes, other)))

			var joined error
			require.NotPanics(t, func() { joined = s.UseCodes(tc.second(codes, other)) })
			tc.assert(t, joined)

			_, err = s.EndSignIns(ctx, oidcprovider.SignInSelector{Family: suiteID(1)}, suiteStart)
			require.NoError(t, err)
			assert.True(t, loadGrant(ctx, t, s, 1).Revoked, "the first source is the one read")
			_, err = s.Load(ctx, suiteID(2))
			require.ErrorIs(t, err, oidcprovider.ErrNotFound, "the source refused is never read")
		})
	}
}

// refusedAsConfig requires a refusal matching ErrConfig.
func refusedAsConfig(t *testing.T, err error) {
	t.Helper()
	require.ErrorIs(t, err, oidcprovider.ErrConfig)
}

func grantCases() []suiteCase[grantWorld] {
	at := suiteStart.Add(time.Minute)
	later := at.Add(time.Minute)

	return []suiteCase[grantWorld]{
		{
			name: "create and load return every field, the sign-in's unchanged",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				g := grantRecord(1, federatedSignIn("u-1", 7, opIssuer, opUpstream))
				g.Offline, g.EndsWithSignIn = true, true
				createGrants(ctx, t, s, g)

				got := loadGrant(ctx, t, s, 1)
				assert.Equal(t, normalGrant(g), normalGrant(got))
				assert.Equal(t, suiteID(7), got.SignInFamily)
				assert.Equal(t, opIssuer, got.ExternalIssuer)
				assert.Equal(t, opUpstream, got.ExternalSessionID)
			},
		},
		{
			name: "a grant recorded to hold no lineage says so (R10)",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				g := grantRecord(1, opSignIn("u-1", 1))
				g.HoldsLineage = false
				createGrants(ctx, t, s, g)

				assert.False(t, loadGrant(ctx, t, s, 1).HoldsLineage)
			},
		},
		{
			name: "a missing grant is not found",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				_, err := s.Load(ctx, suiteID(1))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "a revocation recorded first loads revoked, before and after create (H2)",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseCodeReplay, at)))

				early := loadGrant(ctx, t, s, 1)
				assert.True(t, early.Revoked, "the exchange reads it and refuses")
				assert.Equal(t, oidcprovider.CauseCodeReplay, early.RevokeCause)
				assertTimeEqual(t, at, early.RevokedAt, "RevokedAt")
				assert.Equal(t, suiteID(1), early.Family)

				g := grantRecord(1, opSignIn("u-1", 1))
				require.NoError(t, s.Create(ctx, g), "create over a revocation answers nil")

				want := *g
				want.Revoked, want.RevokedAt, want.RevokeCause = true, at, oidcprovider.CauseCodeReplay
				assert.Equal(t, normalGrant(&want), normalGrant(loadGrant(ctx, t, s, 1)))
			},
		},
		{
			name: "a revocation recorded first keeps its own time and cause over a revoked create",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseCodeReplay, at)))

				g := grantRecord(1, opSignIn("u-1", 1))
				g.Revoked, g.RevokedAt, g.RevokeCause = true, later, oidcprovider.CauseUserRequest
				require.NoError(t, s.Create(ctx, g))

				got := loadGrant(ctx, t, s, 1)
				assert.Equal(t, oidcprovider.CauseCodeReplay, got.RevokeCause)
				assertTimeEqual(t, at, got.RevokedAt, "RevokedAt")
			},
		},
		{
			name: "create over another grant is refused, and neither clears a mark nor rewrites the row",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				g := grantRecord(1, opSignIn("u-1", 1))
				createGrants(ctx, t, s, g)
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseReuse, at)))

				other := grantRecord(1, opSignIn("u-2", 2))
				other.ClientID = opOtherClient
				require.Error(t, s.Create(ctx, other))

				want := *g
				want.Revoked, want.RevokedAt, want.RevokeCause = true, at, oidcprovider.CauseReuse
				assert.Equal(t, normalGrant(&want), normalGrant(loadGrant(ctx, t, s, 1)))
			},
		},
		{
			name: "a revocation recorded first can be filled in once only",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseCodeReplay, at)))
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)))

				require.Error(t, s.Create(ctx, grantRecord(1, opSignIn("u-2", 2))))
				assert.Equal(t, userID("u-1"), loadGrant(ctx, t, s, 1).User)
			},
		},
		{
			name: "a stored grant whose CreatedAt is the zero time is still stored, and a second create is refused",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				first := grantRecord(1, opSignIn("u-1", 1))
				first.CreatedAt = time.Time{}
				createGrants(ctx, t, s, first)

				require.Error(t, s.Create(ctx, grantRecord(1, opSignIn("u-2", 2))))
				got := loadGrant(ctx, t, s, 1)
				assert.Equal(t, userID("u-1"), got.User)
				assert.True(t, got.CreatedAt.IsZero(), "the row is unchanged")
			},
		},
		{
			name: "revoke marks a stored grant",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)))

				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseRevokedByClient, at)))

				got := loadGrant(ctx, t, s, 1)
				assert.True(t, got.Revoked)
				assert.Equal(t, oidcprovider.CauseRevokedByClient, got.RevokeCause)
				assertTimeEqual(t, at, got.RevokedAt, "RevokedAt")
				assert.Equal(t, opClient, got.ClientID, "revoking changes nothing else")
			},
		},
		{
			name: "revoke is idempotent, and keeps the first time and cause, with and without a row",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)))
				for _, family := range []id.ID{suiteID(1), suiteID(2)} {
					require.NoError(t, revokeErr(s.Revoke(ctx, family, oidcprovider.CauseCodeReplay, at)))
					require.NoError(t, revokeErr(s.Revoke(ctx, family, oidcprovider.CauseUserRequest, later)))
				}

				for _, n := range []int{1, 2} {
					got := loadGrant(ctx, t, s, n)
					assert.Equal(t, oidcprovider.CauseCodeReplay, got.RevokeCause)
					assertTimeEqual(t, at, got.RevokedAt, "RevokedAt")
				}
			},
		},
		{
			name: "revoke says whether this call revoked the grant, with and without a row",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)))
				for _, family := range []id.ID{suiteID(1), suiteID(2)} {
					newly, err := s.Revoke(ctx, family, oidcprovider.CauseCodeReplay, at)
					require.NoError(t, err)
					assert.True(t, newly, "the first revocation is this call's")

					newly, err = s.Revoke(ctx, family, oidcprovider.CauseUserRequest, later)
					require.NoError(t, err)
					assert.False(t, newly, "the second changed nothing")
				}
			},
		},
		{
			name: "revoke says false for a revocation recorded first and then filled in",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseCodeReplay, at)))
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)))

				newly, err := s.Revoke(ctx, suiteID(1), oidcprovider.CauseUserRequest, later)
				require.NoError(t, err)
				assert.False(t, newly)
			},
		},
		{
			name: "revoke says false for a grant another write revoked",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)), grantRecord(2, opSignIn("u-2", 2)))
				_, err := s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, at)
				require.NoError(t, err)
				_, err = s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-2"}, at)
				require.NoError(t, err)

				for _, n := range []int{1, 2} {
					newly, err := s.Revoke(ctx, suiteID(n), oidcprovider.CauseReuse, later)
					require.NoError(t, err)
					assert.False(t, newly, "grant %d", n)
				}
			},
		},
		{
			name: "revoke says true for an offline grant an end only marked",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				g := grantRecord(1, opSignIn("u-1", 1))
				g.Offline = true
				createGrants(ctx, t, s, g)
				_, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1"}, at)
				require.NoError(t, err)

				newly, err := s.Revoke(ctx, suiteID(1), oidcprovider.CauseReuse, later)
				require.NoError(t, err)
				assert.True(t, newly, "it outlived its sign-in, and nothing had revoked it")
			},
		},
		{
			name: "revoke says false when it is refused",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				newly, err := s.Revoke(ctx, suiteID(1), oidcprovider.CauseReuse, time.Time{})
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.False(t, newly)
			},
		},
		{
			name: "revoke with a zero time is refused, and records nothing",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				require.ErrorIs(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseReuse, time.Time{})), oidcprovider.ErrConfig)

				_, err := s.Load(ctx, suiteID(1))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "an expired or revoked grant is still returned, because the provider judges it",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				g := grantRecord(1, opSignIn("u-1", 1))
				g.CreatedAt, g.ExpiresAt = longAgo, longAgo.Add(time.Hour)
				createGrants(ctx, t, s, g)

				got := loadGrant(ctx, t, s, 1)
				assert.False(t, got.Revoked)
				assert.True(t, g.ExpiresAt.Equal(got.ExpiresAt))
			},
		},
		{
			name: "revoke by user reaches every grant of that user alone, offline included",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				online := grantRecord(1, opSignIn("u-1", 1))
				offline := grantRecord(2, opSignIn("u-1", 1))
				offline.Offline = true
				other := grantRecord(3, opSignIn("u-2", 2))
				createGrants(ctx, t, s, online, offline, other)

				got, err := s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, at)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(1), suiteID(2)}, familiesOf(got))
				for _, g := range got {
					assert.True(t, g.Revoked, "the grants returned show their revocation")
					assert.Equal(t, oidcprovider.CauseRecovery, g.RevokeCause)
					assertTimeEqual(t, at, g.RevokedAt, "RevokedAt")
				}

				assert.True(t, loadGrant(ctx, t, s, 2).Revoked)
				assert.False(t, loadGrant(ctx, t, s, 3).Revoked)
			},
		},
		{
			name: "revoke by user returns only what it newly revoked, and keeps the first cause",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)), grantRecord(2, opSignIn("u-1", 1)))
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseReuse, at)))

				got, err := s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, later)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(2)}, familiesOf(got))
				assert.Equal(t, oidcprovider.CauseReuse, loadGrant(ctx, t, s, 1).RevokeCause)

				again, err := s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, later)
				require.NoError(t, err)
				assert.Empty(t, again)
			},
		},
		{
			name: "revoke by user and client touches one client only",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				mine := grantRecord(1, opSignIn("u-1", 1))
				offline := grantRecord(2, opSignIn("u-1", 1))
				offline.Offline = true
				otherClient := grantRecord(3, opSignIn("u-1", 1))
				otherClient.ClientID = opOtherClient
				otherUser := grantRecord(4, opSignIn("u-2", 2))
				createGrants(ctx, t, s, mine, offline, otherClient, otherUser)

				got, err := s.RevokeByUserAndClient(ctx, "u-1", opClient, oidcprovider.CauseConsentRevoked, at)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(1), suiteID(2)}, familiesOf(got))
				assert.False(t, loadGrant(ctx, t, s, 3).Revoked)
				assert.False(t, loadGrant(ctx, t, s, 4).Revoked)

				again, err := s.RevokeByUserAndClient(ctx, "u-1", opClient, oidcprovider.CauseConsentRevoked, at)
				require.NoError(t, err)
				assert.Empty(t, again)
			},
		},
		{
			name: "a revoke by user or by user and client leaves no mark, so a later end still reports the grant once",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				// Families 1 and 2 are stored grants, 3 and 4 are codes outstanding whose grants are
				// stored after the revocation. Only an end of the sign-in marks.
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)), grantRecord(2, opSignIn("u-2", 2)))
				s.outstanding(ctx, t, 3, opSignIn("u-1", 1))
				s.outstanding(ctx, t, 4, opSignIn("u-2", 2))

				_, err := s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, at)
				require.NoError(t, err)
				_, err = s.RevokeByUserAndClient(ctx, "u-2", opClient, oidcprovider.CauseConsentRevoked, at)
				require.NoError(t, err)
				createGrants(ctx, t, s, grantRecord(3, opSignIn("u-1", 1)), grantRecord(4, opSignIn("u-2", 2)))

				for n := 1; n <= 4; n++ {
					stored := loadGrant(ctx, t, s, n)
					assert.True(t, stored.Revoked, "family %d", n)
					assert.True(t, stored.SignInEndedAt.IsZero(), "family %d is not marked by a plain revoke", n)
				}

				first, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{Family: suiteID(1)}, later)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(1), suiteID(3)}, familiesOf(first))
				second, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{Family: suiteID(2)}, later)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(2), suiteID(4)}, familiesOf(second))

				again, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1"}, later.Add(time.Minute))
				require.NoError(t, err)
				assert.Empty(t, again, "reported once")
			},
		},
		{
			name: "a revocation recorded first is no one's until its grant is stored",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseCodeReplay, at)))

				got, err := s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, later)
				require.NoError(t, err)
				assert.Empty(t, got)
				got, err = s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1", ExceptFamily: suiteID(9)}, later)
				require.NoError(t, err)
				assert.Empty(t, got)

				assert.Equal(t, oidcprovider.CauseCodeReplay, loadGrant(ctx, t, s, 1).RevokeCause)
			},
		},
		{
			name: "revoking by an empty user or client is refused rather than matching what names none",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseCodeReplay, at)))
				createGrants(ctx, t, s, grantRecord(2, opSignIn("u-1", 1)))

				_, err := s.RevokeByUser(ctx, "", oidcprovider.CauseRecovery, later)
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				_, err = s.RevokeByUserAndClient(ctx, "", opClient, oidcprovider.CauseRecovery, later)
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				_, err = s.RevokeByUserAndClient(ctx, "u-1", "", oidcprovider.CauseRecovery, later)
				require.ErrorIs(t, err, oidcprovider.ErrConfig)

				assert.False(t, loadGrant(ctx, t, s, 2).Revoked)
			},
		},
		{
			name: "revoking with a zero time is refused, and writes nothing",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)))

				_, err := s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, time.Time{})
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				_, err = s.RevokeByUserAndClient(ctx, "u-1", opClient, oidcprovider.CauseRecovery, time.Time{})
				require.ErrorIs(t, err, oidcprovider.ErrConfig)

				assert.False(t, loadGrant(ctx, t, s, 1).Revoked)
			},
		},
		{
			name: "revoke by user reaches a code outstanding, offline included (R7)",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				s.outstanding(ctx, t, 1, opSignIn("u-1", 1))
				s.outstanding(ctx, t, 2, opSignIn("u-1", 1), offlineCode)
				s.outstanding(ctx, t, 3, opSignIn("u-2", 2))

				got, err := s.RevokeByUser(ctx, "u-1", oidcprovider.CauseMFAReset, at)
				require.NoError(t, err)
				assert.Empty(t, got, "a code's grant is not a grant the user held yet")

				for _, n := range []int{1, 2} {
					createGrants(ctx, t, s, grantRecord(n, opSignIn("u-1", 1)))
					stored := loadGrant(ctx, t, s, n)
					assert.True(t, stored.Revoked, "family %d", n)
					assert.Equal(t, oidcprovider.CauseMFAReset, stored.RevokeCause)
				}

				_, err = s.Load(ctx, suiteID(3))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "another user's code is untouched")
			},
		},
		{
			name: "a stored grant whose code's record is still held is returned as newly revoked and newly marked",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				// A code store cannot see a spend, so it names this grant's family too. The
				// grant must still count as this call's, whichever write reaches it first.
				ops := []func() ([]oidcprovider.Grant, error){
					func() ([]oidcprovider.Grant, error) {
						return s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, at)
					},
					func() ([]oidcprovider.Grant, error) {
						return s.RevokeByUserAndClient(ctx, "u-2", opClient, oidcprovider.CauseRecovery, at)
					},
					func() ([]oidcprovider.Grant, error) {
						return s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-3"}, at)
					},
				}
				for i, op := range ops {
					n := i + 1
					signIn := opSignIn(fmt.Sprintf("u-%d", n), n)
					s.outstanding(ctx, t, n, signIn)
					createGrants(ctx, t, s, grantRecord(n, signIn))

					got, err := op()
					require.NoError(t, err)
					assert.ElementsMatch(t, []id.ID{suiteID(n)}, familiesOf(got), "operation %d", n)
				}
			},
		},
		{
			name: "revoke by user and client reaches that client's codes and no other's (R7)",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				otherClient := func(r *oidcprovider.CodeRecord) { r.ClientID = opOtherClient }
				s.outstanding(ctx, t, 1, opSignIn("u-1", 1))
				s.outstanding(ctx, t, 2, opSignIn("u-1", 1), offlineCode)
				s.outstanding(ctx, t, 3, opSignIn("u-1", 1), otherClient)

				_, err := s.RevokeByUserAndClient(ctx, "u-1", opClient, oidcprovider.CauseConsentRevoked, at)
				require.NoError(t, err)

				for _, n := range []int{1, 2} {
					assert.True(t, loadGrant(ctx, t, s, n).Revoked, "family %d", n)
				}
				_, err = s.Load(ctx, suiteID(3))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound,
					"withdrawing consent from one client must not end another client's outstanding code")
			},
		},
		{
			name: "a stored grant is a copy of the caller's, and every grant returned a copy of the stored",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				scribble := func(g *oidcprovider.Grant) {
					g.Scopes[0], g.Resources[0], g.AMR[0] = "scribbled", "scribbled", "scribbled"
				}
				kept := func(t *testing.T, n int) {
					t.Helper()

					got := loadGrant(ctx, t, s, n)
					assert.Equal(t, []string{"openid", "profile"}, got.Scopes)
					assert.Equal(t, []string{"https://api.example.com"}, got.Resources)
					assert.Equal(t, opSignIn("u-1", 1).AMR, got.AMR)
				}

				g := grantRecord(1, opSignIn("u-1", 1))
				createGrants(ctx, t, s, g)
				scribble(g)
				kept(t, 1)

				scribble(loadGrant(ctx, t, s, 1))
				kept(t, 1)

				ended, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1"}, at)
				require.NoError(t, err)
				require.Len(t, ended, 1)
				scribble(&ended[0])
				kept(t, 1)

				createGrants(ctx, t, s, grantRecord(2, opSignIn("u-1", 2)))
				revoked, err := s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, at)
				require.NoError(t, err)
				require.Len(t, revoked, 1)
				scribble(&revoked[0])
				kept(t, 2)
			},
		},
		{
			name: "an outage of the code store fails each operation, and writes nothing",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)))
				boom := errors.New("code store down")
				s.source.down = boom

				_, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1"}, at)
				require.ErrorIs(t, err, boom)
				_, err = s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, at)
				require.ErrorIs(t, err, boom)
				_, err = s.RevokeByUserAndClient(ctx, "u-1", opClient, oidcprovider.CauseRecovery, at)
				require.ErrorIs(t, err, boom)

				got := loadGrant(ctx, t, s, 1)
				assert.False(t, got.Revoked)
				assert.True(t, got.SignInEndedAt.IsZero(), "a failed end marks nothing, so it can be reported again")

				s.source.down = nil
				ended, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1"}, at)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(1)}, familiesOf(ended), "the retry returns the grant")
			},
		},
	}
}

// grantEndCases are the cases of EndSignIns that do not turn on the selector's shape.
func grantEndCases() []suiteCase[grantWorld] {
	at := suiteStart.Add(time.Minute)
	later := at.Add(time.Minute)
	family := oidcprovider.SignInSelector{Family: suiteID(1)}

	return []suiteCase[grantWorld]{
		{
			name: "an invalid selector is refused rather than matching everyone, and writes nothing",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)))
				s.outstanding(ctx, t, 2, opSignIn("u-1", 1))

				for name, sel := range invalidSelectors() {
					got, err := s.EndSignIns(ctx, sel, at)
					require.ErrorIs(t, err, oidcprovider.ErrConfig, name)
					assert.Empty(t, got, name)
				}

				stored := loadGrant(ctx, t, s, 1)
				assert.False(t, stored.Revoked)
				assert.True(t, stored.SignInEndedAt.IsZero())
				_, err := s.Load(ctx, suiteID(2))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "no code was reached")
			},
		},
		{
			name: "an end at a zero time is refused, as its mark could never be seen",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)))

				_, err := s.EndSignIns(ctx, family, time.Time{})
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.False(t, loadGrant(ctx, t, s, 1).Revoked)
			},
		},
		{
			name: "an end at a zero time with a code outstanding is refused before it writes a tombstone",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				s.outstanding(ctx, t, 1, opSignIn("u-1", 1))

				_, err := s.EndSignIns(ctx, family, time.Time{})
				require.ErrorIs(t, err, oidcprovider.ErrConfig)

				_, err = s.Load(ctx, suiteID(1))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "a refused end writes nothing")
			},
		},
		{
			name: "the selector's family is the sign-in's, and never the grant's own",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 2)))

				got, err := s.EndSignIns(ctx, family, at)
				require.NoError(t, err)
				assert.Empty(t, got)
				assert.False(t, loadGrant(ctx, t, s, 1).Revoked)
			},
		},
		{
			name: "an end records the mark at the caller's time, and the cause",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)))

				got, err := s.EndSignIns(ctx, family, at)
				require.NoError(t, err)
				require.Len(t, got, 1)

				for _, g := range []oidcprovider.Grant{got[0], *loadGrant(ctx, t, s, 1)} {
					assertTimeEqual(t, at, g.SignInEndedAt, "SignInEndedAt")
					assertTimeEqual(t, at, g.RevokedAt, "RevokedAt")
					assert.True(t, g.Revoked)
					assert.Equal(t, oidcprovider.CauseSignInEnded, g.RevokeCause)
				}
			},
		},
		{
			name: "an already revoked grant is marked and returned, and keeps its first cause",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)))
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseReuse, at)))

				got, err := s.EndSignIns(ctx, family, later)
				require.NoError(t, err)
				require.Len(t, got, 1)
				assert.Equal(t, oidcprovider.CauseReuse, got[0].RevokeCause)
				assertTimeEqual(t, at, got[0].RevokedAt, "RevokedAt")
				assertTimeEqual(t, later, got[0].SignInEndedAt, "SignInEndedAt")
			},
		},
		{
			name: "an end never clears the revocation of an offline grant",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				g := grantRecord(1, opSignIn("u-1", 1))
				g.Offline = true
				createGrants(ctx, t, s, g)
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseReuse, at)))

				got, err := s.EndSignIns(ctx, family, later)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(1)}, familiesOf(got))

				stored := loadGrant(ctx, t, s, 1)
				assert.True(t, stored.Revoked, "no later write clears the mark")
				assert.Equal(t, oidcprovider.CauseReuse, stored.RevokeCause)
				assertTimeEqual(t, at, stored.RevokedAt, "RevokedAt")
			},
		},
		{
			name: "a selector naming a user stays within that user",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, federatedSignIn("u-2", 2, opIssuer, opUpstream)))

				for name, sel := range selectorsWithinUser() {
					got, err := s.EndSignIns(ctx, sel, at)
					require.NoError(t, err, name)
					assert.Empty(t, got, name)
				}

				stored := loadGrant(ctx, t, s, 1)
				assert.False(t, stored.Revoked, "another user's grant")
				assert.True(t, stored.SignInEndedAt.IsZero(), "another user's grant")
			},
		},
		{
			name: "the mark keeps its first time, and a marked offline grant stays live",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				g := grantRecord(1, opSignIn("u-1", 1))
				g.Offline = true
				createGrants(ctx, t, s, g)

				_, err := s.EndSignIns(ctx, family, at)
				require.NoError(t, err)
				_, err = s.EndSignIns(ctx, family, later)
				require.NoError(t, err)

				stored := loadGrant(ctx, t, s, 1)
				assert.False(t, stored.Revoked)
				assertTimeEqual(t, at, stored.SignInEndedAt, "SignInEndedAt")
			},
		},
		{
			name: "except a family leaves that family's grants untouched",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)), grantRecord(2, opSignIn("u-1", 2)))

				got, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1", ExceptFamily: suiteID(2)}, at)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(1)}, familiesOf(got))

				kept := loadGrant(ctx, t, s, 2)
				assert.False(t, kept.Revoked)
				assert.True(t, kept.SignInEndedAt.IsZero())
			},
		},
		{
			name: "an upstream selector matches only grants that recorded it",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				createGrants(ctx, t, s,
					grantRecord(1, federatedSignIn("u-1", 1, opIssuer, opUpstream)),
					grantRecord(2, federatedSignIn("u-1", 2, opIssuer, opOtherStream)),
					grantRecord(3, federatedSignIn("u-1", 3, opOtherIssuer, opUpstream)),
					grantRecord(4, opSignIn("u-1", 4)),
				)

				got, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{ExternalIssuer: opIssuer, ExternalSessionID: opUpstream}, at)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(1)}, familiesOf(got))

				got, err = s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1", ExternalIssuer: opIssuer}, at)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(2)}, familiesOf(got), "the first is already marked, and a local grant has no issuer")

				assert.False(t, loadGrant(ctx, t, s, 3).Revoked)
				assert.False(t, loadGrant(ctx, t, s, 4).Revoked)
			},
		},
		{
			name: "an end reaches a code outstanding, and a later create keeps the revocation (R7)",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				s.outstanding(ctx, t, 1, opSignIn("u-1", 1))

				got, err := s.EndSignIns(ctx, family, at)
				require.NoError(t, err)
				assert.Empty(t, got, "no grant was stored yet, so none was marked")

				assert.True(t, loadGrant(ctx, t, s, 1).Revoked, "the exchange reads it and refuses")

				require.NoError(t, s.Create(ctx, grantRecord(1, opSignIn("u-1", 1))))
				stored := loadGrant(ctx, t, s, 1)
				assert.True(t, stored.Revoked, "the racing exchange stores it revoked")
				assert.Equal(t, oidcprovider.CauseSignInEnded, stored.RevokeCause)
				assertTimeEqual(t, at, stored.RevokedAt, "RevokedAt")
			},
		},
		{
			name: "an offline code survives an end, and not a revoke by user (R7)",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				s.outstanding(ctx, t, 1, opSignIn("u-1", 1), offlineCode)

				_, err := s.EndSignIns(ctx, family, at)
				require.NoError(t, err)
				_, err = s.Load(ctx, suiteID(1))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "logout spares a code holding offline_access")

				_, err = s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, later)
				require.NoError(t, err)
				assert.True(t, loadGrant(ctx, t, s, 1).Revoked)
			},
		},
		{
			name: "a grant filling an end's revocation keeps the mark, and a later end returns nothing for it (T3)",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				signIn := opSignIn("u-1", 1)
				createGrants(ctx, t, s, grantRecord(1, signIn))
				s.outstanding(ctx, t, 2, signIn)

				first, err := s.EndSignIns(ctx, family, at)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(1)}, familiesOf(first))
				assertTimeEqual(t, at, loadGrant(ctx, t, s, 2).SignInEndedAt, "the record the end left")

				createGrants(ctx, t, s, grantRecord(2, signIn))
				stored := loadGrant(ctx, t, s, 2)
				assert.True(t, stored.Revoked)
				assert.Equal(t, oidcprovider.CauseSignInEnded, stored.RevokeCause)
				assertTimeEqual(t, at, stored.RevokedAt, "RevokedAt")
				assertTimeEqual(t, at, stored.SignInEndedAt, "SignInEndedAt")

				second, err := s.EndSignIns(ctx, family, later)
				require.NoError(t, err)
				assert.Empty(t, familiesOf(second), "a client notified once is not notified again")
				assertTimeEqual(t, at, loadGrant(ctx, t, s, 2).SignInEndedAt, "the first mark stays")
			},
		},
		{
			name: "a plain revoke landing on an end's tombstone keeps its mark, so the end is not reported twice",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				signIn := opSignIn("u-1", 1)
				s.outstanding(ctx, t, 1, signIn)

				ended, err := s.EndSignIns(ctx, family, at)
				require.NoError(t, err)
				assert.Empty(t, ended)
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseCodeReplay, later)))

				createGrants(ctx, t, s, grantRecord(1, signIn))
				stored := loadGrant(ctx, t, s, 1)
				assertTimeEqual(t, at, stored.SignInEndedAt, "SignInEndedAt")
				assert.Equal(t, oidcprovider.CauseSignInEnded, stored.RevokeCause, "the first cause stays")

				again, err := s.EndSignIns(ctx, family, later.Add(time.Minute))
				require.NoError(t, err)
				assert.Empty(t, familiesOf(again), "one end, reported once")
			},
		},
		{
			name: "an end reported twice before the exchange keeps the first mark on what the exchange fills (T3)",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				s.outstanding(ctx, t, 1, opSignIn("u-1", 1))

				for _, when := range []time.Time{at, later} {
					got, err := s.EndSignIns(ctx, family, when)
					require.NoError(t, err)
					assert.Empty(t, got)
				}

				createGrants(ctx, t, s, grantRecord(1, opSignIn("u-1", 1)))
				stored := loadGrant(ctx, t, s, 1)
				assertTimeEqual(t, at, stored.SignInEndedAt, "SignInEndedAt")
				assertTimeEqual(t, at, stored.RevokedAt, "RevokedAt")
			},
		},
		{
			name: "a plain revocation recorded first gains no mark, whatever its cause, and its end is still reported",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				causes := []oidcprovider.RevocationCause{oidcprovider.CauseCodeReplay, oidcprovider.CauseSignInEnded}
				for i, cause := range causes {
					n := i + 1
					require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(n), cause, at)))
					createGrants(ctx, t, s, grantRecord(n, opSignIn("u-1", 1)))
					assert.True(t, loadGrant(ctx, t, s, n).SignInEndedAt.IsZero(), "cause %s", cause)
				}

				got, err := s.EndSignIns(ctx, family, later)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{suiteID(1), suiteID(2)}, familiesOf(got))
				for i, cause := range causes {
					stored := loadGrant(ctx, t, s, i+1)
					assert.Equal(t, cause, stored.RevokeCause)
					assertTimeEqual(t, at, stored.RevokedAt, "RevokedAt")
					assertTimeEqual(t, later, stored.SignInEndedAt, "SignInEndedAt")
				}
			},
		},
		{
			name: "an end reaching a plain revocation through its code leaves it unmarked",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				signIn := opSignIn("u-1", 1)
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseCodeReplay, at)))
				s.outstanding(ctx, t, 1, signIn)

				got, err := s.EndSignIns(ctx, family, later)
				require.NoError(t, err)
				assert.Empty(t, got)

				createGrants(ctx, t, s, grantRecord(1, signIn))
				stored := loadGrant(ctx, t, s, 1)
				assert.True(t, stored.SignInEndedAt.IsZero())
				assert.Equal(t, oidcprovider.CauseCodeReplay, stored.RevokeCause)
			},
		},
		{
			name: "an end reaches a code by every selector the code recorded (R7)",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				for i, shape := range selectorShapes() {
					selected, unselected := 2*i+1, 2*i+2
					s.outstanding(ctx, t, selected, shape.in)
					s.outstanding(ctx, t, unselected, shape.out)

					_, err := s.EndSignIns(ctx, shape.sel, at)
					require.NoError(t, err, shape.name)

					assert.True(t, loadGrant(ctx, t, s, selected).Revoked, shape.name)
					_, err = s.Load(ctx, suiteID(unselected))
					require.ErrorIs(t, err, oidcprovider.ErrNotFound, shape.name)

					// The next shape's sign-ins share these facts, so this one's codes go.
					_, err = s.codes.DeleteExpired(ctx, suiteStart.Add(time.Hour))
					require.NoError(t, err)
				}
			},
		},
	}
}

// grantShapeCases runs the core of an end once per selector shape.
func grantShapeCases() []suiteCase[grantWorld] {
	at := suiteStart.Add(time.Minute)

	var cases []suiteCase[grantWorld]
	for _, shape := range selectorShapes() {
		cases = append(cases,
			suiteCase[grantWorld]{
				name: "end by " + shape.name + ": revokes the online, marks both, returns both, then none",
				assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
					online := grantRecord(1, shape.in)
					offline := grantRecord(2, shape.in)
					offline.Offline = true
					unselected := grantRecord(3, shape.out)
					createGrants(ctx, t, s, online, offline, unselected)

					got, err := s.EndSignIns(ctx, shape.sel, at)
					require.NoError(t, err)
					assert.ElementsMatch(t, []id.ID{suiteID(1), suiteID(2)}, familiesOf(got), "both grants are returned")

					assert.True(t, loadGrant(ctx, t, s, 1).Revoked, "the online grant is revoked")
					assert.False(t, loadGrant(ctx, t, s, 2).Revoked, "the offline grant survives")
					for _, n := range []int{1, 2} {
						assertTimeEqual(t, at, loadGrant(ctx, t, s, n).SignInEndedAt, "SignInEndedAt")
					}

					rest := loadGrant(ctx, t, s, 3)
					assert.False(t, rest.Revoked, "an unselected grant is untouched")
					assert.True(t, rest.SignInEndedAt.IsZero(), "an unselected grant is unmarked")

					again, err := s.EndSignIns(ctx, shape.sel, at.Add(time.Minute))
					require.NoError(t, err)
					assert.Empty(t, again, "the same end reported twice returns nothing the second time")
				},
			},
			suiteCase[grantWorld]{
				name: "end by " + shape.name + ": a client tied to its sign-in loses its offline code too (T3, R7)",
				assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
					s.outstanding(ctx, t, 1, shape.in, tiedOfflineCode)
					s.outstanding(ctx, t, 2, shape.out, tiedOfflineCode)

					got, err := s.EndSignIns(ctx, shape.sel, at)
					require.NoError(t, err)
					assert.Empty(t, got, "no grant was stored yet, so none was marked")
					_, err = s.Load(ctx, suiteID(2))
					require.ErrorIs(t, err, oidcprovider.ErrNotFound, "an unselected code is untouched")

					tied := grantRecord(1, shape.in)
					tied.Offline, tied.EndsWithSignIn = true, true
					createGrants(ctx, t, s, tied)

					stored := loadGrant(ctx, t, s, 1)
					assert.True(t, stored.Revoked, "its grant must not outlive the sign-in")
					assert.Equal(t, oidcprovider.CauseSignInEnded, stored.RevokeCause)
				},
			},
			suiteCase[grantWorld]{
				name: "end by " + shape.name + ": a client tied to its sign-in loses the offline grant too",
				assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
					tied := grantRecord(1, shape.in)
					tied.Offline, tied.EndsWithSignIn = true, true
					createGrants(ctx, t, s, tied)

					got, err := s.EndSignIns(ctx, shape.sel, at)
					require.NoError(t, err)
					assert.ElementsMatch(t, []id.ID{suiteID(1)}, familiesOf(got))
					assert.True(t, loadGrant(ctx, t, s, 1).Revoked)
				},
			},
		)
	}

	return cases
}

// grantSweepCases are the cases of DeleteExpired.
func grantSweepCases() []suiteCase[grantWorld] {
	keep := 10 * time.Minute
	revokedAt := suiteStart.Add(time.Hour)

	return []suiteCase[grantWorld]{
		{
			name: "delete expired removes a live grant past its deadline, strictly",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				now := suiteStart.Add(time.Hour)
				for n, expires := range []time.Time{now.Add(-time.Second), now, now.Add(time.Second)} {
					g := grantRecord(n+1, opSignIn("u-1", 1))
					g.ExpiresAt = expires
					createGrants(ctx, t, s, g)
				}

				n, err := s.DeleteExpired(ctx, now, keep)
				require.NoError(t, err)
				assert.Equal(t, 1, n)

				_, err = s.Load(ctx, suiteID(1))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
				loadGrant(ctx, t, s, 2)
				loadGrant(ctx, t, s, 3)
			},
		},
		{
			name: "delete expired keeps a revoked grant until keepRevoked passes, whatever its deadline",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				expired := grantRecord(1, opSignIn("u-1", 1))
				expired.ExpiresAt = revokedAt.Add(-time.Hour)
				live := grantRecord(2, opSignIn("u-1", 1))
				createGrants(ctx, t, s, expired, live)
				for _, family := range []id.ID{suiteID(1), suiteID(2)} {
					require.NoError(t, revokeErr(s.Revoke(ctx, family, oidcprovider.CauseReuse, revokedAt)))
				}

				n, err := s.DeleteExpired(ctx, revokedAt.Add(keep), keep)
				require.NoError(t, err)
				assert.Zero(t, n, "kept until keepRevoked has passed, strictly")
				loadGrant(ctx, t, s, 1)
				loadGrant(ctx, t, s, 2)

				n, err = s.DeleteExpired(ctx, revokedAt.Add(keep+time.Second), keep)
				require.NoError(t, err)
				assert.Equal(t, 2, n, "a revoked grant goes once no code can name it, even before its own deadline")
			},
		},
		{
			name: "delete expired keeps a revocation recorded first until keepRevoked passes (H2)",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseCodeReplay, revokedAt)))

				n, err := s.DeleteExpired(ctx, revokedAt.Add(keep), keep)
				require.NoError(t, err)
				assert.Zero(t, n, "its zero deadline must not read as long expired")
				loadGrant(ctx, t, s, 1)

				n, err = s.DeleteExpired(ctx, revokedAt.Add(keep+time.Second), keep)
				require.NoError(t, err)
				assert.Equal(t, 1, n, "and it must not stay for ever, or tombstones grow without bound")
			},
		},
		{
			name: "delete expired judges by the caller's time, never the wall clock",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				past := grantRecord(1, opSignIn("u-1", 1))
				past.ExpiresAt = longAgo.Add(time.Hour)
				createGrants(ctx, t, s, past)

				n, err := s.DeleteExpired(ctx, longAgo, keep)
				require.NoError(t, err)
				assert.Zero(t, n, "at the caller's time it has not expired, though the wall clock has passed it")

				future := grantRecord(2, opSignIn("u-1", 1))
				future.ExpiresAt = suiteStart.Add(time.Hour)
				createGrants(ctx, t, s, future)
				n, err = s.DeleteExpired(ctx, suiteStart.Add(2*time.Hour), keep)
				require.NoError(t, err)
				assert.Equal(t, 2, n, "at the caller's time both have expired, wherever the wall clock is")
			},
		},
		{
			name: "delete expired refuses to keep revocations for no time",
			assert: func(t *testing.T, ctx context.Context, s grantWorld, _ *clockwork.FakeClock) {
				require.NoError(t, revokeErr(s.Revoke(ctx, suiteID(1), oidcprovider.CauseCodeReplay, revokedAt)))

				for _, bad := range []time.Duration{0, -time.Second} {
					_, err := s.DeleteExpired(ctx, revokedAt.Add(time.Hour), bad)
					require.ErrorIs(t, err, oidcprovider.ErrConfig)
				}
				loadGrant(ctx, t, s, 1)
			},
		},
	}
}

// revokeErr is what a call to GrantStore.Revoke failed with, for a case that does not ask whether the
// call is what revoked the grant.
func revokeErr(_ bool, err error) error { return err }
