package oidcprovider_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// cannotPurge is a code-token store that implements no onetime.Reaper.
type cannotPurge struct{ onetime.Store }

// runExpiry runs each of the provider's tasks once, by name.
func runExpiry(t *testing.T, p *oidcprovider.Provider) map[string]expiry.Result {
	t.Helper()

	runner, err := expiry.NewRunner(oidcprovider.ExpiryTasks(p))
	require.NoError(t, err)
	// RunOnce reports a failed task as an error too; each task's own outcome is read below.
	report, _ := runner.RunOnce(t.Context())
	require.Len(t, report.Results, 8)
	out := make(map[string]expiry.Result, len(report.Results))
	for _, r := range report.Results {
		out[r.Task] = r
	}

	return out
}

func newGrant(x *exchangeFixture, holdsLineage bool) *oidcprovider.Grant {
	family, err := id.NewV7Generator().NewID()
	if err != nil {
		panic(err)
	}
	signIn, err := id.NewV7Generator().NewID()
	if err != nil {
		panic(err)
	}
	now := x.clk.Now()

	return &oidcprovider.Grant{
		Family: family, User: "u-1", ClientID: "billing-web", Scopes: []string{"openid"},
		AuthTime: now, SignInFamily: signIn, CodeID: signIn, HoldsLineage: holdsLineage,
		CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}
}

func TestExpiryTasks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []oidcprovider.Option
		assert func(t *testing.T, x *exchangeFixture)
	}

	cases := []testCase{
		{
			name: "the orphan sweep spares a grant whose lineage is live, and one recorded to hold none",
			assert: func(t *testing.T, x *exchangeFixture) {
				ctx := t.Context()
				live, orphan, holdsNone := newGrant(x, true), newGrant(x, true), newGrant(x, false)
				for _, g := range []*oidcprovider.Grant{live, orphan, holdsNone} {
					require.NoError(t, x.p.GrantsForTest().Create(ctx, g))
				}
				head := lineageRecord("head-secret", x.clk.Now())
				head.FamilyID = live.Family
				require.NoError(t, x.p.LineageForTest().Create(ctx, head))
				x.clk.Advance(11 * time.Minute)

				res := runExpiry(t, x.p)

				require.NoError(t, res["oidc-provider.orphaned-grants"].Err)
				assert.Equal(t, 1, res["oidc-provider.orphaned-grants"].Removed)
				_, err := x.p.GrantsForTest().Load(ctx, orphan.Family)
				assert.ErrorIs(t, err, oidcprovider.ErrNotFound)
				_, err = x.p.GrantsForTest().Load(ctx, live.Family)
				assert.NoError(t, err)
				_, err = x.p.GrantsForTest().Load(ctx, holdsNone.Family)
				assert.NoError(t, err)
			},
		},
		{
			name: "the refresh-token task removes the lineages past their deadline",
			assert: func(t *testing.T, x *exchangeFixture) {
				require.NoError(t, x.p.LineageForTest().Create(t.Context(), lineageRecord("head-secret", x.clk.Now())))
				require.Equal(t, 1, x.p.LineageHeldForTest())
				x.clk.Advance(2 * time.Hour)

				res := runExpiry(t, x.p)

				require.NoError(t, res["oidc-provider.refresh-tokens"].Err)
				assert.Equal(t, 1, res["oidc-provider.refresh-tokens"].Removed)
				assert.Zero(t, x.p.LineageHeldForTest())
			},
		},
		{
			name: "a valid replay inside the minute past the code's expiry still revokes after the sweep",
			assert: func(t *testing.T, x *exchangeFixture) {
				c := x.issue(t)
				tokens, err := x.p.CodeManagerForTest()
				require.NoError(t, err)
				checked, err := tokens.Check(t.Context(), c.code, "")
				require.NoError(t, err)
				require.NoError(t, tokens.Consume(t.Context(), checked))
				x.clk.Advance(time.Minute + 30*time.Second)

				res := runExpiry(t, x.p)
				require.NoError(t, res["oidc-provider.codes"].Err)
				assert.Zero(t, res["oidc-provider.codes"].Removed, "nothing is a minute past its expiry yet")
				_, err = x.p.Token(t.Context(), byOwner(c))

				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				g, err := x.p.GrantsForTest().Load(t.Context(), recordOf(t, x.parkFixture, c.code).GrantFamily)
				require.NoError(t, err)
				assert.True(t, g.Revoked)
			},
		},
		{
			name: "a code-token store that cannot purge fails the codes task, and the records are swept all the same",
			opts: []oidcprovider.Option{oidcprovider.WithCodeTokenStore(cannotPurge{memoryCodeTokens()})},
			assert: func(t *testing.T, x *exchangeFixture) {
				x.issue(t)
				x.clk.Advance(5 * time.Minute)

				res := runExpiry(t, x.p)

				assert.ErrorIs(t, res["oidc-provider.codes"].Err, expiry.ErrPurgeUnsupported)
				assert.ErrorIs(t, res["oidc-provider.codes"].Err, onetime.ErrReapUnsupported)
				assert.Equal(t, 1, res["oidc-provider.codes"].Removed, "the record")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newExchangeFixture(t, tc.opts...))
		})
	}
}

func memoryCodeTokens() onetime.Store {
	s, err := onetime.NewMemoryStore()
	if err != nil {
		panic(err)
	}

	return s
}
