package oidcprovider_test

import (
	"context"
	"errors"
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

// recordsRetainSince is a code-token store that notes the cutoff its purge was asked for.
type recordsRetainSince struct {
	onetime.Store
	asked *time.Time
}

func (r recordsRetainSince) DeleteExpiredBefore(ctx context.Context, purpose string, retainSince time.Time) (int, error) {
	*r.asked = retainSince

	return r.Store.(onetime.Reaper).DeleteExpiredBefore(ctx, purpose, retainSince)
}

var errSweep = errors.New("the record sweep failed")

// failingCodeRecords is a code store whose sweep fails.
type failingCodeRecords struct {
	oidcprovider.CodeStore
	err error
}

func (f failingCodeRecords) DeleteExpired(context.Context, time.Time) (int, error) { return 0, f.err }

// runExpiry runs each of the provider's tasks once, by name.
func runExpiry(t *testing.T, p *oidcprovider.Provider) map[string]expiry.Result {
	t.Helper()

	runner, err := expiry.NewRunner(oidcprovider.ExpiryTasks(p))
	require.NoError(t, err)
	// RunOnce reports a failed task as an error too; each task's own outcome is read below.
	report, _ := runner.RunOnce(t.Context())
	require.Len(t, report.Results, 7)
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

	// asked is the cutoff the code-token purge was given, read by the one case that sets it.
	var asked time.Time
	records, err := oidcprovider.NewMemoryCodeStore()
	require.NoError(t, err)

	cases := []testCase{
		{
			name: "a grant whose lineage went idle, or never was written, is kept by every task and its sign-in's end still reports it",
			assert: func(t *testing.T, x *exchangeFixture) {
				ctx := t.Context()
				idle, lost, holdsNone := newGrant(x, true), newGrant(x, true), newGrant(x, false)
				for _, g := range []*oidcprovider.Grant{idle, lost, holdsNone} {
					require.NoError(t, x.p.GrantsForTest().Create(ctx, g))
				}
				head := lineageRecord("head-secret", x.clk.Now())
				head.FamilyID = idle.Family
				require.NoError(t, x.p.LineageForTest().Create(ctx, head))
				x.clk.Advance(2 * time.Hour)

				res := runExpiry(t, x.p)

				require.NoError(t, res["oidc-provider.refresh-tokens"].Err)
				assert.Equal(t, 1, res["oidc-provider.refresh-tokens"].Removed, "the idle lineage is gone")
				for _, g := range []*oidcprovider.Grant{idle, lost, holdsNone} {
					_, err := x.p.GrantsForTest().Load(ctx, g.Family)
					assert.NoError(t, err, "the grant is kept: only its own deadline or a revocation removes it")
				}
				ended, err := x.p.GrantsForTest().EndSignIns(ctx, oidcprovider.SignInSelector{Family: idle.SignInFamily}, x.clk.Now())
				require.NoError(t, err)
				require.Len(t, ended, 1, "the sign-in's end still reaches the client")
				assert.Equal(t, "billing-web", ended[0].ClientID)
			},
		},
		{
			name: "a grant past its own deadline is swept all the same",
			assert: func(t *testing.T, x *exchangeFixture) {
				ctx := t.Context()
				g := newGrant(x, true)
				g.ExpiresAt = x.clk.Now().Add(time.Hour)
				require.NoError(t, x.p.GrantsForTest().Create(ctx, g))
				x.clk.Advance(2 * time.Hour)

				res := runExpiry(t, x.p)

				assert.Equal(t, 1, res["oidc-provider.grants"].Removed)
				_, err := x.p.GrantsForTest().Load(ctx, g.Family)
				assert.ErrorIs(t, err, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "a revoked grant is kept until the longest code lifetime and a minute have passed",
			assert: func(t *testing.T, x *exchangeFixture) {
				ctx := t.Context()
				g := newGrant(x, false)
				require.NoError(t, x.p.GrantsForTest().Create(ctx, g))
				require.NoError(t, revokeErr(x.p.GrantsForTest().Revoke(ctx, g.Family, oidcprovider.CauseCodeReplay, x.clk.Now())))

				x.clk.Advance(10*time.Minute + 30*time.Second)
				res := runExpiry(t, x.p)
				assert.Zero(t, res["oidc-provider.grants"].Removed, "a code of the longest lifetime could still name it")
				_, err := x.p.GrantsForTest().Load(ctx, g.Family)
				require.NoError(t, err)

				x.clk.Advance(time.Minute)
				res = runExpiry(t, x.p)
				assert.Equal(t, 1, res["oidc-provider.grants"].Removed)
			},
		},
		{
			name: "the pending, browser, access and assertion tasks keep a record still live at now, and remove one that is not",
			assert: func(t *testing.T, x *exchangeFixture) {
				ctx := t.Context()
				now := x.clk.Now()
				live, gone := now.Add(15*time.Second), now.Add(-time.Second)

				pending := func(expires time.Time) *oidcprovider.PendingRequest {
					return &oidcprovider.PendingRequest{
						ID: id.MustParse("01926a4e-0000-7000-8000-0000000000aa"), HandleDigest: []byte(expires.String()),
						ClientID: "billing-web", ParkedAt: now, ExpiresAt: expires,
					}
				}
				session := func(expires time.Time) *oidcprovider.BrowserSession {
					return &oidcprovider.BrowserSession{
						Digest:        []byte(expires.String()),
						SignIn:        oidcprovider.SignIn{User: "u-1", AuthenticatedAt: now, AbsoluteExpiresAt: now.Add(time.Hour)},
						IdleExpiresAt: expires, AbsoluteExpiresAt: now.Add(time.Hour),
					}
				}
				token := func(expires time.Time) *oidcprovider.AccessTokenRecord {
					family, err := id.NewV7Generator().NewID()
					require.NoError(t, err)
					tokenID, err := id.NewV7Generator().NewID()
					require.NoError(t, err)

					return &oidcprovider.AccessTokenRecord{
						ID: tokenID, Digest: []byte(expires.String()), GrantFamily: family, ClientID: "billing-web",
						User: "u-1", Scopes: []string{"openid"}, IssuedAt: now, ExpiresAt: expires,
					}
				}
				assertions, ok := x.p.AssertionIDsForTest().(*oidcprovider.MemoryAssertionIDStore)
				require.True(t, ok)
				for _, expires := range []time.Time{live, gone} {
					require.NoError(t, x.p.PendingRequestsForTest().Create(ctx, pending(expires)))
					require.NoError(t, x.p.BrowserSessionStoreForTest().Put(ctx, session(expires)))
					require.NoError(t, x.p.AccessTokensForTest().Create(ctx, token(expires)))
					fresh, err := assertions.Record(ctx, "billing-web", expires.String(), expires)
					require.NoError(t, err)
					require.True(t, fresh)
				}

				res := runExpiry(t, x.p)

				for _, task := range []string{
					"oidc-provider.pending-requests", "oidc-provider.browser-sessions",
					"oidc-provider.access-tokens", "oidc-provider.assertion-ids",
				} {
					require.NoError(t, res[task].Err, task)
					assert.Equal(t, 1, res[task].Removed, task+": only the one past its expiry")
				}
				_, err := x.p.PendingRequestsForTest().Load(ctx, []byte(live.String()))
				assert.NoError(t, err, "pending request")
				_, err = x.p.BrowserSessionStoreForTest().Load(ctx, []byte(live.String()), now)
				assert.NoError(t, err, "browser session")
				assert.True(t, assertions.HeldForTest("billing-web", live.String()), "assertion identifier")
				assert.False(t, assertions.HeldForTest("billing-web", gone.String()))
				assert.Equal(t, 1, x.p.AssertionIDsHeldForTest(), "the live identifier alone")
			},
		},
		{
			name: "the code-token purge reaches back the longest code lifetime and a minute, whatever the provider's lifetime",
			opts: []oidcprovider.Option{
				oidcprovider.WithCodeLifetime(time.Minute),
				oidcprovider.WithCodeTokenStore(recordsRetainSince{Store: memoryCodeTokens(), asked: &asked}),
			},
			assert: func(t *testing.T, x *exchangeFixture) {
				x.clk.Advance(time.Hour)

				runExpiry(t, x.p)

				assert.Equal(t, x.clk.Now().Add(-11*time.Minute), asked, "a code issued under a longer lifetime may still be in flight")
			},
		},
		{
			name: "a code-record sweep that fails fails the codes task, and the tokens are purged all the same",
			opts: []oidcprovider.Option{oidcprovider.WithCodeStore(failingCodeRecords{CodeStore: records, err: errSweep})},
			assert: func(t *testing.T, x *exchangeFixture) {
				x.issue(t)
				x.clk.Advance(time.Hour)

				res := runExpiry(t, x.p)

				assert.ErrorIs(t, res["oidc-provider.codes"].Err, errSweep)
				assert.Equal(t, 1, res["oidc-provider.codes"].Removed, "the token")
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
