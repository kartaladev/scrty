package oidcprovider_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

func TestNew_StoreOptions(t *testing.T) {
	t.Parallel()

	var (
		nilPending  *oidcprovider.MemoryPendingRequestStore
		nilCodes    *oidcprovider.MemoryCodeStore
		nilConsents *oidcprovider.MemoryConsentStore
		nilGrants   *oidcprovider.MemoryGrantStore
		nilTokens   *onetime.MemoryStore
		nilAccess   *oidcprovider.MemoryAccessTokenStore
		nilBrowser  *oidcprovider.MemoryBrowserSessionStore
	)
	suppliedTokens := must.Must(onetime.NewMemoryStore())
	suppliedAccess := must.Must(oidcprovider.NewMemoryAccessTokenStore())
	suppliedAssertions := must.Must(oidcprovider.NewMemoryAssertionIDStore())
	suppliedBrowser := must.Must(oidcprovider.NewMemoryBrowserSessionStore())
	refused := func(setting string) func(*testing.T, *oidcprovider.Provider, error) {
		return func(t *testing.T, _ *oidcprovider.Provider, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.ErrorContains(t, err, setting)
		}
	}

	cases := []struct {
		name   string
		opts   []oidcprovider.Option
		assert func(t *testing.T, p *oidcprovider.Provider, err error)
	}{
		{name: "nil pending-request store", opts: []oidcprovider.Option{oidcprovider.WithPendingRequestStore(nil)}, assert: refused("WithPendingRequestStore")},
		{name: "typed nil pending-request store", opts: []oidcprovider.Option{oidcprovider.WithPendingRequestStore(nilPending)}, assert: refused("WithPendingRequestStore")},
		{name: "nil code store", opts: []oidcprovider.Option{oidcprovider.WithCodeStore(nil)}, assert: refused("WithCodeStore")},
		{name: "typed nil code store", opts: []oidcprovider.Option{oidcprovider.WithCodeStore(nilCodes)}, assert: refused("WithCodeStore")},
		{name: "nil consent store", opts: []oidcprovider.Option{oidcprovider.WithConsentStore(nil)}, assert: refused("WithConsentStore")},
		{name: "typed nil consent store", opts: []oidcprovider.Option{oidcprovider.WithConsentStore(nilConsents)}, assert: refused("WithConsentStore")},
		{name: "nil grant store", opts: []oidcprovider.Option{oidcprovider.WithGrantStore(nil)}, assert: refused("WithGrantStore")},
		{name: "typed nil grant store", opts: []oidcprovider.Option{oidcprovider.WithGrantStore(nilGrants)}, assert: refused("WithGrantStore")},
		{name: "nil code-token store", opts: []oidcprovider.Option{oidcprovider.WithCodeTokenStore(nil)}, assert: refused("WithCodeTokenStore")},
		{name: "typed nil code-token store", opts: []oidcprovider.Option{oidcprovider.WithCodeTokenStore(nilTokens)}, assert: refused("WithCodeTokenStore")},
		{name: "nil access-token store", opts: []oidcprovider.Option{oidcprovider.WithAccessTokenStore(nil)}, assert: refused("WithAccessTokenStore")},
		{name: "typed nil access-token store", opts: []oidcprovider.Option{oidcprovider.WithAccessTokenStore(nilAccess)}, assert: refused("WithAccessTokenStore")},
		{name: "nil browser-session store", opts: []oidcprovider.Option{oidcprovider.WithBrowserSessionStore(nil)}, assert: refused("WithBrowserSessionStore")},
		{name: "typed nil browser-session store", opts: []oidcprovider.Option{oidcprovider.WithBrowserSessionStore(nilBrowser)}, assert: refused("WithBrowserSessionStore")},
		{
			name: "a browser-session store under WithoutBrowserSessions is refused, not ignored",
			opts: []oidcprovider.Option{
				oidcprovider.WithoutBrowserSessions(),
				oidcprovider.WithBrowserSessionStore(must.Must(oidcprovider.NewMemoryBrowserSessionStore())),
			},
			assert: refused("WithBrowserSessionStore"),
		},
		{
			name: "the consumer's stores replace the defaults",
			opts: []oidcprovider.Option{
				oidcprovider.WithCodeTokenStore(suppliedTokens),
				oidcprovider.WithAccessTokenStore(suppliedAccess),
				oidcprovider.WithAssertionIDStore(suppliedAssertions),
				oidcprovider.WithBrowserSessionStore(suppliedBrowser),
			},
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Same(t, suppliedTokens, p.CodeTokensForTest())
				assert.Same(t, suppliedAccess, p.AccessTokensForTest())
				assert.Same(t, suppliedAssertions, p.AssertionIDsForTest())
				assert.Same(t, suppliedBrowser, p.BrowserSessionStoreForTest())
			},
		},
		{
			name: "with no option, each store is the in-memory default",
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.IsType(t, &oidcprovider.MemoryPendingRequestStore{}, p.PendingRequestsForTest())
				assert.IsType(t, &oidcprovider.MemoryCodeStore{}, p.CodesForTest())
				assert.IsType(t, &oidcprovider.MemoryConsentStore{}, p.ConsentsForTest())
				assert.IsType(t, &oidcprovider.MemoryGrantStore{}, p.GrantsForTest())
				assert.Implements(t, (*onetime.Reaper)(nil), p.CodeTokensForTest(), "the default code tokens are in memory, and can be purged")
				assert.IsType(t, &oidcprovider.MemoryAccessTokenStore{}, p.AccessTokensForTest())
				assert.IsType(t, &oidcprovider.MemoryAssertionIDStore{}, p.AssertionIDsForTest())
				assert.IsType(t, &oidcprovider.MemoryBrowserSessionStore{}, p.BrowserSessionStoreForTest())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := oidcprovider.New(validDeps(t), tc.opts...)
			tc.assert(t, p, err)
		})
	}
}

// refusingGrants is a consumer's grant store, which refuses to be joined.
type refusingGrants struct {
	*oidcprovider.MemoryGrantStore

	err error
}

func (r refusingGrants) UseCodes(oidcprovider.UnspentCodes) error { return r.err }

// The consumer's stores replace the defaults, and the provider joins whichever grant
// and code stores it ends up with, so a code outstanding is reached however they came.
// One grant store cannot read two providers' codes, so a second provider is refused
// unless it shares the first's code store too.
func TestNew_JoinsGrantsToCodes(t *testing.T) {
	t.Parallel()

	newCodes := func() *oidcprovider.MemoryCodeStore {
		s, err := oidcprovider.NewMemoryCodeStore()
		require.NoError(t, err)

		return s
	}
	newGrants := func() *oidcprovider.MemoryGrantStore {
		s, err := oidcprovider.NewMemoryGrantStore()
		require.NoError(t, err)

		return s
	}
	suppliedPending, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)
	suppliedConsents, err := oidcprovider.NewMemoryConsentStore()
	require.NoError(t, err)

	now := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	signIn := id.MustParse("01926a4e-0000-7000-8000-000000000001")
	family := id.MustParse("01926a4e-0000-7000-8000-00000000000a")

	// reached requires an end of the sign-in to reach a code p's code store holds.
	reached := func(t *testing.T, p *oidcprovider.Provider) {
		t.Helper()
		ctx := t.Context()

		require.NoError(t, p.CodesForTest().Create(ctx, &oidcprovider.CodeRecord{
			TokenID:     family,
			GrantFamily: family,
			SignIn:      oidcprovider.SignIn{User: "u-1", Family: signIn},
			ExpiresAt:   now.Add(time.Minute),
		}))

		_, err := p.GrantsForTest().EndSignIns(ctx, oidcprovider.SignInSelector{Family: signIn}, now)
		require.NoError(t, err)

		got, err := p.GrantsForTest().Load(ctx, family)
		require.NoError(t, err, "the outstanding code was not reached")
		assert.True(t, got.Revoked)
	}
	// joined requires a provider whose stores are the ones same names, joined.
	joined := func(same func(p *oidcprovider.Provider) bool) func(*testing.T, *oidcprovider.Provider, *oidcprovider.Provider, error) {
		return func(t *testing.T, _, p *oidcprovider.Provider, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.True(t, same(p), "the consumer's stores are the ones used")
			reached(t, p)
		}
	}
	// refused requires New to fail, leaving the earlier provider's codes joined.
	refused := func(t *testing.T, earlier, p *oidcprovider.Provider, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrConfig)
		assert.Nil(t, p)
		reached(t, earlier)
	}

	sharedCodes, sharedGrants := newCodes(), newGrants()
	bothCodes, bothGrants := newCodes(), newGrants()
	consumerGrants := newGrants()
	consumerCodes := newCodes()
	loneGrants := newGrants()
	explicitGrants := newGrants()

	cases := []struct {
		name string
		// earlier is a provider built first over stores this row shares, if any.
		earlier []oidcprovider.Option
		opts    []oidcprovider.Option
		assert  func(t *testing.T, earlier, p *oidcprovider.Provider, err error)
	}{
		{
			name:   "both defaults",
			assert: joined(func(*oidcprovider.Provider) bool { return true }),
		},
		{
			name: "both supplied, with the other stores",
			opts: []oidcprovider.Option{
				oidcprovider.WithCodeStore(bothCodes),
				oidcprovider.WithGrantStore(bothGrants),
				oidcprovider.WithPendingRequestStore(suppliedPending),
				oidcprovider.WithConsentStore(suppliedConsents),
			},
			assert: joined(func(p *oidcprovider.Provider) bool {
				return p.CodesForTest() == oidcprovider.CodeStore(bothCodes) &&
					p.GrantsForTest() == oidcprovider.GrantStore(bothGrants) &&
					p.PendingRequestsForTest() == oidcprovider.PendingRequestStore(suppliedPending) &&
					p.ConsentsForTest() == oidcprovider.ConsentStore(suppliedConsents)
			}),
		},
		{
			name: "a consumer's grant store with the default code store",
			opts: []oidcprovider.Option{oidcprovider.WithGrantStore(consumerGrants)},
			assert: joined(func(p *oidcprovider.Provider) bool {
				return p.GrantsForTest() == oidcprovider.GrantStore(consumerGrants)
			}),
		},
		{
			name: "a consumer's code store with the default grant store",
			opts: []oidcprovider.Option{oidcprovider.WithCodeStore(consumerCodes)},
			assert: joined(func(p *oidcprovider.Provider) bool {
				return p.CodesForTest() == oidcprovider.CodeStore(consumerCodes)
			}),
		},
		{
			name:    "two providers sharing both stores",
			earlier: []oidcprovider.Option{oidcprovider.WithCodeStore(sharedCodes), oidcprovider.WithGrantStore(sharedGrants)},
			opts:    []oidcprovider.Option{oidcprovider.WithCodeStore(sharedCodes), oidcprovider.WithGrantStore(sharedGrants)},
			assert: joined(func(p *oidcprovider.Provider) bool {
				return p.CodesForTest() == oidcprovider.CodeStore(sharedCodes) &&
					p.GrantsForTest() == oidcprovider.GrantStore(sharedGrants)
			}),
		},
		{
			name:    "a second provider over one grant store, each on its default code store, is refused",
			earlier: []oidcprovider.Option{oidcprovider.WithGrantStore(loneGrants)},
			opts:    []oidcprovider.Option{oidcprovider.WithGrantStore(loneGrants)},
			assert:  refused,
		},
		{
			name:    "a second provider over one grant store, naming another code store, is refused",
			earlier: []oidcprovider.Option{oidcprovider.WithGrantStore(explicitGrants), oidcprovider.WithCodeStore(newCodes())},
			opts:    []oidcprovider.Option{oidcprovider.WithGrantStore(explicitGrants), oidcprovider.WithCodeStore(newCodes())},
			assert:  refused,
		},
		{
			name: "what a consumer's grant store answers is what New returns",
			opts: []oidcprovider.Option{oidcprovider.WithGrantStore(refusingGrants{
				MemoryGrantStore: newGrants(),
				err:              fmt.Errorf("%w: joined elsewhere", oidcprovider.ErrConfig),
			})},
			assert: func(t *testing.T, _, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "joined elsewhere")
				assert.Nil(t, p)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var earlier *oidcprovider.Provider
			if tc.earlier != nil {
				var err error
				earlier, err = oidcprovider.New(validDeps(t), tc.earlier...)
				require.NoError(t, err)
			}

			p, err := oidcprovider.New(validDeps(t), tc.opts...)
			tc.assert(t, earlier, p, err)
		})
	}
}

// New joins the grant store to the code store only once nothing can fail after it, so a
// New that fails leaves a consumer's grant store free to be wired into a later provider.
// A single case: there is no second variant of the call to table.
func TestNew_FailedNewLeavesGrantStoreUnjoined(t *testing.T) {
	t.Parallel()

	grants, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)
	first, err := oidcprovider.NewMemoryCodeStore()
	require.NoError(t, err)
	second, err := oidcprovider.NewMemoryCodeStore()
	require.NoError(t, err)

	failing := validDeps(t)
	failing.Clients = []oidcprovider.Client{{}} // refused after the stores are chosen
	_, err = oidcprovider.New(failing, oidcprovider.WithGrantStore(grants), oidcprovider.WithCodeStore(first))
	require.Error(t, err, "the first New must fail")

	p, err := oidcprovider.New(validDeps(t), oidcprovider.WithGrantStore(grants), oidcprovider.WithCodeStore(second))
	require.NoError(t, err, "the retry must not find the grant store joined to the failed New's codes")
	assert.Same(t, oidcprovider.CodeStore(second), p.CodesForTest())
}
