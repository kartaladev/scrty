package storetest

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// codeRecord returns a record with every field set: token n, grant family 100+n,
// from signIn, expiring a minute after suiteStart.
func codeRecord(n int, signIn oidcprovider.SignIn) *oidcprovider.CodeRecord {
	return &oidcprovider.CodeRecord{
		TokenID:     suiteID(n),
		ClientID:    opClient,
		RedirectURI: "https://rp.example.com/cb",
		Challenge:   "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		Nonce:       "nonce-1",
		DPoPJKT:     "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
		Scopes:      []string{"openid", "profile"},
		Resources:   []string{"https://api.example.com"},
		SignIn:      signIn,
		GrantFamily: suiteID(100 + n),
		ExpiresAt:   suiteStart.Add(time.Minute),
	}
}

// federatedSignIn returns a sign-in of user in family n, through an upstream.
func federatedSignIn(user string, n int, issuer, session string) oidcprovider.SignIn {
	s := opSignIn(user, n)
	s.ExternalIssuer, s.ExternalSessionID = issuer, session

	return s
}

// normalCode returns r with its times in UTC, for an exact comparison.
func normalCode(r *oidcprovider.CodeRecord) oidcprovider.CodeRecord {
	out := *r
	out.ExpiresAt = utc(r.ExpiresAt)
	out.SignIn = normalSignIn(r.SignIn)

	return out
}

// CodeRecordSuite holds a code store to the contract oidcprovider.CodeStore documents.
// newStore returns an empty store of its own for each case.
func CodeRecordSuite(t *testing.T, newStore func(t *testing.T) oidcprovider.CodeStore) {
	t.Helper()

	runSuite(t, slices.Concat(codeCases(), codeShapeCases()), withoutClock(newStore))
}

func codeCases() []suiteCase[oidcprovider.CodeStore] {
	type store = oidcprovider.CodeStore

	return []suiteCase[store]{
		{
			name: "create and load return every binding",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				signIn := federatedSignIn("u-1", 1, opIssuer, opUpstream)
				r := codeRecord(1, signIn)
				r.Offline, r.EndsWithSignIn = true, true
				require.NoError(t, s.Create(ctx, r))

				got, err := s.Load(ctx, suiteID(1))
				require.NoError(t, err)
				assert.Equal(t, normalCode(r), normalCode(got))
				assert.Equal(t, opIssuer, got.SignIn.ExternalIssuer, "the upstream issuer is kept (R7)")
				assert.Equal(t, opUpstream, got.SignIn.ExternalSessionID, "the upstream session is kept (R7)")
				assert.True(t, got.Offline)
				assert.Equal(t, suiteID(101), got.GrantFamily)
			},
		},
		{
			name: "a missing record is not found",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, codeRecord(1, opSignIn("u-1", 1))))

				_, err := s.Load(ctx, suiteID(2))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)

				_, err = s.Load(ctx, suiteID(101))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "the grant family is no key")
			},
		},
		{
			name: "an identifier already held is refused, and the record stays",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, codeRecord(1, opSignIn("u-1", 1))))

				other := codeRecord(1, opSignIn("u-2", 2))
				other.ClientID = opOtherClient
				require.Error(t, s.Create(ctx, other))

				got, err := s.Load(ctx, suiteID(1))
				require.NoError(t, err)
				assert.Equal(t, opClient, got.ClientID)
			},
		},
		{
			name: "an expired record is still returned, because expiry is the provider's to judge",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := codeRecord(1, opSignIn("u-1", 1))
				r.ExpiresAt = longAgo
				require.NoError(t, s.Create(ctx, r))

				_, err := s.Load(ctx, suiteID(1))
				require.NoError(t, err)
			},
		},
		{
			name: "delete expired removes only what expired before the caller's time",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				cutoff := suiteStart.Add(time.Hour)
				for n, expires := range []time.Time{cutoff.Add(-time.Second), cutoff, cutoff.Add(time.Second)} {
					r := codeRecord(n+1, opSignIn("u-1", 1))
					r.ExpiresAt = expires
					require.NoError(t, s.Create(ctx, r))
				}

				n, err := s.DeleteExpired(ctx, cutoff)
				require.NoError(t, err)
				assert.Equal(t, 1, n, "strictly before the cutoff")

				_, err = s.Load(ctx, suiteID(1))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
				for _, kept := range []int{2, 3} {
					_, err = s.Load(ctx, suiteID(kept))
					require.NoError(t, err)
				}
			},
		},
		{
			name: "delete expired judges by the caller's time, never the wall clock",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := codeRecord(1, opSignIn("u-1", 1))
				r.ExpiresAt = longAgo.Add(time.Hour)
				require.NoError(t, s.Create(ctx, r))

				n, err := s.DeleteExpired(ctx, longAgo)
				require.NoError(t, err)
				assert.Zero(t, n, "at the caller's time it has not expired, though the wall clock has passed it")

				future := codeRecord(2, opSignIn("u-1", 1))
				require.NoError(t, s.Create(ctx, future))
				n, err = s.DeleteExpired(ctx, suiteStart.Add(time.Hour))
				require.NoError(t, err)
				assert.Equal(t, 2, n, "at the caller's time both have expired, wherever the wall clock is")
			},
		},
		{
			name: "a stored record is a copy of the caller's",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := codeRecord(1, opSignIn("u-1", 1))
				require.NoError(t, s.Create(ctx, r))
				scribbleCode(r)

				got, err := s.Load(ctx, suiteID(1))
				require.NoError(t, err)
				assert.Equal(t, normalCode(codeRecord(1, opSignIn("u-1", 1))), normalCode(got))
			},
		},
		{
			name: "a loaded record is a copy of the stored one",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, codeRecord(1, opSignIn("u-1", 1))))

				first, err := s.Load(ctx, suiteID(1))
				require.NoError(t, err)
				scribbleCode(first)

				got, err := s.Load(ctx, suiteID(1))
				require.NoError(t, err)
				assert.Equal(t, normalCode(codeRecord(1, opSignIn("u-1", 1))), normalCode(got))
			},
		},
		{
			name: "an invalid selector is refused rather than matching everyone",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, codeRecord(1, opSignIn("u-1", 1))))

				for name, sel := range invalidSelectors() {
					got, err := s.UnspentBySignIn(ctx, sel, true)
					require.ErrorIs(t, err, oidcprovider.ErrConfig, name)
					assert.Empty(t, got, name)
				}
			},
		},
		{
			name: "records of a client are listed for that user and client, offline included",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				online := codeRecord(1, opSignIn("u-1", 1))
				offline := codeRecord(2, opSignIn("u-1", 1))
				offline.Offline = true
				otherClient := codeRecord(3, opSignIn("u-1", 1))
				otherClient.ClientID = opOtherClient
				otherUser := codeRecord(4, opSignIn("u-2", 1))
				for _, r := range []*oidcprovider.CodeRecord{online, offline, otherClient, otherUser} {
					require.NoError(t, s.Create(ctx, r))
				}

				got, err := s.UnspentByClient(ctx, "u-1", opClient)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{online.GrantFamily, offline.GrantFamily}, got)
			},
		},
		{
			name: "a selector naming a user stays within that user",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, codeRecord(1, federatedSignIn("u-2", 2, opIssuer, opUpstream))))

				for name, sel := range selectorsWithinUser() {
					got, err := s.UnspentBySignIn(ctx, sel, true)
					require.NoError(t, err, name)
					assert.Empty(t, got, name)
				}
			},
		},
		{
			name: "an upstream session selector compares the issuer too",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, codeRecord(1, federatedSignIn("u-1", 1, opOtherIssuer, opUpstream))))

				got, err := s.UnspentBySignIn(ctx, oidcprovider.SignInSelector{ExternalIssuer: opIssuer, ExternalSessionID: opUpstream}, true)
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
		{
			name: "an expired record is still listed, because the port answers for every record held",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := codeRecord(1, opSignIn("u-1", 1))
				r.ExpiresAt = longAgo
				require.NoError(t, s.Create(ctx, r))

				got, err := s.UnspentBySignIn(ctx, oidcprovider.SignInSelector{User: "u-1"}, true)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{r.GrantFamily}, got, "by sign-in")

				got, err = s.UnspentByClient(ctx, "u-1", opClient)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{r.GrantFamily}, got, "by client")
			},
		},
		{
			name: "no code leaves nothing to list",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				got, err := s.UnspentBySignIn(ctx, oidcprovider.SignInSelector{User: "u-1"}, true)
				require.NoError(t, err)
				assert.Empty(t, got)

				got, err = s.UnspentByClient(ctx, "u-1", opClient)
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
	}
}

// codeShapeCases runs the listing once per selector shape.
func codeShapeCases() []suiteCase[oidcprovider.CodeStore] {
	var cases []suiteCase[oidcprovider.CodeStore]
	for _, shape := range selectorShapes() {
		cases = append(cases, suiteCase[oidcprovider.CodeStore]{
			name: "by " + shape.name + ": lists the selected, and offline only when asked",
			assert: func(t *testing.T, ctx context.Context, s oidcprovider.CodeStore, _ *clockwork.FakeClock) {
				online := codeRecord(1, shape.in)
				offline := codeRecord(2, shape.in)
				offline.Offline = true
				unselected := codeRecord(3, shape.out)
				for _, r := range []*oidcprovider.CodeRecord{online, offline, unselected} {
					require.NoError(t, s.Create(ctx, r))
				}

				got, err := s.UnspentBySignIn(ctx, shape.sel, false)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{online.GrantFamily}, got, "offline records are left out unless asked")

				got, err = s.UnspentBySignIn(ctx, shape.sel, true)
				require.NoError(t, err)
				assert.ElementsMatch(t, []id.ID{online.GrantFamily, offline.GrantFamily}, got)
			},
		}, suiteCase[oidcprovider.CodeStore]{
			name: "by " + shape.name + ": an offline record tied to its sign-in is listed even when offline is left out (T3)",
			assert: func(t *testing.T, ctx context.Context, s oidcprovider.CodeStore, _ *clockwork.FakeClock) {
				tied := codeRecord(1, shape.in)
				tied.Offline, tied.EndsWithSignIn = true, true
				unselected := codeRecord(2, shape.out)
				unselected.Offline, unselected.EndsWithSignIn = true, true
				for _, r := range []*oidcprovider.CodeRecord{tied, unselected} {
					require.NoError(t, s.Create(ctx, r))
				}

				for _, includeOffline := range []bool{false, true} {
					got, err := s.UnspentBySignIn(ctx, shape.sel, includeOffline)
					require.NoError(t, err)
					assert.ElementsMatch(t, []id.ID{tied.GrantFamily}, got, "includeOffline %v", includeOffline)
				}
			},
		})
	}

	return cases
}

// scribbleCode overwrites every value of r a store could have kept by reference.
func scribbleCode(r *oidcprovider.CodeRecord) {
	r.Scopes[0], r.Resources[0], r.SignIn.AMR[0] = "scribbled", "scribbled", "scribbled"
}
