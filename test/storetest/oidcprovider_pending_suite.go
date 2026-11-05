package storetest

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// pendingRecord returns a request with every field set, keyed by digest n and
// expiring ten minutes after suiteStart.
func pendingRecord(n byte) *oidcprovider.PendingRequest {
	maxAge := 3600

	return &oidcprovider.PendingRequest{
		ID:                 suiteID(int(n)),
		HandleDigest:       opDigest(n),
		FlowDigest:         opDigest(n + 100),
		ClientID:           opClient,
		RedirectURI:        "https://rp.example.com/cb?tenant=a",
		Scopes:             []string{"openid", "profile"},
		Resources:          []string{"https://api.example.com"},
		State:              "state&=# value",
		Nonce:              "nonce-1",
		Challenge:          "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		Prompt:             []string{"login", "consent"},
		MaxAge:             &maxAge,
		IDTokenHintSubject: "u-1",
		DPoPJKT:            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
		LoginHint:          "user@example.com",
		UILocales:          []string{"id", "en"},
		ClaimsLocales:      []string{"en"},
		ACRValues:          []string{"urn:example:loa:2"},
		ParkedAt:           suiteStart,
		ExpiresAt:          suiteStart.Add(10 * time.Minute),
		Stage:              oidcprovider.StageLogin,
	}
}

// normalPending returns r with its times in UTC, for an exact comparison.
func normalPending(r *oidcprovider.PendingRequest) oidcprovider.PendingRequest {
	out := *r
	out.ParkedAt, out.ExpiresAt = utc(r.ParkedAt), utc(r.ExpiresAt)
	if r.SignIn != nil {
		s := normalSignIn(*r.SignIn)
		out.SignIn = &s
	}

	return out
}

// normalSignIn returns s with its times in UTC.
func normalSignIn(s oidcprovider.SignIn) oidcprovider.SignIn {
	s.AuthenticatedAt, s.AbsoluteExpiresAt = utc(s.AuthenticatedAt), utc(s.AbsoluteExpiresAt)

	return s
}

// loadPending loads the record for digest n, which must exist.
func loadPending(ctx context.Context, t *testing.T, s oidcprovider.PendingRequestStore, n byte) *oidcprovider.PendingRequest {
	t.Helper()

	got, err := s.Load(ctx, opDigest(n))
	require.NoError(t, err)
	require.NotNil(t, got)

	return got
}

// PendingRequestSuite holds a pending-request store to the contract
// oidcprovider.PendingRequestStore documents. newStore returns an empty store of its
// own for each case.
func PendingRequestSuite(t *testing.T, newStore func(t *testing.T) oidcprovider.PendingRequestStore) {
	t.Helper()

	runSuite(t, slices.Concat(pendingCases(), pendingMoveCases()), withoutClock(newStore))
}

func pendingCases() []suiteCase[oidcprovider.PendingRequestStore] {
	type store = oidcprovider.PendingRequestStore

	signIn := opSignIn("u-1", 1)

	return []suiteCase[store]{
		{
			name: "create and load by digest return every field",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, pendingRecord(1)))

				assert.Equal(t, normalPending(pendingRecord(1)), normalPending(loadPending(ctx, t, s, 1)))
			},
		},
		{
			name: "a load by another digest is not found, the flow digest included",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := pendingRecord(1)
				require.NoError(t, s.Create(ctx, r))

				_, err := s.Load(ctx, opDigest(2))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)

				_, err = s.Load(ctx, r.FlowDigest)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound, "the flow digest is no key")
			},
		},
		{
			name: "a digest already held is refused, and the record stays",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, pendingRecord(1)))

				other := pendingRecord(1)
				other.ClientID = opOtherClient
				err := s.Create(ctx, other)
				require.Error(t, err)
				assertNoDigest(t, err, opDigest(1))

				assert.Equal(t, opClient, loadPending(ctx, t, s, 1).ClientID)
			},
		},
		{
			name: "advance is single use: the loser writes nothing",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, pendingRecord(1)))

				require.NoError(t, s.Advance(ctx, opDigest(1), oidcprovider.StageLogin, oidcprovider.StageConsent, &signIn))

				other := opSignIn("u-2", 2)
				err := s.Advance(ctx, opDigest(1), oidcprovider.StageLogin, oidcprovider.StageConsent, &other)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)

				got := loadPending(ctx, t, s, 1)
				assert.Equal(t, oidcprovider.StageConsent, got.Stage)
				require.NotNil(t, got.SignIn)
				assert.Equal(t, normalSignIn(signIn), normalSignIn(*got.SignIn), "the winner's sign-in is the one stored")
			},
		},
		{
			name: "advance from a stage the record is not at writes nothing",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, pendingRecord(1)))

				err := s.Advance(ctx, opDigest(1), oidcprovider.StageConsent, oidcprovider.StageDone, &signIn)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)

				got := loadPending(ctx, t, s, 1)
				assert.Equal(t, oidcprovider.StageLogin, got.Stage)
				assert.Nil(t, got.SignIn)
			},
		},
		{
			name: "advance of an unknown digest is not found",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				err := s.Advance(ctx, opDigest(9), oidcprovider.StageLogin, oidcprovider.StageConsent, nil)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
				assertNoDigest(t, err, opDigest(9))
			},
		},
		{
			name: "advance with no sign-in stores nothing new but the stage",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, pendingRecord(1)))
				require.NoError(t, s.Advance(ctx, opDigest(1), oidcprovider.StageLogin, oidcprovider.StageConsent, &signIn))

				require.NoError(t, s.Advance(ctx, opDigest(1), oidcprovider.StageConsent, oidcprovider.StageDone, nil))

				want := pendingRecord(1)
				want.Stage = oidcprovider.StageDone
				want.SignIn = &signIn
				assert.Equal(t, normalPending(want), normalPending(loadPending(ctx, t, s, 1)))
			},
		},
		{
			name: "a parked end-session request advances from its own stage",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := pendingRecord(1)
				r.Stage = oidcprovider.StageLogout
				require.NoError(t, s.Create(ctx, r))

				require.ErrorIs(t, s.Advance(ctx, opDigest(1), oidcprovider.StageLogin, oidcprovider.StageDone, nil),
					oidcprovider.ErrNotFound)
				require.NoError(t, s.Advance(ctx, opDigest(1), oidcprovider.StageLogout, oidcprovider.StageDone, nil))
				assert.Equal(t, oidcprovider.StageDone, loadPending(ctx, t, s, 1).Stage)
			},
		},
		{
			name: "of many concurrent advances exactly one wins",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Create(ctx, pendingRecord(1)))

				var (
					start    = make(chan struct{})
					wg       sync.WaitGroup
					wins     atomic.Int32
					failures atomic.Int32
				)
				for range 16 {
					wg.Go(func() {
						<-start
						switch err := s.Advance(ctx, opDigest(1), oidcprovider.StageLogin, oidcprovider.StageConsent, nil); {
						case err == nil:
							wins.Add(1)
						case !assert.ErrorIs(t, err, oidcprovider.ErrNotFound):
							failures.Add(1)
						}
					})
				}
				close(start)
				wg.Wait()

				assert.Equal(t, int32(1), wins.Load(), "exactly one racer spends the stage")
				assert.Zero(t, failures.Load())
			},
		},
		{
			name: "an expired record is still returned, because expiry is the provider's to judge",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := pendingRecord(1)
				r.ParkedAt, r.ExpiresAt = longAgo, longAgo.Add(time.Minute)
				require.NoError(t, s.Create(ctx, r))

				got := loadPending(ctx, t, s, 1)
				assert.True(t, r.ExpiresAt.Equal(got.ExpiresAt))
				require.NoError(t, s.Advance(ctx, opDigest(1), oidcprovider.StageLogin, oidcprovider.StageConsent, nil),
					"advance judges the stage alone")
			},
		},
		{
			name: "delete expired removes only what expired before the caller's time",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				cutoff := suiteStart.Add(time.Hour)
				expired, atCutoff, live := pendingRecord(1), pendingRecord(2), pendingRecord(3)
				expired.ExpiresAt = cutoff.Add(-time.Second)
				atCutoff.ExpiresAt = cutoff
				live.ExpiresAt = cutoff.Add(time.Second)
				for _, r := range []*oidcprovider.PendingRequest{expired, atCutoff, live} {
					require.NoError(t, s.Create(ctx, r))
				}

				n, err := s.DeleteExpired(ctx, cutoff)
				require.NoError(t, err)
				assert.Equal(t, 1, n, "strictly before the cutoff")

				_, err = s.Load(ctx, opDigest(1))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
				loadPending(ctx, t, s, 2)
				loadPending(ctx, t, s, 3)
			},
		},
		{
			name: "delete expired judges by the caller's time, never the wall clock",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				past := pendingRecord(1)
				past.ExpiresAt = longAgo.Add(time.Hour)
				require.NoError(t, s.Create(ctx, past))

				n, err := s.DeleteExpired(ctx, longAgo)
				require.NoError(t, err)
				assert.Zero(t, n, "at the caller's time it has not expired, though the wall clock has passed it")
				loadPending(ctx, t, s, 1)

				future := pendingRecord(2)
				future.ExpiresAt = suiteStart.Add(time.Hour)
				require.NoError(t, s.Create(ctx, future))

				n, err = s.DeleteExpired(ctx, suiteStart.Add(2*time.Hour))
				require.NoError(t, err)
				assert.Equal(t, 2, n, "at the caller's time both have expired, wherever the wall clock is")
			},
		},
		{
			name: "a stored record is a copy of the caller's",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				r := pendingRecord(1)
				require.NoError(t, s.Create(ctx, r))
				scribblePending(r)

				assert.Equal(t, normalPending(pendingRecord(1)), normalPending(loadPending(ctx, t, s, 1)))
			},
		},
		{
			name: "a loaded record is a copy of the stored one",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				withSignIn := opSignIn("u-1", 1)
				require.NoError(t, s.Create(ctx, pendingRecord(1)))
				require.NoError(t, s.Advance(ctx, opDigest(1), oidcprovider.StageLogin, oidcprovider.StageConsent, &withSignIn))

				scribblePending(loadPending(ctx, t, s, 1))

				want := pendingRecord(1)
				want.Stage = oidcprovider.StageConsent
				fresh := opSignIn("u-1", 1)
				want.SignIn = &fresh
				assert.Equal(t, normalPending(want), normalPending(loadPending(ctx, t, s, 1)))
			},
		},
		{
			name: "the sign-in an advance stores is a copy of the caller's",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				mine := opSignIn("u-1", 1)
				require.NoError(t, s.Create(ctx, pendingRecord(1)))
				require.NoError(t, s.Advance(ctx, opDigest(1), oidcprovider.StageLogin, oidcprovider.StageConsent, &mine))

				mine.AMR[0], mine.User = "scribbled", "u-2"

				got := loadPending(ctx, t, s, 1)
				require.NotNil(t, got.SignIn)
				assert.Equal(t, normalSignIn(opSignIn("u-1", 1)), normalSignIn(*got.SignIn))
			},
		},
		{
			name: "no error of a missing record carries the digest",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				_, err := s.Load(ctx, opDigest(7))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
				assertNoDigest(t, err, opDigest(7))
			},
		},
	}
}

// pendingMoveCases holds Advance to the order of the stages: login, consent, done, with
// a parked end-session request going straight to done.
func pendingMoveCases() []suiteCase[oidcprovider.PendingRequestStore] {
	type store = oidcprovider.PendingRequestStore

	const (
		login   = oidcprovider.StageLogin
		consent = oidcprovider.StageConsent
		logout  = oidcprovider.StageLogout
		done    = oidcprovider.StageDone
		unnamed = oidcprovider.Stage(200)
	)

	moves := []struct {
		from, to oidcprovider.Stage
		why      string
		allowed  bool
	}{
		{from: login, to: consent, why: "forward", allowed: true},
		{from: login, to: done, why: "forward, with no consent to ask", allowed: true},
		{from: consent, to: done, why: "forward", allowed: true},
		{from: logout, to: done, why: "an end-session request's one move", allowed: true},

		{from: done, to: login, why: "out of done"},
		{from: done, to: consent, why: "out of done"},
		{from: done, to: logout, why: "out of done"},
		{from: done, to: done, why: "the same stage"},
		{from: consent, to: login, why: "backwards"},
		{from: consent, to: consent, why: "the same stage"},
		{from: login, to: login, why: "the same stage"},
		{from: logout, to: logout, why: "the same stage"},
		{from: logout, to: login, why: "out of an end-session request"},
		{from: logout, to: consent, why: "out of an end-session request"},
		{from: login, to: logout, why: "into an end-session request"},
		{from: consent, to: logout, why: "into an end-session request"},
		{from: login, to: unnamed, why: "a stage of no name"},
	}

	var cases []suiteCase[store]
	for _, move := range moves {
		cases = append(cases, suiteCase[store]{
			name: fmt.Sprintf("advance from stage %d to stage %d, %s", move.from, move.to, move.why),
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				signIn := opSignIn("u-1", 1)
				r := pendingRecord(1)
				r.Stage = move.from
				require.NoError(t, s.Create(ctx, r))

				err := s.Advance(ctx, opDigest(1), move.from, move.to, &signIn)

				want := pendingRecord(1)
				want.Stage = move.from
				if move.allowed {
					require.NoError(t, err)
					want.Stage, want.SignIn = move.to, &signIn
				} else {
					require.ErrorIs(t, err, oidcprovider.ErrNotFound, "the error a wrong from gives")
					assertNoDigest(t, err, opDigest(1))
				}
				assert.Equal(t, normalPending(want), normalPending(loadPending(ctx, t, s, 1)))
			},
		})
	}

	return append(cases, suiteCase[store]{
		name: "of many concurrent advances to the same stage at most one wins",
		assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
			require.NoError(t, s.Create(ctx, pendingRecord(1)))

			var (
				start = make(chan struct{})
				wg    sync.WaitGroup
				wins  atomic.Int32
			)
			for range 16 {
				wg.Go(func() {
					<-start
					if s.Advance(ctx, opDigest(1), login, login, nil) == nil {
						wins.Add(1)
					}
				})
			}
			close(start)
			wg.Wait()

			assert.LessOrEqual(t, wins.Load(), int32(1), "a move to the same stage spends nothing")
			assert.Equal(t, login, loadPending(ctx, t, s, 1).Stage)
		},
	})
}

// scribblePending overwrites every value of r a store could have kept by reference.
func scribblePending(r *oidcprovider.PendingRequest) {
	r.HandleDigest[0] ^= 0xff
	r.FlowDigest[0] ^= 0xff
	for _, list := range [][]string{r.Scopes, r.Resources, r.Prompt, r.UILocales, r.ClaimsLocales, r.ACRValues} {
		list[0] = "scribbled"
	}
	*r.MaxAge = -1
	if r.SignIn != nil {
		r.SignIn.User = "scribbled"
		r.SignIn.AMR[0] = "scribbled"
	}
}
