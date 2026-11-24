package oidcprovider_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// countingPending is a pending-request store that can count its live requests: a store mock
// whose writes reach memory, beside a counter mock a row states for itself.
type countingPending struct {
	*MockPendingRequestStore
	*MockPendingRequestCounter
}

// TestPendingRequestLimit refuses a request that would be parked once the live requests reach
// the ceiling, at the redirect URI with temporarily_unavailable, state and iss, storing nothing.
// With no ceiling the counter is never asked. A counter that fails, or answers what no count can
// be, is a dependency failure, answered server_error as Authorize answers any; a caller who left
// hears its own context's error.
func TestPendingRequestLimit(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []oidcprovider.Option
		ctx  func(ctx context.Context) context.Context
		// count answers the n-th CountLive, from zero, and nil expects none.
		count func(ctx context.Context, n int) (int, error)
		// parks is how many requests arrive, and creates how many the store must be given.
		parks, creates int
		assert         func(t *testing.T, f *parkFixture, results []oidcprovider.AuthorizeResult, errs []error)
	}

	parkedAll := func(t *testing.T, _ *parkFixture, results []oidcprovider.AuthorizeResult, errs []error) {
		t.Helper()
		for i := range results {
			require.NoError(t, errs[i])
			assert.NotEmpty(t, results[i].FlowSecret, "request %d is parked", i)
			assert.True(t, strings.HasPrefix(results[i].Location, issuer+"/login?"), "request %d goes to the login page", i)
		}
	}
	// answeredWith asserts that the last request was answered code at its redirect URI, with
	// state and iss and nothing else, and parked nothing.
	answeredWith := func(code string) func(*testing.T, *parkFixture, []oidcprovider.AuthorizeResult, []error) {
		return func(t *testing.T, f *parkFixture, results []oidcprovider.AuthorizeResult, errs []error) {
			t.Helper()
			last := len(results) - 1
			require.NoError(t, errs[last])
			res := results[last]
			assert.Empty(t, res.FlowSecret, "nothing is parked")
			loc, err := url.Parse(res.Location)
			require.NoError(t, err)
			assert.Equal(t, authzRedirect, loc.Scheme+"://"+loc.Host+loc.Path)
			assert.Equal(t, url.Values{"error": {code}, "state": {authzState}, "iss": {issuer}}, loc.Query(),
				"no error_description, no handle, nothing else")
			assert.NotContains(t, f.logs.String(), errOutage.Error(), "a store's text is not repeated")
		}
	}

	cases := []testCase{
		{name: "no ceiling parks every request and counts nothing", parks: 3, creates: 3, assert: parkedAll},
		{
			name:  "a ceiling of 2 parks two, and refuses the third",
			opts:  []oidcprovider.Option{oidcprovider.WithPendingRequestLimit(2)},
			count: func(_ context.Context, n int) (int, error) { return n, nil },
			parks: 3, creates: 2,
			assert: func(t *testing.T, f *parkFixture, results []oidcprovider.AuthorizeResult, errs []error) {
				t.Helper()
				parkedAll(t, f, results[:2], errs[:2])
				answeredWith(oidcprovider.CodeTemporarilyUnavailable)(t, f, results, errs)
			},
		},
		{
			name:  "a refusal logs one WARN, naming nothing of the request or the count",
			opts:  []oidcprovider.Option{oidcprovider.WithPendingRequestLimit(4000)},
			count: func(context.Context, int) (int, error) { return 4242, nil },
			parks: 1, creates: 0,
			assert: func(t *testing.T, f *parkFixture, results []oidcprovider.AuthorizeResult, errs []error) {
				t.Helper()
				answeredWith(oidcprovider.CodeTemporarilyUnavailable)(t, f, results, errs)

				logs := f.logs.String()
				assert.Equal(t, 1, strings.Count(logs, "level=WARN"), "one warning, so a flood is seen: %s", logs)
				assert.Equal(t, 1, strings.Count(logs, "\n"), "and nothing else is logged: %s", logs)
				for name, secret := range map[string]string{
					"handle": "rh.", "state": authzState, "redirect URI": "rp.example.com", "count": "4242", "ceiling": "4000",
				} {
					assert.NotContains(t, logs, secret, "the log names no %s", name)
				}
			},
		},
		{
			name:  "a count over the ceiling refuses",
			opts:  []oidcprovider.Option{oidcprovider.WithPendingRequestLimit(2)},
			count: func(context.Context, int) (int, error) { return 5, nil },
			parks: 1, creates: 0,
			assert: answeredWith(oidcprovider.CodeTemporarilyUnavailable),
		},
		{
			name:  "a count one below the ceiling parks",
			opts:  []oidcprovider.Option{oidcprovider.WithPendingRequestLimit(2)},
			count: func(context.Context, int) (int, error) { return 1, nil },
			parks: 1, creates: 1,
			assert: parkedAll,
		},
		{
			name:  "a counter that fails is answered server_error",
			opts:  []oidcprovider.Option{oidcprovider.WithPendingRequestLimit(2)},
			count: func(context.Context, int) (int, error) { return 0, errOutage },
			parks: 1, creates: 0,
			assert: answeredWith(oidcprovider.CodeServerError),
		},
		{
			name:  "a negative count breaks the counter's contract, and is answered server_error",
			opts:  []oidcprovider.Option{oidcprovider.WithPendingRequestLimit(2)},
			count: func(context.Context, int) (int, error) { return -1, nil },
			parks: 1, creates: 0,
			assert: answeredWith(oidcprovider.CodeServerError),
		},
		{
			name: "a caller who left hears its own context's error, and nothing is parked",
			opts: []oidcprovider.Option{oidcprovider.WithPendingRequestLimit(2)},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			count: func(ctx context.Context, _ int) (int, error) { return 0, ctx.Err() },
			parks: 1, creates: 0,
			assert: func(t *testing.T, _ *parkFixture, results []oidcprovider.AuthorizeResult, errs []error) {
				t.Helper()
				require.ErrorIs(t, errs[0], context.Canceled)
				assert.Empty(t, results[0].Location)
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
			memory, err := oidcprovider.NewMemoryPendingRequestStore()
			require.NoError(t, err)
			ctrl := gomock.NewController(t)
			store := countingPending{NewMockPendingRequestStore(ctrl), NewMockPendingRequestCounter(ctrl)}
			store.MockPendingRequestStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(memory.Create).Times(tc.creates)
			if tc.count != nil {
				calls := 0
				store.MockPendingRequestCounter.EXPECT().CountLive(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ time.Time) (int, error) {
						n := calls
						calls++
						return tc.count(ctx, n)
					}).Times(tc.parks)
			}
			f := newParkFixture(t, issuer+"/login", append(tc.opts, oidcprovider.WithPendingRequestStore(store))...)

			results := make([]oidcprovider.AuthorizeResult, tc.parks)
			errs := make([]error, tc.parks)
			for i := range tc.parks {
				results[i], errs[i] = f.p.Authorize(ctx, oidcprovider.AuthorizeInput{Params: authzParams()})
			}
			tc.assert(t, f, results, errs)
		})
	}
}

// TestPendingRequestLimit_CountsEveryStage counts a request answered already but not yet
// expired, and refuses a request a browser session would park at its consent stage, as it
// refuses one parked for the login page.
func TestPendingRequestLimit_CountsEveryStage(t *testing.T) {
	t.Parallel()

	f := newParkFixture(t, issuer+"/login", oidcprovider.WithPendingRequestLimit(1))
	r := park(t, f, nil)
	signIn := testSignIn(f, "u-1")
	resumed, err := f.p.Resume(t.Context(), r.input(&signIn))
	require.NoError(t, err)
	require.Equal(t, oidcprovider.ResumeOutcomeConsent, resumed.Outcome, "the first request waits for consent")
	require.NotEmpty(t, resumed.BrowserSessionSecret)

	res, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{
		Params: authzParams(), FlowSecret: r.flow, BrowserSessionSecret: resumed.BrowserSessionSecret,
	})
	require.NoError(t, err)
	assert.Empty(t, res.FlowSecret, "nothing is parked")
	assert.Equal(t, "temporarily_unavailable", queryOf(t, res.Location).Get("error"))
}

// TestWithPendingRequestLimit_Construction refuses a ceiling that is not positive, and one
// over a store that cannot count its live requests, naming the store (F23).
func TestWithPendingRequestLimit_Construction(t *testing.T) {
	t.Parallel()

	builds := func(t *testing.T, p *oidcprovider.Provider, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.NotNil(t, p)
	}
	refused := func(contains string) func(*testing.T, *oidcprovider.Provider, error) {
		return func(t *testing.T, p *oidcprovider.Provider, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.Contains(t, err.Error(), "WithPendingRequestLimit")
			assert.Contains(t, err.Error(), contains)
			assert.Nil(t, p)
		}
	}

	type testCase struct {
		name   string
		opts   func(t *testing.T) []oidcprovider.Option
		assert func(t *testing.T, p *oidcprovider.Provider, err error)
	}
	ceiling := func(n int, store oidcprovider.PendingRequestStore) func(t *testing.T) []oidcprovider.Option {
		return func(*testing.T) []oidcprovider.Option {
			opts := []oidcprovider.Option{oidcprovider.WithPendingRequestLimit(n)}
			if store != nil {
				opts = append(opts, oidcprovider.WithPendingRequestStore(store))
			}
			return opts
		}
	}
	ctrl := gomock.NewController(t)
	memory, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)

	cases := []testCase{
		{name: "over the default store", opts: ceiling(1000, nil), assert: builds},
		{name: "over a memory store the consumer built", opts: ceiling(1000, memory), assert: builds},
		{
			name:   "over a store that can count",
			opts:   ceiling(1, countingPending{NewMockPendingRequestStore(ctrl), NewMockPendingRequestCounter(ctrl)}),
			assert: builds,
		},
		{name: "zero", opts: ceiling(0, nil), assert: refused("positive")},
		{name: "negative", opts: ceiling(-1, nil), assert: refused("positive")},
		{
			name:   "over a store that cannot count",
			opts:   ceiling(1000, NewMockPendingRequestStore(ctrl)),
			assert: refused("*oidcprovider_test.MockPendingRequestStore"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := oidcprovider.New(validDeps(t), tc.opts(t)...)
			tc.assert(t, p, err)
		})
	}
}

// TestMemoryPendingRequestStore_CountLive counts the records whose expiry is strictly after the
// time given, whatever their stage, and reads no clock of its own.
func TestMemoryPendingRequestStore_CountLive(t *testing.T) {
	t.Parallel()

	now := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name    string
		expires []time.Time
		stages  []oidcprovider.Stage
		assert  func(t *testing.T, n int, err error)
	}
	counts := func(want int) func(*testing.T, int, error) {
		return func(t *testing.T, n int, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, want, n)
		}
	}
	cases := []testCase{
		{name: "an empty store", assert: counts(0)},
		{
			name:    "a record expiring a nanosecond after now counts, and one expiring at now does not",
			expires: []time.Time{now.Add(time.Nanosecond), now, now.Add(-time.Minute)},
			assert:  counts(1),
		},
		{
			name:    "every stage counts while unexpired",
			expires: []time.Time{now.Add(time.Minute), now.Add(time.Minute), now.Add(time.Minute), now.Add(time.Minute)},
			stages:  []oidcprovider.Stage{oidcprovider.StageLogin, oidcprovider.StageConsent, oidcprovider.StageDone, oidcprovider.StageLogout},
			assert:  counts(4),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The store's own clock is a year off: only the time given may decide.
			s, err := oidcprovider.NewMemoryPendingRequestStore(oidcprovider.WithMemoryStoreClock(clockwork.NewFakeClockAt(now.AddDate(1, 0, 0))))
			require.NoError(t, err)
			for i, expires := range tc.expires {
				stage := oidcprovider.StageLogin
				if tc.stages != nil {
					stage = tc.stages[i]
				}
				require.NoError(t, s.Create(t.Context(), &oidcprovider.PendingRequest{
					ID: id.MustParse("01926a4e-0000-7000-8000-0000000000cc"), HandleDigest: []byte{byte(i)},
					ExpiresAt: expires, Stage: stage,
				}))
			}

			n, err := s.CountLive(t.Context(), now)
			tc.assert(t, n, err)
		})
	}
}

// TestPendingRequestLimit_ExemptsDeviceAndLogout parks a request for a device's code entry, and
// one for a logout, at the ceiling: neither has a redirect URI to answer a refusal at, so both
// park, as they do with no ceiling.
func TestPendingRequestLimit_ExemptsDeviceAndLogout(t *testing.T) {
	t.Parallel()

	atCeiling := oidcprovider.WithPendingRequestLimit(1)
	// live is a request that holds the ceiling's one place.
	live := func(clk clockwork.Clock) *oidcprovider.PendingRequest {
		return &oidcprovider.PendingRequest{
			ID: id.MustParse("01926a4e-0000-7000-8000-0000000000dd"), HandleDigest: []byte("holder"),
			ExpiresAt: clk.Now().Add(time.Hour), Stage: oidcprovider.StageLogin,
		}
	}

	type testCase struct {
		name string
		// park fills the ceiling, then parks, and returns where the browser goes.
		park   func(t *testing.T) (oidcprovider.AuthorizeResult, error)
		assert func(t *testing.T, res oidcprovider.AuthorizeResult, err error)
	}
	parked := func(location string) func(*testing.T, oidcprovider.AuthorizeResult, error) {
		return func(t *testing.T, res oidcprovider.AuthorizeResult, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.NotEmpty(t, res.FlowSecret, "the request is parked")
			assert.True(t, strings.HasPrefix(res.Location, issuer+location+"?"), res.Location)
		}
	}
	cases := []testCase{
		{
			name: "a device's code entry parks",
			park: func(t *testing.T) (oidcprovider.AuthorizeResult, error) {
				t.Helper()
				f := newEntryFixture(t, entrySetup{opts: []oidcprovider.Option{atCeiling}})
				f.seed(t, entryCode, nil)
				require.NoError(t, f.pending.Create(t.Context(), live(f.clk)))

				return f.p.EnterUserCode(t.Context(), oidcprovider.DeviceEntryInput{UserCode: entryDisplay, Source: entrySource})
			},
			assert: parked("/login"),
		},
		{
			name: "a logout's confirmation parks",
			park: func(t *testing.T) (oidcprovider.AuthorizeResult, error) {
				t.Helper()
				f := newLogoutFixture(t, atCeiling)
				require.NoError(t, f.pending.Create(t.Context(), live(f.clk)))

				res, err := f.p.EndSession(t.Context(), oidcprovider.EndSessionInput{Params: url.Values{}})
				if err != nil {
					return oidcprovider.AuthorizeResult{}, err
				}

				return oidcprovider.AuthorizeResult{Location: res.Location, FlowSecret: res.FlowSecret}, nil
			},
			assert: parked("/logout"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res, err := tc.park(t)
			tc.assert(t, res, err)
		})
	}
}
