package oidcprovider_test

import (
	"context"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
)

// pendingLifetime is the default lifetime of a parked request, which every row below
// leaves as it is.
const pendingLifetime = 10 * time.Minute

// graceOp is one of the calls that answer an expired request within the grace window.
type graceOp struct {
	name string
	call func(t *testing.T, f *parkFixture, r parked) (oidcprovider.ResumeResult, error)
}

func graceOps() []graceOp {
	return []graceOp{
		{name: "resume", call: func(t *testing.T, f *parkFixture, r parked) (oidcprovider.ResumeResult, error) {
			t.Helper()
			signIn := testSignIn(f, "u-1")

			return f.p.Resume(t.Context(), r.input(&signIn))
		}},
		{name: "end", call: func(t *testing.T, f *parkFixture, r parked) (oidcprovider.ResumeResult, error) {
			t.Helper()

			// The code asked for is not the one answered: an expired request is denied.
			return f.p.EndPending(t.Context(), r.end(oidcprovider.CodeTemporarilyUnavailable))
		}},
		{name: "end asking server_error", call: func(t *testing.T, f *parkFixture, r parked) (oidcprovider.ResumeResult, error) {
			t.Helper()

			return f.p.EndPending(t.Context(), r.end(oidcprovider.CodeServerError))
		}},
	}
}

// changeTenant replaces tenant-web after a request was parked for it.
func changeTenant(t *testing.T, f *parkFixture, change func(*oidcprovider.Client)) {
	t.Helper()

	for _, c := range authzClients() {
		if c.ID == "tenant-web" {
			change(&c)
			require.NoError(t, f.registry.Put(t.Context(), c))

			return
		}
	}
	t.Fatal("tenant-web is not among the clients")
}

// TestPendingRequestGrace answers a request expired less than the grace window ago, and bound
// to the flow presented, with access_denied at the client's redirect URI, spending it, at a
// resume and at an end alike. Past the window, under a grace of zero, from another flow, or for
// a client that can no longer be redirected to, it is an unknown handle and stays as it was
// (F13). The window is [ExpiresAt, ExpiresAt+grace): its last instant is answered, and its end
// is not.
func TestPendingRequestGrace(t *testing.T) {
	t.Parallel()

	// denied asserts access_denied at the registered redirect URI, with state and iss and
	// nothing else, and that the request is spent: a second call of the same kind is an
	// unknown handle.
	denied := func(t *testing.T, f *parkFixture, r parked, op graceOp, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.Equal(t, oidcprovider.ResumeOutcomeClientError, res.Outcome)
		assert.Empty(t, res.BrowserSessionSecret, "no session is made for an expired request")

		loc, perr := url.Parse(res.RedirectTo)
		require.NoError(t, perr)
		assert.Equal(t, "https://rp.example.com/cb", loc.Scheme+"://"+loc.Host+loc.Path)
		assert.Equal(t, url.Values{"tenant": {"a"}, "error": {"access_denied"}, "state": {"s-1"}, "iss": {issuer}}, loc.Query(),
			"no code, no error_description, nothing else")

		assert.Equal(t, oidcprovider.StageDone, stageOf(t, f, r), "the request is spent")
		_, again := op.call(t, f, r)
		require.ErrorIs(t, again, oidcprovider.ErrUnknownHandle, "it is answered once")
	}
	// unknown asserts an unknown handle, with no redirect, and the request left as it was.
	unknown := func(t *testing.T, f *parkFixture, r parked, _ graceOp, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
		assert.Empty(t, res.RedirectTo)
		assert.Equal(t, oidcprovider.StageLogin, stageOf(t, f, r), "the request is left as it was")
	}

	type testCase struct {
		name string
		opts []oidcprovider.Option
		// past is how long past its expiry the call is made.
		past time.Duration
		// before changes the fixture, or the browser's flow, before the call.
		before func(t *testing.T, f *parkFixture, r *parked)
		assert func(t *testing.T, f *parkFixture, r parked, op graceOp, res oidcprovider.ResumeResult, err error)
	}
	cases := []testCase{
		{name: "expired 2 minutes ago, within the default grace", past: 2 * time.Minute, assert: denied},
		{name: "expired at this instant", past: 0, assert: denied},
		{name: "the last instant of the default grace", past: 10*time.Minute - time.Nanosecond, assert: denied},
		{name: "exactly the default grace past expiry", past: 10 * time.Minute, assert: unknown},
		{name: "expired 11 minutes ago, past the default grace", past: 11 * time.Minute, assert: unknown},
		{
			name: "a grace of zero answers nothing expired",
			opts: []oidcprovider.Option{oidcprovider.WithPendingRequestGrace(0)},
			past: time.Minute, assert: unknown,
		},
		{
			name: "a longer grace the consumer chose",
			opts: []oidcprovider.Option{oidcprovider.WithPendingRequestGrace(30 * time.Minute)},
			past: 29 * time.Minute, assert: denied,
		},
		{
			name: "within the grace, from another browser's flow",
			past: 2 * time.Minute,
			before: func(t *testing.T, f *parkFixture, r *parked) {
				t.Helper()
				other := park(t, f, asTenant("s-2"))
				r.flow = other.flow
			},
			assert: unknown,
		},
		{
			name: "within the grace, for a client that has since lost the code grant: expiry is the answer, not unauthorized_client",
			past: 2 * time.Minute,
			before: func(t *testing.T, f *parkFixture, _ *parked) {
				t.Helper()
				changeTenant(t, f, func(c *oidcprovider.Client) {
					c.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantRefreshToken}
				})
			},
			assert: denied,
		},
		{
			name: "within the grace, for a client that has since lost openid: expiry is the answer, not invalid_scope",
			past: 2 * time.Minute,
			before: func(t *testing.T, f *parkFixture, _ *parked) {
				t.Helper()
				changeTenant(t, f, func(c *oidcprovider.Client) { c.Scopes = []string{"profile"} })
			},
			assert: denied,
		},
		{
			name: "within the grace, for a client since removed",
			past: 2 * time.Minute,
			before: func(t *testing.T, f *parkFixture, _ *parked) {
				t.Helper()
				require.NoError(t, f.registry.Delete(t.Context(), "tenant-web"))
			},
			assert: unknown,
		},
	}
	for _, tc := range cases {
		for _, op := range graceOps() {
			t.Run(tc.name+"/"+op.name, func(t *testing.T) {
				t.Parallel()
				f := newParkFixture(t, issuer+"/login", tc.opts...)
				r := park(t, f, asTenant("s-1"))
				if tc.before != nil {
					tc.before(t, f, &r)
				}
				f.clk.Advance(pendingLifetime + tc.past)

				res, err := op.call(t, f, r)
				tc.assert(t, f, r, op, res, err)
			})
		}
	}
}

// TestPendingRequestGrace_ViewRefuses keeps the page's view to live requests: a request
// expired within the grace window is an unknown handle there, and is left to be answered.
func TestPendingRequestGrace_ViewRefuses(t *testing.T) {
	t.Parallel()

	f := newParkFixture(t, issuer+"/login")
	r := park(t, f, asTenant("s-1"))
	f.clk.Advance(pendingLifetime + 2*time.Minute)

	view, err := f.p.PendingRequest(t.Context(), r.handle, r.flow)
	require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
	assert.Nil(t, view)
	assert.Equal(t, oidcprovider.StageLogin, stageOf(t, f, r), "the view spends nothing")
}

// TestWithPendingRequestGrace_Bounds holds the grace window between zero and 30 minutes,
// inclusive, and refuses anything else at construction (F23).
func TestWithPendingRequestGrace_Bounds(t *testing.T) {
	t.Parallel()

	builds := func(t *testing.T, p *oidcprovider.Provider, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.NotNil(t, p)
	}
	refused := func(t *testing.T, p *oidcprovider.Provider, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrConfig)
		assert.Contains(t, err.Error(), "WithPendingRequestGrace", "the error names the option")
		assert.Nil(t, p)
	}

	type testCase struct {
		name   string
		grace  time.Duration
		assert func(t *testing.T, p *oidcprovider.Provider, err error)
	}
	cases := []testCase{
		{name: "zero turns it off", grace: 0, assert: builds},
		{name: "the default", grace: 10 * time.Minute, assert: builds},
		{name: "the maximum", grace: 30 * time.Minute, assert: builds},
		{name: "negative", grace: -time.Nanosecond, assert: refused},
		{name: "just over the maximum", grace: 30*time.Minute + time.Nanosecond, assert: refused},
		{name: "two hours", grace: 2 * time.Hour, assert: refused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := oidcprovider.New(validDeps(t), oidcprovider.WithPendingRequestGrace(tc.grace))
			tc.assert(t, p, err)
		})
	}
}

// TestEndPending_ExpiredGraceIsSpentOnce moves the clock back between two calls (Review Focus
// 3). A request answered as expired is spent by the same conditional write a resume spends it
// by, so once the clock says it is live again, neither a resume with a valid sign-in nor
// another end can answer it a second time.
func TestEndPending_ExpiredGraceIsSpentOnce(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		second func(t *testing.T, f *parkFixture, r parked) (oidcprovider.ResumeResult, error)
		assert func(t *testing.T, res oidcprovider.ResumeResult, err error)
	}
	refused := func(t *testing.T, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
		assert.Empty(t, res.RedirectTo, "no second answer")
	}
	cases := []testCase{
		{
			name: "a resume with a valid sign-in, at a time the request reads as live",
			second: func(t *testing.T, f *parkFixture, r parked) (oidcprovider.ResumeResult, error) {
				t.Helper()
				signIn := testSignIn(f, "u-1")

				return f.p.Resume(t.Context(), r.input(&signIn))
			},
			assert: refused,
		},
		{
			name: "another end, at a time the request reads as live",
			second: func(t *testing.T, f *parkFixture, r parked) (oidcprovider.ResumeResult, error) {
				t.Helper()

				return f.p.EndPending(t.Context(), r.end(oidcprovider.CodeAccessDenied))
			},
			assert: refused,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newParkFixture(t, issuer+"/login")
			r := park(t, f, asTenant("s-1"))

			f.clk.Advance(pendingLifetime + 30*time.Second)
			first, err := f.p.EndPending(t.Context(), r.end(oidcprovider.CodeServerError))
			require.NoError(t, err)
			assert.Equal(t, "access_denied", queryOf(t, first.RedirectTo).Get("error"))

			f.clk.Advance(-time.Minute)
			res, err := tc.second(t, f, r)
			tc.assert(t, res, err)
			assert.Equal(t, oidcprovider.StageDone, stageOf(t, f, r))
		})
	}
}

// TestMemoryPendingRequestStore_KeepsGraceWindow keeps a request through the store's own sweep
// until the grace window has passed (F14). A store the consumer builds keeps it for the longest
// window the option allows, so that any provider it is given to can answer it, and the
// provider's own default store keeps it for the provider's window.
func TestMemoryPendingRequestStore_KeepsGraceWindow(t *testing.T) {
	t.Parallel()

	start := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name string
		// store returns the store under test, on clk.
		store func(t *testing.T, clk *clockwork.FakeClock) oidcprovider.PendingRequestStore
		// past is how long past the record's expiry a later write sweeps.
		past   time.Duration
		assert func(t *testing.T, held bool)
	}
	consumers := func(t *testing.T, clk *clockwork.FakeClock) oidcprovider.PendingRequestStore {
		t.Helper()
		s, err := oidcprovider.NewMemoryPendingRequestStore(oidcprovider.WithMemoryStoreClock(clk))
		require.NoError(t, err)

		return s
	}
	providers := func(opts ...oidcprovider.Option) func(t *testing.T, clk *clockwork.FakeClock) oidcprovider.PendingRequestStore {
		return func(t *testing.T, clk *clockwork.FakeClock) oidcprovider.PendingRequestStore {
			t.Helper()
			p, err := oidcprovider.New(validDeps(t), append([]oidcprovider.Option{oidcprovider.WithClock(clk)}, opts...)...)
			require.NoError(t, err)

			return p.PendingRequestsForTest()
		}
	}
	kept := func(t *testing.T, held bool) {
		t.Helper()
		assert.True(t, held, "a request inside the window is kept")
	}
	forgotten := func(t *testing.T, held bool) {
		t.Helper()
		assert.False(t, held, "a request past the window is forgotten")
	}
	cases := []testCase{
		{name: "a consumer's store, 29 minutes past expiry", store: consumers, past: 29 * time.Minute, assert: kept},
		{name: "a consumer's store, 31 minutes past expiry", store: consumers, past: 31 * time.Minute, assert: forgotten},
		{name: "the provider's store, 9 minutes past expiry", store: providers(), past: 9 * time.Minute, assert: kept},
		{name: "the provider's store, 11 minutes past expiry", store: providers(), past: 11 * time.Minute, assert: forgotten},
		{
			name:  "the provider's store under a grace of zero, a minute past expiry",
			store: providers(oidcprovider.WithPendingRequestGrace(0)), past: time.Minute, assert: forgotten,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			clk := clockwork.NewFakeClockAt(start)
			s := tc.store(t, clk)

			expires := start.Add(time.Second)
			require.NoError(t, s.Create(t.Context(), &oidcprovider.PendingRequest{HandleDigest: []byte("old"), ExpiresAt: expires}))
			clk.Advance(expires.Sub(start) + tc.past)
			require.NoError(t, s.Create(t.Context(), &oidcprovider.PendingRequest{HandleDigest: []byte("new"), ExpiresAt: clk.Now().Add(time.Hour)}))

			_, err := s.Load(t.Context(), []byte("old"))
			tc.assert(t, err == nil)
		})
	}
}

// TestPendingRequestGrace_DeviceRequestIsUnknown keeps a request parked for a device's code
// entry out of the grace window: it has no redirect URI to answer at, so once expired it is an
// unknown handle, with no redirect and its stage left as it was, at a resume and at an end alike.
func TestPendingRequestGrace_DeviceRequestIsUnknown(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		call func(t *testing.T, f *deviceConsentFixture, handle, flow string) (oidcprovider.ResumeResult, error)
		// assert says what the call left: an unknown handle, with no redirect, and the stage as it was.
		assert func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error)
	}
	unknown := func(t *testing.T, f *deviceConsentFixture, handle string, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
		assert.Empty(t, res.RedirectTo, "no redirect, a device request has no redirect URI")
		assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle), "the request is left as it was")
	}
	cases := []testCase{
		{
			name: "resume",
			call: func(t *testing.T, f *deviceConsentFixture, handle, flow string) (oidcprovider.ResumeResult, error) {
				t.Helper()
				signIn := f.signIn(t, "u-1")

				return f.p.Resume(t.Context(), oidcprovider.ResumeInput{Handle: handle, FlowSecret: flow, SignIn: &signIn})
			},
			assert: unknown,
		},
		{
			name: "end",
			call: func(t *testing.T, f *deviceConsentFixture, handle, flow string) (oidcprovider.ResumeResult, error) {
				t.Helper()

				return f.p.EndPending(t.Context(), oidcprovider.EndPendingInput{Handle: handle, FlowSecret: flow, Code: oidcprovider.CodeAccessDenied})
			},
			assert: unknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newDeviceConsentFixture(t, deviceConsentSetup{})
			handle, flow := f.atLogin(t)
			f.clk.Advance(pendingLifetime + 2*time.Minute)

			res, err := tc.call(t, f, handle, flow)
			tc.assert(t, f, handle, res, err)
		})
	}
}

// TestPendingRequestGrace_FailedSpend leaves a request expired within the grace window parked,
// and answers a dependency failure, when the spend fails: no redirect, and no second attempt to
// answer server_error through the same store that just failed (F16).
func TestPendingRequestGrace_FailedSpend(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		op   graceOp
		// assert says what the failed spend left, given how many times Advance was called.
		assert func(t *testing.T, stage oidcprovider.Stage, advances int32, res oidcprovider.ResumeResult, err error)
	}
	failed := func(t *testing.T, stage oidcprovider.Stage, advances int32, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrDependency)
		assert.Empty(t, res.RedirectTo, "no redirect")
		assert.EqualValues(t, 1, advances, "the spend is tried once, and not again to answer server_error")
		assert.Equal(t, oidcprovider.StageLogin, stage, "the request stays parked")
	}

	var cases []testCase
	for _, op := range graceOps() {
		cases = append(cases, testCase{name: op.name, op: op, assert: failed})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			memory, err := oidcprovider.NewMemoryPendingRequestStore()
			require.NoError(t, err)
			var advances atomic.Int32
			ctrl := gomock.NewController(t)
			store := NewMockPendingRequestStore(ctrl)
			store.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(memory.Create).AnyTimes()
			store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(memory.Load).AnyTimes()
			store.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memory.DeleteExpired).AnyTimes()
			// The first spend fails with an outage; a second would succeed, which the row refuses.
			store.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, digest []byte, from, to oidcprovider.Stage, s *oidcprovider.SignIn) error {
					if advances.Add(1) == 1 {
						return errOutage
					}

					return memory.Advance(ctx, digest, from, to, s)
				}).AnyTimes()
			f := newParkFixture(t, issuer+"/login", oidcprovider.WithPendingRequestStore(store))
			r := park(t, f, asTenant("s-1"))
			f.clk.Advance(pendingLifetime + 2*time.Minute)

			res, err := tc.op.call(t, f, r)

			stored, lerr := memory.Load(t.Context(), handleDigestOf(t, r.handle))
			require.NoError(t, lerr)
			tc.assert(t, stored.Stage, advances.Load(), res, err)
		})
	}
}

// TestPendingRequestGrace_ConsentStage answers a request waiting at its consent stage, expired
// within the grace window, with access_denied at the client's redirect URI, spending it, and
// issuing nothing, as it does one waiting at login. An end refuses a consent-stage request.
func TestPendingRequestGrace_ConsentStage(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		call func(t *testing.T, f *parkFixture, r parked, signIn oidcprovider.SignIn) (oidcprovider.ResumeResult, error)
		// assert says what the call answered, and left.
		assert func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error)
	}
	cases := []testCase{
		{
			name: "a consent answer is access_denied at the client, and spends the stage",
			call: func(t *testing.T, f *parkFixture, r parked, signIn oidcprovider.SignIn) (oidcprovider.ResumeResult, error) {
				t.Helper()
				in := r.input(&signIn)
				answerWith(&in, "openid")

				return f.p.Resume(t.Context(), in)
			},
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, oidcprovider.ResumeOutcomeClientError, res.Outcome)
				assert.Equal(t, url.Values{"error": {"access_denied"}, "state": {authzState}, "iss": {issuer}}, queryOf(t, res.RedirectTo))
				assert.True(t, strings.HasPrefix(res.RedirectTo, authzRedirect), res.RedirectTo)
				assert.Equal(t, oidcprovider.StageDone, stageOf(t, f, r), "the stage is spent")
				assert.Zero(t, codesHeld(t, f, "u-1", "billing-web"), "no code")
			},
		},
		{
			name: "an end is an unknown handle, as it is for a live consent stage",
			call: func(t *testing.T, f *parkFixture, r parked, _ oidcprovider.SignIn) (oidcprovider.ResumeResult, error) {
				t.Helper()

				return f.p.EndPending(t.Context(), r.end(oidcprovider.CodeAccessDenied))
			},
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.Empty(t, res.RedirectTo)
				assert.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r), "the request is left as it was")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newParkFixture(t, issuer+"/login")
			signIn := testSignIn(f, "u-1")
			r, _ := atConsent(t, f, nil, signIn)
			f.clk.Advance(pendingLifetime + 2*time.Minute)

			res, err := tc.call(t, f, r, signIn)
			tc.assert(t, f, r, res, err)
		})
	}
}
