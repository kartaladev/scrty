package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// renewAfter renews credential and advances the fake clock by step first, and
// returns the successor's credential.
func (f *renewalFixture) renewAfter(t *testing.T, step time.Duration, credential string) string {
	t.Helper()

	f.clk.Advance(step)

	return f.renew(t, httpsec.DefaultSessionRenewalPath, credential)
}

// atLimit renews credential ten times, 30 seconds apart, and returns the
// credential the last renewal handed back.
func (f *renewalFixture) atLimit(t *testing.T, credential string) string {
	t.Helper()

	for range 10 {
		credential = f.renewAfter(t, 30*time.Second, credential)
	}

	return credential
}

// TestSessionRenewalThrottle pins the per-family renewal limit: its default,
// that families are independent, that the window slides, what counts toward
// it, and that an outage of the limiter refuses the renewal.
func TestSessionRenewalThrottle(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T) renewalSetup
		assert func(t *testing.T, f *renewalFixture)
	}

	cases := []testCase{
		{
			name: "an eleventh renewal of a family is refused",
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				last := f.atLimit(t, f.old)
				f.clk.Advance(30 * time.Second)

				out := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, last)

				require.ErrorIs(t, out.err, httpsec.ErrRenewalThrottled)
				assert.Equal(t, http.StatusTooManyRequests, httpsec.StatusForError(out.err))

				s, err := f.sessions.LoadForRenewal(t.Context(), last)
				require.NoError(t, err)
				assert.True(t, s.SupersededAt.IsZero(), "the presented session was not superseded")
			},
		},
		{
			name: "another family is unaffected",
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				other, err := f.sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				f.atLimit(t, f.old)

				f.renewAfter(t, 30*time.Second, other.ID)
			},
		},
		{
			name: "the window slides",
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				last := f.atLimit(t, f.old)

				f.renewAfter(t, 10*time.Minute+time.Second, last)
			},
		},
		{
			name: "retries count but fit",
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				f.renewAfter(t, time.Second, f.old)

				// Two re-rotations of the same renewed credential, inside its window.
				f.renewAfter(t, time.Second, f.old)
				last := f.renewAfter(t, time.Second, f.old)

				for range 7 {
					last = f.renewAfter(t, 30*time.Second, last)
				}

				// Ten renewals were charged, the two re-rotations included, so the
				// eleventh is refused.
				f.clk.Advance(30 * time.Second)

				out := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, last)
				require.ErrorIs(t, out.err, httpsec.ErrRenewalThrottled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			setup := renewalSetup{}
			if tc.setup != nil {
				setup = tc.setup(t)
			}

			tc.assert(t, newRenewalFixture(t, setup))
		})
	}
}

// TestSessionRenewalThrottle_ConsumerLimiter pins that a limiter the consumer
// supplies replaces the default, and is asked and charged by family.
func TestSessionRenewalThrottle_ConsumerLimiter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		setup func(t *testing.T) renewalSetup
		// drive runs the renewal under test, and defaults to one renewal of the
		// fixture's session.
		drive   func(t *testing.T, f *renewalFixture) served
		exceed  func() (bool, error)
		assert  func(t *testing.T, f *renewalFixture, out served, keys []string)
		asked   int
		charged int
	}

	cases := []testCase{
		{
			name:    "it is asked and charged under the family's key",
			exceed:  func() (bool, error) { return false, nil },
			asked:   1,
			charged: 1,
			assert: func(t *testing.T, f *renewalFixture, out served, keys []string) {
				t.Helper()

				require.NoError(t, out.err)

				s, err := f.sessions.LoadForRenewal(t.Context(), f.old)
				require.NoError(t, err)
				assert.Equal(t, []string{"family:" + s.FamilyID.String(), "family:" + s.FamilyID.String()}, keys)
			},
		},
		{
			name:   "an outage refuses the renewal and rotates nothing",
			exceed: func() (bool, error) { return true, errors.New("store down") },
			asked:  1,
			assert: func(t *testing.T, f *renewalFixture, out served, _ []string) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrRenewalThrottled)
				assert.NotContains(t, out.err.Error(), "store down")

				s, err := f.sessions.LoadForRenewal(t.Context(), f.old)
				require.NoError(t, err)
				assert.True(t, s.SupersededAt.IsZero(), "nothing was rotated")
			},
		},
		{
			name:   "an exceeded key refuses without charging",
			exceed: func() (bool, error) { return true, nil },
			asked:  1,
			assert: func(t *testing.T, _ *renewalFixture, out served, _ []string) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrRenewalThrottled)
			},
		},
		{
			name:    "a recovery pass-through renewal is charged under the family's key",
			setup:   func(*testing.T) renewalSetup { return renewalSetup{recovery: true} },
			exceed:  func() (bool, error) { return false, nil },
			asked:   1,
			charged: 1,
			drive: func(t *testing.T, f *renewalFixture) served {
				t.Helper()

				f.supersede(t)
				f.clk.Advance(24 * time.Hour)

				return f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
			},
			assert: func(t *testing.T, f *renewalFixture, out served, keys []string) {
				t.Helper()

				require.NoError(t, out.err)

				s, err := f.sessions.LoadForRenewal(t.Context(), f.old)
				require.NoError(t, err)
				assert.Equal(t, []string{"family:" + s.FamilyID.String(), "family:" + s.FamilyID.String()}, keys)
			},
		},
		{
			name: "a late renewal the per-request policy denies is neither asked nor charged",
			setup: func(t *testing.T) renewalSetup {
				t.Helper()

				return renewalSetup{
					recovery:     true,
					interceptors: []httpsec.Option{httpsec.WithPolicyEngine(lateDenyEngine(t))},
				}
			},
			drive: func(t *testing.T, f *renewalFixture) served {
				t.Helper()

				f.supersede(t)
				f.clk.Advance(24 * time.Hour)

				return f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
			},
			assert: func(t *testing.T, _ *renewalFixture, out served, keys []string) {
				t.Helper()

				require.ErrorIs(t, out.err, policy.ErrDenied)
				assert.Empty(t, keys)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var keys []string

			limiter := NewMockLimiter(gomock.NewController(t))
			limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, key string) (bool, error) {
					keys = append(keys, key)

					return tc.exceed()
				}).Times(tc.asked)
			limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, key string) error {
					keys = append(keys, key)

					return nil
				}).Times(tc.charged)

			setup := renewalSetup{}
			if tc.setup != nil {
				setup = tc.setup(t)
			}

			setup.opts = append(setup.opts, httpsec.WithRenewalLimiter(limiter))
			f := newRenewalFixture(t, setup)

			drive := func(t *testing.T, f *renewalFixture) served {
				t.Helper()

				return f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
			}
			if tc.drive != nil {
				drive = tc.drive
			}

			out := drive(t, f)

			tc.assert(t, f, out, keys)
		})
	}
}

// TestSessionRenewalThrottle_NilLimiterIsRefused pins that a nil limiter is a
// wiring mistake caught when the chain is built.
func TestSessionRenewalThrottle_NilLimiterIsRefused(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)

	cases := map[string]ratelimit.Limiter{
		"nil":       nil,
		"typed nil": (*ratelimit.MemoryLimiter)(nil),
	}

	for name, limiter := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(
				httpsec.EnableSessionBearer(h.sessionBearerDeps()),
				httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: h.sessions, Users: h.users},
					httpsec.WithRenewalLimiter(limiter)),
			)

			require.ErrorIs(t, err, httpsec.ErrConfig)
		})
	}
}

// TestSessionRenewalThrottle_FactoryErrorNamesTheEndpoint pins that a renewal
// limiter the factory cannot build is reported against EnableSessionRenewal,
// in its own namespace with its own defaults, and names no other endpoint.
func TestSessionRenewalThrottle_FactoryErrorNamesTheEndpoint(t *testing.T) {
	t.Parallel()

	memory := ratelimit.MemoryLimiterFactory()
	factory := NewMockLimiterFactory(gomock.NewController(t))

	factory.EXPECT().NewLimiter("session-renewal", 10, 10*time.Minute).
		Return(nil, errors.New("backend down"))
	factory.EXPECT().NewLimiter(gomock.Not("session-renewal"), gomock.Any(), gomock.Any()).
		AnyTimes().DoAndReturn(memory.NewLimiter)

	h := newAuthHarness(t)

	_, err := httpsec.New(
		httpsec.WithRateLimiterFactory(factory),
		httpsec.EnableSessionBearer(h.sessionBearerDeps()),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: h.sessions, Users: h.users}),
	)

	require.ErrorIs(t, err, httpsec.ErrConfig)
	assert.Contains(t, err.Error(), "EnableSessionRenewal")
	assert.NotContains(t, err.Error(), "EnableMFAEnrolment")
}

// TestSessionRenewalThrottle_RemovedUserIsNotCharged pins that a renewal
// refused because its user is gone neither asks nor charges the limiter.
func TestSessionRenewalThrottle_RemovedUserIsNotCharged(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC))
	sessions, err := session.New(
		session.WithClock(clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))),
	)
	require.NoError(t, err)

	s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	users := NewMockUserLoader(ctrl)
	gomock.InOrder(
		users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil),
		users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, errors.New("removed")),
	)

	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Times(0)
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Times(0)

	chain, err := httpsec.New(
		httpsec.WithClock(clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: sessions, Users: users},
			httpsec.WithRenewalLimiter(limiter)),
	)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
	req.Header.Set("Authorization", "Bearer "+s.ID)

	out := serve(t, chain, req)

	require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
}
