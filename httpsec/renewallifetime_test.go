package httpsec_test

// The renewal lifetime tests run on a real manager over the memory store and a
// fake clock, because what they pin is the absolute deadline the successor is
// stored with, and the maxima the manager holds it to.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

const day = 24 * time.Hour

func TestSessionRenewal_Lifetime(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

	// thirtyDays asks for 30 days on every renewal.
	thirtyDays := func(*httpsec.Exchange, *session.Session) time.Duration { return 30 * day }

	type testCase struct {
		name string
		// manager is the lifetime options the manager is built with.
		manager []session.ManagerOption
		// created is the absolute lifetime the first session is created with;
		// zero keeps the manager's absolute timeout.
		created time.Duration
		opts    []httpsec.SessionRenewalOption
		// advances are the days the clock moves before each renewal; every one
		// but the last renewal is expected to succeed.
		advances []time.Duration
		assert   func(t *testing.T, f *lifetimeFixture, out served)
	}

	family90 := []session.ManagerOption{
		session.WithMaxAbsoluteLifetime(30 * day),
		session.WithMaxFamilyLifetime(90 * day),
	}

	cases := []testCase{
		{
			// Signed in at 09:00 with a 12 hour lifetime, renewed at 15:00: the
			// successor keeps the 21:00 deadline, not 15:00 plus twelve hours.
			name:     "no function carries the deadline over",
			advances: []time.Duration{6 * time.Hour},
			assert: func(t *testing.T, f *lifetimeFixture, out served) {
				require.NoError(t, out.err)
				require.Len(t, f.results, 1)
				assert.Equal(t, time.Date(2026, 10, 21, 15, 0, 0, 0, time.UTC), f.clk.Now(),
					"the renewal happened at 15:00")
				assert.Equal(t, time.Date(2026, 10, 21, 21, 0, 0, 0, time.UTC),
					f.results[0].Session.AbsoluteExpiresAt)
			},
		},
		{
			name:     "a lifetime inside the maxima is now plus the lifetime",
			manager:  family90,
			created:  30 * day,
			opts:     []httpsec.SessionRenewalOption{httpsec.WithRenewalLifetime(thirtyDays)},
			advances: []time.Duration{10 * day},
			assert: func(t *testing.T, f *lifetimeFixture, out served) {
				require.NoError(t, out.err)
				require.Len(t, f.results, 1)
				assert.Equal(t, start.Add(10*day).Add(30*day), f.results[0].Session.AbsoluteExpiresAt)
			},
		},
		{
			name:     "a lifetime past the family maximum is cut to the family's end",
			manager:  family90,
			created:  30 * day,
			opts:     []httpsec.SessionRenewalOption{httpsec.WithRenewalLifetime(thirtyDays)},
			advances: []time.Duration{20 * day, 20 * day, 20 * day, 20 * day},
			assert: func(t *testing.T, f *lifetimeFixture, out served) {
				require.NoError(t, out.err)
				require.Len(t, f.results, 4)
				assert.Equal(t, start.Add(90*day), f.results[3].Session.AbsoluteExpiresAt)
			},
		},
		{
			name:    "a lifetime above the lifetime maximum is a configuration error and stores nothing",
			manager: []session.ManagerOption{session.WithMaxAbsoluteLifetime(30 * day)},
			opts: []httpsec.SessionRenewalOption{httpsec.WithRenewalLifetime(
				func(*httpsec.Exchange, *session.Session) time.Duration { return 45 * day })},
			advances: []time.Duration{time.Hour},
			assert: func(t *testing.T, f *lifetimeFixture, out served) {
				require.ErrorIs(t, out.err, session.ErrConfig)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.Empty(t, f.results)

				old, err := f.sessions.LoadForRenewal(t.Context(), f.first)
				require.NoError(t, err)
				assert.True(t, old.SupersededAt.IsZero(), "nothing was rotated")
			},
		},
		{
			name: "a function returning a negative lifetime carries the deadline over",
			opts: []httpsec.SessionRenewalOption{httpsec.WithRenewalLifetime(
				func(*httpsec.Exchange, *session.Session) time.Duration { return -time.Hour })},
			advances: []time.Duration{time.Hour},
			assert: func(t *testing.T, f *lifetimeFixture, out served) {
				require.NoError(t, out.err)
				require.Len(t, f.results, 1)
				assert.Equal(t, start.Add(12*time.Hour), f.results[0].Session.AbsoluteExpiresAt)
			},
		},
		{
			name: "a function returning zero carries the deadline over",
			opts: []httpsec.SessionRenewalOption{httpsec.WithRenewalLifetime(
				func(*httpsec.Exchange, *session.Session) time.Duration { return 0 })},
			advances: []time.Duration{time.Hour},
			assert: func(t *testing.T, f *lifetimeFixture, out served) {
				require.NoError(t, out.err)
				require.Len(t, f.results, 1)
				assert.Equal(t, start.Add(12*time.Hour), f.results[0].Session.AbsoluteExpiresAt)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newLifetimeFixture(t, start, tc.manager, tc.created, tc.opts)

			var out served

			for _, d := range tc.advances {
				f.clk.Advance(d)
				out = f.renew(t)
			}

			tc.assert(t, f, out)
		})
	}
}

func TestSessionRenewal_LifetimeFunctionSeesTheRenewedSession(t *testing.T) {
	t.Parallel()

	var (
		gotEx *httpsec.Exchange
		gotID string
	)

	f := newLifetimeFixture(t, time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC), nil, 0,
		[]httpsec.SessionRenewalOption{httpsec.WithRenewalLifetime(
			func(ex *httpsec.Exchange, s *session.Session) time.Duration {
				gotEx, gotID = ex, s.ID

				return time.Hour
			})})

	f.clk.Advance(time.Minute)
	out := f.renew(t)

	require.NoError(t, out.err)
	assert.NotNil(t, gotEx)
	assert.Equal(t, f.first, gotID)
}

func TestWithRenewalLifetime_NilFunctionIsRefused(t *testing.T) {
	t.Parallel()

	sessions, err := session.NewManager()
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))

	chain, err := httpsec.New(
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: users},
			httpsec.WithRenewalLifetime(nil)),
	)

	require.ErrorIs(t, err, httpsec.ErrConfig)
	assert.Contains(t, err.Error(), "WithRenewalLifetime")
	assert.Nil(t, chain)
}

// lifetimeFixture is a session-reference chain with the renewal endpoint over
// a manager on a fake clock, and the first session in it.
type lifetimeFixture struct {
	clk      *clockwork.FakeClock
	sessions *session.Manager
	chain    *httpsec.Chain

	// first is the identifier of the first session, and current of the latest.
	first, current string

	results []httpsec.RenewalResult
}

func newLifetimeFixture(
	t *testing.T,
	start time.Time,
	managerOpts []session.ManagerOption,
	created time.Duration,
	opts []httpsec.SessionRenewalOption,
) *lifetimeFixture {
	t.Helper()

	f := &lifetimeFixture{clk: clockwork.NewFakeClockAt(start)}

	var err error

	f.sessions, err = session.NewManager(append([]session.ManagerOption{
		session.WithClock(f.clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(f.clk))),
		session.WithIdleTimeout(100 * day),
		session.WithAbsoluteTimeout(12 * time.Hour),
	}, managerOpts...)...)
	require.NoError(t, err)

	var createOpts []session.CreateOption
	if created > 0 {
		createOpts = append(createOpts, session.WithAbsoluteLifetime(created))
	}

	s, err := f.sessions.Create(t.Context(), "u-1",
		append(createOpts, session.WithFirstFactor(factor.Password))...)
	require.NoError(t, err)

	f.first, f.current = s.ID, s.ID

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

	record := httpsec.WithRenewalResponder(func(ex *httpsec.Exchange, r httpsec.RenewalResult) error {
		f.results = append(f.results, r)
		f.current = r.Credential

		ex.Writer.WriteHeader(http.StatusOK)

		return nil
	})

	f.chain, err = httpsec.New(
		httpsec.WithClock(f.clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: f.sessions, Users: users}),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: users}, append(opts, record)...),
	)
	require.NoError(t, err)

	return f
}

// renew posts the latest credential to the renewal endpoint.
func (f *lifetimeFixture) renew(t *testing.T) served {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
	req.Header.Set("Authorization", "Bearer "+f.current)

	return serve(t, f.chain, req)
}
