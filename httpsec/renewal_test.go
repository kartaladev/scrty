package httpsec_test

// The renewal tests run on a real session manager over the memory store and a
// fake clock, because what they pin is the rotation the store records and the
// windows the clock opens and closes. The signed-token case, the concurrent
// pair and the enrolment gate each need a different setup shape (a verifier
// and generator, a barrier store, the enrolment harness), so they are tests of
// their own beside the main table.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// lockedBuffer is a log sink several requests may write to at once.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// renewalSetup is what a renewal case varies about its fixture.
type renewalSetup struct {
	// recovery turns the manager's unused-successor recovery on.
	recovery bool

	// defaultSessions leaves SessionRenewalDeps.Sessions nil, so the endpoint
	// takes the bearer's manager.
	defaultSessions bool

	// withoutRenewal leaves the renewal endpoint off the chain.
	withoutRenewal bool

	// record installs a responder that records every result and writes the
	// credential as the body, with 201.
	record bool

	opts []httpsec.SessionRenewalOption

	// interceptors are consumer interceptors registered on the chain.
	interceptors []httpsec.Option

	// users replaces the default user loader, which answers u-1 active.
	users identity.UserLoader
}

// renewalFixture is a session-reference chain with the renewal endpoint, over
// a manager on the memory store and a fake clock, and a session O created in
// it.
type renewalFixture struct {
	clk      *clockwork.FakeClock
	logs     *lockedBuffer
	sessions *session.Sessions
	chain    *httpsec.Chain

	// old is O's identifier, which is its credential in this mode.
	old string

	mu      sync.Mutex
	results []httpsec.RenewalResult
}

func newRenewalFixture(t *testing.T, setup renewalSetup) *renewalFixture {
	t.Helper()

	f := &renewalFixture{
		clk:  clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)),
		logs: &lockedBuffer{},
	}
	logger := slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Long idle and absolute timeouts, so a session renewed the next day is
	// still stored and only its renewal window has ended.
	managerOpts := []session.Option{
		session.WithClock(f.clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(f.clk))),
		session.WithLogger(logger),
		session.WithIdleTimeout(7 * 24 * time.Hour),
		session.WithAbsoluteTimeout(30 * 24 * time.Hour),
	}
	if setup.recovery {
		managerOpts = append(managerOpts, session.WithUnusedSuccessorRecovery())
	}

	var err error

	f.sessions, err = session.New(managerOpts...)
	require.NoError(t, err)

	s, err := f.sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	f.old = s.ID

	users := setup.users
	if users == nil {
		defaults := NewMockUserLoader(gomock.NewController(t))
		defaults.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()
		users = defaults
	}

	opts := setup.opts
	if setup.record {
		opts = append(opts, httpsec.WithRenewalResponder(f.recordingResponder))
	}

	chainOpts := []httpsec.Option{
		httpsec.WithClock(f.clk),
		httpsec.WithLogger(logger),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: f.sessions, Users: users}),
	}
	if !setup.withoutRenewal {
		deps := httpsec.SessionRenewalDeps{Sessions: f.sessions, Users: users}
		if setup.defaultSessions {
			deps.Sessions = nil
		}

		chainOpts = append(chainOpts, httpsec.EnableSessionRenewal(deps, opts...))
	}

	chainOpts = append(chainOpts, setup.interceptors...)

	f.chain, err = httpsec.New(chainOpts...)
	require.NoError(t, err)

	return f
}

// supersede renews O directly through the manager, as a renewal whose
// response was lost would have, and returns the successor's identifier.
func (f *renewalFixture) supersede(t *testing.T) string {
	t.Helper()

	s, err := f.sessions.LoadForRenewal(t.Context(), f.old)
	require.NoError(t, err)

	next, _, err := f.sessions.RotateWithGrace(t.Context(), s, 30*time.Second)
	require.NoError(t, err)

	return next.ID
}

// unpresented asserts that O is still superseded by successor, which was never
// presented: nothing recovered or revoked the family.
func (f *renewalFixture) unpresented(t *testing.T, successor string) {
	t.Helper()

	old, err := f.sessions.LoadForRenewal(t.Context(), f.old)
	require.NoError(t, err)
	assert.False(t, old.SupersededAt.IsZero())

	_, err = f.sessions.Load(t.Context(), successor)
	require.NoError(t, err, "the successor is still stored")
}

// lateDenyEngine denies every request at the per-request phase.
func lateDenyEngine(t *testing.T) *policy.Engine {
	t.Helper()

	return engineOf(t, denyPolicy{phase: policy.PerRequest})
}

// recordingResponder records r and writes its credential as a plain body.
func (f *renewalFixture) recordingResponder(ex *httpsec.Exchange, r httpsec.RenewalResult) error {
	f.mu.Lock()
	f.results = append(f.results, r)
	f.mu.Unlock()

	ex.Writer.WriteHeader(http.StatusCreated)
	_, err := ex.Writer.Write([]byte(r.Credential))

	return err
}

func (f *renewalFixture) recorded() []httpsec.RenewalResult {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]httpsec.RenewalResult(nil), f.results...)
}

// request runs method path through the chain, bearing credential when it is
// not empty.
func (f *renewalFixture) request(t *testing.T, method, path, credential string) served {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}

	return serve(t, f.chain, req)
}

// renew posts credential to path and returns the credential the default
// responder answered with.
func (f *renewalFixture) renew(t *testing.T, path, credential string) string {
	t.Helper()

	out := f.request(t, http.MethodPost, path, credential)
	require.NoError(t, out.err)
	require.Equal(t, http.StatusOK, out.rec.Code)

	var body loginBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.AccessToken)

	return body.AccessToken
}

// use is an ordinary request bearing credential.
func (f *renewalFixture) use(t *testing.T, credential string) served {
	t.Helper()

	return f.request(t, http.MethodGet, "/api/resource", credential)
}

func authenticatedRequest(t *testing.T, s served) {
	t.Helper()

	require.NoError(t, s.err)
	require.True(t, s.handlerRan)

	_, ok := authenticate.AuthenticationFromContext(s.handled.Context())
	assert.True(t, ok, "the request is authenticated")
}

func reusedCredential(t *testing.T, s served) {
	t.Helper()

	require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
	require.ErrorIs(t, s.err, session.ErrReused)
	assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
	assert.False(t, s.handlerRan)
}

func refusedUnauthenticated(t *testing.T, s served) {
	t.Helper()

	require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
	assert.NotErrorIs(t, s.err, session.ErrReused)
	assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
	assert.False(t, s.handlerRan)
}

// TestSessionRenewal pins the renewal endpoint in the session-reference mode:
// what it answers, which requests it claims, the windows it opens, the kinds
// it reports, and the late renewals it recovers or refuses.
func TestSessionRenewal(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  renewalSetup
		assert func(t *testing.T, f *renewalFixture)
	}

	cases := []testCase{
		{
			name: "default: POST answers 200 with a successor credential in the login shape, not cached",
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				out := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
				require.NoError(t, out.err)
				require.Equal(t, http.StatusOK, out.rec.Code)
				assert.False(t, out.handlerRan, "the endpoint answers, not the application")
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
				assert.Equal(t, "application/json", out.rec.Header().Get("Content-Type"))

				var body loginBody
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))
				require.NotEmpty(t, body.AccessToken)
				assert.NotEqual(t, f.old, body.AccessToken, "the credential names a successor")
				assert.True(t, session.ValidIdentifier(body.AccessToken), "the credential is a session reference")
				assert.False(t, body.ValidUntil.IsZero(), "the document carries the successor's validity")

				authenticatedRequest(t, f.use(t, body.AccessToken))
			},
		},
		{
			name: "default: the old credential authenticates for 30 seconds, and is reuse after",
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				f.renew(t, httpsec.DefaultSessionRenewalPath, f.old)

				f.clk.Advance(29 * time.Second)
				authenticatedRequest(t, f.use(t, f.old))

				f.clk.Advance(2 * time.Second)
				reusedCredential(t, f.use(t, f.old))
			},
		},
		{
			name: "a POST with no authentication result is refused",
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, ""))
			},
		},
		{
			name: "a GET on the renewal path passes through, renewing nothing",
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				authenticatedRequest(t, f.request(t, http.MethodGet, httpsec.DefaultSessionRenewalPath, f.old))

				stored, err := f.sessions.Load(t.Context(), f.old)
				require.NoError(t, err)
				assert.True(t, stored.SupersededAt.IsZero(), "nothing was rotated")
			},
		},
		{
			name: "a POST on another path passes through",
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				authenticatedRequest(t, f.request(t, http.MethodPost, "/api/orders", f.old))
			},
		},
		{
			name: "consumer path, 60-second grace and responder: the responder gets the successor, the user and fresh",
			setup: renewalSetup{
				record: true,
				opts: []httpsec.SessionRenewalOption{
					httpsec.WithRenewalPath("/api/v1/session/renewal"),
					httpsec.WithRenewalGrace(60 * time.Second),
				},
			},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				// The default path is no longer the endpoint's.
				authenticatedRequest(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))

				out := f.request(t, http.MethodPost, "/api/v1/session/renewal", f.old)
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusCreated, out.rec.Code, "the consumer's responder answered")

				results := f.recorded()
				require.Len(t, results, 1)
				r := results[0]
				assert.Equal(t, session.RenewalFresh, r.Kind)
				require.NotNil(t, r.Session)
				assert.NotEqual(t, f.old, r.Session.ID)
				assert.Equal(t, r.Session.ID, r.Credential, "in this mode the credential is the reference")
				require.NotNil(t, r.User)
				assert.Equal(t, identity.UserID("u-1"), r.User.ID)
				assert.Equal(t, r.Credential, out.rec.Body.String())

				f.clk.Advance(59 * time.Second)
				authenticatedRequest(t, f.use(t, f.old))

				f.clk.Advance(2 * time.Second)
				reusedCredential(t, f.use(t, f.old))
			},
		},
		{
			name:  "re-rotation: the old credential renewed again inside its window is a re-rotation",
			setup: renewalSetup{record: true},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				first := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
				require.NoError(t, first.err)

				f.clk.Advance(10 * time.Second)

				second := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
				require.NoError(t, second.err)

				results := f.recorded()
				require.Len(t, results, 2)
				assert.Equal(t, session.RenewalFresh, results[0].Kind)
				assert.Equal(t, session.RenewalReRotation, results[1].Kind)
				assert.NotEqual(t, results[0].Credential, results[1].Credential)

				// The first successor was knocked out by the re-rotation, so
				// whoever presents it reveals two parties hold the family.
				reusedCredential(t, f.use(t, results[0].Credential))
			},
		},
		{
			name:  "recovery on: a next-day renewal of an unused successor recovers, and that successor is then reuse",
			setup: renewalSetup{recovery: true, record: true},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				first := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
				require.NoError(t, first.err)

				f.clk.Advance(24 * time.Hour)

				out := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusCreated, out.rec.Code)
				assert.False(t, out.handlerRan)

				results := f.recorded()
				require.Len(t, results, 2)
				assert.Equal(t, session.RenewalRecovery, results[1].Kind)
				assert.Equal(t, identity.UserID("u-1"), results[1].User.ID)

				authenticatedRequest(t, f.use(t, results[1].Credential))
				reusedCredential(t, f.use(t, results[0].Credential))
			},
		},
		{
			name:  "recovery on: a next-day ordinary request is refused 401 and revokes nothing",
			setup: renewalSetup{recovery: true, record: true},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				first := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
				require.NoError(t, first.err)
				successor := f.recorded()[0].Credential

				f.clk.Advance(24 * time.Hour)

				refusedUnauthenticated(t, f.use(t, f.old))

				// So is a late request that is not the renewal endpoint's:
				// another method on its path, and its method on another path.
				refusedUnauthenticated(t, f.request(t, http.MethodGet, httpsec.DefaultSessionRenewalPath, f.old))
				refusedUnauthenticated(t, f.request(t, http.MethodPost, "/api/orders", f.old))

				authenticatedRequest(t, f.use(t, successor))
			},
		},
		{
			name:  "recovery on: a next-day renewal after the successor was used is reuse, and the family is revoked",
			setup: renewalSetup{recovery: true, record: true},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				first := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
				require.NoError(t, first.err)
				successor := f.recorded()[0].Credential

				authenticatedRequest(t, f.use(t, successor))

				f.clk.Advance(24 * time.Hour)

				reusedCredential(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))
				assert.Len(t, f.recorded(), 1, "nothing was renewed")

				refusedUnauthenticated(t, f.use(t, successor))
			},
		},
		{
			name:  "recovery on: a late renewal of a session owing a second factor is refused, and nothing is rotated",
			setup: renewalSetup{recovery: true, record: true},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				// No gate on this chain would refuse it; the late path must.
				s, err := f.sessions.Load(t.Context(), f.old)
				require.NoError(t, err)
				s.MFA = session.MFAPending
				require.NoError(t, f.sessions.Save(t.Context(), s))

				successor := f.supersede(t)

				f.clk.Advance(24 * time.Hour)

				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))
				assert.Empty(t, f.recorded(), "nothing was renewed")
				f.unpresented(t, successor)
			},
		},
		{
			name: "recovery on: a late renewal the per-request phase denies is refused with its reason",
			setup: renewalSetup{
				recovery:     true,
				record:       true,
				interceptors: []httpsec.Option{httpsec.WithPolicyEngine(lateDenyEngine(t))},
			},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				successor := f.supersede(t)

				f.clk.Advance(24 * time.Hour)

				out := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
				require.ErrorIs(t, out.err, policy.ErrDenied)
				assert.Empty(t, f.recorded(), "nothing was renewed")
				f.unpresented(t, successor)
			},
		},
		{
			name:  "recovery on: a late renewal of a session owing a password change is refused, and nothing is rotated",
			setup: renewalSetup{recovery: true, record: true},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				s, err := f.sessions.Load(t.Context(), f.old)
				require.NoError(t, err)
				s.PasswordChangePending = true
				require.NoError(t, f.sessions.Save(t.Context(), s))

				successor := f.supersede(t)

				f.clk.Advance(24 * time.Hour)

				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))
				assert.Empty(t, f.recorded(), "nothing was renewed")
				f.unpresented(t, successor)
			},
		},
		{
			name:  "recovery on: a late renewal of an enrolment-pending session is refused, and nothing is rotated",
			setup: renewalSetup{recovery: true, record: true},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				s, err := f.sessions.Load(t.Context(), f.old)
				require.NoError(t, err)
				s.MFA = session.MFAEnrolmentPending
				require.NoError(t, f.sessions.Save(t.Context(), s))

				successor := f.supersede(t)

				f.clk.Advance(24 * time.Hour)

				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))
				assert.Empty(t, f.recorded(), "nothing was renewed")
				f.unpresented(t, successor)
			},
		},
		{
			name:  "recovery on: a late renewal of a recovery-pending session is refused, and nothing is rotated",
			setup: renewalSetup{recovery: true, record: true},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				s, err := f.sessions.Load(t.Context(), f.old)
				require.NoError(t, err)
				s.MFA = session.MFARecoveryPending
				require.NoError(t, f.sessions.Save(t.Context(), s))

				successor := f.supersede(t)

				f.clk.Advance(24 * time.Hour)

				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))
				assert.Empty(t, f.recorded(), "nothing was renewed")
				f.unpresented(t, successor)
			},
		},
		{
			name: "recovery on: a late renewal the per-request phase challenges is refused, and nothing is rotated",
			setup: renewalSetup{
				recovery: true,
				record:   true,
				interceptors: []httpsec.Option{httpsec.WithPolicyEngine(
					challengingIn(t, policy.PerRequest, policy.ChallengeMFA))},
			},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				successor := f.supersede(t)

				f.clk.Advance(24 * time.Hour)

				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))
				assert.Empty(t, f.recorded(), "nothing was renewed")
				f.unpresented(t, successor)
			},
		},
		{
			name:  "no manager given: the renewal rotates through the bearer's own",
			setup: renewalSetup{record: true, defaultSessions: true},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				out := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
				require.NoError(t, out.err)

				results := f.recorded()
				require.Len(t, results, 1)
				assert.Equal(t, session.RenewalFresh, results[0].Kind)
				authenticatedRequest(t, f.use(t, results[0].Credential))
			},
		},
		{
			name:  "recovery off: a next-day renewal is reuse",
			setup: renewalSetup{record: true},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				first := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
				require.NoError(t, first.err)
				successor := f.recorded()[0].Credential

				f.clk.Advance(24 * time.Hour)

				reusedCredential(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))
				refusedUnauthenticated(t, f.use(t, successor))
			},
		},
		{
			name:  "recovery on, renewal off: a next-day POST to the default path is refused, not passed through",
			setup: renewalSetup{recovery: true, withoutRenewal: true},
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				// Renew directly through the manager, as a consumer endpoint
				// would, so O is superseded with an unused successor.
				s, err := f.sessions.LoadForRenewal(t.Context(), f.old)
				require.NoError(t, err)
				_, _, err = f.sessions.RotateWithGrace(t.Context(), s, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(24 * time.Hour)

				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))
			},
		},
		{
			name: "no log record holds either credential",
			assert: func(t *testing.T, f *renewalFixture) {
				t.Helper()

				successor := f.renew(t, httpsec.DefaultSessionRenewalPath, f.old)
				authenticatedRequest(t, f.use(t, successor))

				f.clk.Advance(31 * time.Second)
				reusedCredential(t, f.use(t, f.old))
				// The family is gone now, so the renewal finds nothing.
				refusedUnauthenticated(t, f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old))

				logs := f.logs.String()
				require.NotEmpty(t, logs, "the reuse was logged, so the capture works")
				assert.NotContains(t, logs, f.old)
				assert.NotContains(t, logs, successor)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newRenewalFixture(t, tc.setup))
		})
	}
}

// TestSessionRenewal_RecoveryPassThroughIsConfined pins that a late credential
// let through to the renewal endpoint authenticates nothing on its way there:
// a consumer interceptor between the bearer and the endpoint sees no caller
// and no session, and the application handler is never reached.
func TestSessionRenewal_RecoveryPassThroughIsConfined(t *testing.T) {
	t.Parallel()

	var (
		mu   sync.Mutex
		seen []string
	)

	witness := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		_, authenticated := authenticate.AuthenticationFromContext(ex.Context())
		_, carried := httpsec.SessionFromContext(ex.Context())

		mu.Lock()
		if authenticated || carried || ex.Authentication != nil || ex.Session != nil {
			seen = append(seen, ex.Request.Method()+" "+ex.Request.Path())
		}
		mu.Unlock()

		return next(ex)
	})

	f := newRenewalFixture(t, renewalSetup{
		recovery:     true,
		record:       true,
		interceptors: []httpsec.Option{httpsec.RegisterInterceptor(witness, httpsec.After(httpsec.OrderBearerToken))},
	})

	first := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
	require.NoError(t, first.err)

	mu.Lock()
	seen = nil
	mu.Unlock()

	f.clk.Advance(24 * time.Hour)

	out := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
	require.NoError(t, out.err)
	assert.False(t, out.handlerRan, "the application is never reached")

	results := f.recorded()
	require.Len(t, results, 2)
	assert.Equal(t, session.RenewalRecovery, results[1].Kind)

	mu.Lock()
	defer mu.Unlock()
	assert.Empty(t, seen, "nothing between the bearer and the endpoint saw a caller or a session")
}

// TestSessionRenewal_SignedTokenMode pins that, with signed bearer tokens, the
// endpoint mints the successor's credential with its own token generator,
// naming the successor.
func TestSessionRenewal_SignedTokenMode(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC))

	sessions, err := session.New(session.WithClock(clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
	require.NoError(t, err)

	s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	verifier := NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(gomock.Any(), "signed-old").Return(token.NewClaims(testSubject, s.ID), nil)

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil)

	var successor string

	tokens := NewMockGenerator(ctrl)
	tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, id string, p *identity.Principal) (string, error) {
			assert.NotEqual(t, s.ID, id, "the token names the successor")
			assert.Equal(t, identity.UserID("u-1"), p.ID)
			successor = id

			return "signed-new", nil
		})

	chain, err := httpsec.New(
		httpsec.WithClock(clk),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: verifier, Sessions: sessions, Users: users}),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: sessions, Users: users, Tokens: tokens}),
	)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
	req.Header.Set("Authorization", "Bearer signed-old")

	out := serve(t, chain, req)
	require.NoError(t, out.err)
	require.Equal(t, http.StatusOK, out.rec.Code)

	var body loginBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))
	assert.Equal(t, "signed-new", body.AccessToken)

	stored, err := sessions.Load(t.Context(), successor)
	require.NoError(t, err)
	assert.Equal(t, identity.UserID("u-1"), stored.UserID)
}

// barrierStore holds the first two supersessions until both have arrived, so
// two renewals that both loaded the same session race on the store's
// conditional write.
type barrierStore struct {
	session.Store

	arrived sync.WaitGroup
}

func newBarrierStore(inner session.Store) *barrierStore {
	b := &barrierStore{Store: inner}
	b.arrived.Add(2)

	return b
}

func (b *barrierStore) Supersede(ctx context.Context, op session.Supersession) error {
	b.arrived.Done()

	both := make(chan struct{})
	go func() {
		b.arrived.Wait()
		close(both)
	}()

	select {
	case <-both:
	case <-time.After(5 * time.Second):
		return errors.New("barrier: the other renewal never reached the store")
	}

	return b.Store.Supersede(ctx, op)
}

// TestSessionRenewal_ConcurrentPair pins that two renewals of one session at
// the same time produce one successor: one is answered 200 and the other is
// refused with the renewal-conflict error, a 409.
func TestSessionRenewal_ConcurrentPair(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC))
	store := newBarrierStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))

	sessions, err := session.New(session.WithClock(clk), session.WithStore(store))
	require.NoError(t, err)

	s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

	chain, err := httpsec.New(
		httpsec.WithClock(clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: sessions, Users: users}),
	)
	require.NoError(t, err)

	outs := make([]served, 2)

	var wg sync.WaitGroup
	for i := range outs {
		wg.Go(func() {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
			req.Header.Set("Authorization", "Bearer "+s.ID)
			outs[i] = serve(t, chain, req)
		})
	}
	wg.Wait()

	var won, lost int

	for _, out := range outs {
		switch {
		case out.err == nil && out.rec.Code == http.StatusOK:
			won++
		case errors.Is(out.err, httpsec.ErrSessionRenewalConflict):
			assert.Equal(t, http.StatusConflict, httpsec.StatusForError(out.err))
			lost++
		default:
			t.Errorf("unexpected outcome: err=%v code=%d", out.err, out.rec.Code)
		}
	}

	assert.Equal(t, 1, won, "one renewal succeeds")
	assert.Equal(t, 1, lost, "the other is refused with the renewal conflict")
}

// TestSessionRenewal_EnrolmentGateConfines pins that a session confined to
// second-factor enrolment cannot escape the confinement by renewing: the
// enrolment gate refuses its renewal before the endpoint runs, and nothing is
// rotated or issued.
func TestSessionRenewal_EnrolmentGateConfines(t *testing.T) {
	t.Parallel()

	h := newEnrolHarness(t)
	h.extra = append(h.extra, httpsec.EnableSessionRenewal(
		httpsec.SessionRenewalDeps{Sessions: h.sessions, Users: h.users, Tokens: h.tokens}))

	s := h.enrolmentOnly(t, factor.Password)
	chain := h.chain(t, s)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
	out := serve(t, chain, req)

	var challenge *httpsec.ChallengeError
	require.ErrorAs(t, out.err, &challenge)
	assert.Equal(t, policy.ChallengeMFAEnrolment, challenge.Kind)
	assert.False(t, out.handlerRan)

	stored, err := h.sessions.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.True(t, stored.SupersededAt.IsZero(), "the confined session was not rotated")
}

// TestEnableSessionRenewal_Construction pins the wiring mistakes the renewal
// endpoint refuses when the chain is built, and the configurations it takes.
func TestEnableSessionRenewal_Construction(t *testing.T) {
	t.Parallel()

	// otherManager is a session manager that is not the harness's.
	otherManager := func(t *testing.T, _ *authHarness) *session.Sessions {
		t.Helper()

		m, err := session.New(session.WithStore(session.NewMemoryStore()))
		require.NoError(t, err)

		return m
	}

	type testCase struct {
		name    string
		options func(h *authHarness) []httpsec.Option
		assert  func(t *testing.T, err error)
	}

	configError := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, httpsec.ErrConfig)
	}

	built := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}

	reference := func(h *authHarness, d httpsec.SessionRenewalDeps, opts ...httpsec.SessionRenewalOption) []httpsec.Option {
		return []httpsec.Option{
			httpsec.EnableSessionBearer(h.sessionBearerDeps()),
			httpsec.EnableSessionRenewal(d, opts...),
		}
	}

	deps := func(h *authHarness) httpsec.SessionRenewalDeps {
		return httpsec.SessionRenewalDeps{Sessions: h.sessions, Users: h.users}
	}

	cases := []testCase{
		{
			name:    "the default configuration builds",
			options: func(h *authHarness) []httpsec.Option { return reference(h, deps(h)) },
			assert:  built,
		},
		{
			name: "a grace at the ceiling builds",
			options: func(h *authHarness) []httpsec.Option {
				return reference(h, deps(h), httpsec.WithRenewalGrace(session.MaxRenewalGrace))
			},
			assert: built,
		},
		{
			name: "a zero grace builds",
			options: func(h *authHarness) []httpsec.Option {
				return reference(h, deps(h), httpsec.WithRenewalGrace(0))
			},
			assert: built,
		},
		{
			name: "a grace above the ceiling is refused",
			options: func(h *authHarness) []httpsec.Option {
				return reference(h, deps(h), httpsec.WithRenewalGrace(10*time.Minute))
			},
			assert: configError,
		},
		{
			name: "a negative grace is refused",
			options: func(h *authHarness) []httpsec.Option {
				return reference(h, deps(h), httpsec.WithRenewalGrace(-time.Second))
			},
			assert: configError,
		},
		{
			name: "signed-token mode without a generator is refused",
			options: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
					httpsec.EnableSessionRenewal(deps(h)),
				}
			},
			assert: configError,
		},
		{
			name: "signed-token mode with a generator builds",
			options: func(h *authHarness) []httpsec.Option {
				d := deps(h)
				d.Tokens = h.tokens

				return []httpsec.Option{
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
					httpsec.EnableSessionRenewal(d),
				}
			},
			assert: built,
		},
		{
			name: "the session-reference mode with a generator is refused, whatever the option order",
			options: func(h *authHarness) []httpsec.Option {
				d := deps(h)
				d.Tokens = h.tokens

				return []httpsec.Option{
					httpsec.EnableSessionRenewal(d),
					httpsec.EnableSessionBearer(h.sessionBearerDeps()),
				}
			},
			assert: configError,
		},
		{
			name: "no session manager and no bearer to default to is refused",
			options: func(h *authHarness) []httpsec.Option {
				d := deps(h)
				d.Sessions = nil

				return []httpsec.Option{httpsec.EnableSessionRenewal(d)}
			},
			assert: configError,
		},
		{
			name: "no session manager defaults to the session bearer's",
			options: func(h *authHarness) []httpsec.Option {
				d := deps(h)
				d.Sessions = nil

				return reference(h, d)
			},
			assert: built,
		},
		{
			name: "no session manager defaults to the signed-token bearer's, whatever the option order",
			options: func(h *authHarness) []httpsec.Option {
				d := deps(h)
				d.Sessions = nil
				d.Tokens = h.tokens

				return []httpsec.Option{
					httpsec.EnableSessionRenewal(d),
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
				}
			},
			assert: built,
		},
		{
			name: "the bearer's own session manager given explicitly builds",
			options: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableSessionRenewal(deps(h)),
					httpsec.EnableSessionBearer(h.sessionBearerDeps()),
				}
			},
			assert: built,
		},
		{
			name: "a session manager other than the session bearer's is refused",
			options: func(h *authHarness) []httpsec.Option {
				d := deps(h)
				d.Sessions = otherManager(t, h)

				return reference(h, d)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "SessionRenewalDeps.Sessions")
			},
		},
		{
			name: "a session manager other than the signed-token bearer's is refused, whatever the option order",
			options: func(h *authHarness) []httpsec.Option {
				d := deps(h)
				d.Sessions = otherManager(t, h)
				d.Tokens = h.tokens

				return []httpsec.Option{
					httpsec.EnableSessionRenewal(d),
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
				}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "SessionRenewalDeps.Sessions")
			},
		},
		{
			name: "no user loader is refused",
			options: func(h *authHarness) []httpsec.Option {
				d := deps(h)
				d.Users = nil

				return reference(h, d)
			},
			assert: configError,
		},
		{
			name: "an empty path is refused",
			options: func(h *authHarness) []httpsec.Option {
				return reference(h, deps(h), httpsec.WithRenewalPath(""))
			},
			assert: configError,
		},
		{
			name: "a nil responder is refused",
			options: func(h *authHarness) []httpsec.Option {
				return reference(h, deps(h), httpsec.WithRenewalResponder(nil))
			},
			assert: configError,
		},
		{
			name: "the endpoint given twice is refused",
			options: func(h *authHarness) []httpsec.Option {
				return append(reference(h, deps(h)), httpsec.EnableSessionRenewal(deps(h)))
			},
			assert: configError,
		},
		{
			name: "a renewal path that is the logout path is refused",
			options: func(h *authHarness) []httpsec.Option {
				return append(reference(h, deps(h), httpsec.WithRenewalPath(httpsec.DefaultLogoutPath)),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}))
			},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			_, err := httpsec.New(tc.options(h)...)
			tc.assert(t, err)
		})
	}
}

// TestSessionRenewal_UserReloadPrecedesRotation pins the order of work: the
// bearer's user lookup succeeds, the endpoint's reload fails (the user was
// removed between), and the renewal is refused without the session being
// superseded.
func TestSessionRenewal_UserReloadPrecedesRotation(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC))
	sessions, err := session.New(
		session.WithClock(clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))),
	)
	require.NoError(t, err)

	s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))
	gomock.InOrder(
		users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil),
		users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, errors.New("removed")),
	)

	chain, err := httpsec.New(
		httpsec.WithClock(clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: sessions, Users: users}),
	)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
	req.Header.Set("Authorization", "Bearer "+s.ID)

	out := serve(t, chain, req)
	refusedUnauthenticated(t, out)

	stored, err := sessions.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.True(t, stored.SupersededAt.IsZero(), "a removed user's session was not rotated")
}
