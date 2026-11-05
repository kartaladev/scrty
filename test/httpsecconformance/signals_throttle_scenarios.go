package httpsecconformance

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// signalsThrottleScenarios are the rows that pin what a throttled sign-in and a failing family read
// do to the stream on a real server, identically on every adapter that can stream.
func signalsThrottleScenarios() []Scenario {
	return []Scenario{
		{Name: "signals: a throttled sign-in is answered 200 with only a retry, and the stream opens once it is not", Stream: signalsThrottledRetry},
		{Name: "signals: a throttle RetryableError refuses keeps the chain's 401 and no stream type", Stream: signalsThrottleNotRetryable},
		{Name: "signals: a throttled request from another site is refused with 403, as an unthrottled one is", Stream: signalsThrottledCrossSiteRefused},
		{Name: "signals: a throttled bearer stream from a wildcard's origin is answered with a retry", Stream: signalsThrottledBearerFromWildcard},
		{Name: "signals: a failing family read is answered with a retry at admission, and leaves an open stream open", Stream: signalsFamilyReadFailing},
	}
}

// throttlingPolicy denies the per-request phase with a throttle while on is set, or always when on is nil.
type throttlingPolicy struct {
	on *atomic.Bool
}

func (throttlingPolicy) Name() string           { return "signals-throttle" }
func (throttlingPolicy) Phases() []policy.Phase { return []policy.Phase{policy.PerRequest} }

func (p throttlingPolicy) Evaluate(context.Context, *policy.Input) policy.Decision {
	if p.on != nil && !p.on.Load() {
		return policy.Decision{Outcome: policy.Allow}
	}

	return policy.Decision{Outcome: policy.Deny, Reason: ratelimit.ErrThrottled}
}

// throttling is the option that puts p on the chain.
func throttling(t *testing.T, p throttlingPolicy) httpsec.Option {
	t.Helper()

	e, err := policy.NewEngine(p)
	require.NoError(t, err)

	return httpsec.WithPolicyEngine(e)
}

// signalsThrottledRetry is R1 on a real server: the policy's throttle is a 200 with the stream's type
// and one retry, counted as a throttle and no reload failure, and once the throttle is off the stream opens.
func signalsThrottledRetry(t *testing.T, listen func(ChainSpec) StreamServer) {
	const busy = 10 * time.Second

	var (
		on    atomic.Bool
		chain *httpsec.Chain
	)

	on.Store(true)

	spec := newSignalsSpec(t, httpsec.SessionSignals{BusyDelay: busy}, throttling(t, throttlingPolicy{on: &on}))
	spec.Built = func(c *httpsec.Chain) { chain = c }
	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	c := openSignals(t, srv.URL, s, "")
	assert.Equal(t, []string{"text/event-stream"}, c.resp.Header["Content-Type"])
	assert.Equal(t, "no-store, no-transform", c.resp.Header.Get("Cache-Control"))
	assert.Equal(t, "no", c.resp.Header.Get("X-Accel-Buffering"))
	assert.Empty(t, c.resp.Header.Get("WWW-Authenticate"))
	requireWithinJitter(t, busy, c.noPlace())

	st := chain.SessionSignalStats()
	assert.EqualValues(t, 1, st.Throttled)
	assert.Zero(t, st.ReloadFailures)
	assert.Zero(t, st.Open)

	on.Store(false)

	open := openSignals(t, srv.URL, s, "")
	open.opens()
	open.receivesPing(chain, UserID)
}

// signalsThrottleNotRetryable is the override: RetryableError saying no leaves the chain's 401, with no
// stream type, and is handed the policy's own reason.
func signalsThrottleNotRetryable(t *testing.T, listen func(ChainSpec) StreamServer) {
	var asked atomic.Pointer[error]

	spec := newSignalsSpec(t,
		httpsec.SessionSignals{RetryableError: func(err error) bool { asked.Store(&err); return false }},
		throttling(t, throttlingPolicy{}))
	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	c := openSignals(t, srv.URL, s, "")
	body, err := io.ReadAll(c.r)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, c.resp.StatusCode)
	assert.NotContains(t, c.resp.Header.Get("Content-Type"), "text/event-stream")
	assert.NotContains(t, string(body), "retry:")

	got := asked.Load()
	require.NotNil(t, got)
	assert.True(t, *got == ratelimit.ErrThrottled, "RetryableError is handed the policy's own reason") //nolint:errorlint // the point: the reason arrives as the policy gave it
}

// signalsThrottledCrossSiteRefused is the cross-site rule ahead of the retry: a throttled request from a
// site nothing trusts is refused as an unthrottled one is, and is no throttle to count.
func signalsThrottledCrossSiteRefused(t *testing.T, listen func(ChainSpec) StreamServer) {
	var chain *httpsec.Chain

	spec := newSignalsSpec(t, httpsec.SessionSignals{}, throttling(t, throttlingPolicy{}))
	spec.Built = func(c *httpsec.Chain) { chain = c }
	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	crossSite := func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		r.Header.Set("Origin", "https://evil.example")
	}

	refused := openSignals(t, srv.URL, s, "", crossSite)
	body, err := io.ReadAll(refused.r)
	require.NoError(t, err)

	assert.Equal(t, http.StatusForbidden, refused.resp.StatusCode)
	assert.Equal(t, "no-store, no-transform", refused.resp.Header.Get("Cache-Control"))
	assert.NotContains(t, refused.resp.Header.Get("Content-Type"), "text/event-stream")
	assert.NotContains(t, string(body), "retry:")
	assert.Zero(t, chain.SessionSignalStats().Throttled)

	// The same request from its own site is still told to retry.
	openSignals(t, srv.URL, s, "").noPlace()
	assert.EqualValues(t, 1, chain.SessionSignalStats().Throttled)
}

// signalsThrottledBearerFromWildcard is the bearer's rule ahead of the retry: a page can send a bearer only
// if it holds it, so a CORS wildcard's origin that an unthrottled stream opens from is told to retry
// when throttled, and the stream opens from there once the throttle is off.
func signalsThrottledBearerFromWildcard(t *testing.T, listen func(ChainSpec) StreamServer) {
	const busy = 10 * time.Second

	var (
		on    atomic.Bool
		chain *httpsec.Chain
	)

	on.Store(true)

	spec := newSignalsSpec(t, httpsec.SessionSignals{BusyDelay: busy},
		throttling(t, throttlingPolicy{on: &on}),
		httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{"*"}}))
	spec.Built = func(c *httpsec.Chain) { chain = c }
	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	crossSite := func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		r.Header.Set("Origin", "https://app.example")
	}

	requireWithinJitter(t, busy, openSignals(t, srv.URL, s, "", crossSite).noPlace())

	st := chain.SessionSignalStats()
	assert.EqualValues(t, 1, st.Throttled)
	assert.Zero(t, st.ReloadFailures)
	assert.Zero(t, st.Open)

	on.Store(false)

	open := openSignals(t, srv.URL, s, "", crossSite)
	open.opens()
	open.receivesPing(chain, UserID)
}

// failingFamilyStore is a session store whose family read fails while armed. It embeds the memory store
// itself, so the optional family read stays visible to the chain.
type failingFamilyStore struct {
	*session.MemoryStore

	armed atomic.Bool
	reads atomic.Int64
}

func (s *failingFamilyStore) ListByFamily(ctx context.Context, u identity.UserID, f id.ID, now time.Time) ([]*session.Session, error) {
	s.reads.Add(1)

	if s.armed.Load() {
		return nil, errors.New("family read down")
	}

	return s.MemoryStore.ListByFamily(ctx, u, f, now)
}

// signalsFamilyReadFailing is R8 on a real server: when the family read fails, admission is told to
// retry, a stream already open stays open and counts the failure, and a recovered read is used again.
func signalsFamilyReadFailing(t *testing.T, listen func(ChainSpec) StreamServer) {
	const busy = 10 * time.Second

	var (
		store *failingFamilyStore
		chain *httpsec.Chain
	)

	spec := newSignalsSpecOver(t, signalsIdleTimeout, func(inner session.Store) session.Store {
		store = &failingFamilyStore{MemoryStore: inner.(*session.MemoryStore)} //nolint:forcetypeassert // the fixture's store is the memory store

		return store
	}, httpsec.SessionSignals{BusyDelay: busy})
	spec.Built = func(c *httpsec.Chain) { chain = c }
	srv := listen(spec)
	s := signalsSignIn(t, spec.Effects, UserID)

	store.armed.Store(true)
	requireWithinJitter(t, busy, openSignals(t, srv.URL, s, "").noPlace())
	assert.EqualValues(t, 1, chain.SessionSignalStats().ReloadFailures)
	assert.Positive(t, store.reads.Load(), "the family read was the one asked")

	store.armed.Store(false)

	open := openSignals(t, srv.URL, s, "")
	open.opens()

	before := chain.SessionSignalStats().ReloadFailures

	store.armed.Store(true)
	require.Eventually(t, func() bool { return chain.SessionSignalStats().ReloadFailures > before }, signalsBound, 50*time.Millisecond)
	assert.EqualValues(t, 1, chain.SessionSignalStats().Open, "an outage leaves the stream open")

	store.armed.Store(false)
	require.Eventually(t, func() bool { return chain.SessionSignalStats().ConsecutiveReloadFailures == 0 }, signalsBound, 50*time.Millisecond)
	open.receivesPing(chain, UserID)
}
