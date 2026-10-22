package httpsec_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

const sessionReferenceSource = "203.0.113.7"

var errReferencePolicyDenied = errors.New("sessionbearer_test: outside office hours")

// referenceStore wires the harness's store to know testReference alone, and
// counts the lookups by whether they asked for the live reference.
type referenceStore struct {
	unknown atomic.Int64
	live    atomic.Int64
}

func (h *authHarness) knowsOnlyTestReference() *referenceStore {
	counts := &referenceStore{}

	h.store.EXPECT().Load(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string) (*session.Session, error) {
			if id != testReference {
				counts.unknown.Add(1)

				return nil, session.ErrSessionNotFound
			}

			counts.live.Add(1)

			return referencedSession(), nil
		})
	h.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).AnyTimes().Return(storedUser(), nil)
	h.acceptsActivityWriteBack()

	return counts
}

// unknownReference is the n-th well-formed identifier no session answers to.
func unknownReference(n int) string {
	raw := make([]byte, 32)
	binary.BigEndian.PutUint32(raw, uint32(n)) //nolint:gosec // n is a small non-negative loop index
	raw[31] = 0xff

	return base64.RawURLEncoding.EncodeToString(raw)
}

func fromReferenceSource(t *testing.T, chain *httpsec.Chain, source, header string) served {
	t.Helper()

	req := bearerRequest(t.Context(), header)
	req.RemoteAddr = source + ":51000"

	return serve(t, chain, req)
}

// TestSessionBearerThrottle pins that references no session answers to are
// counted per source, that a source over its allowance is refused before any
// lookup, and that nothing but a refused reference is counted.
func TestSessionBearerThrottle(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		engine func(t *testing.T) *policy.Engine
		drive  func(t *testing.T, chain *httpsec.Chain) []served
		assert func(t *testing.T, out []served, counts *referenceStore)
	}

	refusedAuth := func(t *testing.T, s served) {
		t.Helper()
		require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
		assert.False(t, s.handlerRan)
	}

	cases := []testCase{
		{
			name: "a flooded source is refused before any lookup",
			drive: func(t *testing.T, chain *httpsec.Chain) []served {
				var out []served
				for i := range 100 {
					out = append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+unknownReference(i)))
				}

				return append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+testReference))
			},
			assert: func(t *testing.T, out []served, counts *referenceStore) {
				refusedAuth(t, out[100])
				assert.Zero(t, counts.live.Load(), "the live reference was never looked up")
				assert.Equal(t, int64(100), counts.unknown.Load())
			},
		},
		{
			name: "malformed values count",
			drive: func(t *testing.T, chain *httpsec.Chain) []served {
				var out []served
				for range 100 {
					out = append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer not-a-reference"))
				}

				return append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+testReference))
			},
			assert: func(t *testing.T, out []served, counts *referenceStore) {
				refusedAuth(t, out[100])
				assert.Zero(t, counts.live.Load())
				assert.Zero(t, counts.unknown.Load(), "a malformed value costs no lookup")
			},
		},
		{
			name: "another source is unaffected",
			drive: func(t *testing.T, chain *httpsec.Chain) []served {
				for i := range 100 {
					_ = fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+unknownReference(i))
				}

				return []served{fromReferenceSource(t, chain, "198.51.100.4", "Bearer "+testReference)}
			},
			assert: func(t *testing.T, out []served, _ *referenceStore) {
				require.NoError(t, out[0].err)
				assert.True(t, out[0].handlerRan)
			},
		},
		{
			name: "live sessions spend nothing",
			drive: func(t *testing.T, chain *httpsec.Chain) []served {
				var out []served
				for range 1000 {
					out = append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+testReference))
				}

				return out
			},
			assert: func(t *testing.T, out []served, _ *referenceStore) {
				for i, s := range out {
					require.NoError(t, s.err, "request %d", i)
				}
			},
		},
		{
			name: "a request carrying no reference never reaches the limiter",
			drive: func(t *testing.T, chain *httpsec.Chain) []served {
				var out []served
				for range 300 {
					out = append(out, fromReferenceSource(t, chain, sessionReferenceSource, ""))
				}

				return append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+testReference))
			},
			assert: func(t *testing.T, out []served, _ *referenceStore) {
				require.NoError(t, out[300].err)
			},
		},
		{
			name: "a policy refusal is not recorded",
			engine: func(t *testing.T) *policy.Engine {
				return denyingIn(t, policy.PerRequest, errReferencePolicyDenied)
			},
			drive: func(t *testing.T, chain *httpsec.Chain) []served {
				var out []served
				for range 200 {
					out = append(out, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+testReference))
				}

				return out
			},
			assert: func(t *testing.T, out []served, counts *referenceStore) {
				for i, s := range out {
					require.ErrorIs(t, s.err, errReferencePolicyDenied, "request %d", i)
				}

				assert.Equal(t, int64(200), counts.live.Load(), "none was throttled before its lookup")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			counts := h.knowsOnlyTestReference()

			opts := []httpsec.Option{
				httpsec.WithLogger(h.logger()),
				httpsec.EnableSessionBearer(h.sessionBearerDeps()),
			}
			if tc.engine != nil {
				opts = append(opts, httpsec.WithPolicyEngine(tc.engine(t)))
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, tc.drive(t, chain), counts)
		})
	}
}

// TestSessionBearerConsumerLimiter pins that a consumer's limiter is asked
// about every claimed request and told about every refused reference, keyed by
// the source, and nothing else.
func TestSessionBearerConsumerLimiter(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		checks   int
		failures []string
	)

	limiter := NewMockLimiter(gomock.NewController(t))
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			checks++

			return false, nil
		})
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, key string) error {
			mu.Lock()
			defer mu.Unlock()
			failures = append(failures, key)

			return nil
		})

	h := newAuthHarness(t)
	h.knowsOnlyTestReference()

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableSessionBearer(h.sessionBearerDeps(), httpsec.WithSessionBearerLimiter(limiter)),
	)
	require.NoError(t, err)

	require.Error(t, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+unknownReference(1)).err)
	require.Error(t, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer junk").err)
	require.NoError(t, fromReferenceSource(t, chain, sessionReferenceSource, "Bearer "+testReference).err)

	mu.Lock()
	defer mu.Unlock()

	assert.Equal(t, 3, checks, "every claimed request is checked against its source")
	require.Len(t, failures, 2, "and only the two refused references are recorded")

	for _, key := range failures {
		assert.True(t, strings.Contains(key, sessionReferenceSource), "keyed by the source: %q", key)
	}
}

// TestSessionBearerSharedFactory pins that the chain's factory builds the
// flow's limiter under its own namespace and default allowance.
func TestSessionBearerSharedFactory(t *testing.T) {
	t.Parallel()

	memory := ratelimit.MemoryLimiterFactory()
	factory := NewMockLimiterFactory(gomock.NewController(t))

	factory.EXPECT().NewLimiter("session-reference", 100, time.Minute).
		DoAndReturn(memory.NewLimiter)
	factory.EXPECT().NewLimiter(gomock.Not("session-reference"), gomock.Any(), gomock.Any()).
		AnyTimes().DoAndReturn(memory.NewLimiter)

	h := newAuthHarness(t)

	_, err := httpsec.New(
		httpsec.WithRateLimiterFactory(factory),
		httpsec.EnableSessionBearer(h.sessionBearerDeps()),
	)
	require.NoError(t, err)
}

func TestSessionBearerLimiterConstruction(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)

	for name, l := range map[string]ratelimit.Limiter{
		"nil":       nil,
		"typed nil": (*ratelimit.MemoryLimiter)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(httpsec.EnableSessionBearer(h.sessionBearerDeps(),
				httpsec.WithSessionBearerLimiter(l)))

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), "WithSessionBearerLimiter")
		})
	}

}

// errStoreDown is the store fault the late-renewal cases inject.
var errStoreDown = errors.New("store down")

// loadCountingStore counts the loads that reach the store, and can be armed to
// fail the loads from the nth one on.
type loadCountingStore struct {
	session.Store

	loads atomic.Int64

	// failFrom, when positive, is the load number from which loads fail with
	// failErr; loads before it reach the store.
	failFrom atomic.Int64
	failErr  error
}

func (s *loadCountingStore) Load(ctx context.Context, id string) (*session.Session, error) {
	n := s.loads.Add(1)

	if from := s.failFrom.Load(); from > 0 && n >= from {
		return nil, s.failErr
	}

	return s.Store.Load(ctx, id)
}

// failEndpointLoad makes the load the renewal endpoint makes of the old
// identifier fail with err: the bearer's load, which lets the late credential
// through, is the first after this call, and the endpoint's is the second.
func (s *loadCountingStore) failEndpointLoad(err error) {
	s.failErr = err
	s.failFrom.Store(s.loads.Load() + 2)
}

// failureRecordingLimiter is the default allowance, 100 failures a minute, that
// also lists the keys it was charged.
type failureRecordingLimiter struct {
	ratelimit.Limiter

	owner *lateRenewals
}

func (l *failureRecordingLimiter) RecordFailure(ctx context.Context, key string) error {
	l.owner.mu.Lock()
	l.owner.failures = append(l.owner.failures, key)
	l.owner.mu.Unlock()

	return l.Limiter.RecordFailure(ctx, key)
}

// lateRenewals is a session-reference chain with the renewal endpoint over a
// manager with unused-successor recovery, and a session whose renewal window
// has ended.
type lateRenewals struct {
	clk     *clockwork.FakeClock
	store   *loadCountingStore
	manager *session.Manager
	chain   *httpsec.Chain

	mu       sync.Mutex
	failures []string
}

func newLateRenewals(t *testing.T) *lateRenewals {
	t.Helper()

	l := &lateRenewals{clk: clockwork.NewFakeClockAt(time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC))}
	l.store = &loadCountingStore{Store: session.NewMemoryStore(session.WithMemoryStoreClock(l.clk))}

	var err error

	l.manager, err = session.NewManager(
		session.WithClock(l.clk),
		session.WithStore(l.store),
		session.WithUnusedSuccessorRecovery(),
		session.WithIdleTimeout(7*24*time.Hour),
		session.WithAbsoluteTimeout(30*24*time.Hour),
	)
	require.NoError(t, err)

	inner, err := ratelimit.NewMemoryLimiter(100, time.Minute, ratelimit.WithMemoryLimiterClock(l.clk))
	require.NoError(t, err)

	limiter := &failureRecordingLimiter{Limiter: inner, owner: l}

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

	l.chain, err = httpsec.New(
		httpsec.WithClock(l.clk),
		httpsec.WithLogger(slog.New(slog.DiscardHandler)),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: l.manager, Users: users},
			httpsec.WithSessionBearerLimiter(limiter)),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: users}),
	)
	require.NoError(t, err)

	return l
}

// superseded creates a session and renews it directly through the manager, as
// a renewal whose response was lost would have, and returns the old identifier
// and the successor's.
func (l *lateRenewals) superseded(t *testing.T) (string, string) {
	t.Helper()

	s, err := l.manager.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	next, _, err := l.manager.RotateWithGrace(t.Context(), s, 30*time.Second)
	require.NoError(t, err)

	return s.ID, next.ID
}

func (l *lateRenewals) renew(t *testing.T, credential string) served {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
	req.Header.Set("Authorization", "Bearer "+credential)
	req.RemoteAddr = sessionReferenceSource + ":51000"

	return serve(t, l.chain, req)
}

func (l *lateRenewals) recorded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.failures...)
}

// TestSessionBearerLateRenewals pins that, under unused-successor recovery, a
// late renewal the endpoint refuses is counted against its source like any
// refused reference, and one it recovers is not.
func TestSessionBearerLateRenewals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		drive  func(t *testing.T, l *lateRenewals) []served
		assert func(t *testing.T, l *lateRenewals, out []served)
	}

	cases := []testCase{
		{
			name: "refused late renewals throttle the source",
			drive: func(t *testing.T, l *lateRenewals) []served {
				old, _ := l.superseded(t)

				// Past the window and past the session's own deadlines, with
				// the successor never used: each renewal is refused as
				// expired, and nothing is revoked, so the next one reaches
				// the endpoint again.
				l.clk.Advance(8 * 24 * time.Hour)

				var out []served
				for range 100 {
					out = append(out, l.renew(t, old))
				}

				l.store.loads.Store(0)

				return append(out, l.renew(t, old))
			},
			assert: func(t *testing.T, l *lateRenewals, out []served) {
				for _, s := range out[:100] {
					require.ErrorIs(t, s.err, httpsec.ErrAuthenticationRequired)
				}

				require.ErrorIs(t, out[100].err, httpsec.ErrAuthenticationRequired)
				assert.Zero(t, l.store.loads.Load(), "a throttled source is refused before any store lookup")
			},
		},
		{
			name: "a refused late renewal is recorded once against its source",
			drive: func(t *testing.T, l *lateRenewals) []served {
				old, _ := l.superseded(t)
				l.clk.Advance(8 * 24 * time.Hour)

				return []served{l.renew(t, old)}
			},
			assert: func(t *testing.T, l *lateRenewals, out []served) {
				require.ErrorIs(t, out[0].err, httpsec.ErrAuthenticationRequired)

				failures := l.recorded()
				require.Len(t, failures, 1)
				assert.Contains(t, failures[0], sessionReferenceSource)
			},
		},
		{
			name: "a reused late renewal is recorded against its source",
			drive: func(t *testing.T, l *lateRenewals) []served {
				old, successor := l.superseded(t)

				// The successor is used and kept alive past the old
				// session's own deadlines, then the old identifier is
				// presented late, which is reuse.
				next, err := l.manager.Load(t.Context(), successor)
				require.NoError(t, err)

				l.clk.Advance(6 * 24 * time.Hour)
				require.NoError(t, l.manager.Touch(t.Context(), next))
				l.clk.Advance(2 * 24 * time.Hour)

				return []served{l.renew(t, old)}
			},
			assert: func(t *testing.T, l *lateRenewals, out []served) {
				require.ErrorIs(t, out[0].err, session.ErrSessionReused)
				assert.Len(t, l.recorded(), 1)
			},
		},
		{
			name: "a lost race at the endpoint's load is not recorded",
			drive: func(t *testing.T, l *lateRenewals) []served {
				old, _ := l.superseded(t)
				l.clk.Advance(8 * 24 * time.Hour)
				l.store.failEndpointLoad(session.ErrSessionRenewalConflict)

				return []served{l.renew(t, old)}
			},
			assert: func(t *testing.T, l *lateRenewals, out []served) {
				require.ErrorIs(t, out[0].err, httpsec.ErrSessionRenewalConflict)
				assert.NotErrorIs(t, out[0].err, httpsec.ErrAuthenticationRequired)
				assert.Empty(t, l.recorded(), "a lost race is not a failed guess")
			},
		},
		{
			name: "a store fault at the endpoint's load is not recorded",
			drive: func(t *testing.T, l *lateRenewals) []served {
				old, _ := l.superseded(t)
				l.clk.Advance(8 * 24 * time.Hour)
				l.store.failEndpointLoad(errStoreDown)

				return []served{l.renew(t, old)}
			},
			assert: func(t *testing.T, l *lateRenewals, out []served) {
				require.ErrorIs(t, out[0].err, errStoreDown)
				assert.NotErrorIs(t, out[0].err, httpsec.ErrAuthenticationRequired)
				assert.Empty(t, l.recorded(), "a store fault is not a failed guess")
			},
		},
		{
			name: "a recovered late renewal spends nothing",
			drive: func(t *testing.T, l *lateRenewals) []served {
				old, _ := l.superseded(t)
				l.clk.Advance(time.Minute)

				return []served{l.renew(t, old)}
			},
			assert: func(t *testing.T, l *lateRenewals, out []served) {
				require.NoError(t, out[0].err)
				assert.Empty(t, l.recorded(), "a recovered renewal is not a failed guess")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l := newLateRenewals(t)
			out := tc.drive(t, l)
			tc.assert(t, l, out)
		})
	}
}
