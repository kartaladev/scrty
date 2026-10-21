package httpsec_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

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
