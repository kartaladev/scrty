package httpsec_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/pkg/logsample"
)

// capturingHandler keeps every record written through it, so a test asserts on
// the records themselves rather than on formatted text.
type capturingHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.recs = append(h.recs, r.Clone())

	return nil
}

func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

func (h *capturingHandler) records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]slog.Record(nil), h.recs...)
}

// attrValue reads one attribute off a record, reporting whether it was there at
// all — an attribute that is absent and one that is zero are different claims.
func attrValue(r slog.Record, name string) (slog.Value, bool) {
	var (
		v     slog.Value
		found bool
	)

	r.Attrs(func(a slog.Attr) bool {
		if a.Key == name {
			v, found = a.Value, true

			return false
		}

		return true
	})

	return v, found
}

func hasAttr(r slog.Record, name string) bool {
	_, ok := attrValue(r, name)

	return ok
}

func suppressedCount(t *testing.T, r slog.Record) int64 {
	t.Helper()

	v, ok := attrValue(r, "suppressed")
	require.True(t, ok, "the record carries no suppressed count")

	return v.Int64()
}

// throttledAPIKeyChain builds a chain whose API key flow refuses every source as
// over its limit, logging through log, so each attempt from a source is one
// throttled-source refusal on the real throttle path.
//
// attempt presents the harness's live key from source once; the refusal it
// gets is the throttle's, because the limiter answers before the key is read.
func throttledAPIKeyChain(
	t *testing.T,
	log *slog.Logger,
	opts ...httpsec.Option,
) (c *httpsec.Chain, attempt func(source string)) {
	t.Helper()

	h := newAPIKeyHarness(t)

	// The limiter is a mock, which reports no policy, so the chain would warn
	// at construction that the flow counts no IPv6 aggregate. Every source
	// here is IPv4, which no aggregate counts, and the records under test are
	// the refusals alone, so the aggregate is turned off outright.
	c, err := httpsec.New(append([]httpsec.Option{
		httpsec.WithLogger(log),
		httpsec.WithoutIPv6Aggregate(),
		httpsec.EnableAPIKey(h.keys, httpsec.WithAPIKeyLimiter(exceededLimiter(t))),
	}, opts...)...)
	require.NoError(t, err)

	return c, func(source string) {
		t.Helper()

		out := h.withKey(t, c, source, h.valid)
		require.Error(t, out.err, "a throttled source never authenticates")
	}
}

// throttledRecords returns the throttled-source records among recs.
func throttledRecords(recs []slog.Record) []slog.Record {
	var out []slog.Record

	for _, r := range recs {
		if r.Message == guardThrottledMsg {
			out = append(out, r)
		}
	}

	return out
}

// TestRefusalLogSampling pins the window over the throttled-source record a
// chain-built guard writes: a refusal is driven by whoever is being refused, so
// an unsampled one is a log flood an attacker chooses the size of.
func TestRefusalLogSampling(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []httpsec.Option
		// act drives the chain's throttled API key flow through attempt, and
		// the OIDC handoff flow of a chain over the same log through redeem.
		act    func(t *testing.T, attempt func(source string), redeem func(), advance func(time.Duration))
		assert func(t *testing.T, records []slog.Record)
	}

	cases := []testCase{
		{
			name: "a flood from one source writes one warning in the window",
			act: func(_ *testing.T, attempt func(string), _ func(), _ func(time.Duration)) {
				for range 50 {
					attempt("198.51.100.7")
				}
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 1,
					"an unsampled refusal is a log flood the attacker chooses the size of")
			},
		},
		{
			name: "two sources do not suppress each other",
			act: func(_ *testing.T, attempt func(string), _ func(), _ func(time.Duration)) {
				attempt("198.51.100.7")
				attempt("203.0.113.9")
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 2)
			},
		},
		{
			name: "a flood against one flow does not suppress another flow",
			act: func(_ *testing.T, attempt func(string), redeem func(), _ func(time.Duration)) {
				for range 10 {
					attempt(flushSource)
				}
				redeem()
			},
			assert: func(t *testing.T, records []slog.Record) {
				require.Len(t, records, 2, "every key starts with the flow, so flows never share a window")

				flows := make([]string, 0, len(records))
				for _, r := range records {
					v, _ := attrValue(r, "flow")
					flows = append(flows, v.String())
				}
				assert.ElementsMatch(t, []string{"api-key", "oidc.handoff"}, flows)
			},
		},
		{
			name: "an interval of zero disables sampling",
			opts: []httpsec.Option{httpsec.WithRefusalLogInterval(0)},
			act: func(_ *testing.T, attempt func(string), _ func(), _ func(time.Duration)) {
				for range 5 {
					attempt("198.51.100.7")
				}
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 5, "the documented way to ask for the full stream")
			},
		},
		{
			name: "a written record carries the count suppressed before it",
			act: func(_ *testing.T, attempt func(string), _ func(), advance func(time.Duration)) {
				for range 4 {
					attempt("198.51.100.7")
				}
				advance(time.Minute + time.Second) // the window rolls
				attempt("198.51.100.7")
			},
			assert: func(t *testing.T, records []slog.Record) {
				require.Len(t, records, 2)
				assert.Equal(t, int64(3), suppressedCount(t, records[1]),
					"the second record reports the three it stood in for")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The chain's sampler reads the chain's clock, which a case moves
			// by advancing it.
			fc := clockwork.NewFakeClock()

			var h capturingHandler

			log := slog.New(&h)
			_, attempt := throttledAPIKeyChain(t, log, append([]httpsec.Option{httpsec.WithClock(fc)}, tc.opts...)...)
			handoffs := oidcChain(t, log, newTestOIDCManager(t), newTestHandoffManager(t),
				httpsec.WithHandoffLimiter(exceededLimiter(t)))

			tc.act(t, attempt, func() { redeemGarbage(t, handoffs, 1) }, fc.Advance)
			tc.assert(t, throttledRecords(h.records()))
		})
	}
}

// reporterCall is one call the consumer's reporter received.
type reporterCall struct {
	key        string
	suppressed int
}

// TestRefusalLogReporter pins that the counts a chain-built source guard
// suppressed are always accounted for, through the chain's reporter: a key
// that goes quiet still reports what it stood for, and a consumer who wants
// those counts somewhere else gets them on flush.
func TestRefusalLogReporter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		attempts int
		opts     func(r *reporterCalls) []httpsec.Option
		assert   func(t *testing.T, records []slog.Record, calls []reporterCall)
	}

	cases := []testCase{
		{
			name:     "the default reporter summarises a key that goes quiet",
			attempts: 5,
			opts:     func(*reporterCalls) []httpsec.Option { return nil },
			assert: func(t *testing.T, records []slog.Record, _ []reporterCall) {
				require.Len(t, records, 2, "one sampled warning, then one summary")
				assert.Equal(t, guardThrottledMsg, records[0].Message)
				assert.Equal(t, "httpsec: refusal logs suppressed", records[1].Message)
				assert.Equal(t, slog.LevelWarn, records[1].Level)

				key, ok := attrValue(records[1], "key")
				require.True(t, ok, "the summary must name the key it stands for")
				assert.Contains(t, key.String(), "api-key", "the key names the flow")
				assert.Contains(t, key.String(), flushSource, "the key names the source")
				assert.Equal(t, int64(4), suppressedCount(t, records[1]))
			},
		},
		{
			name:     "a consumer reporter replaces it",
			attempts: 4,
			opts: func(r *reporterCalls) []httpsec.Option {
				return []httpsec.Option{httpsec.WithRefusalLogReporter(r.report)}
			},
			assert: func(t *testing.T, records []slog.Record, calls []reporterCall) {
				require.Len(t, calls, 1, "the consumer's reporter did not receive the throttled-source count")
				assert.Equal(t, 3, calls[0].suppressed)
				assert.Contains(t, calls[0].key, flushSource, "the key names the source")
				assert.Len(t, records, 1,
					"the consumer's reporter replaces the summary record, it does not add to it")
			},
		},
		{
			name:     "an interval of zero has nothing to summarise",
			attempts: 5,
			opts: func(*reporterCalls) []httpsec.Option {
				return []httpsec.Option{httpsec.WithRefusalLogInterval(0)}
			},
			assert: func(t *testing.T, records []slog.Record, _ []reporterCall) {
				assert.Len(t, records, 5, "every record was written, so none was suppressed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				h     capturingHandler
				calls reporterCalls
			)

			c, attempt := throttledAPIKeyChain(t, slog.New(&h), tc.opts(&calls)...)
			for range tc.attempts {
				attempt(flushSource)
			}

			c.FlushRefusalLogs()

			tc.assert(t, h.records(), calls.received())
		})
	}
}

// reporterCalls is a consumer's reporter that keeps every call it receives. A
// guard reports on whichever goroutine evicted the key, so it is guarded.
type reporterCalls struct {
	mu    sync.Mutex
	calls []reporterCall
}

func (r *reporterCalls) report(key string, suppressed int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls = append(r.calls, reporterCall{key: key, suppressed: suppressed})
}

func (r *reporterCalls) received() []reporterCall {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]reporterCall(nil), r.calls...)
}

// TestRefusalLogUnsampledDebug pins that a request the client itself ended is
// not treated as a refusal worth a sampled warning. Sampling it would let
// ordinary disconnections consume the window a real outage needs.
func TestRefusalLogUnsampledDebug(t *testing.T) {
	t.Parallel()

	var h capturingHandler
	log := slog.New(&h)
	sampler := logsample.New(time.Minute)

	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Times(5).
		DoAndReturn(func(ctx context.Context, _ string) (bool, error) {
			return true, ctx.Err()
		})
	guard := guardOver(t, limiter)

	for range 5 {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, err := httpsec.SourceThrottledForTest(ctx, guard, "198.51.100.7", "login",
			sampler, log, time.Now())
		require.Error(t, err)
	}

	records := h.records()
	require.Len(t, records, 5, "the ended requests went through the sampler")
	for i, r := range records {
		assert.Equal(t, slog.LevelDebug, r.Level, "record %d is not a debug record", i)
		assert.False(t, hasAttr(r, "suppressed"), "record %d was sampled", i)
	}
}
