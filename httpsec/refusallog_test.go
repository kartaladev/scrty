package httpsec_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
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

// TestRefusalLogSampling pins the window: a refusal is driven by whoever is
// being refused, so an unsampled one is a log flood an attacker chooses the
// size of.
func TestRefusalLogSampling(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		interval time.Duration
		act      func(t *testing.T, s *logsample.Sampler, log *slog.Logger)
		assert   func(t *testing.T, records []slog.Record)
	}

	write := func(s *logsample.Sampler, log *slog.Logger, key string) {
		httpsec.LogSampledForTest(context.Background(), s, log, slog.LevelWarn, time.Now(),
			key, "httpsec: source throttled", slog.String("source", key))
	}

	cases := []testCase{
		{
			name:     "a flood from one source writes one warning in the window",
			interval: time.Minute,
			act: func(_ *testing.T, s *logsample.Sampler, log *slog.Logger) {
				for range 50 {
					write(s, log, "login|198.51.100.7")
				}
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 1,
					"an unsampled refusal is a log flood the attacker chooses the size of")
			},
		},
		{
			name:     "two sources do not suppress each other",
			interval: time.Minute,
			act: func(_ *testing.T, s *logsample.Sampler, log *slog.Logger) {
				write(s, log, "login|198.51.100.7")
				write(s, log, "login|203.0.113.9")
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 2)
			},
		},
		{
			name:     "a flood against one flow does not suppress another flow",
			interval: time.Minute,
			act: func(_ *testing.T, s *logsample.Sampler, log *slog.Logger) {
				for range 10 {
					write(s, log, "login|198.51.100.7")
				}
				write(s, log, "magiclink|198.51.100.7")
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 2,
					"every key starts with the flow, so flows never share a window")
			},
		},
		{
			name:     "an interval of zero disables sampling",
			interval: 0,
			act: func(_ *testing.T, s *logsample.Sampler, log *slog.Logger) {
				for range 5 {
					write(s, log, "login|198.51.100.7")
				}
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 5, "the documented way to ask for the full stream")
			},
		},
		{
			name:     "a written record carries the count suppressed before it",
			interval: time.Minute,
			act: func(_ *testing.T, s *logsample.Sampler, log *slog.Logger) {
				for range 4 {
					write(s, log, "login|198.51.100.7")
				}
				synctest.Wait()
				time.Sleep(time.Minute + time.Second) // the window rolls
				write(s, log, "login|198.51.100.7")
			},
			assert: func(t *testing.T, records []slog.Record) {
				require.Len(t, records, 2)
				assert.Equal(t, int64(3), suppressedCount(t, records[1]),
					"the second record reports the three it stood in for")
				assert.False(t, hasAttr(records[0], "suppressed"),
					"the first suppressed nothing, so it carries no count")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// No t.Parallel: synctest.Test owns the bubble's goroutines.
			synctest.Test(t, func(t *testing.T) {
				var h capturingHandler

				tc.act(t, logsample.New(tc.interval), slog.New(&h))
				synctest.Wait()
				tc.assert(t, h.records())
			})
		})
	}
}

// reporterCall is one call the consumer's reporter received.
type reporterCall struct {
	key        string
	suppressed int
}

// TestRefusalLogReporter pins that the counts a sampled key suppressed are
// always accounted for: a key that goes quiet still reports what it stood for,
// and a consumer who wants those counts somewhere else gets them.
func TestRefusalLogReporter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(calls *[]reporterCall) []httpsec.Option
		act    func(t *testing.T, c *httpsec.Chain, log *slog.Logger)
		assert func(t *testing.T, records []slog.Record, calls []reporterCall)
	}

	writeN := func(c *httpsec.Chain, log *slog.Logger, n int, key string) {
		for range n {
			httpsec.LogSampledForTest(context.Background(), httpsec.SamplerForTest(c), log,
				slog.LevelWarn, time.Now(), key, "httpsec: source throttled")
		}
	}

	cases := []testCase{
		{
			name: "the default reporter summarises a key that goes quiet",
			opts: func(*[]reporterCall) []httpsec.Option { return nil },
			act: func(_ *testing.T, c *httpsec.Chain, log *slog.Logger) {
				writeN(c, log, 5, "login|198.51.100.7")
				c.FlushRefusalLogs()
			},
			assert: func(t *testing.T, records []slog.Record, _ []reporterCall) {
				require.Len(t, records, 2, "one sampled warning, then one summary")
				assert.Equal(t, "httpsec: refusal logs suppressed", records[1].Message)
				assert.Equal(t, slog.LevelWarn, records[1].Level)

				key, ok := attrValue(records[1], "key")
				require.True(t, ok, "the summary must name the key it stands for")
				assert.Equal(t, "login|198.51.100.7", key.String())
				assert.Equal(t, int64(4), suppressedCount(t, records[1]))
			},
		},
		{
			name: "a consumer reporter replaces it",
			opts: func(calls *[]reporterCall) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithRefusalLogReporter(func(key string, suppressed int) {
						*calls = append(*calls, reporterCall{key: key, suppressed: suppressed})
					}),
				}
			},
			act: func(_ *testing.T, c *httpsec.Chain, log *slog.Logger) {
				writeN(c, log, 4, "login|198.51.100.7")
				c.FlushRefusalLogs()
			},
			assert: func(t *testing.T, records []slog.Record, calls []reporterCall) {
				require.Len(t, calls, 1)
				assert.Equal(t, reporterCall{key: "login|198.51.100.7", suppressed: 3}, calls[0])
				assert.Len(t, records, 1,
					"the consumer's reporter replaces the summary record, it does not add to it")
			},
		},
		{
			name: "an interval of zero has nothing to summarise",
			opts: func(*[]reporterCall) []httpsec.Option {
				return []httpsec.Option{httpsec.WithRefusalLogInterval(0)}
			},
			act: func(_ *testing.T, c *httpsec.Chain, log *slog.Logger) {
				writeN(c, log, 5, "login|198.51.100.7")
				c.FlushRefusalLogs()
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
				calls []reporterCall
			)
			log := slog.New(&h)

			c, err := httpsec.New(append(tc.opts(&calls), httpsec.WithLogger(log))...)
			require.NoError(t, err)

			tc.act(t, c, log)
			tc.assert(t, h.records(), calls)
		})
	}
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

// TestFlushRefusalLogsScope pins that the chain flushes its own sampler and
// nothing else.
//
// authenticate and policy each sample under their own option and expose their
// own flush. Reaching into them from here would make one call govern three
// subsystems, so what a consumer gets from this call would depend on which of
// them they happened to wire — and a consumer who wanted only the chain's
// counts would have no way to ask for them. The settled answer is that no
// shared flusher is declared: the chain drains the sampler it owns, and the
// counts the other subsystems hold stay theirs until the consumer flushes them.
func TestFlushRefusalLogsScope(t *testing.T) {
	t.Parallel()

	// A policy that refuses every login it is given, wired into an engine the
	// chain evaluates through: a magic-link login whose only enrolled second
	// factor arrives by email is two factors on one channel, so it is refused
	// and the refusal is sampled under the policy's own window.
	method := NewMockMFAMethodLookup(gomock.NewController(t))
	method.EXPECT().Channel().Return(factor.Email).AnyTimes()
	method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

	var policyLog capturingHandler

	p, err := policy.NewMFAPolicy(method,
		policy.WithMFAPolicyLogger(slog.New(&policyLog)),
		policy.WithMFAPolicyLogInterval(time.Hour))
	require.NoError(t, err)

	engine, err := policy.NewEngine(p)
	require.NoError(t, err)

	var (
		chainLog capturingHandler
		calls    []reporterCall
	)

	// The policy above can raise a second-factor challenge, so the chain must
	// count its gate as enabled — a chain that marks a challenge nothing acts
	// on is refused at construction. What enforces it is not this test's
	// subject, so the gate is recorded without being registered.
	c, err := httpsec.New(
		httpsec.WithPolicyEngine(engine),
		httpsec.EnableGateForTest(policy.ChallengeMFA),
		httpsec.WithLogger(slog.New(&chainLog)),
		httpsec.WithRefusalLogReporter(func(key string, suppressed int) {
			calls = append(calls, reporterCall{key: key, suppressed: suppressed})
		}),
	)
	require.NoError(t, err)

	const chainKey = "login|198.51.100.7"

	for range 4 {
		httpsec.LogSampledForTest(t.Context(), httpsec.SamplerForTest(c), slog.New(&chainLog),
			slog.LevelWarn, time.Now(), chainKey, "httpsec: source throttled")
	}

	login := &policy.Input{
		User:        identity.UserID("u-1"),
		FirstFactor: factor.MagicLink,
		Now:         time.Now(),
	}
	for range 4 {
		d := engine.EvaluatePhase(t.Context(), policy.PostAuthentication, login)
		require.Equal(t, policy.Deny, d.Outcome, "the policy under test stopped refusing")
	}

	require.Len(t, policyLog.records(), 1,
		"the policy wrote one record and is holding the other three")

	c.FlushRefusalLogs()

	require.Len(t, calls, 1, "the chain did not report the counts its own sampler held")
	assert.Equal(t, reporterCall{key: chainKey, suppressed: 3}, calls[0])

	assert.Len(t, policyLog.records(), 1,
		"the chain drained a sampler that is not its own: the policy's held counts were written")

	// The counts really were pending, so the assertion above is about what the
	// chain left alone rather than about a policy that had nothing to report.
	flusher, ok := p.(policy.RefusalLogFlusher)
	require.True(t, ok, "the policy offers no way to report what it suppressed")
	require.NoError(t, flusher.FlushRefusalLogs())

	records := policyLog.records()
	require.Len(t, records, 2, "the consumer's own flush released what the policy was holding")
	assert.Equal(t, int64(3), suppressedCount(t, records[1]))
}
