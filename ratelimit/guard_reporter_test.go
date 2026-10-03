package ratelimit_test

import (
	"sync"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
)

// summaryCall is one report a consumer's summary reporter received.
type summaryCall struct {
	key        string
	suppressed int
}

// summaryRecorder is a consumer's reporter that keeps every call it receives.
type summaryRecorder struct {
	mu    sync.Mutex
	calls []summaryCall
}

func (r *summaryRecorder) report(key string, suppressed int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls = append(r.calls, summaryCall{key: key, suppressed: suppressed})
}

func (r *summaryRecorder) received() []summaryCall {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]summaryCall(nil), r.calls...)
}

// TestSourceGuardLogReporter pins where a guard's suppressed refusal counts go
// when its sampler lets them go: by default a summary record through the
// guard's logger, and to the consumer's reporter instead when one is given.
func TestSourceGuardLogReporter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// opts returns the guard options under test; r is the consumer's
		// reporter, for the rows that install it.
		opts   func(r *summaryRecorder) []ratelimit.GuardOption
		assert func(t *testing.T, records []map[string]any, calls []summaryCall)
	}

	cases := []testCase{
		{
			name: "the default writes a summary record through the guard's logger",
			opts: func(*summaryRecorder) []ratelimit.GuardOption { return nil },
			assert: func(t *testing.T, records []map[string]any, calls []summaryCall) {
				t.Helper()

				assert.Empty(t, calls)
				require.Len(t, records, 2, "one throttled-source record, then one summary")
				assert.Equal(t, "ratelimit: refusal records suppressed", records[1]["msg"])
				assert.Equal(t, testFlow, records[1]["flow"])
				assert.Equal(t, float64(4), records[1]["suppressed"])
			},
		},
		{
			name: "a consumer reporter receives the summary in its place",
			opts: func(r *summaryRecorder) []ratelimit.GuardOption {
				return []ratelimit.GuardOption{ratelimit.WithSourceGuardLogReporter(r.report)}
			},
			assert: func(t *testing.T, records []map[string]any, calls []summaryCall) {
				t.Helper()

				require.Len(t, calls, 1, "the consumer's reporter was not given the suppressed count")
				assert.Equal(t, 4, calls[0].suppressed)
				assert.Contains(t, calls[0].key, testFlow, "the key names the flow it was sampled under")
				assert.Contains(t, calls[0].key, testSource, "the key names the source it was sampled under")
				assert.Len(t, records, 1,
					"the consumer's reporter replaces the summary record, it does not add to it")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				recorder, logger := newLogRecorder()
				r := &summaryRecorder{}
				g := alwaysThrottling(t, testFlow, logger, tc.opts(r)...)

				for range 5 {
					_, _ = g.Check(t.Context(), testSource)
				}

				g.Flush()

				tc.assert(t, logRecords(t, recorder), r.received())
			})
		})
	}
}
