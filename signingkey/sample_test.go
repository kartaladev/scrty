// The sampling tests are not parallel: goleak counts goroutines process-wide.
package signingkey_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

// TestFailureLogsAreSampled drives a store that keeps failing and pins the
// exact records that reach the logger. The counts are exact because the clock
// is controlled: the sampler reads it, so the test decides which failures fall
// in the same window.
func TestFailureLogsAreSampled(t *testing.T) {
	const (
		window     = time.Hour
		everyOther = 5 // failures driven inside the first window, after the first
		afterward  = 2 // failures driven after the second window's record
	)

	type testCase struct {
		name   string
		verb   string
		assert func(t *testing.T, recorder *logRecorder, report *failureReport)
	}

	// assertSampled is shared: the two cases differ only in which store verb
	// fails, and make the same claims about what was written.
	assertSampled := func(t *testing.T, recorder *logRecorder, report *failureReport) {
		records := recorder.records(t)
		require.Len(t, records, 2,
			"%d failures in the first window and one in the next write two records",
			everyOther)
		assert.Equal(t, float64(0), records[0]["suppressed"],
			"the first record suppressed nothing before it")
		assert.Equal(t, float64(everyOther-1), records[1]["suppressed"],
			"the next window's record states how many failures were suppressed before it")

		assert.Equal(t, everyOther+1+afterward, report.hooks(),
			"the error hook is never sampled: every failure reaches it")
	}

	cases := []testCase{
		{name: "rotation failures", verb: opRotate, assert: assertSampled},
		{name: "reload failures", verb: opReload, assert: assertSampled},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock(epoch)
			report := &failureReport{}
			recorder, logger := newLogRecorder()

			km, err := signingkey.NewKeyManager(t.Context(),
				signingkey.WithKeyStore(failingStore(t, report, tc.verb)),
				signingkey.WithClock(clock),
				signingkey.WithAlgs(signingkey.EdDSA),
				signingkey.WithLogger(logger),
				signingkey.WithErrorHook(report.hook),
				signingkey.WithLogSampleWindow(window),
				signingkey.WithRotateInterval(time.Minute),
				signingkey.WithReloadInterval(30*time.Second),
				signingkey.WithHousekeepingInterval(12*time.Hour),
				signingkey.WithLifetime(24*time.Hour),
			)
			require.NoError(t, err)
			stopAndVerify(t, km)

			require.NoError(t, km.Start(t.Context()))

			drive := func(by time.Duration, want int) {
				clock.Advance(by)
				require.Eventually(t, func() bool { return report.hooks() >= want },
					10*time.Second, 5*time.Millisecond,
					"failure %d should have been reported", want)
			}

			for failure := 1; failure <= everyOther; failure++ {
				drive(time.Minute, failure)
			}
			drive(window, everyOther+1) // the window has turned over
			for failure := 1; failure <= afterward; failure++ {
				drive(time.Minute, everyOther+1+failure)
			}

			tc.assert(t, recorder, report)

			require.NoError(t, km.Stop())
			records := recorder.records(t)
			require.Len(t, records, 3, "stopping accounts for what was still suppressed")
			assert.Equal(t, float64(afterward), records[2]["suppressed"])
			assert.Equal(t, tc.verb, records[2]["op"],
				"the flushed record names the operation it stands for")
		})
	}
}
