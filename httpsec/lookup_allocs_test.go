package httpsec_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
)

// TestLookupStatus_Allocs pins that classifying the short error shapes a
// request raises allocates no more than the classification did before the
// bounded walk: 1 allocation per call on each row, measured on the pre-walk
// baseline with this same test.
//
// It is not parallel: testing.AllocsPerRun counts every allocation in the
// process, so no other test may run during the measurement.
func TestLookupStatus_Allocs(t *testing.T) { //nolint:paralleltest // allocation counts are process-wide
	type testCase struct {
		name string
		err  error
		// baseline is the pre-walk classification's allocations per call.
		baseline float64
		assert   func(t *testing.T, status int, ok bool)
	}

	recognised := func(want int) func(t *testing.T, status int, ok bool) {
		return func(t *testing.T, status int, ok bool) {
			t.Helper()
			assert.True(t, ok)
			assert.Equal(t, want, status)
		}
	}

	cases := []testCase{
		{
			name:     "bare-sentinel",
			err:      authorize.ErrAccessDenied,
			baseline: 1,
			assert:   recognised(403),
		},
		{
			name:     "wrap-5",
			err:      wrapN(authorize.ErrAccessDenied, 5),
			baseline: 1,
			assert:   recognised(403),
		},
		{
			name: "join-3-challenge",
			err: errors.Join(
				&httpsec.ChallengeError{Kind: policy.ChallengeMFA},
				authorize.ErrAccessDenied,
				errors.New("second sentinel"),
			),
			baseline: 1,
			assert:   recognised(401),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, ok := httpsec.LookupStatus(tc.err)
			tc.assert(t, status, ok)

			allocs := testing.AllocsPerRun(1000, func() {
				status, ok = httpsec.LookupStatus(tc.err)
			})
			t.Logf("%s: %v allocations per call (pre-walk baseline %v)", tc.name, allocs, tc.baseline)
			// The walk flattens into a stack buffer, so a chain that fits
			// allocates nothing; the baseline is logged for comparison.
			require.Zero(t, allocs, "allocations per call")
		})
	}
}
