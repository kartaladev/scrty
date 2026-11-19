package httpsec_test

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/policy"
)

// countArms counts the deferred recovers errwalk arms until the test ends.
// The hook is process-wide, so a test that uses it must not run in parallel.
func countArms(t *testing.T) *atomic.Int64 {
	t.Helper()

	n := new(atomic.Int64)
	restore := errwalk.SetArmHook(func() { n.Add(1) })
	t.Cleanup(restore)

	return n
}

// TestLookup_ArmsBounded pins that one LookupStatus call arms a small, fixed
// number of deferred recovers, whatever the length of the chain or of the
// status table: one for the walk, one per As check, and one per batch of
// sentinels. Arming one per sentinel and per link was most of a
// classification's time: before the batch, these rows armed 53, 58, 6, 82 and
// 103.
//
// The bounds are the counts measured today, asserted as upper bounds so a
// new check in lookup does not break the test; the regression they catch is
// a return to one recover per node or per target (53 to 160). A 403 takes the walk, the issuing-failure
// As, the unavailable batch, the challenge As and the status batch: 5, for a
// chain of 1, 6 or 51 links alike. A challenge stops after its As: 4. An
// unrecognised error takes every check, the fault As and the dependency batch
// too: 7, the most any error takes.
//
// It is not parallel: the arm counter is process-wide.
func TestLookup_ArmsBounded(t *testing.T) { //nolint:paralleltest // the arm counter is process-wide
	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, arms int64, status int, ok bool)
	}

	armsAtMost := func(limit int64, want int) func(t *testing.T, arms int64, status int, ok bool) {
		return func(t *testing.T, arms int64, status int, ok bool) {
			t.Helper()
			t.Logf("arms per call: %d", arms)
			assert.Equal(t, want, status)
			assert.Equal(t, want != 500, ok)
			assert.LessOrEqual(t, arms, limit, "recovers armed by one LookupStatus call")
		}
	}

	cases := []testCase{
		{name: "bare-sentinel", err: authorize.ErrAccessDenied, assert: armsAtMost(5, 403)},
		{name: "wrap-5", err: wrapN(authorize.ErrAccessDenied, 5), assert: armsAtMost(5, 403)},
		{
			name: "join-3-challenge",
			err: errors.Join(
				&httpsec.ChallengeError{Kind: policy.ChallengeMFA},
				authorize.ErrAccessDenied,
				errors.New("second sentinel"),
			),
			assert: armsAtMost(4, 401),
		},
		{name: "unknown", err: errors.New("nothing recognises this"), assert: armsAtMost(7, 500)},
		{name: "chain-50", err: wrapN(authorize.ErrAccessDenied, 50), assert: armsAtMost(5, 403)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arms := countArms(t)

			status, ok := httpsec.LookupStatus(tc.err)
			tc.assert(t, arms.Load(), status, ok)
		})
	}
}
