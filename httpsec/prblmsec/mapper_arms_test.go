package prblmsec_test

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/kartaladev/prblm"
	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/policy"
)

// TestMapError_ArmsBounded pins that one MapError call arms a small, fixed
// number of deferred recovers, whatever the length of the chain or of the
// selector targets: the core's lookup arms its own, and the mapper adds one
// for its walk, one per As check and one for the batch of specific targets.
// Before the batch, these rows armed 60, 70, 8, 82 and 160.
//
// The bounds are the counts measured today, asserted as upper bounds; the
// regression they catch is a return to one recover per node or per target.
// A 403 takes the lookup's 5, then the
// mapper's walk, challenge As and specific batch: 8, for a chain of 1, 6 or 51
// links alike. A challenge takes the lookup's 4, the walk and the challenge
// As: 6. An unrecognised error takes only the lookup's 7: the mapper answers
// nil without walking.
//
// It is not parallel: the arm counter is process-wide.
func TestMapError_ArmsBounded(t *testing.T) { //nolint:paralleltest // the arm counter is process-wide
	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, arms int64, got *prblm.Problem)
	}

	mapper := newProblems(t).Mapper()

	answered := func(limit int64, status int) func(t *testing.T, arms int64, got *prblm.Problem) {
		return func(t *testing.T, arms int64, got *prblm.Problem) {
			t.Helper()
			t.Logf("arms per call: %d", arms)

			if status == 0 {
				assert.Nil(t, got)
			} else if assert.NotNil(t, got) {
				assert.Equal(t, status, got.Status)
			}

			assert.LessOrEqual(t, arms, limit, "recovers armed by one MapError call")
		}
	}

	cases := []testCase{
		{name: "bare-sentinel", err: authorize.ErrAccessDenied, assert: answered(8, 403)},
		{name: "wrap-5", err: benchWrapN(authorize.ErrAccessDenied, 5), assert: answered(8, 403)},
		{
			name: "join-3-challenge",
			err: errors.Join(
				&httpsec.ChallengeError{Kind: policy.ChallengeMFA},
				authorize.ErrAccessDenied,
				errors.New("second sentinel"),
			),
			assert: answered(6, 401),
		},
		{name: "unknown", err: errors.New("nothing recognises this"), assert: answered(7, 0)},
		{name: "chain-50", err: benchWrapN(authorize.ErrAccessDenied, 50), assert: answered(8, 403)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := new(atomic.Int64)
			t.Cleanup(errwalk.SetArmHook(func() { n.Add(1) }))

			got := mapper.MapError(t.Context(), tc.err)
			tc.assert(t, n.Load(), got)
		})
	}
}
