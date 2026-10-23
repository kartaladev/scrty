package gorm

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

func TestUntilSettled(t *testing.T) {
	t.Parallel()

	errPass := errors.New("pass failed")

	type testCase struct {
		name string
		// removed is what the i-th pass removes, or its error.
		removed func(i int) (int, error)
		assert  func(t *testing.T, passes, total int, err error)
	}

	cases := []testCase{
		{
			name: "stops at the first pass that removes nothing, summing the passes before it",
			removed: func(i int) (int, error) {
				if i < 3 {
					return 2, nil
				}
				return 0, nil
			},
			assert: func(t *testing.T, passes, total int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 4, passes)
				assert.Equal(t, 6, total)
			},
		},
		{
			name:    "gives up after maxDeletePasses passes that each removed something",
			removed: func(int) (int, error) { return 1, nil },
			assert: func(t *testing.T, passes, total int, err error) {
				require.ErrorIs(t, err, session.ErrDeleteDidNotSettle)
				require.ErrorIs(t, err, ErrDeleteDidNotSettle)
				assert.Equal(t, maxDeletePasses, passes)
				assert.Equal(t, maxDeletePasses, total, "what the passes removed is reported")
			},
		},
		{
			name: "a failing pass ends the delete with what the earlier passes removed",
			removed: func(i int) (int, error) {
				if i == 2 {
					return 0, errPass
				}
				return 5, nil
			},
			assert: func(t *testing.T, passes, total int, err error) {
				require.ErrorIs(t, err, errPass)
				assert.NotErrorIs(t, err, session.ErrDeleteDidNotSettle)
				assert.Equal(t, 3, passes)
				assert.Equal(t, 10, total)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			passes := 0
			total, err := untilSettled("delete", func() (int, error) {
				i := passes
				passes++
				return tc.removed(i)
			})
			tc.assert(t, passes, total, err)
		})
	}
}
