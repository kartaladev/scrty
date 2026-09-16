package id_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/pkg/id"
)

func TestID_IsZero(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		value  id.ID
		assert func(t *testing.T, zero bool)
	}

	cases := []testCase{
		{
			name:   "unassigned value",
			value:  id.ID{},
			assert: func(t *testing.T, zero bool) { assert.True(t, zero) },
		},
		{
			name:   "Nil",
			value:  id.Nil,
			assert: func(t *testing.T, zero bool) { assert.True(t, zero) },
		},
		{
			name:   "any non-zero byte",
			value:  id.ID{15: 1},
			assert: func(t *testing.T, zero bool) { assert.False(t, zero) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.value.IsZero())
		})
	}
}
