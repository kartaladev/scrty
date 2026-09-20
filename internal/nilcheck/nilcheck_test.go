package nilcheck_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/nilcheck"
)

func TestIsNil(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		value  any
		assert func(t *testing.T, got bool)
	}

	var nilPointer *bytes.Buffer
	var nilMap map[string]string
	var nilFunc func()

	cases := []testCase{
		{
			name:   "an untyped nil interface",
			value:  nil,
			assert: func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			// What an unchecked constructor error hands over: the interface is
			// not nil, so `if v == nil` misses it, and the first call panics.
			name:   "a non-nil interface holding a nil pointer",
			value:  nilPointer,
			assert: func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			name:   "a nil map",
			value:  nilMap,
			assert: func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			name:   "a nil func",
			value:  nilFunc,
			assert: func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			name:   "a live value",
			value:  &bytes.Buffer{},
			assert: func(t *testing.T, got bool) { assert.False(t, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, nilcheck.IsNil(tc.value))
		})
	}
}
