package storefix

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChildSkipped(t *testing.T) {
	t.Parallel()

	const child = "TestX"

	tests := []struct {
		name   string
		output string
		assert func(t *testing.T, skipped bool)
	}{
		{
			name:   "the child skipping counts",
			output: "=== RUN   TestX\n--- SKIP: TestX (0.00s)\nSKIP\n",
			assert: func(t *testing.T, skipped bool) { assert.True(t, skipped) },
		},
		{
			name:   "a skipped nested subtest does not count",
			output: "=== RUN   TestX\n    --- SKIP: TestX/double/foo (0.00s)\n--- FAIL: TestX (0.01s)\n",
			assert: func(t *testing.T, skipped bool) { assert.False(t, skipped) },
		},
		{
			name:   "a skipped test whose name extends the child's does not count",
			output: "--- SKIP: TestXY (0.00s)\n",
			assert: func(t *testing.T, skipped bool) { assert.False(t, skipped) },
		},
		{
			name:   "no skip at all",
			output: "--- PASS: TestX (0.00s)\n",
			assert: func(t *testing.T, skipped bool) { assert.False(t, skipped) },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, childSkipped(tc.output, child))
		})
	}
}
