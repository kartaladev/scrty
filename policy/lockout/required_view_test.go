package lockout_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy/lockout"
)

func TestPolicy_RequiredAttemptView(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []lockout.Option
		assert func(t *testing.T, p *lockout.Policy, required bool)
	}

	tests := []testCase{
		{
			name: "with a cap the policy requires its view",
			opts: []lockout.Option{lockout.WithCap(lockout.NISTCap)},
			assert: func(t *testing.T, _ *lockout.Policy, required bool) {
				assert.True(t, required)
			},
		},
		{
			name: "without a cap the policy does not require its view",
			assert: func(t *testing.T, _ *lockout.Policy, required bool) {
				assert.False(t, required)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := lockout.New(tc.opts...)
			require.NoError(t, err)

			view, required := p.RequiredAttemptView()

			assert.Same(t, p.Attempts(), view, "the view is the one the policy hands out")
			tc.assert(t, p, required)
		})
	}
}
