package ratelimit_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
)

// TestMemoryLimiter_Policy pins the "In-memory limiter" scenario: the limiter
// reports, through the optional contract, the limit and window it was built
// with.
func TestMemoryLimiter_Policy(t *testing.T) {
	t.Parallel()

	l, err := ratelimit.NewMemoryLimiter(20, time.Minute)
	require.NoError(t, err)

	var r ratelimit.PolicyReporter = l
	limit, window := r.Policy()

	assert.Equal(t, 20, limit)
	assert.Equal(t, time.Minute, window)
}
