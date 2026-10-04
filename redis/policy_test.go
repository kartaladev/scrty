package scrtyredis_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	scrtyredis "github.com/kartaladev/scrty/redis"
)

// TestLimiter_Policy pins the "Shared limiter" scenario: the limiter reports,
// through the optional contract, the limit and window it was built with.
// Construction does no I/O, so a client pointed at nothing is enough.
func TestLimiter_Policy(t *testing.T) {
	t.Parallel()

	client, _ := recordingClient(t, nil)
	l, err := scrtyredis.NewLimiter(client, "ns", 10, 15*time.Minute)
	require.NoError(t, err)

	var r ratelimit.PolicyReporter = l
	limit, window := r.Policy()

	assert.Equal(t, 10, limit)
	assert.Equal(t, 15*time.Minute, window)
}
