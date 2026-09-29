package clock_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/clock"
)

// clockwork's clocks satisfy both interfaces with no adapter (D1).
var (
	_ clock.Timed = clockwork.NewFakeClock()
	_ clock.Timed = clockwork.NewRealClock()
	_ clock.Clock = clockwork.NewFakeClock()
)

func TestSystem(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, c clock.Timed)
	}

	cases := []testCase{
		{
			name: "Now reads the system time",
			assert: func(t *testing.T, c clock.Timed) {
				before := time.Now()
				got := c.Now()
				after := time.Now()
				assert.False(t, got.Before(before))
				assert.False(t, got.After(after))
			},
		},
		{
			name: "After fires once the duration has passed",
			assert: func(t *testing.T, c clock.Timed) {
				start := time.Now()
				select {
				case fired := <-c.After(10 * time.Millisecond):
					assert.GreaterOrEqual(t, fired.Sub(start), 10*time.Millisecond)
				case <-time.After(5 * time.Second):
					require.FailNow(t, "After never fired")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, clock.System())
		})
	}
}
