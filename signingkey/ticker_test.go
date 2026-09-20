// The real-ticker tests are not parallel: goleak counts goroutines
// process-wide. They are the only tests that wait on real time, because they
// are the only ones asserting on the clock a consumer actually ships with.
package signingkey_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/signingkey"
)

// bareClock implements Clock and nothing more. It is the shape WithClock's
// godoc invites — "one that does not leaves the loops on time.NewTicker" — and
// the only way to reach that fallback: the default system clock happens to
// implement TickerClock, and every other test injects a clock that does too.
type bareClock struct{}

func (bareClock) Now() time.Time { return time.Now() }

// TestRealTickerDrivesTheLoops runs the loops on time.NewTicker, which is what
// every consumer that does not supply a TickerClock gets, and the one path a
// controlled clock can never exercise.
//
// The intervals are milliseconds so the test finishes, but nothing else is
// faked: a real tick has to rotate, and a real tick has to stop publishing the
// key that rotation replaced once it is past its lifetime.
func TestRealTickerDrivesTheLoops(t *testing.T) {
	type testCase struct {
		name string
		// clockOpt is how the case reaches the real ticker: a bare Clock takes
		// the fallback, and no option at all takes the default clock, which is
		// what a consumer configuring nothing runs on.
		clockOpt signingkey.Option
	}

	cases := []testCase{
		{name: "a consumer clock that paces nothing", clockOpt: signingkey.WithClock(bareClock{})},
		{name: "the default clock", clockOpt: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ignore := goleak.IgnoreCurrent()

			km, err := signingkey.NewKeyManager(t.Context(),
				signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
				signingkey.WithAlgs(signingkey.EdDSA),
				tc.clockOpt,
				signingkey.WithRotateInterval(50*time.Millisecond),
				signingkey.WithReloadInterval(10*time.Millisecond),
				signingkey.WithHousekeepingInterval(10*time.Millisecond),
				signingkey.WithLifetime(120*time.Millisecond),
			)
			require.NoError(t, err)

			first := currentKid(t, km, signingkey.EdDSA)
			require.NoError(t, km.Start(t.Context()))

			second := waitForRotation(t, km, signingkey.EdDSA, first)
			require.NotEqual(t, first, second, "a real tick rotates")

			assert.Eventually(t, func() bool { return !publishes(km, first) },
				10*time.Second, 5*time.Millisecond,
				"and a real tick stops publishing the replaced key once it is past its lifetime")

			require.NoError(t, km.Stop())
			assert.True(t, publishes(km, currentKid(t, km, signingkey.EdDSA)),
				"whatever is current when Stop returns is still published")
			goleak.VerifyNone(t, ignore)
		})
	}
}
