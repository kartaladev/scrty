// Not parallel: goleak counts goroutines process-wide, as for the other
// rotation tests.
package signingkey_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/security"
	"github.com/kartaladev/scrty/token/signingkey"
)

func TestSecurityEvents_SigningKeyRotated(t *testing.T) {
	type testCase struct {
		name string

		// sink is the option's argument, built over the row's recorder.
		sink func(rec *rotationEvents) security.Sink

		// rotate is whether the row starts the manager and lets one rotation
		// interval elapse.
		rotate bool

		assert func(t *testing.T, rec *rotationEvents, km *signingkey.Keys, err error)
	}

	cases := []testCase{
		{
			name:   "a rotation is reported once, at the clock's time, carrying no key material",
			sink:   func(rec *rotationEvents) security.Sink { return rec.sink },
			rotate: true,
			assert: func(t *testing.T, rec *rotationEvents, km *signingkey.Keys, err error) {
				require.NoError(t, err)

				got := rec.all()
				require.Len(t, got, 1)
				assert.Equal(t, security.SigningKeyRotated, got[0].Name)
				assert.Equal(t, security.OutcomeSuccess, got[0].Outcome)
				assert.Equal(t, epoch.Add(6*time.Hour), got[0].At)

				kid := currentKid(t, km, signingkey.RS256)
				for _, v := range []string{got[0].Session, got[0].ClientIP, string(got[0].User)} {
					assert.NotContains(t, v, kid)
				}
			},
		},
		{
			name: "a panicking sink: the rotation stands",
			sink: func(rec *rotationEvents) security.Sink {
				return func(ctx context.Context, e security.Event) {
					rec.sink(ctx, e)
					panic("sink")
				}
			},
			rotate: true,
			assert: func(t *testing.T, rec *rotationEvents, km *signingkey.Keys, err error) {
				require.NoError(t, err)
				assert.Len(t, rec.all(), 1)
				assert.NotEqual(t, rec.first, currentKid(t, km, signingkey.RS256), "the key rotated")
			},
		},
		{
			name: "a nil sink is a configuration error",
			sink: func(*rotationEvents) security.Sink { return nil },
			assert: func(t *testing.T, _ *rotationEvents, _ *signingkey.Keys, err error) {
				require.ErrorIs(t, err, signingkey.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := newClock()
			rec := &rotationEvents{}

			km, err := signingkey.New(t.Context(),
				signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
				signingkey.WithClock(clk),
				signingkey.WithRotateInterval(6*time.Hour),
				signingkey.WithReloadInterval(time.Minute),
				signingkey.WithHousekeepingInterval(time.Hour),
				signingkey.WithKeyLifetime(24*time.Hour),
				signingkey.WithSecurityEvents(tc.sink(rec)),
			)
			if err == nil {
				shutdownAndVerify(t, km)
			}

			if tc.rotate {
				rec.first = currentKid(t, km, signingkey.RS256)
				require.NoError(t, km.Start(t.Context()))
				advance(t, clk, 6*time.Hour, loopCount)
			}

			tc.assert(t, rec, km, err)
		})
	}
}

// rotationEvents keeps the events a manager reports.
type rotationEvents struct {
	mu     sync.Mutex
	events []security.Event
	first  string
}

func (r *rotationEvents) sink(_ context.Context, e security.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, e)
}

func (r *rotationEvents) all() []security.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]security.Event(nil), r.events...)
}
