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

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/token/signingkey"
)

func TestSecurityEvents_SigningKeyRotated(t *testing.T) {
	type testCase struct {
		name string

		// sink is the option's argument, built over the row's recorder.
		sink func(rec *rotationEvents) event.Sink

		// rotate is whether the row starts the manager and lets one rotation
		// interval elapse.
		rotate bool

		// opts are added after the row's sink; store, when set, replaces the
		// memory key store.
		opts  []signingkey.Option
		store func(t *testing.T, report *failureReport) signingkey.KeyStore

		// alg is the algorithm whose current key the row reads; empty is
		// RS256.
		alg signingkey.Alg

		assert func(t *testing.T, rec *rotationEvents, km *signingkey.Keys, report *failureReport, err error)
	}

	cases := []testCase{
		{
			name:   "a rotation is reported once, at the clock's time, carrying no key material",
			sink:   func(rec *rotationEvents) event.Sink { return rec.sink },
			rotate: true,
			assert: func(t *testing.T, rec *rotationEvents, km *signingkey.Keys, _ *failureReport, err error) {
				require.NoError(t, err)

				got := rec.all()
				require.Len(t, got, 1)
				assert.Equal(t, event.SigningKeyRotated, got[0].Name)
				assert.Equal(t, event.OutcomeSuccess, got[0].Outcome)
				assert.Equal(t, epoch.Add(6*time.Hour), got[0].At)

				kid := currentKid(t, km, signingkey.RS256)
				for _, v := range []string{got[0].Session, got[0].ClientIP, string(got[0].User)} {
					assert.NotContains(t, v, kid)
				}
			},
		},
		{
			name: "a panicking sink: the rotation stands",
			sink: func(rec *rotationEvents) event.Sink {
				return func(ctx context.Context, e event.Event) {
					rec.sink(ctx, e)
					panic("sink")
				}
			},
			rotate: true,
			assert: func(t *testing.T, rec *rotationEvents, km *signingkey.Keys, _ *failureReport, err error) {
				require.NoError(t, err)
				assert.Len(t, rec.all(), 1)
				assert.NotEqual(t, rec.first, currentKid(t, km, signingkey.RS256), "the key rotated")
			},
		},
		{
			name:   "a rotation whose key could not be stored reports nothing",
			sink:   func(rec *rotationEvents) event.Sink { return rec.sink },
			rotate: true,
			opts:   []signingkey.Option{signingkey.WithAlgs(signingkey.EdDSA)},
			alg:    signingkey.EdDSA,
			store: func(t *testing.T, report *failureReport) signingkey.KeyStore {
				return failingStore(t, report, opRotate)
			},
			assert: func(t *testing.T, rec *rotationEvents, _ *signingkey.Keys, report *failureReport, err error) {
				require.NoError(t, err)

				_, rejected := report.snapshot()
				require.NotEmpty(t, rejected, "a rotation was tried and its key refused")
				assert.Empty(t, rec.all(), "only a key minted and stored is a rotation")
			},
		},
		{
			name: "the option given twice is a configuration error",
			sink: func(rec *rotationEvents) event.Sink { return rec.sink },
			opts: []signingkey.Option{signingkey.WithSecurityEvents(func(context.Context, event.Event) {})},
			assert: func(t *testing.T, _ *rotationEvents, _ *signingkey.Keys, _ *failureReport, err error) {
				require.ErrorIs(t, err, signingkey.ErrConfig)
			},
		},
		{
			name: "a nil sink is a configuration error",
			sink: func(*rotationEvents) event.Sink { return nil },
			assert: func(t *testing.T, _ *rotationEvents, _ *signingkey.Keys, _ *failureReport, err error) {
				require.ErrorIs(t, err, signingkey.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := newClock()
			rec := &rotationEvents{}
			report := &failureReport{}

			store := signingkey.KeyStore(signingkey.NewMemoryKeyStore())
			if tc.store != nil {
				store = tc.store(t, report)
			}

			km, err := signingkey.New(t.Context(), append([]signingkey.Option{
				signingkey.WithKeyStore(store),
				signingkey.WithClock(clk),
				signingkey.WithRotateInterval(6 * time.Hour),
				signingkey.WithReloadInterval(time.Minute),
				signingkey.WithHousekeepingInterval(time.Hour),
				signingkey.WithKeyLifetime(24 * time.Hour),
				signingkey.WithErrorHook(report.hook),
				signingkey.WithSecurityEvents(tc.sink(rec)),
			}, tc.opts...)...)
			if err == nil {
				shutdownAndVerify(t, km)
			}

			if tc.rotate {
				alg := tc.alg
				if alg == "" {
					alg = signingkey.RS256
				}

				rec.first = currentKid(t, km, alg)
				require.NoError(t, km.Start(t.Context()))
				advance(t, clk, 6*time.Hour, loopCount)
			}

			tc.assert(t, rec, km, report, err)
		})
	}
}

// rotationEvents keeps the events a manager reports.
type rotationEvents struct {
	mu     sync.Mutex
	events []event.Event
	first  string
}

func (r *rotationEvents) sink(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, e)
}

func (r *rotationEvents) all() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]event.Event(nil), r.events...)
}
