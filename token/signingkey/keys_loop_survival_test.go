// TestKeys_LoopSurvivesConsumerPlumbing pins two consumer faults that must not
// end a loop: a logger whose handler panics on the loop's own failure record,
// and a clock whose After returns a nil channel without panicking. Both end the
// process or the loop today, so each row runs in a child process: the child
// prints a marker line only once its checks have passed.
package signingkey_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token/signingkey"
)

const (
	survivalRowEnv = "SCRTY_SIGNINGKEY_SURVIVAL_ROW"
	survivalRan    = "signingkey-survival-row-ran:"
)

var errSurvivalStore = errors.New("survival: store write failed")

// panickingHandler panics on every Error record, as a broken consumer handler.
type panickingHandler struct{ slog.Handler }

func (h panickingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h panickingHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		panic("handler: " + hostileSecret)
	}

	return nil
}

// failingOnceStore fails the first Store once armed, then delegates.
type failingOnceStore struct {
	signingkey.KeyStore

	armed  atomic.Bool
	failed atomic.Bool
	stores atomic.Int32
}

func (s *failingOnceStore) Store(ctx context.Context, rec signingkey.Record) error {
	if s.armed.Load() {
		s.stores.Add(1)

		if s.failed.CompareAndSwap(false, true) {
			return errSurvivalStore
		}
	}

	return s.KeyStore.Store(ctx, rec)
}

// nilAfterClock returns a nil channel from After once armed.
type nilAfterClock struct {
	*clockwork.FakeClock

	armed atomic.Bool
}

func (c *nilAfterClock) After(d time.Duration) <-chan time.Time {
	if c.armed.Load() {
		return nil
	}

	return c.FakeClock.After(d)
}

func survivalRows() map[string]func(t *testing.T) {
	return map[string]func(t *testing.T){
		"a logger handler that panics on a failure record": func(t *testing.T) {
			store := &failingOnceStore{KeyStore: signingkey.NewMemoryKeyStore()}
			fake := newClock()
			logger := slog.New(panickingHandler{})

			km, err := signingkey.New(t.Context(),
				signingkey.WithAlgs(signingkey.ES256),
				signingkey.WithKeyStore(store),
				signingkey.WithClock(fake),
				signingkey.WithLogger(logger),
				signingkey.WithKeyLifetime(24*time.Hour),
				signingkey.WithRotateInterval(20*time.Millisecond),
				signingkey.WithReloadInterval(10*time.Millisecond),
				signingkey.WithHousekeepingInterval(10*time.Millisecond),
			)
			require.NoError(t, err)
			shutdownAndVerify(t, km)

			before := currentKid(t, km, signingkey.ES256)

			require.NoError(t, km.Start(t.Context()))
			awaitParked(t, fake, loopCount)
			store.armed.Store(true)

			advance(t, fake, 20*time.Millisecond, loopCount) // the write fails, the record panics
			require.Eventually(t, store.failed.Load, 10*time.Second, 5*time.Millisecond)
			advance(t, fake, 20*time.Millisecond, loopCount) // the loop must still be there

			require.Eventually(t, func() bool {
				return currentKid(t, km, signingkey.ES256) != before
			}, 10*time.Second, 5*time.Millisecond, "no rotation followed the panicking handler")
		},
		"a clock whose After returns a nil channel": func(t *testing.T) {
			store := &failingOnceStore{KeyStore: signingkey.NewMemoryKeyStore()}
			fake := newClock()
			clk := &nilAfterClock{FakeClock: fake}
			hooked := &failureReport{}

			km, err := signingkey.New(t.Context(),
				signingkey.WithAlgs(signingkey.ES256),
				signingkey.WithKeyStore(store),
				signingkey.WithClock(clk),
				signingkey.WithErrorHook(hooked.hook),
				signingkey.WithKeyLifetime(24*time.Hour),
				signingkey.WithRotateInterval(20*time.Millisecond),
				signingkey.WithReloadInterval(10*time.Millisecond),
				signingkey.WithHousekeepingInterval(10*time.Millisecond),
			)
			require.NoError(t, err)
			shutdownAndVerify(t, km)

			require.NoError(t, km.Start(t.Context()))
			awaitParked(t, fake, loopCount)
			clk.armed.Store(true)
			store.failed.Store(true) // the store never fails in this row
			store.armed.Store(true)

			fake.Advance(20 * time.Millisecond) // one rotation; every loop's next wait is nil

			require.Eventually(t, func() bool { return store.stores.Load() >= 2 },
				10*time.Second, 5*time.Millisecond, "no rotation after the nil wait: the loop stopped")

			errs, _ := hooked.snapshot()
			rotateWaits := 0

			for _, e := range errs {
				if strings.Contains(e.Error(), "next rotate run") {
					rotateWaits++
				}
			}

			assert.GreaterOrEqual(t, rotateWaits, 1, "the nil wait of the rotate loop is reported: %v", errs)
		},
	}
}

func TestKeys_LoopSurvivesConsumerPlumbing(t *testing.T) { //nolint:paralleltest // goleak counts goroutines process-wide
	childRow := os.Getenv(survivalRowEnv)

	for name, row := range survivalRows() {
		t.Run(name, func(t *testing.T) {
			if childRow == "" {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()

				top, _, _ := strings.Cut(t.Name(), "/")

				//nolint:gosec // G204: re-runs this test binary with this test's own name
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
				cmd.Env = append(os.Environ(), survivalRowEnv+"="+name)

				out, err := cmd.CombinedOutput()
				lines := strings.Split(strings.TrimSpace(string(out)), "\n")
				require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))
				assert.Contains(t, lines, survivalRan+name, "the child did not run its row")

				return
			}

			if childRow != name {
				t.Skip("another row's child")
			}

			row(t)

			if !t.Failed() {
				_, _ = fmt.Fprintln(os.Stdout, survivalRan+name)
			}
		})
	}
}
