package oidc_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
)

// flowStoreStart is the clock every flow store case begins at.
var flowStoreStart = time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

func flowStoreFlow(provider, state string, ttl time.Duration) oidc.Flow {
	return oidc.Flow{
		Provider: provider, State: state, Nonce: "nonce-" + state, Verifier: "verifier-" + state,
		Next: "/next-" + state, ExpiresAt: flowStoreStart.Add(ttl),
	}
}

// TestMemoryFlowStore pins the in-memory store's completion contract. Every
// refusal row makes the wrong call first and the right one after it: a store
// that spends the flow before it has judged the call passes the refusal and
// fails the retry.
func TestMemoryFlowStore(t *testing.T) {
	t.Parallel()

	victim := flowStoreFlow("a", "st", 10*time.Minute)

	type testCase struct {
		name string
		opts []oidc.MemoryFlowStoreOption
		// first is the call under test, made after the victim's flow is begun
		// under handle h.
		first func(t *testing.T, s *oidc.MemoryFlowStore, clock *clockwork.FakeClock, h string) error
		// assert receives first's error and the outcome of then completing the
		// victim's flow correctly.
		assert func(t *testing.T, first error, got oidc.Flow, retry error)
	}

	// stillCompletable is the pairing every refusal row shares.
	stillCompletable := func(t *testing.T, first error, got oidc.Flow, retry error) {
		require.ErrorIs(t, first, oidc.ErrInvalidState)
		require.NoError(t, retry, "a refused completion must leave the flow exactly as it was")
		assert.Equal(t, victim, got)
	}
	complete := func(handle, provider, state string) func(*testing.T, *oidc.MemoryFlowStore, *clockwork.FakeClock, string) error {
		return func(t *testing.T, s *oidc.MemoryFlowStore, _ *clockwork.FakeClock, h string) error {
			if handle == "" {
				handle = h
			}
			_, err := s.Complete(t.Context(), handle, provider, state)
			return err
		}
	}

	cases := []testCase{
		{
			name:  "the begun flow completes unchanged",
			first: func(*testing.T, *oidc.MemoryFlowStore, *clockwork.FakeClock, string) error { return nil },
			assert: func(t *testing.T, first error, got oidc.Flow, retry error) {
				require.NoError(t, first)
				require.NoError(t, retry)
				assert.Equal(t, victim, got)
			},
		},
		{name: "unknown handle", first: complete("nope", "a", "st"), assert: stillCompletable},
		{name: "wrong provider", first: complete("", "b", "st"), assert: stillCompletable},
		{name: "wrong state", first: complete("", "a", "attacker"), assert: stillCompletable},
		{name: "empty state", first: complete("", "a", ""), assert: stillCompletable},
		{name: "state differing only in case", first: complete("", "a", "ST"), assert: stillCompletable},
		{
			name: "a zero purge cutoff is refused and deletes nothing",
			first: func(t *testing.T, s *oidc.MemoryFlowStore, clock *clockwork.FakeClock, _ string) error {
				clock.Advance(time.Minute)
				n, err := s.DeleteExpired(t.Context(), time.Time{})
				assert.Zero(t, n)
				return err
			},
			assert: func(t *testing.T, first error, got oidc.Flow, retry error) {
				require.ErrorIs(t, first, oidc.ErrRetainSinceRequired)
				require.NoError(t, retry, "a refused purge must leave every flow completable")
				assert.Equal(t, victim, got)
			},
		},
		{
			name: "a purge removes only flows expired before the cutoff",
			first: func(t *testing.T, s *oidc.MemoryFlowStore, clock *clockwork.FakeClock, _ string) error {
				early, err := s.Begin(t.Context(), flowStoreFlow("a", "early", time.Minute))
				require.NoError(t, err)
				clock.Advance(2 * time.Minute)
				n, err := s.DeleteExpired(t.Context(), clock.Now())
				require.NoError(t, err)
				assert.Equal(t, 1, n, "the count is of the flows removed")
				_, err = s.Complete(t.Context(), early, "a", "early")
				assert.ErrorIs(t, err, oidc.ErrInvalidState)
				return nil
			},
			assert: func(t *testing.T, first error, got oidc.Flow, retry error) {
				require.NoError(t, first)
				require.NoError(t, retry, "a flow expiring after the cutoff must stay")
				assert.Equal(t, victim, got)
			},
		},
		{
			name: "an expired flow is refused",
			first: func(_ *testing.T, _ *oidc.MemoryFlowStore, c *clockwork.FakeClock, _ string) error {
				c.Advance(11 * time.Minute)
				return nil
			},
			assert: func(t *testing.T, _ error, _ oidc.Flow, retry error) {
				require.ErrorIs(t, retry, oidc.ErrInvalidState)
			},
		},
		{
			name: "a flow is refused at its expiry instant",
			first: func(_ *testing.T, _ *oidc.MemoryFlowStore, c *clockwork.FakeClock, _ string) error {
				c.Advance(10 * time.Minute)
				return nil
			},
			assert: func(t *testing.T, _ error, _ oidc.Flow, retry error) {
				require.ErrorIs(t, retry, oidc.ErrInvalidState)
			},
		},
		{
			name: "a flow completes just before its expiry",
			first: func(_ *testing.T, _ *oidc.MemoryFlowStore, c *clockwork.FakeClock, _ string) error {
				c.Advance(10*time.Minute - time.Nanosecond)
				return nil
			},
			assert: func(t *testing.T, _ error, got oidc.Flow, retry error) {
				require.NoError(t, retry)
				assert.Equal(t, victim, got)
			},
		},
		{
			name:  "a completed flow is refused the second time",
			first: complete("", "a", "st"),
			assert: func(t *testing.T, first error, _ oidc.Flow, second error) {
				require.NoError(t, first)
				require.ErrorIs(t, second, oidc.ErrInvalidState)
			},
		},
		{
			name: "the store refuses above its maximum and evicts nothing",
			opts: []oidc.MemoryFlowStoreOption{oidc.WithMaxFlows(2)},
			first: func(t *testing.T, s *oidc.MemoryFlowStore, _ *clockwork.FakeClock, _ string) error {
				second, err := s.Begin(t.Context(), flowStoreFlow("a", "second", 10*time.Minute))
				require.NoError(t, err)
				_, refused := s.Begin(t.Context(), flowStoreFlow("a", "third", 10*time.Minute))
				_, err = s.Complete(t.Context(), second, "a", "second")
				require.NoError(t, err, "a refused Begin must evict no flow")
				return refused
			},
			assert: func(t *testing.T, first error, got oidc.Flow, retry error) {
				require.ErrorIs(t, first, oidc.ErrFlowStoreFull)
				require.NoError(t, retry, "a refused Begin must evict no flow")
				assert.Equal(t, victim, got)
			},
		},
		{
			name: "expired flows do not count toward the maximum",
			opts: []oidc.MemoryFlowStoreOption{oidc.WithMaxFlows(2)},
			first: func(t *testing.T, s *oidc.MemoryFlowStore, c *clockwork.FakeClock, _ string) error {
				_, err := s.Begin(t.Context(), flowStoreFlow("a", "short", time.Minute))
				require.NoError(t, err)
				c.Advance(2 * time.Minute)
				_, err = s.Begin(t.Context(), flowStoreFlow("a", "later", 10*time.Minute))
				return err
			},
			assert: func(t *testing.T, first error, got oidc.Flow, retry error) {
				require.NoError(t, first, "an expired flow must be pruned to make room")
				require.NoError(t, retry)
				assert.Equal(t, victim, got)
			},
		},
		{
			name: "a full store refuses again until a flow expires",
			opts: []oidc.MemoryFlowStoreOption{oidc.WithMaxFlows(2)},
			first: func(t *testing.T, s *oidc.MemoryFlowStore, c *clockwork.FakeClock, _ string) error {
				_, err := s.Begin(t.Context(), flowStoreFlow("a", "short", 5*time.Minute))
				require.NoError(t, err)
				for range 2 {
					_, err = s.Begin(t.Context(), flowStoreFlow("a", "x", 10*time.Minute))
					require.ErrorIs(t, err, oidc.ErrFlowStoreFull)
				}
				c.Advance(5 * time.Minute)
				_, err = s.Begin(t.Context(), flowStoreFlow("a", "x", 10*time.Minute))
				return err
			},
			assert: func(t *testing.T, first error, got oidc.Flow, retry error) {
				require.NoError(t, first, "the flow that expired must make room")
				require.NoError(t, retry)
				assert.Equal(t, victim, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clock := clockwork.NewFakeClockAt(flowStoreStart)
			s, err := oidc.NewMemoryFlowStore(append([]oidc.MemoryFlowStoreOption{
				oidc.WithMemoryFlowStoreClock(clock),
			}, tc.opts...)...)
			require.NoError(t, err)
			h, err := s.Begin(t.Context(), victim)
			require.NoError(t, err)
			require.NotEmpty(t, h)

			first := tc.first(t, s, clock, h)
			got, retry := s.Complete(t.Context(), h, "a", "st")
			tc.assert(t, first, got, retry)
		})
	}
}

// TestMemoryFlowStoreOptions pins the store's defaults and the wiring
// mistakes its options refuse.
func TestMemoryFlowStoreOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []oidc.MemoryFlowStoreOption
		assert func(t *testing.T, build func() (*oidc.MemoryFlowStore, error))
	}

	refused := func(fragment string) func(t *testing.T, build func() (*oidc.MemoryFlowStore, error)) {
		return func(t *testing.T, build func() (*oidc.MemoryFlowStore, error)) {
			s, err := build()
			require.Nil(t, s, "a wiring mistake must not return a store")
			require.ErrorIs(t, err, oidc.ErrConfig)
			assert.Contains(t, err.Error(), fragment)
		}
	}
	var typedNilReader *errReader

	cases := []testCase{
		{
			name: "defaults need no options and hand out distinct random handles",
			assert: func(t *testing.T, build func() (*oidc.MemoryFlowStore, error)) {
				s, err := build()
				require.NoError(t, err)
				f := flowStoreFlow("a", "st", 24*time.Hour)
				f.ExpiresAt = time.Now().Add(time.Hour)
				h1, err := s.Begin(t.Context(), f)
				require.NoError(t, err)
				h2, err := s.Begin(t.Context(), f)
				require.NoError(t, err)
				assert.NotEqual(t, h1, h2)
				assert.Len(t, h1, 43, "a handle is 32 random bytes, base64url")
			},
		},
		{
			name: "the configured random source draws the handle",
			opts: []oidc.MemoryFlowStoreOption{oidc.WithMemoryFlowStoreRandom(errReader{})},
			assert: func(t *testing.T, build func() (*oidc.MemoryFlowStore, error)) {
				s, err := build()
				require.NoError(t, err)
				_, err = s.Begin(t.Context(), flowStoreFlow("a", "st", time.Hour))
				require.ErrorIs(t, err, errFlowRandom)
			},
		},
		{
			name: "a handle the store already holds is refused, not overwritten",
			opts: []oidc.MemoryFlowStoreOption{oidc.WithMemoryFlowStoreRandom(zeroReader{})},
			assert: func(t *testing.T, build func() (*oidc.MemoryFlowStore, error)) {
				s, err := build()
				require.NoError(t, err)
				f := flowStoreFlow("a", "st", time.Hour)
				f.ExpiresAt = time.Now().Add(time.Hour)
				h, err := s.Begin(t.Context(), f)
				require.NoError(t, err)
				other := f
				other.State = "attacker"
				_, err = s.Begin(t.Context(), other)
				require.Error(t, err)
				_, err = s.Complete(t.Context(), h, "a", "st")
				require.NoError(t, err, "the first flow must survive a colliding handle")
			},
		},
		{name: "a zero maximum is refused", opts: []oidc.MemoryFlowStoreOption{oidc.WithMaxFlows(0)},
			assert: refused("WithMaxFlows")},
		{name: "a negative maximum is refused", opts: []oidc.MemoryFlowStoreOption{oidc.WithMaxFlows(-1)},
			assert: refused("WithMaxFlows")},
		{name: "a nil clock is refused", opts: []oidc.MemoryFlowStoreOption{oidc.WithMemoryFlowStoreClock(nil)},
			assert: refused("WithMemoryFlowStoreClock")},
		{name: "a typed-nil clock is refused like an untyped one",
			opts:   []oidc.MemoryFlowStoreOption{oidc.WithMemoryFlowStoreClock((*nilClock)(nil))},
			assert: refused("WithMemoryFlowStoreClock")},
		{name: "a nil random source is refused", opts: []oidc.MemoryFlowStoreOption{oidc.WithMemoryFlowStoreRandom(nil)},
			assert: refused("WithMemoryFlowStoreRandom")},
		{name: "a typed-nil random source is refused",
			opts:   []oidc.MemoryFlowStoreOption{oidc.WithMemoryFlowStoreRandom(typedNilReader)},
			assert: refused("WithMemoryFlowStoreRandom")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, func() (*oidc.MemoryFlowStore, error) { return oidc.NewMemoryFlowStore(tc.opts...) })
		})
	}
}

// errFlowRandom is what errReader fails with.
var errFlowRandom = errors.New("random source failed")

// errReader is a random source that always fails.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errFlowRandom }

// zeroReader is a random source that yields only zero bytes, so every handle
// it draws is the same.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// flowStoreRacers is how many concurrent completions of one flow the race
// test starts.
const flowStoreRacers = 8

// TestMemoryFlowStoreRacingComplete pins single completion under concurrency:
// of eight callers completing one flow with the right arguments at once,
// exactly one succeeds and the rest are refused as for an unknown handle.
func TestMemoryFlowStoreRacingComplete(t *testing.T) {
	t.Parallel()

	clock := clockwork.NewFakeClockAt(flowStoreStart)
	s, err := oidc.NewMemoryFlowStore(oidc.WithMemoryFlowStoreClock(clock))
	require.NoError(t, err)
	h, err := s.Begin(t.Context(), flowStoreFlow("a", "st", 10*time.Minute))
	require.NoError(t, err)

	var (
		start = make(chan struct{})
		wg    sync.WaitGroup
		errs  = make([]error, flowStoreRacers)
	)
	for i := range flowStoreRacers {
		wg.Go(func() {
			<-start
			_, errs[i] = s.Complete(t.Context(), h, "a", "st")
		})
	}
	close(start)
	wg.Wait()

	won, lost := 0, 0
	for i, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, oidc.ErrInvalidState):
			lost++
		default:
			t.Errorf("completion %d failed with %v, not ErrInvalidState", i, err)
		}
	}
	assert.Equal(t, 1, won, "exactly one racing completion may succeed")
	assert.Equal(t, flowStoreRacers-1, lost)
}
