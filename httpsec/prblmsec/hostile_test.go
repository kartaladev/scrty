package prblmsec_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/kartaladev/prblm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/policy"
)

// selfCycle unwraps to itself through Unwrap() error.
type selfCycle struct{}

func (c *selfCycle) Error() string { return "self cycle" }
func (c *selfCycle) Unwrap() error { return c }

// selfCycleMulti unwraps to itself through Unwrap() []error.
type selfCycleMulti struct{}

func (c *selfCycleMulti) Error() string   { return "self cycle multi" }
func (c *selfCycleMulti) Unwrap() []error { return []error{c} }

// panicsOnIs panics when asked whether it matches a target.
type panicsOnIs struct{}

func (panicsOnIs) Error() string { return "panics on Is" }
func (panicsOnIs) Is(error) bool { panic("hostile Is") }

// panicsOnAs panics when asked to present itself as a target.
type panicsOnAs struct{}

func (panicsOnAs) Error() string { return "panics on As" }
func (panicsOnAs) As(any) bool   { panic("hostile As") }

// flaky answers its first Unwrap with a refusal and panics on every later
// one, so a second walk of it disagrees with the first.
type flaky struct {
	mu    sync.Mutex
	calls int
}

func (*flaky) Error() string { return "flaky" }

func (f *flaky) Unwrap() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls++
	if f.calls > 1 {
		panic("second walk")
	}

	return authorize.ErrAccessDenied
}

// fanOut joins a node with itself, depth levels deep: 2^depth leaves.
func fanOut(depth int) error {
	n := errors.New("leaf")
	for range depth {
		n = errors.Join(n, n)
	}

	return n
}

// mapWatched maps err on its own goroutine under a 2 s watchdog, and reports a
// panic or a hang as a failure of the case, not of the process.
func mapWatched(t *testing.T, m prblm.Mapper, err error) *prblm.Problem {
	t.Helper()

	type result struct {
		prob     *prblm.Problem
		panicked any
	}

	done := make(chan result, 1)

	go func() {
		var r result

		defer func() {
			if v := recover(); v != nil {
				r.panicked = v
			}

			done <- r
		}()

		r.prob = m.MapError(context.Background(), err)
	}()

	select {
	case r := <-done:
		require.Nil(t, r.panicked, "the mapper let a panic escape")

		return r.prob
	case <-time.After(2 * time.Second):
		require.FailNow(t, "the mapper did not return within 2s")

		return nil
	}
}

// countingHandler keeps the messages of the records written to it.
type countingHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (*countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.msgs = append(h.msgs, r.Message)

	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

func (h *countingHandler) messages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]string(nil), h.msgs...)
}

// swapDefaultLogger makes a counting handler the default logger until the test
// ends. The caller's test must not run in parallel.
func swapDefaultLogger(t *testing.T) *countingHandler {
	t.Helper()

	h := &countingHandler{}
	prev := slog.Default()

	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return h
}

func TestMapper_HostileChains(t *testing.T) {
	// Not parallel: the serial row swaps slog.Default, and a parallel top-level
	// test would log into it. The other rows run in parallel under this one.
	type testCase struct {
		name string
		// serial rows swap slog.Default, so they cannot run in parallel.
		serial bool
		err    error
		assert func(t *testing.T, err error, prob *prblm.Problem)
	}

	// refused asserts the lookup gives up on err and the mapper answers nil.
	refused := func(t *testing.T, err error, prob *prblm.Problem) {
		t.Helper()
		_, ok := httpsec.LookupStatus(err)
		require.False(t, ok, "the lookup must give up on this chain")
		assert.Nil(t, prob)
	}
	// typed asserts the problem has the type sub and the lookup's status.
	typed := func(sub string, status int) func(t *testing.T, err error, prob *prblm.Problem) {
		return func(t *testing.T, err error, prob *prblm.Problem) {
			t.Helper()
			got, ok := httpsec.LookupStatus(err)
			require.True(t, ok)
			require.NotNil(t, prob)
			assert.Equal(t, got, prob.Status, "the mapper agrees with the lookup")
			assert.Equal(t, status, prob.Status)
			assert.Equal(t, "security/"+sub, prob.Type)
		}
	}

	mfa := func() *httpsec.ChallengeError {
		return &httpsec.ChallengeError{
			Kind: policy.ChallengeMFA, Methods: twoMethods,
			Token: "tok-as", TokenType: httpsec.TokenTypeBearer,
		}
	}
	typedNilChallenge := (*httpsec.ChallengeError)(nil)
	typedNilRejected := (*password.RejectedError)(nil)

	cases := []testCase{
		{name: "self-cycle through Unwrap() error", err: &selfCycle{}, assert: refused},
		{name: "self-cycle through Unwrap() []error", err: &selfCycleMulti{}, assert: refused},
		{name: "25-level join fan-out", err: fanOut(25), assert: refused},
		{name: "panicking Is", err: errors.Join(panicsOnIs{}, authorize.ErrAccessDenied), assert: refused},
		{name: "panicking As", err: errors.Join(panicsOnAs{}, mfa()), assert: refused},
		{
			name:   "typed-nil RejectedError joined ahead of access denied",
			err:    errors.Join(typedNilRejected, authorize.ErrAccessDenied),
			assert: typed("access-denied", 403),
		},
		{
			name: "typed-nil challenge joined ahead of a challenge through As",
			err:  errors.Join(typedNilChallenge, asChallenge{ch: mfa()}),
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				typed("mfa-required", 401)(t, err, prob)
				_, doc := document(t, prob)
				ext := extensions(doc)
				assert.Equal(t, "mfa", ext["challenge"])
				assert.Equal(t, "tok-as", ext["access_token"])
				assert.Contains(t, ext, "methods")
			},
		},
		{
			name:   "challenge inside the budget",
			err:    errors.Join(typedNilChallenge, wrapLayers(mfa(), errwalk.Budget-3)),
			assert: typed("mfa-required", 401),
		},
		{
			name:   "challenge past the budget",
			err:    errors.Join(typedNilChallenge, wrapLayers(mfa(), errwalk.Budget-2)),
			assert: refused,
		},
		{
			// The assert is the log check: the lookup's own record is the
			// only one, and the mapper adds none.
			name:   "an aborted chain writes one record, the lookup's",
			serial: true,
			err:    &selfCycle{},
			assert: func(t *testing.T, _ error, prob *prblm.Problem) {
				t.Helper()
				assert.Nil(t, prob)
			},
		},
	}

	m := newProblems(t).Mapper()

	for _, tc := range cases {
		if tc.serial {
			t.Run(tc.name, func(t *testing.T) {
				h := swapDefaultLogger(t)
				prob := mapWatched(t, m, tc.err)
				assert.Equal(t, []string{"httpsec: error classification aborted"}, h.messages(),
					"the lookup's record alone")
				tc.assert(t, tc.err, prob)
			})

			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.err, mapWatched(t, m, tc.err))
		})
	}
}

// TestMapper_SecondWalkGivesUp pins that a second walk that gives up, which
// only a nondeterministic chain can cause, answers nil and writes no record.
func TestMapper_SecondWalkGivesUp(t *testing.T) {
	h := swapDefaultLogger(t)
	m := newProblems(t).Mapper()

	prob := mapWatched(t, m, &flaky{})

	assert.Nil(t, prob)
	assert.Empty(t, h.messages(), "only the lookup logs, and its walk succeeded")
}
