package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
)

// flushablePolicy is a stubPolicy that also implements
// policy.RefusalLogFlusher, counting how many times FlushRefusalLogs was
// called on it. It shares stubPolicy's value semantics, so it registers on
// the engine exactly as any other policy in this file's tests does.
type flushablePolicy struct {
	stubPolicy
	flushes *int
}

func (p flushablePolicy) FlushRefusalLogs() error {
	*p.flushes++

	return nil
}

var _ policy.RefusalLogFlusher = flushablePolicy{}

// newFlushablePolicy returns a flushable policy registered for phases and a
// pointer to its own flush counter.
func newFlushablePolicy(name string, phases ...policy.Phase) (flushablePolicy, *int) {
	n := 0

	return flushablePolicy{stubPolicy: stubPolicy{name: name, phases: phases}, flushes: &n}, &n
}

// TestEngineFlushRefusalLogs pins spec http-security-chain scenario
// "Registered policy flushed": the engine reaches every registered policy
// that can flush, once each, skips one that cannot without panicking, and
// flushes a policy registered for more than one phase only once.
func TestEngineFlushRefusalLogs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) (e *policy.Engine, counts []*int)
		assert func(t *testing.T, counts []*int)
	}

	cases := []testCase{
		{
			name: "two flushable policies are each flushed once",
			build: func(t *testing.T) (*policy.Engine, []*int) {
				t.Helper()

				a, countA := newFlushablePolicy("a", policy.PerRequest)
				b, countB := newFlushablePolicy("b", policy.PerRequest)

				e, err := policy.NewEngine(a, b)
				require.NoError(t, err)

				return e, []*int{countA, countB}
			},
			assert: func(t *testing.T, counts []*int) {
				require.Len(t, counts, 2)
				assert.Equal(t, 1, *counts[0])
				assert.Equal(t, 1, *counts[1])
			},
		},
		{
			name: "a policy without a flush is skipped without a panic",
			build: func(t *testing.T) (*policy.Engine, []*int) {
				t.Helper()

				e, err := policy.NewEngine(stubPolicy{name: "no flush", phases: []policy.Phase{policy.PerRequest}})
				require.NoError(t, err)

				return e, nil
			},
			assert: func(t *testing.T, _ []*int) {
				t.Helper()
				// Reaching this closure at all is the assertion: a policy
				// with no RefusalLogFlusher must not panic the flush.
			},
		},
		{
			name: "a policy registered for two phases is flushed once",
			build: func(t *testing.T) (*policy.Engine, []*int) {
				t.Helper()

				p, count := newFlushablePolicy("both-phases", policy.PreAuthentication, policy.PostAuthentication)

				e, err := policy.NewEngine(p)
				require.NoError(t, err)

				return e, []*int{count}
			},
			assert: func(t *testing.T, counts []*int) {
				require.Len(t, counts, 1)
				assert.Equal(t, 1, *counts[0],
					"a policy registered for two phases must be flushed once, from asked, not once per phase")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, counts := tc.build(t)
			e.FlushRefusalLogs()
			tc.assert(t, counts)
		})
	}

	t.Run("a policy added after a first flush is flushed by the next", func(t *testing.T) {
		t.Parallel()

		e, err := policy.NewEngine()
		require.NoError(t, err)

		e.FlushRefusalLogs() // nothing registered yet; must not panic

		p, count := newFlushablePolicy("added-later", policy.PerRequest)
		require.NoError(t, e.Add(p))

		e.FlushRefusalLogs()
		assert.Equal(t, 1, *count, "the policy added after construction was never flushed")

		e.FlushRefusalLogs()
		assert.Equal(t, 2, *count, "a second flush must reach the same policy again")
	})
}
