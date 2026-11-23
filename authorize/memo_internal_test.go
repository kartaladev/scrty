// This internal test drives the memo's retry rounds directly: it needs to
// plant finished entries under the memo's lock, which no public API allows.
package authorize

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// TestMemoLoad_LiveWaiterLoadsForItselfAfterRounds keeps planting, under the
// memo's lock, a fresh entry for the key whose loading check's context had
// ended, before waking the waiter on the previous one. A live waiter thus
// never finds the key free and reaches its retry cap; it must then load for
// itself rather than return the last cancelled load's result.
func TestMemoLoad_LiveWaiterLoadsForItselfAfterRounds(t *testing.T) {
	t.Parallel()

	own := []*identity.ResourcePrivileges{{Group: "own", Resource: "own"}}

	type result struct {
		privileges []*identity.ResourcePrivileges
		err        error
	}

	type testCase struct {
		name       string
		privileges []*identity.ResourcePrivileges
		err        error
		assert     func(t *testing.T, got result, ownCalls int)
	}

	ownResult := func(t *testing.T, got result, ownCalls int) {
		t.Helper()
		require.NoError(t, got.err)
		assert.Equal(t, own, got.privileges)
		assert.Equal(t, 1, ownCalls, "the live waiter's own loader must run exactly once")
	}

	cases := []testCase{
		{
			name:   "cancelled load answered not-found",
			err:    identity.ErrPrivilegesNotFound,
			assert: ownResult,
		},
		{
			name:   "cancelled load answered nil, nil",
			assert: ownResult,
		},
		{
			name:   "cancelled load answered context.Canceled",
			err:    context.Canceled,
			assert: ownResult,
		},
		{
			name:       "cancelled load answered partial data",
			privileges: []*identity.ResourcePrivileges{{Group: "partial", Resource: "partial"}},
			assert:     ownResult,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := &requestMemo{entries: make(map[memoKey]*memoEntry)}
			key := memoKey{owner: &PrivilegeAuthorizer{}, role: "role"}

			ended := func() *memoEntry {
				return &memoEntry{
					done:        make(chan struct{}),
					privileges:  tc.privileges,
					err:         tc.err,
					loaderEnded: true,
				}
			}

			prev := ended()
			m.mu.Lock()
			m.entries[key] = prev
			m.mu.Unlock()

			// ownCalls is written only by the waiter's goroutine and read
			// after its result arrives, which orders the two.
			ownCalls := 0
			done := make(chan result, 1)

			go func() {
				privileges, err := m.load(t.Context(), key, func(context.Context) ([]*identity.ResourcePrivileges, error) {
					ownCalls++

					return own, nil
				})
				done <- result{privileges: privileges, err: err}
			}()

			var got result

		drive:
			for {
				next := ended()
				m.mu.Lock()
				m.entries[key] = next
				m.mu.Unlock()
				close(prev.done)
				prev = next

				select {
				case got = <-done:
					break drive
				case <-t.Context().Done():
					t.Fatal("the waiter never returned")
				default:
				}
			}

			close(prev.done)
			tc.assert(t, got, ownCalls)
		})
	}
}
