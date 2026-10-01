package recovery_test

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/recovery"
)

// codeStoreCase is one case of the CodeStore contract. It receives a fresh,
// empty store and exercises it through the contract alone, so any
// implementation can be held to it.
type codeStoreCase struct {
	name string
	run  func(t *testing.T, s recovery.CodeStore)
}

// storeTime is the instant every case stamps its writes with.
var storeTime = time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)

// testHashes returns n distinct 32-byte hashes, derived from label so two sets
// built with different labels share none.
func testHashes(label string, n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		h := sha256.Sum256(fmt.Appendf(nil, "%s-%d", label, i))
		out[i] = h[:]
	}

	return out
}

// codeStoreCases is the CodeStore contract, one case per behaviour the
// security-state-stores specification requires of a saved-code store. The
// cases are kept here, apart from any one store, because they are the seed of
// the conformance suite every durable store runs.
func codeStoreCases() []codeStoreCase {
	return []codeStoreCase{
		{
			name: "concurrent spends: exactly one of 8 succeeds, the rest look like an unknown code",
			run: func(t *testing.T, s recovery.CodeStore) {
				ctx := t.Context()
				hashes := testHashes("race", 10)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, storeTime))

				const callers = 8

				var (
					start = make(chan struct{})
					wg    sync.WaitGroup
					mu    sync.Mutex
					spent int
					errs  []error
				)

				for range callers {
					wg.Go(func() {
						<-start

						ok, err := s.Spend(ctx, "u-1", hashes[0], storeTime)

						mu.Lock()
						defer mu.Unlock()

						if err != nil {
							errs = append(errs, err)
						}
						if ok {
							spent++
						}
					})
				}

				close(start)
				wg.Wait()

				assert.Empty(t, errs)
				assert.Equal(t, 1, spent)

				n, err := s.Remaining(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 9, n)
			},
		},
		{
			name: "another user's hash is refused and the owner's code stays unspent",
			run: func(t *testing.T, s recovery.CodeStore) {
				ctx := t.Context()
				hashes := testHashes("owner", 1)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, storeTime))

				matched, err := s.Match(ctx, "u-2", hashes[0])
				require.NoError(t, err)
				assert.False(t, matched)

				ok, err := s.Spend(ctx, "u-2", hashes[0], storeTime)
				require.NoError(t, err)
				assert.False(t, ok)

				matched, err = s.Match(ctx, "u-1", hashes[0])
				require.NoError(t, err)
				assert.True(t, matched)

				n, err := s.Remaining(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 1, n)
			},
		},
		{
			name: "replacement is whole: no old code, spent or not, survives",
			run: func(t *testing.T, s recovery.CodeStore) {
				ctx := t.Context()
				old := testHashes("old", 10)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", old, storeTime))

				for _, h := range old[:3] {
					ok, err := s.Spend(ctx, "u-1", h, storeTime)
					require.NoError(t, err)
					require.True(t, ok)
				}

				fresh := testHashes("new", 10)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", fresh, storeTime.Add(time.Minute)))

				n, err := s.Remaining(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 10, n)

				for _, h := range old {
					matched, err := s.Match(ctx, "u-1", h)
					require.NoError(t, err)
					assert.False(t, matched)

					ok, err := s.Spend(ctx, "u-1", h, storeTime)
					require.NoError(t, err)
					assert.False(t, ok)
				}

				for _, h := range fresh {
					matched, err := s.Match(ctx, "u-1", h)
					require.NoError(t, err)
					assert.True(t, matched)
				}
			},
		},
		{
			name: "replacement touches no other user's set",
			run: func(t *testing.T, s recovery.CodeStore) {
				ctx := t.Context()
				require.NoError(t, s.ReplaceSet(ctx, "u-1", testHashes("one", 3), storeTime))
				require.NoError(t, s.ReplaceSet(ctx, "u-2", testHashes("two", 5), storeTime))

				n, err := s.Remaining(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 3, n)
			},
		},
		{
			name: "replacing with an empty set leaves the user none",
			run: func(t *testing.T, s recovery.CodeStore) {
				ctx := t.Context()
				require.NoError(t, s.ReplaceSet(ctx, "u-1", testHashes("gone", 4), storeTime))
				require.NoError(t, s.ReplaceSet(ctx, "u-1", nil, storeTime))

				n, err := s.Remaining(ctx, "u-1")
				require.NoError(t, err)
				assert.Zero(t, n)
			},
		},
		{
			name: "match writes nothing: three matches, then the code is still spendable",
			run: func(t *testing.T, s recovery.CodeStore) {
				ctx := t.Context()
				hashes := testHashes("match", 3)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, storeTime))

				for range 3 {
					matched, err := s.Match(ctx, "u-1", hashes[0])
					require.NoError(t, err)
					assert.True(t, matched)
				}

				n, err := s.Remaining(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 3, n)

				ok, err := s.Spend(ctx, "u-1", hashes[0], storeTime)
				require.NoError(t, err)
				assert.True(t, ok)
			},
		},
		{
			name: "a spent code neither matches nor spends again",
			run: func(t *testing.T, s recovery.CodeStore) {
				ctx := t.Context()
				hashes := testHashes("spent", 2)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, storeTime))

				ok, err := s.Spend(ctx, "u-1", hashes[0], storeTime)
				require.NoError(t, err)
				require.True(t, ok)

				matched, err := s.Match(ctx, "u-1", hashes[0])
				require.NoError(t, err)
				assert.False(t, matched)

				ok, err = s.Spend(ctx, "u-1", hashes[0], storeTime.Add(time.Minute))
				require.NoError(t, err)
				assert.False(t, ok)

				n, err := s.Remaining(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 1, n)
			},
		},
		{
			name: "an unknown code and an unknown user are refused without error",
			run: func(t *testing.T, s recovery.CodeStore) {
				ctx := t.Context()
				require.NoError(t, s.ReplaceSet(ctx, "u-1", testHashes("known", 2), storeTime))
				unknown := testHashes("unknown", 1)[0]

				matched, err := s.Match(ctx, "u-1", unknown)
				require.NoError(t, err)
				assert.False(t, matched)

				ok, err := s.Spend(ctx, "u-1", unknown, storeTime)
				require.NoError(t, err)
				assert.False(t, ok)

				n, err := s.Remaining(ctx, "nobody")
				require.NoError(t, err)
				assert.Zero(t, n)
			},
		},
		{
			name: "the caller's slices mutated after ReplaceSet leave the stored set unchanged",
			run: func(t *testing.T, s recovery.CodeStore) {
				ctx := t.Context()
				hashes := testHashes("owned", 2)
				original := append([]byte(nil), hashes[0]...)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, storeTime))

				hashes[0][0] ^= 0xFF
				hashes[1] = original // reusing the outer slice must not matter either

				matched, err := s.Match(ctx, "u-1", original)
				require.NoError(t, err)
				assert.True(t, matched)

				matched, err = s.Match(ctx, "u-1", hashes[0])
				require.NoError(t, err)
				assert.False(t, matched)

				n, err := s.Remaining(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 2, n)
			},
		},
		{
			name: "the presented hash slice mutated after a spend does not unspend the code",
			run: func(t *testing.T, s recovery.CodeStore) {
				ctx := t.Context()
				hashes := testHashes("presented", 1)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, storeTime))

				presented := append([]byte(nil), hashes[0]...)
				ok, err := s.Spend(ctx, "u-1", presented, storeTime)
				require.NoError(t, err)
				require.True(t, ok)

				presented[0] ^= 0xFF

				ok, err = s.Spend(ctx, "u-1", hashes[0], storeTime)
				require.NoError(t, err)
				assert.False(t, ok)
			},
		},
		{
			name: "delete user removes every code, spent or not, and reports how many",
			run: func(t *testing.T, s recovery.CodeStore) {
				ctx := t.Context()
				hashes := testHashes("delete", 4)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, storeTime))
				require.NoError(t, s.ReplaceSet(ctx, "u-2", testHashes("kept", 2), storeTime))

				ok, err := s.Spend(ctx, "u-1", hashes[0], storeTime)
				require.NoError(t, err)
				require.True(t, ok)

				removed, err := s.DeleteUser(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 4, removed)

				n, err := s.Remaining(ctx, "u-1")
				require.NoError(t, err)
				assert.Zero(t, n)

				matched, err := s.Match(ctx, "u-1", hashes[1])
				require.NoError(t, err)
				assert.False(t, matched)

				n, err = s.Remaining(ctx, "u-2")
				require.NoError(t, err)
				assert.Equal(t, 2, n)

				removed, err = s.DeleteUser(ctx, "u-1")
				require.NoError(t, err)
				assert.Zero(t, removed)
			},
		},
	}
}

func TestMemoryCodeStore(t *testing.T) {
	t.Parallel()

	for _, tc := range codeStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.run(t, recovery.NewMemoryCodeStore())
		})
	}
}
