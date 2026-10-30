package recovery_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
)

// generousLimiter lets a test present many wrong codes without the default
// presentation limit getting in the way of what it is testing.
func generousLimiter(t *testing.T) ratelimit.Limiter {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(1000, time.Minute)
	require.NoError(t, err)

	return l
}

// hashOf is the hash a code is stored under.
func hashOf(t *testing.T, code string) []byte {
	t.Helper()

	h, err := recovery.ParseCode(code)
	require.NoError(t, err)

	return h[:]
}

// switchReader draws from crypto/rand until it is told to fail.
type switchReader struct{ fail atomic.Bool }

func (r *switchReader) Read(p []byte) (int, error) {
	if r.fail.Load() {
		return 0, errors.New("entropy exhausted")
	}

	return rand.Read(p)
}

func TestNewCodes_Config(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options []recovery.CodesOption
		assert  func(t *testing.T, c *recovery.Codes, err error)
	}

	refused := func(t *testing.T, c *recovery.Codes, err error) {
		require.ErrorIs(t, err, recovery.ErrConfig)
		assert.Nil(t, c)
	}

	cases := []testCase{
		{name: "set size 0", options: []recovery.CodesOption{recovery.WithCodesSetSize(0)}, assert: refused},
		{name: "set size -1", options: []recovery.CodesOption{recovery.WithCodesSetSize(-1)}, assert: refused},
		{name: "set size 101", options: []recovery.CodesOption{recovery.WithCodesSetSize(101)}, assert: refused},
		{name: "low threshold -1", options: []recovery.CodesOption{recovery.WithCodesLowThreshold(-1)}, assert: refused},
		{name: "nil store", options: []recovery.CodesOption{recovery.WithCodesStore(nil)}, assert: refused},
		{name: "typed nil store", options: []recovery.CodesOption{recovery.WithCodesStore((*recovery.MemoryCodeStore)(nil))}, assert: refused},
		{name: "nil limiter", options: []recovery.CodesOption{recovery.WithCodesLimiter(nil)}, assert: refused},
		{name: "typed nil limiter", options: []recovery.CodesOption{recovery.WithCodesLimiter((*ratelimit.MemoryLimiter)(nil))}, assert: refused},
		{name: "nil clock", options: []recovery.CodesOption{recovery.WithCodesClock(nil)}, assert: refused},
		{name: "nil random", options: []recovery.CodesOption{recovery.WithCodesRandom(nil)}, assert: refused},
		{
			name:    "set size 1 and 100 are the bounds, both allowed",
			options: []recovery.CodesOption{recovery.WithCodesSetSize(1), recovery.WithCodesSetSize(100)},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.NoError(t, err)

				codes := mustGenerate(t, c, "u-1")
				assert.Len(t, codes, 100)
			},
		},
		{
			name:    "low threshold 0 flags only an exhausted set",
			options: []recovery.CodesOption{recovery.WithCodesSetSize(1), recovery.WithCodesLowThreshold(0)},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.NoError(t, err)

				codes := mustGenerate(t, c, "u-1")

				count, err := c.Remaining(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, recovery.RemainingCodes{N: 1, Low: false}, count)

				spendCode(t, c, "u-1", codes[0])

				count, err = c.Remaining(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, recovery.RemainingCodes{N: 0, Low: true}, count)
			},
		},
		{
			name:    "a nil logger is ignored, not refused",
			options: []recovery.CodesOption{recovery.WithCodesLogger(nil)},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.NoError(t, err)
				assert.NotNil(t, c)
			},
		},
		{
			name: "defaults: 10 codes and a low threshold of 2",
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.NoError(t, err)

				codes := mustGenerate(t, c, "u-1")
				require.Len(t, codes, 10)

				for _, code := range codes[:7] {
					spendCode(t, c, "u-1", code)
				}

				count, err := c.Remaining(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, recovery.RemainingCodes{N: 3, Low: false}, count)

				spendCode(t, c, "u-1", codes[7])

				count, err = c.Remaining(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, recovery.RemainingCodes{N: 2, Low: true}, count)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := recovery.NewCodes(tc.options...)
			tc.assert(t, c, err)
		})
	}
}

func TestCodeThrottleKey(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "recovery-code|u-1", recovery.CodeThrottleKey("u-1"))
}

// TestCodes covers the manager's behaviour. Each row wires its own
// dependencies, because what a row proves is often which dependency was asked
// what, and in which order.
func TestCodes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T, ctrl *gomock.Controller) []recovery.CodesOption
		assert  func(t *testing.T, c *recovery.Codes)
	}

	key := recovery.CodeThrottleKey("u-1")
	storeFault := errors.New("store fault: row u-1 holds 7ZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZ")

	cases := []testCase{
		{
			name: "default count is 10 distinct codes of the pinned shape",
			assert: func(t *testing.T, c *recovery.Codes) {
				codes := mustGenerate(t, c, "u-1")
				require.Len(t, codes, 10)

				seen := map[string]bool{}
				for _, code := range codes {
					assert.Regexp(t, codeShape, code)
					assert.False(t, seen[code], "duplicate code")
					seen[code] = true
					require.NoError(t, c.Confirm(t.Context(), "u-1", code))
				}
			},
		},
		{
			name: "consumer count of 16",
			options: func(*testing.T, *gomock.Controller) []recovery.CodesOption {
				return []recovery.CodesOption{recovery.WithCodesSetSize(16)}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				codes := mustGenerate(t, c, "u-1")
				assert.Len(t, codes, 16)

				count, err := c.Remaining(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, 16, count.N)
			},
		},
		func() testCase {
			var stored [][]byte

			return testCase{
				name: "only 32-byte hashes of the decoded bytes reach the store, in one write, at the clock's time",
				options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
					store := NewMockCodeStore(ctrl)
					store.EXPECT().ReplaceSet(gomock.Any(), identity.UserID("u-1"), gomock.Len(10), codesTime).
						DoAndReturn(func(_ context.Context, _ identity.UserID, hashes [][]byte, _ time.Time) error {
							stored = hashes
							return nil
						}).Times(1)

					return []recovery.CodesOption{recovery.WithCodesStore(store)}
				},
				assert: func(t *testing.T, c *recovery.Codes) {
					codes := mustGenerate(t, c, "u-1")

					require.Len(t, stored, len(codes))

					for i, code := range codes {
						assert.Len(t, stored[i], 32)
						assert.Equal(t, hashOf(t, code), stored[i])
						assert.False(t, bytes.Contains(stored[i], []byte(code)))
						assert.False(t, bytes.Contains(stored[i], []byte(strings.ReplaceAll(code, "-", ""))))
					}
				},
			}
		}(),
		{
			name: "regeneration voids the old set, spent codes and unspent alike",
			options: func(t *testing.T, _ *gomock.Controller) []recovery.CodesOption {
				return []recovery.CodesOption{recovery.WithCodesLimiter(generousLimiter(t))}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				old := mustGenerate(t, c, "u-1")
				spendCode(t, c, "u-1", old[0])

				fresh := mustGenerate(t, c, "u-1")

				for _, code := range old {
					assert.ErrorIs(t, c.Confirm(t.Context(), "u-1", code), recovery.ErrRefused)
				}

				for _, code := range fresh {
					assert.NoError(t, c.Confirm(t.Context(), "u-1", code))
				}
			},
		},
		{
			name: "confirmation spends nothing",
			assert: func(t *testing.T, c *recovery.Codes) {
				codes := mustGenerate(t, c, "u-1")

				require.NoError(t, c.Confirm(t.Context(), "u-1", codes[0]))
				require.NoError(t, c.Confirm(t.Context(), "u-1", codes[0]))

				count, err := c.Remaining(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, 10, count.N)
			},
		},
		{
			name: "confirmation writes nothing to the store",
			options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				mem := recovery.NewMemoryCodeStore()
				store := NewMockCodeStore(ctrl)
				store.EXPECT().ReplaceSet(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(mem.ReplaceSet).Times(1)
				store.EXPECT().Match(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(mem.Match).Times(3)
				// No Spend, DeleteUser or further ReplaceSet: the mock fails on any.

				return []recovery.CodesOption{recovery.WithCodesStore(store)}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				codes := mustGenerate(t, c, "u-1")

				require.NoError(t, c.Confirm(t.Context(), "u-1", codes[0]))
				require.NoError(t, c.Confirm(t.Context(), "u-1", codes[1]))
				require.ErrorIs(t, c.Confirm(t.Context(), "u-1", wrongCode), recovery.ErrRefused)
			},
		},
		{
			name: "a spent code is refused",
			assert: func(t *testing.T, c *recovery.Codes) {
				codes := mustGenerate(t, c, "u-1")
				spendCode(t, c, "u-1", codes[0])

				assert.ErrorIs(t, c.Confirm(t.Context(), "u-1", codes[0]), recovery.ErrRefused)

				_, err := c.Check(t.Context(), "u-1", codes[0])
				assert.ErrorIs(t, err, recovery.ErrRefused)
			},
		},
		{
			name: "a spend that loses to another is refused",
			assert: func(t *testing.T, c *recovery.Codes) {
				codes := mustGenerate(t, c, "u-1")

				first, err := c.Check(t.Context(), "u-1", codes[0])
				require.NoError(t, err)
				second, err := c.Check(t.Context(), "u-1", codes[0])
				require.NoError(t, err)

				require.NoError(t, c.Spend(t.Context(), "u-1", first))
				assert.ErrorIs(t, c.Spend(t.Context(), "u-1", second), recovery.ErrRefused)
			},
		},
		{
			name: "racing spends: exactly one of 16 succeeds",
			assert: func(t *testing.T, c *recovery.Codes) {
				codes := mustGenerate(t, c, "u-1")

				hash, err := c.Check(t.Context(), "u-1", codes[0])
				require.NoError(t, err)

				var (
					start  = make(chan struct{})
					wg     sync.WaitGroup
					won    atomic.Int32
					others atomic.Int32
				)

				for range 16 {
					wg.Go(func() {
						<-start

						switch err := c.Spend(t.Context(), "u-1", hash); {
						case err == nil:
							won.Add(1)
						case errors.Is(err, recovery.ErrRefused):
							others.Add(1)
						}
					})
				}

				close(start)
				wg.Wait()

				assert.Equal(t, int32(1), won.Load())
				assert.Equal(t, int32(15), others.Load())
			},
		},
		{
			name: "the spend is stamped with the clock's time",
			options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				store := NewMockCodeStore(ctrl)
				store.EXPECT().Spend(gomock.Any(), identity.UserID("u-1"), gomock.Len(32), codesTime).Return(true, nil)

				return []recovery.CodesOption{recovery.WithCodesStore(store)}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				require.NoError(t, c.Spend(t.Context(), "u-1", [32]byte{1}))
			},
		},
		{
			name: "another user's code is refused",
			assert: func(t *testing.T, c *recovery.Codes) {
				codes := mustGenerate(t, c, "u-2")

				assert.ErrorIs(t, c.Confirm(t.Context(), "u-1", codes[0]), recovery.ErrRefused)
			},
		},
		{
			name: "the low count: 8 of 10 spent",
			assert: func(t *testing.T, c *recovery.Codes) {
				codes := mustGenerate(t, c, "u-1")

				for _, code := range codes[:8] {
					spendCode(t, c, "u-1", code)
				}

				count, err := c.Remaining(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, recovery.RemainingCodes{N: 2, Low: true}, count)
			},
		},
		{
			name: "consumer threshold 4: 4 left is low, 5 is not",
			options: func(*testing.T, *gomock.Controller) []recovery.CodesOption {
				return []recovery.CodesOption{recovery.WithCodesLowThreshold(4)}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				codes := mustGenerate(t, c, "u-1")

				for _, code := range codes[:5] {
					spendCode(t, c, "u-1", code)
				}

				count, err := c.Remaining(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, recovery.RemainingCodes{N: 5, Low: false}, count)

				spendCode(t, c, "u-1", codes[5])

				count, err = c.Remaining(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, recovery.RemainingCodes{N: 4, Low: true}, count)
			},
		},
		{
			name: "a user with no set has none, flagged low",
			assert: func(t *testing.T, c *recovery.Codes) {
				count, err := c.Remaining(t.Context(), "nobody")
				require.NoError(t, err)
				assert.Equal(t, recovery.RemainingCodes{N: 0, Low: true}, count)
			},
		},
		{
			name: "guessing: five wrong codes, then a valid one is throttled by the default limiter",
			assert: func(t *testing.T, c *recovery.Codes) {
				codes := mustGenerate(t, c, "u-1")

				for range 5 {
					require.ErrorIs(t, c.Confirm(t.Context(), "u-1", wrongCode), recovery.ErrRefused)
				}

				err := c.Confirm(t.Context(), "u-1", codes[0])
				require.ErrorIs(t, err, recovery.ErrCodeThrottled)
				require.ErrorIs(t, err, ratelimit.ErrThrottled)

				_, err = c.Check(t.Context(), "u-1", codes[0])
				require.ErrorIs(t, err, recovery.ErrCodeThrottled)

				// The limit is the user's: another user is unaffected.
				other := mustGenerate(t, c, "u-2")
				assert.NoError(t, c.Confirm(t.Context(), "u-2", other[0]))
			},
		},
		{
			name: "the limiter is asked before the store, and a wrong code is charged under the user's key",
			options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				limiter := NewMockLimiter(ctrl)
				store := NewMockCodeStore(ctrl)
				gomock.InOrder(
					limiter.EXPECT().Exceeded(gomock.Any(), key).Return(false, nil),
					store.EXPECT().Match(gomock.Any(), identity.UserID("u-1"), gomock.Len(32)).Return(false, nil),
					limiter.EXPECT().RecordFailure(gomock.Any(), key).Return(nil),
				)

				return []recovery.CodesOption{recovery.WithCodesLimiter(limiter), recovery.WithCodesStore(store)}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				assert.ErrorIs(t, c.Confirm(t.Context(), "u-1", wrongCode), recovery.ErrRefused)
			},
		},
		{
			name: "a good code is not charged",
			options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				limiter := NewMockLimiter(ctrl)
				store := NewMockCodeStore(ctrl)
				gomock.InOrder(
					limiter.EXPECT().Exceeded(gomock.Any(), key).Return(false, nil),
					store.EXPECT().Match(gomock.Any(), identity.UserID("u-1"), gomock.Len(32)).Return(true, nil),
				)

				return []recovery.CodesOption{recovery.WithCodesLimiter(limiter), recovery.WithCodesStore(store)}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				hash, err := c.Check(t.Context(), "u-1", wrongCode)
				require.NoError(t, err)
				assert.Equal(t, hashOf(t, wrongCode), hash[:])
			},
		},
		{
			name: "a throttled user is refused without the code being looked up or charged",
			options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				limiter := NewMockLimiter(ctrl)
				limiter.EXPECT().Exceeded(gomock.Any(), key).Return(true, nil)

				return []recovery.CodesOption{recovery.WithCodesLimiter(limiter), recovery.WithCodesStore(NewMockCodeStore(ctrl))}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				assert.ErrorIs(t, c.Confirm(t.Context(), "u-1", wrongCode), recovery.ErrCodeThrottled)
			},
		},
		{
			name: "a malformed code is charged and the store is not asked",
			options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				limiter := NewMockLimiter(ctrl)
				gomock.InOrder(
					limiter.EXPECT().Exceeded(gomock.Any(), key).Return(false, nil),
					limiter.EXPECT().RecordFailure(gomock.Any(), key).Return(nil),
				)

				return []recovery.CodesOption{recovery.WithCodesLimiter(limiter), recovery.WithCodesStore(NewMockCodeStore(ctrl))}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				assert.ErrorIs(t, c.Confirm(t.Context(), "u-1", "UUUU-0000"), recovery.ErrRefused)
			},
		},
		{
			name: "an already cancelled context still records the failure",
			options: func(t *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				limiter := NewMockLimiter(ctrl)
				// A limiter that honours its context cannot answer on an ended
				// one, as the port says to expect.
				limiter.EXPECT().Exceeded(gomock.Any(), key).DoAndReturn(honouringExceeded)
				limiter.EXPECT().RecordFailure(gomock.Any(), key).
					DoAndReturn(func(ctx context.Context, _ string) error {
						assert.NoError(t, ctx.Err())
						return nil
					})

				return []recovery.CodesOption{recovery.WithCodesLimiter(limiter), recovery.WithCodesStore(NewMockCodeStore(ctrl))}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				assert.ErrorIs(t, c.Confirm(ctx, "u-1", "not a code"), recovery.ErrRefused)
			},
		},
		{
			name: "a client hanging up during the lookup is still charged",
			options: func(t *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				limiter := NewMockLimiter(ctrl)
				store := NewMockCodeStore(ctrl)
				gomock.InOrder(
					limiter.EXPECT().Exceeded(gomock.Any(), key).DoAndReturn(honouringExceeded),
					// A store that honours its context abandons the lookup with the
					// context's error, as a database driver does.
					store.EXPECT().Match(gomock.Any(), identity.UserID("u-1"), gomock.Any()).
						DoAndReturn(func(ctx context.Context, _ identity.UserID, _ []byte) (bool, error) {
							ctx.Value(hangUpKey{}).(context.CancelFunc)()
							return false, ctx.Err()
						}),
					limiter.EXPECT().RecordFailure(gomock.Any(), key).
						DoAndReturn(func(ctx context.Context, _ string) error {
							assert.NoError(t, ctx.Err())
							return nil
						}),
				)

				return []recovery.CodesOption{recovery.WithCodesLimiter(limiter), recovery.WithCodesStore(store)}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				ctx, cancel := context.WithCancel(t.Context())
				ctx = context.WithValue(ctx, hangUpKey{}, cancel)

				err := c.Confirm(ctx, "u-1", wrongCode)
				require.ErrorIs(t, err, context.Canceled)
			},
		},
		{
			name: "the default limiter charges wrong codes on an ended context: five, then a valid code is throttled",
			assert: func(t *testing.T, c *recovery.Codes) {
				codes := mustGenerate(t, c, "u-1")

				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				for range 5 {
					assert.Error(t, c.Confirm(ctx, "u-1", wrongCode))
				}

				assert.ErrorIs(t, c.Confirm(t.Context(), "u-1", codes[0]), recovery.ErrCodeThrottled)
			},
		},
		func() testCase {
			limiter, err := ratelimit.NewMemoryLimiter(1, time.Minute)
			if err != nil {
				panic(err)
			}

			return testCase{
				name: "a store abandoning the lookup because the client hung up still charges the user",
				options: func(*testing.T, *gomock.Controller) []recovery.CodesOption {
					return []recovery.CodesOption{
						recovery.WithCodesLimiter(limiter),
						recovery.WithCodesStore(hangingUpStore{recovery.NewMemoryCodeStore()}),
					}
				},
				assert: func(t *testing.T, c *recovery.Codes) {
					ctx, cancel := context.WithCancel(t.Context())
					ctx = context.WithValue(ctx, hangUpKey{}, cancel)

					err := c.Confirm(ctx, "u-1", wrongCode)
					require.ErrorIs(t, err, context.Canceled)

					exceeded, err := limiter.Exceeded(t.Context(), key)
					require.NoError(t, err)
					assert.True(t, exceeded, "the abandoned presentation was not charged")
				},
			}
		}(),
		{
			name: "a limiter that cannot decide refuses without a lookup",
			options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				limiter := NewMockLimiter(ctrl)
				limiter.EXPECT().Exceeded(gomock.Any(), key).Return(false, errors.New("limiter unreachable"))

				return []recovery.CodesOption{recovery.WithCodesLimiter(limiter), recovery.WithCodesStore(NewMockCodeStore(ctrl))}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				err := c.Confirm(t.Context(), "u-1", wrongCode)
				require.ErrorIs(t, err, recovery.ErrCodeThrottled)
				assert.NotContains(t, err.Error(), "limiter unreachable")
			},
		},
		{
			name: "a limiter that cannot record leaves the refusal as it was",
			options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				limiter := NewMockLimiter(ctrl)
				limiter.EXPECT().Exceeded(gomock.Any(), key).Return(false, nil)
				limiter.EXPECT().RecordFailure(gomock.Any(), key).Return(errors.New("limiter unreachable"))

				return []recovery.CodesOption{recovery.WithCodesLimiter(limiter)}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				err := c.Confirm(t.Context(), "u-1", wrongCode)
				require.ErrorIs(t, err, recovery.ErrRefused)
				assert.NotContains(t, err.Error(), "limiter unreachable")
			},
		},
		{
			name: "a store that cannot answer is an error, not a refusal, and nobody is charged",
			options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				limiter := NewMockLimiter(ctrl)
				limiter.EXPECT().Exceeded(gomock.Any(), key).Return(false, nil)
				store := NewMockCodeStore(ctrl)
				store.EXPECT().Match(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, storeFault)

				return []recovery.CodesOption{recovery.WithCodesLimiter(limiter), recovery.WithCodesStore(store)}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				_, err := c.Check(t.Context(), "u-1", wrongCode)
				require.ErrorIs(t, err, storeFault)
				assert.NotErrorIs(t, err, recovery.ErrRefused)
				assert.NotContains(t, err.Error(), storeFault.Error())
			},
		},
		{
			name: "a store that cannot spend is an error carrying none of its text",
			options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				store := NewMockCodeStore(ctrl)
				store.EXPECT().Spend(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, storeFault)

				return []recovery.CodesOption{recovery.WithCodesStore(store)}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				err := c.Spend(t.Context(), "u-1", [32]byte{1})
				require.ErrorIs(t, err, storeFault)
				assert.NotErrorIs(t, err, recovery.ErrRefused)
				assert.NotContains(t, err.Error(), storeFault.Error())
			},
		},
		{
			name: "a store that cannot replace the set returns no codes",
			options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				store := NewMockCodeStore(ctrl)
				store.EXPECT().ReplaceSet(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(storeFault)

				return []recovery.CodesOption{recovery.WithCodesStore(store)}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				codes, err := c.Generate(t.Context(), "u-1")
				require.ErrorIs(t, err, storeFault)
				assert.Nil(t, codes)
				assert.NotContains(t, err.Error(), storeFault.Error())
			},
		},
		{
			name: "a store that cannot count is an error carrying none of its text",
			options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				store := NewMockCodeStore(ctrl)
				store.EXPECT().Remaining(gomock.Any(), identity.UserID("u-1")).Return(0, storeFault)

				return []recovery.CodesOption{recovery.WithCodesStore(store)}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				count, err := c.Remaining(t.Context(), "u-1")
				require.ErrorIs(t, err, storeFault)
				assert.Equal(t, recovery.RemainingCodes{}, count)
				assert.NotContains(t, err.Error(), storeFault.Error())
			},
		},
		func() testCase {
			random := &switchReader{}

			return testCase{
				name: "a random failure leaves the existing set",
				options: func(*testing.T, *gomock.Controller) []recovery.CodesOption {
					return []recovery.CodesOption{recovery.WithCodesRandom(random)}
				},
				assert: func(t *testing.T, c *recovery.Codes) {
					codes := mustGenerate(t, c, "u-1")

					random.fail.Store(true)

					again, err := c.Generate(t.Context(), "u-1")
					require.Error(t, err)
					assert.Nil(t, again)

					count, err := c.Remaining(t.Context(), "u-1")
					require.NoError(t, err)
					assert.Equal(t, 10, count.N)

					for _, code := range codes {
						assert.NoError(t, c.Confirm(t.Context(), "u-1", code))
					}
				},
			}
		}(),
		{
			name: "a random source failing part way through a set writes nothing",
			options: func(_ *testing.T, ctrl *gomock.Controller) []recovery.CodesOption {
				partial := io.MultiReader(bytes.NewReader(make([]byte, 3*recovery.CodeBytes)), iotest.ErrReader(errors.New("entropy exhausted")))
				// No ReplaceSet expected: the mock fails on any store call.
				return []recovery.CodesOption{recovery.WithCodesRandom(partial), recovery.WithCodesStore(NewMockCodeStore(ctrl))}
			},
			assert: func(t *testing.T, c *recovery.Codes) {
				codes, err := c.Generate(t.Context(), "u-1")
				require.Error(t, err)
				assert.Nil(t, codes)
				assert.NotContains(t, err.Error(), "entropy exhausted")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			var opts []recovery.CodesOption
			if tc.options != nil {
				opts = tc.options(t, ctrl)
			}

			tc.assert(t, newCodes(t, opts...))
		})
	}
}

// hangUpKey carries the cancel function a store call uses to simulate the
// client hanging up mid-lookup.
type hangUpKey struct{}

// honouringExceeded is what a limiter that honours its context answers: an
// error on an ended context, true beside it, and otherwise not exceeded.
func honouringExceeded(ctx context.Context, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return true, fmt.Errorf("check %q: %w", key, err)
	}

	return false, nil
}

// hangingUpStore is a memory store whose lookup simulates the client hanging up
// mid-lookup, and then abandons it with the context's error, as a driver that
// honours its context does.
type hangingUpStore struct{ *recovery.MemoryCodeStore }

func (s hangingUpStore) Match(ctx context.Context, _ identity.UserID, _ []byte) (bool, error) {
	ctx.Value(hangUpKey{}).(context.CancelFunc)()

	return false, ctx.Err()
}

// TestCodes_NoCodesInLogs holds every log record and every returned error to
// the rule that no code, in any spelling, is written. It stands apart from
// TestCodes because it captures the logger and runs a whole sequence against
// one manager, rather than asserting one behaviour.
func TestCodes_NoCodesInLogs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctrl := gomock.NewController(t)
	mem := recovery.NewMemoryCodeStore()
	store := NewMockCodeStore(ctrl)
	store.EXPECT().ReplaceSet(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(mem.ReplaceSet).AnyTimes()
	store.EXPECT().Spend(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(mem.Spend).AnyTimes()
	store.EXPECT().Remaining(gomock.Any(), gomock.Any()).DoAndReturn(mem.Remaining).AnyTimes()

	// The first lookup answers; the second fails with text quoting the code, as
	// a careless dependency might.
	var codes []string
	gomock.InOrder(
		store.EXPECT().Match(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(mem.Match).Times(2),
		store.EXPECT().Match(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(context.Context, identity.UserID, []byte) (bool, error) {
				return false, errors.New("lookup failed for " + codes[1])
			}),
	)

	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).Times(3)
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, errors.New("limiter down"))
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(errors.New("record failed")).AnyTimes()

	c := newCodes(t,
		recovery.WithCodesLogger(logger),
		recovery.WithCodesStore(store),
		recovery.WithCodesLimiter(limiter),
	)

	codes = mustGenerate(t, c, "u-1")

	wrong := codes[0][:len(codes[0])-1] + "Z"
	if wrong == codes[0] {
		wrong = codes[0][:len(codes[0])-1] + "Y"
	}

	var errs []error
	errs = append(errs, c.Confirm(t.Context(), "u-1", wrong))    // wrong
	errs = append(errs, c.Confirm(t.Context(), "u-1", codes[0])) // right
	errs = append(errs, c.Confirm(t.Context(), "u-1", codes[1])) // store fails
	errs = append(errs, c.Confirm(t.Context(), "u-1", codes[2])) // limiter fails

	require.ErrorIs(t, errs[0], recovery.ErrRefused)
	require.NoError(t, errs[1])
	require.Error(t, errs[2])
	require.ErrorIs(t, errs[3], recovery.ErrCodeThrottled)

	logs := buf.String()
	require.NotEmpty(t, logs, "the failures above must have been logged, or this test proves nothing")

	for _, code := range append(codes, wrong) {
		for _, spelling := range []string{code, strings.ReplaceAll(code, "-", ""), strings.ToLower(code)} {
			assert.NotContains(t, logs, spelling)

			for _, err := range errs {
				if err != nil {
					assert.NotContains(t, err.Error(), spelling)
				}
			}
		}
	}
}

// levelRecorder is a slog handler that keeps each record's level and message,
// so a test can say at which level a failure was written.
type levelRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *levelRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (h *levelRecorder) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.records = append(h.records, r)

	return nil
}

func (h *levelRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *levelRecorder) WithGroup(string) slog.Handler      { return h }

// levels returns the level of every record written with msg.
func (h *levelRecorder) levels(msg string) []slog.Level {
	h.mu.Lock()
	defer h.mu.Unlock()

	var out []slog.Level

	for _, r := range h.records {
		if r.Message == msg {
			out = append(out, r.Level)
		}
	}

	return out
}

// TestCodes_FailureLogLevel pins that a dependency failure the caller's own
// cancellation caused is written at debug level — a client that hung up is not
// an incident — while every other dependency failure stays at error level.
func TestCodes_FailureLogLevel(t *testing.T) {
	t.Parallel()

	const (
		msgLimiter = "recovery: saved-code limiter could not be consulted"
		msgStore   = "recovery: saved-code store failed"
	)

	type testCase struct {
		name    string
		options func(ctrl *gomock.Controller) []recovery.CodesOption
		ctx     func(ctx context.Context) context.Context
		msg     string
		assert  func(t *testing.T, levels []slog.Level)
	}

	hangingUp := func(ctx context.Context) context.Context {
		ctx, cancel := context.WithCancel(ctx)

		return context.WithValue(ctx, hangUpKey{}, cancel)
	}
	ended := func(ctx context.Context) context.Context {
		ctx, cancel := context.WithCancel(ctx)
		cancel()

		return ctx
	}
	atLevel := func(want slog.Level) func(t *testing.T, levels []slog.Level) {
		return func(t *testing.T, levels []slog.Level) {
			assert.Equal(t, []slog.Level{want}, levels)
		}
	}

	cases := []testCase{
		{
			name: "a lookup abandoned because the client hung up is written at debug",
			options: func(*gomock.Controller) []recovery.CodesOption {
				return []recovery.CodesOption{
					recovery.WithCodesLimiter(generousLimiter(t)),
					recovery.WithCodesStore(hangingUpStore{recovery.NewMemoryCodeStore()}),
				}
			},
			ctx:    hangingUp,
			msg:    msgStore,
			assert: atLevel(slog.LevelDebug),
		},
		{
			name: "a store fault on a live context is written at error",
			options: func(ctrl *gomock.Controller) []recovery.CodesOption {
				store := NewMockCodeStore(ctrl)
				store.EXPECT().Match(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, errors.New("store down"))

				return []recovery.CodesOption{recovery.WithCodesLimiter(generousLimiter(t)), recovery.WithCodesStore(store)}
			},
			msg:    msgStore,
			assert: atLevel(slog.LevelError),
		},
		{
			name: "a limiter failing with the caller's own cancellation is written at debug",
			options: func(ctrl *gomock.Controller) []recovery.CodesOption {
				limiter := NewMockLimiter(ctrl)
				limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
					Return(true, fmt.Errorf("limiter call: %w", context.Canceled))

				return []recovery.CodesOption{recovery.WithCodesLimiter(limiter)}
			},
			ctx:    ended,
			msg:    msgLimiter,
			assert: atLevel(slog.LevelDebug),
		},
		{
			name: "a limiter outage on an ended context is still written at error",
			options: func(ctrl *gomock.Controller) []recovery.CodesOption {
				limiter := NewMockLimiter(ctrl)
				limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, errors.New("limiter down"))

				return []recovery.CodesOption{recovery.WithCodesLimiter(limiter)}
			},
			ctx:    ended,
			msg:    msgLimiter,
			assert: atLevel(slog.LevelError),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := &levelRecorder{}
			opts := append(tc.options(gomock.NewController(t)), recovery.WithCodesLogger(slog.New(rec)))
			c := newCodes(t, opts...)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			require.Error(t, c.Confirm(ctx, "u-1", wrongCode))
			tc.assert(t, rec.levels(tc.msg))
		})
	}
}

// codeShape is the only shape a generated code may take: 26 Crockford base32
// characters grouped in fours with dashes, the first in 0–7 because 128 bits
// fill 130 bits of capacity with two leading zeros.
var codeShape = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{3}(-[0-9A-HJKMNP-TV-Z]{4}){5}-[0-9A-HJKMNP-TV-Z]{2}$`)

// TestCodeBytesPinned pins the entropy of a saved code. The constant is the
// whole guarantee that codes carry 128 bits, so a change that shortens it must
// fail here rather than ship.
func TestCodeBytesPinned(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 16, recovery.CodeBytes)
}

func TestNewCode(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		random io.Reader
		assert func(t *testing.T, text string, hash [32]byte, err error)
	}

	fixed := func(b ...byte) []byte {
		out := make([]byte, 16)
		copy(out[16-len(b):], b)

		return out
	}
	allOnes := bytes.Repeat([]byte{0xFF}, 16)

	cases := []testCase{
		{
			name:   "all zero bytes encode to all zeros",
			random: bytes.NewReader(fixed()),
			assert: func(t *testing.T, text string, hash [32]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, "0000-0000-0000-0000-0000-0000-00", text)
				assert.Equal(t, sha256.Sum256(fixed()), hash)
			},
		},
		{
			name:   "a value of one encodes to a trailing one",
			random: bytes.NewReader(fixed(0x01)),
			assert: func(t *testing.T, text string, hash [32]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, "0000-0000-0000-0000-0000-0000-01", text)
				assert.Equal(t, sha256.Sum256(fixed(0x01)), hash)
			},
		},
		{
			name:   "all one bits start with 7 and fill with Z",
			random: bytes.NewReader(allOnes),
			assert: func(t *testing.T, text string, hash [32]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, "7ZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZ", text)
				assert.Equal(t, sha256.Sum256(allOnes), hash)
			},
		},
		{
			name:   "the hash is SHA-256 of the 16 bytes read, not of the text",
			random: bytes.NewReader([]byte("0123456789abcdef")),
			assert: func(t *testing.T, text string, hash [32]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, sha256.Sum256([]byte("0123456789abcdef")), hash)
				assert.NotEqual(t, sha256.Sum256([]byte(text)), hash)
			},
		},
		{
			name:   "a failing random source is an error with no code",
			random: iotest.ErrReader(errors.New("entropy exhausted")),
			assert: func(t *testing.T, text string, hash [32]byte, err error) {
				require.Error(t, err)
				assert.Empty(t, text)
				assert.Equal(t, [32]byte{}, hash)
			},
		},
		{
			name:   "a random source that runs short is an error with no code",
			random: bytes.NewReader(make([]byte, 10)),
			assert: func(t *testing.T, text string, hash [32]byte, err error) {
				require.Error(t, err)
				assert.Empty(t, text)
				assert.Equal(t, [32]byte{}, hash)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			text, hash, err := recovery.NewCode(tc.random)
			tc.assert(t, text, hash, err)
		})
	}
}

// TestNewCode_Shape generates many codes from the real random source and holds
// every one to the pinned shape: grouped, 26 alphabet characters, decoding to
// the 16 bytes whose hash it was stored under.
// It stands apart from TestNewCode because it loops over the real random source
// and round-trips each code through ParseCode.
func TestNewCode_Shape(t *testing.T) {
	t.Parallel()

	for range 1000 {
		text, hash, err := recovery.NewCode(rand.Reader)
		require.NoError(t, err)

		require.Regexp(t, codeShape, text)
		assert.Len(t, strings.ReplaceAll(text, "-", ""), 26)

		parsed, err := recovery.ParseCode(text)
		require.NoError(t, err)
		require.Equal(t, hash, parsed)
	}
}

func TestParseCode(t *testing.T) {
	t.Parallel()

	// A code built from a value of one holds both 0 and 1, which is what the
	// look-alike row needs.
	oneBytes := make([]byte, 16)
	oneBytes[15] = 0x01
	oneText, oneHash, err := recovery.NewCode(bytes.NewReader(oneBytes))
	require.NoError(t, err)
	require.Equal(t, "0000-0000-0000-0000-0000-0000-01", oneText)

	text, hash, err := recovery.NewCode(rand.Reader)
	require.NoError(t, err)

	dashless := strings.ReplaceAll(text, "-", "")

	type testCase struct {
		name      string
		presented string
		assert    func(t *testing.T, got [32]byte, err error)
	}

	matches := func(want [32]byte) func(t *testing.T, got [32]byte, err error) {
		return func(t *testing.T, got [32]byte, err error) {
			require.NoError(t, err)
			assert.Equal(t, want, got)
		}
	}
	refused := func(t *testing.T, got [32]byte, err error) {
		require.ErrorIs(t, err, recovery.ErrRefused)
		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
		assert.Equal(t, [32]byte{}, got)
	}

	cases := []testCase{
		{name: "canonical", presented: text, assert: matches(hash)},
		{name: "lower case, no dashes", presented: strings.ToLower(dashless), assert: matches(hash)},
		{name: "dashes anywhere", presented: "-" + dashless[:2] + "-" + dashless[2:7] + "--" + dashless[7:] + "-", assert: matches(hash)},
		{name: "O for 0 and l for 1", presented: "oooo-OOOO-0000-oOoO-0000-0000-Ol", assert: matches(oneHash)},
		{name: "I for 1", presented: "0000-0000-0000-0000-0000-0000-0I", assert: matches(oneHash)},
		{name: "25 characters", presented: dashless[:25], assert: refused},
		{name: "27 characters", presented: dashless + "0", assert: refused},
		{name: "contains U", presented: "U" + dashless[1:], assert: refused},
		{name: "contains u", presented: "0000-0000-0000-0000-0000-0000-0u", assert: refused},
		{name: "first character 8", presented: "8" + dashless[1:], assert: refused},
		{name: "first character Z", presented: "Z" + dashless[1:], assert: refused},
		{name: "empty", presented: "", assert: refused},
		{name: "only dashes", presented: "----", assert: refused},
		{name: "space inside", presented: dashless[:13] + " " + dashless[13:], assert: refused},
		{name: "non-ASCII look-alike", presented: "０" + dashless[1:], assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := recovery.ParseCode(tc.presented)
			tc.assert(t, got, err)

			// No spelling of a presented code may reach a refusal's text.
			if err != nil && tc.presented != "" {
				assert.NotContains(t, err.Error(), tc.presented)
			}
		})
	}
}

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

// TestNewCodes_LimiterFactory pins where the code-presentation limiter comes
// from: the explicit limiter, then the factory, then the in-memory default.
// It is a table of its own because Codes and Recoverer are built over different
// fixtures.
// It stands apart from TestNewCodes_Config because each case builds its mocked
// factory on a controller of its own.
func TestNewCodes_LimiterFactory(t *testing.T) {
	t.Parallel()

	key := recovery.CodeThrottleKey(anaID)

	type testCase struct {
		name   string
		opts   func(t *testing.T) []recovery.CodesOption
		assert func(t *testing.T, c *recovery.Codes, err error)
	}

	cases := []testCase{
		{
			name: "default builds in-memory",
			opts: func(*testing.T) []recovery.CodesOption { return nil },
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.NoError(t, err)

				for range 5 {
					require.ErrorIs(t, c.Confirm(t.Context(), anaID, wrongCode), recovery.ErrRefused)
				}

				_, err = c.Check(t.Context(), anaID, wrongCode)
				assert.ErrorIs(t, err, recovery.ErrCodeThrottled, "the default counts 5 failures per 15 minutes")
			},
		},
		{
			name: "factory asked with namespace, limit, window",
			opts: func(t *testing.T) []recovery.CodesOption {
				ctrl := gomock.NewController(t)
				f := NewMockLimiterFactory(ctrl)
				f.EXPECT().NewLimiter("recovery-codes", 5, 15*time.Minute).
					Return(refusingLimiter(ctrl, key), nil).Times(1)

				return []recovery.CodesOption{recovery.WithCodesLimiterFactory(f)}
			},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.NoError(t, err)

				_, err = c.Check(t.Context(), anaID, wrongCode)
				assert.ErrorIs(t, err, recovery.ErrCodeThrottled,
					"the presentation is counted through the limiter the factory built")
			},
		},
		{
			name: "explicit limiter wins and factory not asked",
			opts: func(t *testing.T) []recovery.CodesOption {
				ctrl := gomock.NewController(t)

				// No expectation: gomock fails the case if the factory is asked.
				f := NewMockLimiterFactory(ctrl)

				return []recovery.CodesOption{
					recovery.WithCodesLimiter(refusingLimiter(ctrl, key)),
					recovery.WithCodesLimiterFactory(f),
				}
			},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.NoError(t, err)

				_, err = c.Check(t.Context(), anaID, wrongCode)
				assert.ErrorIs(t, err, recovery.ErrCodeThrottled)
			},
		},
		{
			name: "nil factory refused",
			opts: func(*testing.T) []recovery.CodesOption {
				return []recovery.CodesOption{recovery.WithCodesLimiterFactory(nil)}
			},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, c)
			},
		},
		{
			name: "typed-nil factory refused",
			opts: func(*testing.T) []recovery.CodesOption {
				return []recovery.CodesOption{recovery.WithCodesLimiterFactory((*MockLimiterFactory)(nil))}
			},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, c)
			},
		},
		{
			// The explicit limiter wins, but a factory replaced with nothing is
			// a wiring mistake whatever else was given.
			name: "typed-nil factory refused beside an explicit limiter",
			opts: func(t *testing.T) []recovery.CodesOption {
				return []recovery.CodesOption{
					recovery.WithCodesLimiter(NewMockLimiter(gomock.NewController(t))),
					recovery.WithCodesLimiterFactory((*MockLimiterFactory)(nil)),
				}
			},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, c)
			},
		},
		{
			name: "factory error fails construction",
			opts: func(t *testing.T) []recovery.CodesOption {
				f := NewMockLimiterFactory(gomock.NewController(t))
				f.EXPECT().NewLimiter("recovery-codes", 5, 15*time.Minute).Return(nil, errFactory)

				return []recovery.CodesOption{recovery.WithCodesLimiterFactory(f)}
			},
			assert: func(t *testing.T, c *recovery.Codes, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				require.ErrorIs(t, err, errFactory)
				assert.Contains(t, err.Error(), `"recovery-codes"`, "the error names the namespace")
				assert.Nil(t, c)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := recovery.NewCodes(tc.opts(t)...)
			tc.assert(t, c, err)
		})
	}
}
