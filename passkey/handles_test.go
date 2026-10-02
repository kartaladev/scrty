package passkey_test

import (
	"bytes"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
)

// offer returns a HandleSize offer filled with b.
func offer(b byte) []byte { return bytes.Repeat([]byte{b}, passkey.HandleSize) }

// assignConcurrently assigns offers 1..n to user from n goroutines released
// together, and returns every handle received.
func assignConcurrently(t *testing.T, s passkey.HandleStore, user identity.UserID, n int) [][]byte {
	t.Helper()

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		got   [][]byte
		errs  []error
		start = make(chan struct{})
	)

	for i := range n {
		wg.Go(func() {
			<-start

			h, err := s.Assign(t.Context(), user, offer(byte(i+1))) //nolint:gosec // G115: a small test index

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				errs = append(errs, err)

				return
			}

			got = append(got, h)
		})
	}

	close(start)
	wg.Wait()
	require.Empty(t, errs)

	return got
}

func TestMemoryHandleStore(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, s passkey.HandleStore)
	}

	cases := []testCase{
		{
			name: "8 concurrent assignments of different offers agree on one",
			assert: func(t *testing.T, s passkey.HandleStore) {
				got := assignConcurrently(t, s, "u-1", 8)
				require.Len(t, got, 8)

				for _, h := range got[1:] {
					assert.Equal(t, got[0], h)
				}

				assert.Len(t, got[0], passkey.HandleSize)
				assert.Equal(t, offer(got[0][0]), got[0], "the handle is one of the offers")
				assert.NotZero(t, got[0][0])
			},
		},
		{
			name: "a later assignment returns the held handle",
			assert: func(t *testing.T, s passkey.HandleStore) {
				first, err := s.Assign(t.Context(), "u-1", offer(1))
				require.NoError(t, err)

				again, err := s.Assign(t.Context(), "u-1", offer(2))
				require.NoError(t, err)
				assert.Equal(t, offer(1), first)
				assert.Equal(t, offer(1), again)

				_, ok, err := s.UserFor(t.Context(), offer(2))
				require.NoError(t, err)
				assert.False(t, ok, "a refused offer is not stored")
			},
		},
		{
			name: "reverse lookup returns the user",
			assert: func(t *testing.T, s passkey.HandleStore) {
				got := assignConcurrently(t, s, "u-1", 8)

				user, ok, err := s.UserFor(t.Context(), got[0])
				require.NoError(t, err)
				assert.True(t, ok)
				assert.Equal(t, identity.UserID("u-1"), user)
			},
		},
		{
			name: "unknown handle is not held",
			assert: func(t *testing.T, s passkey.HandleStore) {
				user, ok, err := s.UserFor(t.Context(), offer(7))
				require.NoError(t, err)
				assert.False(t, ok)
				assert.Empty(t, user)
			},
		},
		{
			name: "two users hold two handles",
			assert: func(t *testing.T, s passkey.HandleStore) {
				_, err := s.Assign(t.Context(), "u-1", offer(1))
				require.NoError(t, err)

				h2, err := s.Assign(t.Context(), "u-2", offer(2))
				require.NoError(t, err)
				assert.Equal(t, offer(2), h2)

				user, ok, err := s.UserFor(t.Context(), offer(2))
				require.NoError(t, err)
				assert.True(t, ok)
				assert.Equal(t, identity.UserID("u-2"), user)
			},
		},
		{
			name: "an offer another user holds is refused",
			assert: func(t *testing.T, s passkey.HandleStore) {
				_, err := s.Assign(t.Context(), "u-1", offer(1))
				require.NoError(t, err)

				h, err := s.Assign(t.Context(), "u-2", offer(1))
				require.Error(t, err)
				assert.Nil(t, h)

				user, ok, err := s.UserFor(t.Context(), offer(1))
				require.NoError(t, err)
				assert.True(t, ok)
				assert.Equal(t, identity.UserID("u-1"), user)
			},
		},
		{
			name: "an offer of the wrong length is refused",
			assert: func(t *testing.T, s passkey.HandleStore) {
				for _, bad := range [][]byte{nil, make([]byte, passkey.HandleSize-1), make([]byte, passkey.HandleSize+1)} {
					h, err := s.Assign(t.Context(), "u-1", bad)
					require.ErrorIs(t, err, passkey.ErrConfig)
					assert.Nil(t, h)
				}
			},
		},
		{
			name: "the store keeps its own copies",
			assert: func(t *testing.T, s passkey.HandleStore) {
				in := offer(1)
				out, err := s.Assign(t.Context(), "u-1", in)
				require.NoError(t, err)

				in[0] = 9
				out[1] = 9

				again, err := s.Assign(t.Context(), "u-1", offer(2))
				require.NoError(t, err)
				assert.Equal(t, offer(1), again)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, passkey.NewMemoryHandleStore())
		})
	}
}
