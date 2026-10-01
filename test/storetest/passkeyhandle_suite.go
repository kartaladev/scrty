package storetest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
)

// passkeyOffer returns a passkey.HandleSize offer filled with b.
func passkeyOffer(b byte) []byte { return bytes.Repeat([]byte{b}, passkey.HandleSize) }

// assignOffers assigns offers 1..n to user from n goroutines released
// together, and returns every handle received. Every assignment must succeed.
func assignOffers(ctx context.Context, t *testing.T, s passkey.HandleStore, user identity.UserID, n int) [][]byte {
	t.Helper()

	var (
		start = make(chan struct{})
		wg    sync.WaitGroup
		mu    sync.Mutex
		got   [][]byte
		errs  []error
	)
	for i := range n {
		wg.Go(func() {
			<-start
			h, err := s.Assign(ctx, user, passkeyOffer(byte(i+1))) //nolint:gosec // G115: a small test index

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

	require.Empty(t, errs, "an assignment for a user failed")

	return got
}

// requireHolder requires handle to be held by user, or by no one for "".
func requireHolder(ctx context.Context, t *testing.T, s passkey.HandleStore, handle []byte, user identity.UserID) {
	t.Helper()

	got, ok, err := s.UserFor(ctx, handle)
	require.NoError(t, err)
	assert.Equal(t, user != "", ok, "whether the handle is held")
	assert.Equal(t, user, got, "the handle's holder")
}

// RunPasskeyHandleStoreSuite checks a passkey.HandleStore against the
// contract the passkey manager relies on: an assignment stores the offer only
// for a user who holds no handle, and returns the handle the user holds
// afterwards, so 8 concurrent assignments of different offers to one user
// all receive the same one; a handle maps back to its one user; an offer
// another user holds is refused with an error that names no handle bytes; an
// offer that is not passkey.HandleSize bytes is refused with
// passkey.ErrConfig; and the store keeps its own copies.
//
// newStore is called once per case and must return an empty store.
func RunPasskeyHandleStoreSuite(t *testing.T, newStore func(t *testing.T) passkey.HandleStore) {
	t.Helper()

	type handleCase = suiteCase[passkey.HandleStore]

	cases := []handleCase{
		{
			name: "8 concurrent assignments of different offers agree on one",
			assert: func(t *testing.T, ctx context.Context, s passkey.HandleStore, _ *clockwork.FakeClock) {
				got := assignOffers(ctx, t, s, "u-1", 8)
				require.Len(t, got, 8)
				for _, h := range got[1:] {
					assert.Equal(t, got[0], h, "every caller receives the same handle")
				}
				require.Len(t, got[0], passkey.HandleSize)
				assert.Equal(t, passkeyOffer(got[0][0]), got[0], "the handle is one of the offers")

				requireHolder(ctx, t, s, got[0], "u-1")
				for b := byte(1); b <= 8; b++ {
					if b != got[0][0] {
						requireHolder(ctx, t, s, passkeyOffer(b), "")
					}
				}
			},
		},
		{
			name: "a later assignment returns the held handle and stores no other",
			assert: func(t *testing.T, ctx context.Context, s passkey.HandleStore, _ *clockwork.FakeClock) {
				first, err := s.Assign(ctx, "u-1", passkeyOffer(1))
				require.NoError(t, err)
				again, err := s.Assign(ctx, "u-1", passkeyOffer(2))
				require.NoError(t, err)

				assert.Equal(t, passkeyOffer(1), first)
				assert.Equal(t, passkeyOffer(1), again)
				requireHolder(ctx, t, s, passkeyOffer(1), "u-1")
				requireHolder(ctx, t, s, passkeyOffer(2), "")
			},
		},
		{
			name: "an unknown handle is held by no user",
			assert: func(t *testing.T, ctx context.Context, s passkey.HandleStore, _ *clockwork.FakeClock) {
				_, err := s.Assign(ctx, "u-1", passkeyOffer(1))
				require.NoError(t, err)

				requireHolder(ctx, t, s, passkeyOffer(7), "")
				requireHolder(ctx, t, s, nil, "")
			},
		},
		{
			name: "two users hold two handles, each mapped back to its user",
			assert: func(t *testing.T, ctx context.Context, s passkey.HandleStore, _ *clockwork.FakeClock) {
				h1, err := s.Assign(ctx, "u-1", passkeyOffer(1))
				require.NoError(t, err)
				h2, err := s.Assign(ctx, "Alice@Example.COM ", passkeyOffer(2))
				require.NoError(t, err)

				assert.Equal(t, passkeyOffer(1), h1)
				assert.Equal(t, passkeyOffer(2), h2)
				requireHolder(ctx, t, s, h1, "u-1")
				requireHolder(ctx, t, s, h2, "Alice@Example.COM ")
			},
		},
		{
			name: "an offer another user holds is refused, naming no handle bytes",
			assert: func(t *testing.T, ctx context.Context, s passkey.HandleStore, _ *clockwork.FakeClock) {
				offer := passkeyOffer(0xAB)
				_, err := s.Assign(ctx, "u-1", offer)
				require.NoError(t, err)

				h, err := s.Assign(ctx, "u-2", offer)
				require.Error(t, err)
				assert.Nil(t, h)
				text := err.Error()
				for _, form := range []string{
					string(offer[:8]),
					hex.EncodeToString(offer[:8]),
					base64.RawURLEncoding.EncodeToString(offer[:8]),
					base64.StdEncoding.EncodeToString(offer[:8]),
				} {
					assert.NotContains(t, text, form, "the refusal names the handle")
				}

				requireHolder(ctx, t, s, offer, "u-1")
				h, err = s.Assign(ctx, "u-2", passkeyOffer(2))
				require.NoError(t, err, "the refused user may still be assigned a handle of their own")
				assert.Equal(t, passkeyOffer(2), h)
			},
		},
		{
			name: "an offer of the wrong length is refused as a configuration error",
			assert: func(t *testing.T, ctx context.Context, s passkey.HandleStore, _ *clockwork.FakeClock) {
				for _, bad := range [][]byte{nil, {}, make([]byte, passkey.HandleSize-1), make([]byte, passkey.HandleSize+1)} {
					h, err := s.Assign(ctx, "u-1", bad)
					require.ErrorIs(t, err, passkey.ErrConfig, "an offer of %d bytes", len(bad))
					assert.Nil(t, h)
				}

				h, err := s.Assign(ctx, "u-1", passkeyOffer(3))
				require.NoError(t, err)
				assert.Equal(t, passkeyOffer(3), h, "a refused offer stores nothing")
			},
		},
		{
			name: "the store keeps its own copies",
			assert: func(t *testing.T, ctx context.Context, s passkey.HandleStore, _ *clockwork.FakeClock) {
				in := passkeyOffer(1)
				out, err := s.Assign(ctx, "u-1", in)
				require.NoError(t, err)

				in[0] = 9
				out[1] = 9

				again, err := s.Assign(ctx, "u-1", passkeyOffer(2))
				require.NoError(t, err)
				assert.Equal(t, passkeyOffer(1), again)
				requireHolder(ctx, t, s, passkeyOffer(1), "u-1")
			},
		},
	}

	runSuite(t, cases, withoutClock(newStore))
}
