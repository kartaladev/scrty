// The keyring-lock tests are not parallel: goleak counts goroutines
// process-wide.
package signingkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/signingkey"
)

// blockingStore holds one write inside the store until it is released, so a
// test can ask what the manager serves while a rotation is waiting on I/O.
type blockingStore struct {
	inner   signingkey.KeyStore
	writing chan struct{} // receives once a held write is inside the store
	release chan struct{} // closed to let the held write finish
	armed   bool          // set after construction, so construction's write is not held
}

func (s *blockingStore) Store(ctx context.Context, rec signingkey.Record) error {
	if s.armed {
		s.writing <- struct{}{}
		<-s.release
	}
	return s.inner.Store(ctx, rec)
}

func (s *blockingStore) LoadAll(ctx context.Context) ([]signingkey.Record, error) {
	return s.inner.LoadAll(ctx)
}

// TestSigningStaysAvailableDuringASlowStoreWrite pins the reason the keyring
// lock is taken after the store write and not before it: signing and
// verification must not queue behind store I/O.
//
// A durable store on a slow network makes a rotation's write arbitrarily long,
// and every signature and every JWK Set read would wait for it. Nothing else
// in the suite observes the order — the shutdown test holds a write too, but it
// never reads the keyring while the write is held.
func TestSigningStaysAvailableDuringASlowStoreWrite(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	store := &blockingStore{
		inner:   signingkey.NewInMemoryKeyStore(),
		writing: make(chan struct{}, 1),
		release: make(chan struct{}),
	}

	clock := newFakeClock(epoch)
	km, err := signingkey.NewKeyManager(t.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithClock(clock),
		signingkey.WithAlgs(signingkey.EdDSA),
		signingkey.WithRotateInterval(time.Hour),
		signingkey.WithReloadInterval(time.Minute),
		signingkey.WithHousekeepingInterval(time.Hour),
		signingkey.WithLifetime(24*time.Hour),
	)
	require.NoError(t, err)

	signing := currentKid(t, km, signingkey.EdDSA)

	store.armed = true
	require.NoError(t, km.Start(t.Context()))

	clock.Advance(time.Hour)
	<-store.writing // a rotation is now inside the store write

	// Both halves of KeySource, asked from another goroutine so a blocked one
	// is a failed assertion rather than a hung test.
	served := make(chan string, 1)
	go func() {
		kid, signer, ok := km.GetSigner(signingkey.EdDSA)
		if !ok || signer == nil || !publishes(km, kid) {
			kid = ""
		}
		served <- kid
	}()

	select {
	case kid := <-served:
		require.Equal(t, signing, kid,
			"the key the rotation is replacing still signs and is still published")
	case <-time.After(10 * time.Second):
		t.Fatal("GetSigner blocked while a rotation was inside the store write: " +
			"the keyring lock is held across store I/O")
	}

	close(store.release)
	require.NoError(t, km.Stop())
	goleak.VerifyNone(t, ignore)
}
