package storefix_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/test/internal/storefix"
)

func TestGatedCipher_HoldsFirstOpenUntilReleased(t *testing.T) {
	t.Parallel()

	inner := storefix.TestCipher(t)
	sealed, err := inner.Seal([]byte("plaintext"), []byte("aad"))
	require.NoError(t, err)

	gated := storefix.NewGatedCipher(inner)

	opened := make(chan []byte, 1)
	go func() {
		pt, _, err := gated.Open(sealed, []byte("aad"))
		assert.NoError(t, err)
		opened <- pt
	}()

	select {
	case <-gated.Opening():
	case <-time.After(5 * time.Second):
		t.Fatal("the first Open never signalled it was opening")
	}

	select {
	case <-opened:
		t.Fatal("the first Open returned before it was released")
	case <-time.After(50 * time.Millisecond):
	}

	gated.Release()
	select {
	case pt := <-opened:
		assert.Equal(t, []byte("plaintext"), pt)
	case <-time.After(5 * time.Second):
		t.Fatal("the first Open did not return once released")
	}

	// Later opens pass straight through.
	pt, _, err := gated.Open(sealed, []byte("aad"))
	require.NoError(t, err)
	assert.Equal(t, []byte("plaintext"), pt)
}

func TestCountingCipher_RecordsAdditionalData(t *testing.T) {
	t.Parallel()

	c := &storefix.CountingCipher{Cipher: storefix.TestCipher(t)}

	sealed, err := c.Seal([]byte("plaintext"), []byte("seal-aad"))
	require.NoError(t, err)
	_, _, err = c.Open(sealed, []byte("seal-aad"))
	require.NoError(t, err)

	assert.Equal(t, []string{"seal-aad"}, c.Seals())
	assert.Equal(t, []string{"seal-aad"}, c.Opens())
}
