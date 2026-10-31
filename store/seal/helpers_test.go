package seal_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/store/seal"
)

// mustCipher builds the default cipher over a keyring of opts.
func mustCipher(t *testing.T, opts ...seal.KeyringOption) seal.Cipher {
	t.Helper()

	kr, err := seal.NewKeyring(opts...)
	require.NoError(t, err)

	c, err := seal.NewAEADCipher(kr)
	require.NoError(t, err)

	return c
}

// Recognisable key material, so a key leaking into an error's text is obvious
// in both its raw and its hex form.
var (
	keyOne   = []byte("key-one-0123456789abcdefghijklmn")
	keyTwo   = []byte("key-two-0123456789abcdefghijklmn")
	keyThree = []byte("key-three-23456789abcdefghijklmn")
)

// cancelled returns ctx already cancelled.
func cancelled(ctx context.Context) context.Context {
	cctx, cancel := context.WithCancel(ctx)
	cancel()

	return cctx
}

var errCipherDown = errors.New("consumer cipher: kms endpoint kms.internal refused the request")

// ciphers are the three views of one rotation every sealing test uses.
type ciphers struct {
	retired seal.Cipher // active k1: seals values as they were before the rotation
	current seal.Cipher // active k2, retired k1: what a store is built with
	k2Only  seal.Cipher // k2 alone: opens only what was sealed after the rotation
}

func newCiphers(t *testing.T) ciphers {
	t.Helper()

	return ciphers{
		retired: mustCipher(t, seal.WithKeyringEncryptionKey("k1", keyOne)),
		current: mustCipher(t, seal.WithKeyringEncryptionKey("k2", keyTwo), seal.WithKeyringRetiredEncryptionKey("k1", keyOne)),
		k2Only:  mustCipher(t, seal.WithKeyringEncryptionKey("k2", keyTwo)),
	}
}

// assertNoLeak checks that an error's text names no key id or secret.
func assertNoLeak(t *testing.T, err error, values ...string) {
	t.Helper()

	for _, v := range append(values, privateSentinel, "kms.internal") {
		assert.NotContains(t, err.Error(), v)
	}
}

// privateSentinel marks signing-key private material, so a test can tell
// whether plaintext reached the inner store or an error's text.
const privateSentinel = "PKCS8-SENTINEL-private-material"
