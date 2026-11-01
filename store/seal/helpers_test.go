package seal_test

import (
	"context"
	"errors"
	"slices"
	"sync"
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

// ctxKey keys the value a test puts in a context to recognise it wherever it
// arrives.
type ctxKey struct{}

// ctxMark is the value carried under ctxKey.
const ctxMark = "the store call's context"

// marked returns ctx carrying ctxMark.
func marked(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, ctxMark)
}

// ctxCall is one call a recordingCipher saw: the method, and the value its
// context carried under ctxKey.
type ctxCall struct {
	method string
	value  any
}

// recordingCipher records the context of every call and delegates to the
// embedded cipher. It is safe for concurrent use.
type recordingCipher struct {
	seal.Cipher

	mu    sync.Mutex
	calls []ctxCall
}

func (c *recordingCipher) record(ctx context.Context, method string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.calls = append(c.calls, ctxCall{method: method, value: ctx.Value(ctxKey{})})
}

func (c *recordingCipher) Seal(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	c.record(ctx, "Seal")

	return c.Cipher.Seal(ctx, plaintext, aad)
}

func (c *recordingCipher) Open(ctx context.Context, sealed, aad []byte) ([]byte, string, error) {
	c.record(ctx, "Open")

	return c.Cipher.Open(ctx, sealed, aad)
}

func (c *recordingCipher) ActiveKeyID(ctx context.Context) (string, error) {
	c.record(ctx, "ActiveKeyID")

	return c.Cipher.ActiveKeyID(ctx)
}

// Calls returns every call so far, in order.
func (c *recordingCipher) Calls() []ctxCall {
	c.mu.Lock()
	defer c.mu.Unlock()

	return slices.Clone(c.calls)
}

// assertCallsMarked requires calls to be exactly the methods named, each
// carrying ctxMark.
func assertCallsMarked(t *testing.T, calls []ctxCall, methods ...string) {
	t.Helper()

	got := make([]string, len(calls))
	for i, c := range calls {
		got[i] = c.method
		assert.Equal(t, ctxMark, c.value, "context value of call %d (%s)", i, c.method)
	}
	assert.Equal(t, methods, got, "the cipher calls")
}

// faultyCipher delegates to the embedded cipher, except that ActiveKeyID
// fails with activeErr, Seal with sealErr and Open with openErr when they are
// set.
type faultyCipher struct {
	seal.Cipher

	activeErr, sealErr, openErr error
}

func (c faultyCipher) Open(ctx context.Context, sealed, aad []byte) ([]byte, string, error) {
	if c.openErr != nil {
		return nil, "", c.openErr
	}

	return c.Cipher.Open(ctx, sealed, aad)
}

func (c faultyCipher) Seal(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	if c.sealErr != nil {
		return nil, c.sealErr
	}

	return c.Cipher.Seal(ctx, plaintext, aad)
}

func (c faultyCipher) ActiveKeyID(ctx context.Context) (string, error) {
	if c.activeErr != nil {
		return "", c.activeErr
	}

	return c.Cipher.ActiveKeyID(ctx)
}
