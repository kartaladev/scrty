package seal_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/signingkey"
)

// privateSentinel marks signing-key private material, so a test can tell
// whether plaintext reached the inner store or an error's text.
const privateSentinel = "PKCS8-SENTINEL-private-material"

var errCipherDown = errors.New("consumer cipher: kms endpoint kms.internal refused the request")

// signingRecord returns a signing key record whose private material is
// privateSentinel followed by kid; n orders it by creation time.
func signingRecord(kid string, n int) signingkey.Record {
	return signingkey.Record{
		Kid:       kid,
		Alg:       signingkey.ES256,
		Private:   []byte(privateSentinel + kid),
		PublicJWK: []byte(`{"kid":"` + kid + `"}`),
		CreatedAt: time.Date(2026, 9, 1, 0, 0, n, 0, time.UTC),
	}
}

// ciphers are the three views of one rotation every sealing test uses.
type ciphers struct {
	retired seal.Cipher // active k1: seals values as they were before the rotation
	current seal.Cipher // active k2, retired k1: what a store is built with
	k2Only  seal.Cipher // k2 alone: opens only what was sealed after the rotation
}

func newCiphers(t *testing.T) ciphers {
	t.Helper()

	return ciphers{
		retired: mustCipher(t, seal.WithEncryptionKey("k1", keyOne)),
		current: mustCipher(t, seal.WithEncryptionKey("k2", keyTwo), seal.WithRetiredEncryptionKey("k1", keyOne)),
		k2Only:  mustCipher(t, seal.WithEncryptionKey("k2", keyTwo)),
	}
}

// storeSealed writes rec to inner with its private material sealed by c,
// bypassing the store under test.
func storeSealed(t *testing.T, inner signingkey.KeyStore, c seal.Cipher, rec signingkey.Record) []byte {
	t.Helper()

	sealed, err := c.Seal(rec.Private, seal.SigningKeyAAD(rec.Kid))
	require.NoError(t, err)

	rec.Private = sealed
	require.NoError(t, inner.Store(t.Context(), rec))

	return sealed
}

// innerRecord returns the record inner holds for kid.
func innerRecord(t *testing.T, inner signingkey.KeyStore, kid string) signingkey.Record {
	t.Helper()

	recs, err := inner.LoadAll(t.Context())
	require.NoError(t, err)
	for _, rec := range recs {
		if rec.Kid == kid {
			return rec
		}
	}
	require.FailNow(t, "no inner record", "kid %s", kid)

	return signingkey.Record{}
}

// assertNoLeak checks that an error's text names no key id or secret.
func assertNoLeak(t *testing.T, err error, values ...string) {
	t.Helper()

	for _, v := range append(values, privateSentinel, "kms.internal") {
		assert.NotContains(t, err.Error(), v)
	}
}

func TestNewSigningKeyStore(t *testing.T) {
	t.Parallel()

	c := newCiphers(t).current
	var typedNilCipher *MockCipher
	var typedNilResealer *MockSigningKeyResealer

	type testCase struct {
		name          string
		inner         signingkey.KeyStore
		resealer      bool
		resealerValue seal.SigningKeyResealer // set (typed nil included) overrides resealer
		cipher        seal.Cipher
		opts          []seal.Option
		assert        func(t *testing.T, store signingkey.KeyStore, err error)
	}

	refused := func(t *testing.T, store signingkey.KeyStore, err error) {
		t.Helper()
		require.ErrorIs(t, err, seal.ErrInvalidConfiguration)
		assert.Nil(t, store)
	}
	built := func(t *testing.T, store signingkey.KeyStore, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.NotNil(t, store)
	}

	cases := []testCase{
		{
			name:     "a complete wiring builds a store",
			inner:    signingkey.NewInMemoryKeyStore(),
			resealer: true,
			cipher:   c,
			assert:   built,
		},
		{
			name:     "a nil inner store is refused",
			resealer: true,
			cipher:   c,
			assert:   refused,
		},
		{
			name:     "a nil cipher is refused",
			inner:    signingkey.NewInMemoryKeyStore(),
			resealer: true,
			assert:   refused,
		},
		{
			name:     "a typed-nil cipher is refused",
			inner:    signingkey.NewInMemoryKeyStore(),
			resealer: true,
			cipher:   typedNilCipher,
			assert:   refused,
		},
		{
			name:   "a nil resealer is refused while re-sealing on read is on",
			inner:  signingkey.NewInMemoryKeyStore(),
			cipher: c,
			assert: refused,
		},
		{
			name:   "a nil resealer is accepted with re-sealing on read off",
			inner:  signingkey.NewInMemoryKeyStore(),
			cipher: c,
			opts:   []seal.Option{seal.WithResealOnRead(false)},
			assert: built,
		},
		{
			name:     "a nil option is refused",
			inner:    signingkey.NewInMemoryKeyStore(),
			resealer: true,
			cipher:   c,
			opts:     []seal.Option{nil},
			assert:   refused,
		},
		{
			// Signing keys have no expiry the store judges, so a clock
			// would be silently ignored; it is refused instead.
			name:     "a clock is refused: the signing-key store judges no time",
			inner:    signingkey.NewInMemoryKeyStore(),
			resealer: true,
			cipher:   c,
			opts:     []seal.Option{seal.WithClock(time.Now)},
			assert:   refused,
		},
		{
			name:          "a typed-nil resealer is refused",
			inner:         signingkey.NewInMemoryKeyStore(),
			resealerValue: typedNilResealer,
			cipher:        c,
			assert:        refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var r seal.SigningKeyResealer
			switch {
			case tc.resealerValue != nil:
				r = tc.resealerValue
			case tc.resealer:
				r = NewMockSigningKeyResealer(gomock.NewController(t))
			}

			store, err := seal.NewSigningKeyStore(tc.inner, r, tc.cipher, tc.opts...)
			tc.assert(t, store, err)
		})
	}
}

func TestSigningKeyStore_Store(t *testing.T) {
	t.Parallel()

	cs := newCiphers(t)

	type testCase struct {
		name   string
		cipher func(ctrl *gomock.Controller) seal.Cipher
		inner  func(ctrl *gomock.Controller) signingkey.KeyStore
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, inner signingkey.KeyStore, err error)
	}

	rec := signingRecord("kid-a", 1)

	cases := []testCase{
		{
			name: "the inner store holds a sealed value, bound to the key id",
			assert: func(t *testing.T, inner signingkey.KeyStore, err error) {
				require.NoError(t, err)

				got := innerRecord(t, inner, "kid-a")
				assert.NotContains(t, string(got.Private), privateSentinel)

				opened, keyID, err := cs.k2Only.Open(got.Private, seal.SigningKeyAAD("kid-a"))
				require.NoError(t, err)
				assert.Equal(t, "k2", keyID)
				assert.Equal(t, rec.Private, opened)

				got.Private = rec.Private
				assert.Equal(t, rec, got, "every other field is stored as given")
			},
		},
		{
			name: "a consumer cipher that fails to seal stores nothing",
			cipher: func(ctrl *gomock.Controller) seal.Cipher {
				c := NewMockCipher(ctrl)
				c.EXPECT().Seal(rec.Private, seal.SigningKeyAAD("kid-a")).Return(nil, errCipherDown)

				return c
			},
			assert: func(t *testing.T, inner signingkey.KeyStore, err error) {
				require.ErrorIs(t, err, errCipherDown)
				assertNoLeak(t, err, "kid-a")

				recs, err := inner.LoadAll(t.Context())
				require.NoError(t, err)
				assert.Empty(t, recs)
			},
		},
		{
			name: "an inner store failure is returned behind fixed text",
			inner: func(ctrl *gomock.Controller) signingkey.KeyStore {
				inner := NewMockKeyStore(ctrl)
				inner.EXPECT().Store(gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, _ signingkey.Record) error { return ctx.Err() })

				return inner
			},
			ctx: cancelled,
			assert: func(t *testing.T, _ signingkey.KeyStore, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.NotEqual(t, context.Canceled.Error(), err.Error())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			c := cs.current
			if tc.cipher != nil {
				c = tc.cipher(ctrl)
			}
			inner := signingkey.NewInMemoryKeyStore()
			if tc.inner != nil {
				inner = tc.inner(ctrl)
			}
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			store, err := seal.NewSigningKeyStore(inner, NewMockSigningKeyResealer(ctrl), c)
			require.NoError(t, err)

			tc.assert(t, inner, store.Store(ctx, rec))
		})
	}
}

// signingFixture is what a LoadAll case sets up and asserts against.
type signingFixture struct {
	store    signingkey.KeyStore
	inner    signingkey.KeyStore
	resealer *MockSigningKeyResealer
}

func TestSigningKeyStore_LoadAll(t *testing.T) {
	t.Parallel()

	cs := newCiphers(t)
	gone := mustCipher(t, seal.WithEncryptionKey("gone", keyThree))

	// aliasBacking is the slice a mocked inner store keeps: LoadAll must open
	// into a copy, never scribble the plaintext back into aliasBacking itself.
	aliasRec := signingRecord("kid-a", 1)
	aliasSealed, err := cs.current.Seal(aliasRec.Private, seal.SigningKeyAAD("kid-a"))
	require.NoError(t, err)
	aliasRec.Private = aliasSealed
	aliasBacking := []signingkey.Record{aliasRec}

	type testCase struct {
		name   string
		opts   []seal.Option
		cipher func(ctrl *gomock.Controller) seal.Cipher
		inner  func(ctrl *gomock.Controller) signingkey.KeyStore
		setup  func(t *testing.T, f signingFixture)
		assert func(t *testing.T, f signingFixture, recs []signingkey.Record, err error)
	}

	cases := []testCase{
		{
			name: "stored keys load with their private material",
			setup: func(t *testing.T, f signingFixture) {
				require.NoError(t, f.store.Store(t.Context(), signingRecord("kid-a", 1)))
				require.NoError(t, f.store.Store(t.Context(), signingRecord("kid-b", 2)))
			},
			assert: func(t *testing.T, _ signingFixture, recs []signingkey.Record, err error) {
				require.NoError(t, err)
				assert.Equal(t, []signingkey.Record{signingRecord("kid-a", 1), signingRecord("kid-b", 2)}, recs)
			},
		},
		{
			name: "an empty store loads no keys",
			assert: func(t *testing.T, _ signingFixture, recs []signingkey.Record, err error) {
				require.NoError(t, err)
				assert.Empty(t, recs)
			},
		},
		{
			name: "one of three keys unreadable fails the whole load",
			setup: func(t *testing.T, f signingFixture) {
				storeSealed(t, f.inner, cs.retired, signingRecord("kid-a", 1))
				tampered := bytes.Clone(storeSealed(t, f.inner, cs.current, signingRecord("kid-b", 2)))
				tampered[len(tampered)-1] ^= 0x01
				rec := signingRecord("kid-b", 2)
				rec.Private = tampered
				require.NoError(t, f.inner.Store(t.Context(), rec))
				storeSealed(t, f.inner, cs.current, signingRecord("kid-c", 3))
				// No re-seal is expected: kid-a is under the retired key, and a
				// load that fails re-seals nothing.
			},
			assert: func(t *testing.T, _ signingFixture, recs []signingkey.Record, err error) {
				require.ErrorIs(t, err, seal.ErrDecryptionFailed)
				assert.Nil(t, recs)
				assertNoLeak(t, err, "kid-a", "kid-b", "kid-c")
			},
		},
		{
			name: "a value moved to another key's record does not open",
			setup: func(t *testing.T, f signingFixture) {
				moved := signingRecord("kid-b", 2)
				moved.Private = storeSealed(t, f.inner, cs.current, signingRecord("kid-a", 1))
				require.NoError(t, f.inner.Store(t.Context(), moved))
			},
			assert: func(t *testing.T, _ signingFixture, recs []signingkey.Record, err error) {
				require.ErrorIs(t, err, seal.ErrDecryptionFailed)
				assert.Nil(t, recs)
			},
		},
		{
			name: "a key sealed under a key the ring no longer holds is an unknown key id",
			setup: func(t *testing.T, f signingFixture) {
				storeSealed(t, f.inner, gone, signingRecord("kid-a", 1))
			},
			assert: func(t *testing.T, _ signingFixture, recs []signingkey.Record, err error) {
				require.ErrorIs(t, err, seal.ErrUnknownKeyID)
				assert.NotErrorIs(t, err, seal.ErrDecryptionFailed)
				assert.Nil(t, recs)
				assertNoLeak(t, err, "kid-a", "gone")
			},
		},
		{
			name: "a key sealed under the retired key is re-sealed under the active key",
			setup: func(t *testing.T, f signingFixture) {
				storeSealed(t, f.inner, cs.current, signingRecord("kid-a", 1))
				old := storeSealed(t, f.inner, cs.retired, signingRecord("kid-b", 2))
				f.resealer.EXPECT().ResealSigningKey(gomock.Any(), "kid-b", old, gomock.Any()).DoAndReturn(
					func(_ context.Context, _ string, _, resealed []byte) error {
						opened, keyID, err := cs.k2Only.Open(resealed, seal.SigningKeyAAD("kid-b"))
						require.NoError(t, err)
						assert.Equal(t, "k2", keyID)
						assert.Equal(t, signingRecord("kid-b", 2).Private, opened)

						return nil
					})
			},
			assert: func(t *testing.T, _ signingFixture, recs []signingkey.Record, err error) {
				require.NoError(t, err)
				assert.Equal(t, []signingkey.Record{signingRecord("kid-a", 1), signingRecord("kid-b", 2)}, recs)
			},
		},
		{
			name: "a failed re-seal does not fail the load",
			setup: func(t *testing.T, f signingFixture) {
				storeSealed(t, f.inner, cs.retired, signingRecord("kid-a", 1))
				f.resealer.EXPECT().ResealSigningKey(gomock.Any(), "kid-a", gomock.Any(), gomock.Any()).
					Return(errors.New("conditional update failed"))
			},
			assert: func(t *testing.T, _ signingFixture, recs []signingkey.Record, err error) {
				require.NoError(t, err)
				assert.Equal(t, []signingkey.Record{signingRecord("kid-a", 1)}, recs)
			},
		},
		{
			name: "re-sealing switched off leaves the retired-key value alone",
			opts: []seal.Option{seal.WithResealOnRead(false)},
			setup: func(t *testing.T, f signingFixture) {
				storeSealed(t, f.inner, cs.retired, signingRecord("kid-a", 1))
			},
			assert: func(t *testing.T, f signingFixture, recs []signingkey.Record, err error) {
				require.NoError(t, err)
				assert.Equal(t, []signingkey.Record{signingRecord("kid-a", 1)}, recs)

				_, keyID, err := cs.retired.Open(innerRecord(t, f.inner, "kid-a").Private, seal.SigningKeyAAD("kid-a"))
				require.NoError(t, err)
				assert.Equal(t, "k1", keyID)
			},
		},
		{
			name: "a cipher that cannot name its active key skips the re-seal, not the load",
			cipher: func(ctrl *gomock.Controller) seal.Cipher {
				c := NewMockCipher(ctrl)
				c.EXPECT().Open(gomock.Any(), seal.SigningKeyAAD("kid-a")).
					Return(signingRecord("kid-a", 1).Private, "k1", nil)
				c.EXPECT().ActiveKeyID().Return("", errCipherDown)

				return c
			},
			setup: func(t *testing.T, f signingFixture) {
				storeSealed(t, f.inner, cs.retired, signingRecord("kid-a", 1))
			},
			assert: func(t *testing.T, _ signingFixture, recs []signingkey.Record, err error) {
				require.NoError(t, err)
				assert.Equal(t, []signingkey.Record{signingRecord("kid-a", 1)}, recs)
			},
		},
		{
			name: "an inner store failure is returned behind fixed text",
			inner: func(ctrl *gomock.Controller) signingkey.KeyStore {
				inner := NewMockKeyStore(ctrl)
				inner.EXPECT().LoadAll(gomock.Any()).Return(nil, errCipherDown)

				return inner
			},
			assert: func(t *testing.T, _ signingFixture, recs []signingkey.Record, err error) {
				require.ErrorIs(t, err, errCipherDown)
				assert.Nil(t, recs)
				assertNoLeak(t, err)
			},
		},
		{
			name: "LoadAll does not decrypt in place into the inner store's slice",
			inner: func(ctrl *gomock.Controller) signingkey.KeyStore {
				inner := NewMockKeyStore(ctrl)
				inner.EXPECT().LoadAll(gomock.Any()).Return(aliasBacking, nil)

				return inner
			},
			assert: func(t *testing.T, _ signingFixture, recs []signingkey.Record, err error) {
				require.NoError(t, err)
				require.Len(t, recs, 1)
				assert.Equal(t, signingRecord("kid-a", 1).Private, recs[0].Private)
				assert.NotContains(t, string(aliasBacking[0].Private), privateSentinel,
					"the inner store's own record must still hold the sealed envelope")
			},
		},
		{
			name: "a failed re-seal Seal does not call the resealer",
			cipher: func(ctrl *gomock.Controller) seal.Cipher {
				c := NewMockCipher(ctrl)
				c.EXPECT().Open(gomock.Any(), seal.SigningKeyAAD("kid-a")).
					Return(signingRecord("kid-a", 1).Private, "k1", nil)
				c.EXPECT().ActiveKeyID().Return("k2", nil)
				c.EXPECT().Seal(signingRecord("kid-a", 1).Private, seal.SigningKeyAAD("kid-a")).
					Return(nil, errCipherDown)

				return c
			},
			setup: func(t *testing.T, f signingFixture) {
				storeSealed(t, f.inner, cs.retired, signingRecord("kid-a", 1))
			},
			assert: func(t *testing.T, _ signingFixture, recs []signingkey.Record, err error) {
				require.NoError(t, err)
				assert.Equal(t, []signingkey.Record{signingRecord("kid-a", 1)}, recs)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			c := cs.current
			if tc.cipher != nil {
				c = tc.cipher(ctrl)
			}
			inner := signingkey.NewInMemoryKeyStore()
			if tc.inner != nil {
				inner = tc.inner(ctrl)
			}
			resealer := NewMockSigningKeyResealer(ctrl)

			store, err := seal.NewSigningKeyStore(inner, resealer, c, tc.opts...)
			require.NoError(t, err)

			f := signingFixture{store: store, inner: inner, resealer: resealer}
			if tc.setup != nil {
				tc.setup(t, f)
			}

			recs, err := store.LoadAll(t.Context())
			tc.assert(t, f, recs, err)
		})
	}
}
