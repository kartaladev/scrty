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

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
)

// mfaSentinel marks an MFA secret, so a test can tell whether plaintext
// reached the inner store or an error's text.
const mfaSentinel = "TOTP-SENTINEL-shared-secret"

// userRef is the user reference every MFA case enrols; its trailing space
// must be kept byte for byte.
const userRef identity.UserID = "Alice "

// pendingEnrolment returns a pending enrolment of user on a new generation.
func pendingEnrolment(t *testing.T, user identity.UserID) mfa.Enrolment {
	t.Helper()

	gen, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	return mfa.Enrolment{
		User:       user,
		Secret:     []byte(mfaSentinel + string(user)),
		CreatedAt:  time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Generation: gen,
	}
}

// putSealed stores e in inner with its secret sealed by c, bypassing the
// store under test, and returns the stored value.
func putSealed(t *testing.T, inner mfa.EnrolmentStore, c seal.Cipher, e mfa.Enrolment) []byte {
	t.Helper()

	sealed, err := c.Seal(e.Secret, seal.MFASecretAAD(e.User))
	require.NoError(t, err)

	e.Secret = sealed
	require.NoError(t, inner.PutPending(t.Context(), e))

	return sealed
}

// innerSecret returns the secret inner holds for user.
func innerSecret(t *testing.T, inner mfa.EnrolmentStore, user identity.UserID) []byte {
	t.Helper()

	e, ok, err := inner.Get(t.Context(), user)
	require.NoError(t, err)
	require.True(t, ok)

	return e.Secret
}

// codeSentinel marks an emailed code, so a test can tell whether plaintext
// reached the inner store or an error's text.
const codeSentinel = "EMAILED-CODE-SENTINEL-987654"

// proveSealed records a device proof of user's enrolment on gen in inner,
// with codeSentinel sealed by c against the additional data of sealedFor,
// bypassing the store under test, and returns the stored code.
func proveSealed(t *testing.T, inner mfa.EnrolmentStore, c seal.Cipher, gen, sealedFor id.ID) []byte {
	t.Helper()

	sealed, err := c.Seal([]byte(codeSentinel), seal.MFAEmailCodeAAD(sealedFor, userRef))
	require.NoError(t, err)

	p, ok := inner.(mfa.DeviceProofStore)
	require.True(t, ok)
	proven, err := p.ProveDevice(t.Context(), userRef, gen, 9, sealed, codeUntil, codeIssuedAt)
	require.NoError(t, err)
	require.True(t, proven)

	return sealed
}

// codeIssuedAt and codeUntil are when proveSealed issues its code and when
// that code expires; codeLive is a read clock before the expiry.
var (
	codeIssuedAt = time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	codeUntil    = codeIssuedAt.Add(10 * time.Minute)
	codeLive     = codeIssuedAt.Add(5 * time.Minute)
)

// clockAt returns a clock stopped at at.
func clockAt(at time.Time) func() time.Time { return func() time.Time { return at } }

// cancelled returns ctx already cancelled.
func cancelled(ctx context.Context) context.Context {
	cctx, cancel := context.WithCancel(ctx)
	cancel()

	return cctx
}

func TestNewEnrolmentStore(t *testing.T) {
	t.Parallel()

	c := newCiphers(t).current
	var typedNilCipher *MockCipher
	var typedNilResealer *MockEnrolmentResealer

	type testCase struct {
		name          string
		inner         func(ctrl *gomock.Controller) mfa.EnrolmentStore
		resealer      bool
		resealerValue seal.EnrolmentResealer // set (typed nil included) overrides resealer
		cipher        seal.Cipher
		opts          []seal.Option
		assert        func(t *testing.T, store mfa.EnrolmentStore, err error)
	}

	memory := func(*gomock.Controller) mfa.EnrolmentStore { return mfa.NewMemoryEnrolmentStore() }
	refused := func(t *testing.T, store mfa.EnrolmentStore, err error) {
		t.Helper()
		require.ErrorIs(t, err, seal.ErrInvalidConfiguration)
		assert.Nil(t, store)
	}

	cases := []testCase{
		{
			name:     "over a store with device proofs, the enrolment path stays available",
			inner:    memory,
			resealer: true,
			cipher:   c,
			assert: func(t *testing.T, store mfa.EnrolmentStore, err error) {
				require.NoError(t, err)
				assert.Implements(t, (*mfa.DeviceProofStore)(nil), store)

				totp, err := mfa.NewTOTP(store, "scrty")
				require.NoError(t, err)
				assert.True(t, totp.SupportsEnrolmentPath())
			},
		},
		{
			name: "over a store without device proofs, the wrapper claims none",
			inner: func(ctrl *gomock.Controller) mfa.EnrolmentStore {
				return NewMockEnrolmentStore(ctrl)
			},
			resealer: true,
			cipher:   c,
			assert: func(t *testing.T, store mfa.EnrolmentStore, err error) {
				require.NoError(t, err)
				_, ok := store.(mfa.DeviceProofStore)
				assert.False(t, ok)
			},
		},
		{
			name:     "a nil inner store is refused",
			inner:    func(*gomock.Controller) mfa.EnrolmentStore { return nil },
			resealer: true,
			cipher:   c,
			assert:   refused,
		},
		{
			name:     "a nil cipher is refused",
			inner:    memory,
			resealer: true,
			assert:   refused,
		},
		{
			name:     "a typed-nil cipher is refused",
			inner:    memory,
			resealer: true,
			cipher:   typedNilCipher,
			assert:   refused,
		},
		{
			name:   "a nil resealer is refused while re-sealing on read is on",
			inner:  memory,
			cipher: c,
			assert: refused,
		},
		{
			name:   "a nil resealer is accepted with re-sealing on read off",
			inner:  memory,
			cipher: c,
			opts:   []seal.Option{seal.WithResealOnRead(false)},
			assert: func(t *testing.T, store mfa.EnrolmentStore, err error) {
				require.NoError(t, err)
				assert.NotNil(t, store)
			},
		},
		{
			name:     "a nil option is refused",
			inner:    memory,
			resealer: true,
			cipher:   c,
			opts:     []seal.Option{seal.WithResealOnRead(true), nil},
			assert:   refused,
		},
		{
			name:     "a nil clock is refused",
			inner:    memory,
			resealer: true,
			cipher:   c,
			opts:     []seal.Option{seal.WithClock(nil)},
			assert:   refused,
		},
		{
			name:     "a clock is accepted",
			inner:    memory,
			resealer: true,
			cipher:   c,
			opts:     []seal.Option{seal.WithClock(time.Now)},
			assert: func(t *testing.T, store mfa.EnrolmentStore, err error) {
				require.NoError(t, err)
				assert.NotNil(t, store)
			},
		},
		{
			name:          "a typed-nil resealer is refused",
			inner:         memory,
			resealerValue: typedNilResealer,
			cipher:        c,
			assert:        refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			var r seal.EnrolmentResealer
			switch {
			case tc.resealerValue != nil:
				r = tc.resealerValue
			case tc.resealer:
				r = NewMockEnrolmentResealer(ctrl)
			}

			store, err := seal.NewEnrolmentStore(tc.inner(ctrl), r, tc.cipher, tc.opts...)
			tc.assert(t, store, err)
		})
	}
}

func TestEnrolmentStore_PutPending(t *testing.T) {
	t.Parallel()

	cs := newCiphers(t)

	type testCase struct {
		name   string
		cipher func(ctrl *gomock.Controller) seal.Cipher
		inner  func(ctrl *gomock.Controller) mfa.EnrolmentStore
		setup  func(t *testing.T, inner mfa.EnrolmentStore)
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, inner mfa.EnrolmentStore, e mfa.Enrolment, err error)
	}

	cases := []testCase{
		{
			name: "the inner store holds a sealed secret, bound to the user",
			assert: func(t *testing.T, inner mfa.EnrolmentStore, e mfa.Enrolment, err error) {
				require.NoError(t, err)

				got, ok, err := inner.Get(t.Context(), userRef)
				require.NoError(t, err)
				require.True(t, ok)
				assert.NotContains(t, string(got.Secret), mfaSentinel)

				opened, keyID, err := cs.k2Only.Open(got.Secret, seal.MFASecretAAD(userRef))
				require.NoError(t, err)
				assert.Equal(t, "k2", keyID)
				assert.Equal(t, e.Secret, opened)

				got.Secret = e.Secret
				assert.Equal(t, e, got, "every other field is stored as given")
			},
		},
		{
			name: "a consumer cipher that fails to seal stores nothing",
			cipher: func(ctrl *gomock.Controller) seal.Cipher {
				c := NewMockCipher(ctrl)
				c.EXPECT().Seal([]byte(mfaSentinel+string(userRef)), seal.MFASecretAAD(userRef)).
					Return(nil, errCipherDown)

				return c
			},
			assert: func(t *testing.T, inner mfa.EnrolmentStore, _ mfa.Enrolment, err error) {
				require.ErrorIs(t, err, errCipherDown)
				assertNoLeak(t, err, string(userRef), mfaSentinel)

				_, ok, err := inner.Get(t.Context(), userRef)
				require.NoError(t, err)
				assert.False(t, ok)
			},
		},
		{
			name: "a confirmed enrolment is refused with the store's own sentinel",
			setup: func(t *testing.T, inner mfa.EnrolmentStore) {
				putSealed(t, inner, cs.current, pendingEnrolment(t, userRef))
				ok, err := inner.Confirm(t.Context(), userRef, 1, time.Now())
				require.NoError(t, err)
				require.True(t, ok)
			},
			assert: func(t *testing.T, _ mfa.EnrolmentStore, _ mfa.Enrolment, err error) {
				assert.Same(t, mfa.ErrAlreadyEnrolled, err, "the bare sentinel comes back as itself")
			},
		},
		{
			name: "an inner store failure is returned behind fixed text",
			inner: func(ctrl *gomock.Controller) mfa.EnrolmentStore {
				inner := NewMockEnrolmentStore(ctrl)
				inner.EXPECT().PutPending(gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, _ mfa.Enrolment) error { return ctx.Err() })

				return inner
			},
			ctx: cancelled,
			assert: func(t *testing.T, _ mfa.EnrolmentStore, _ mfa.Enrolment, err error) {
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
			var inner mfa.EnrolmentStore = mfa.NewMemoryEnrolmentStore()
			if tc.inner != nil {
				inner = tc.inner(ctrl)
			}
			if tc.setup != nil {
				tc.setup(t, inner)
			}
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			store, err := seal.NewEnrolmentStore(inner, NewMockEnrolmentResealer(ctrl), c)
			require.NoError(t, err)

			e := pendingEnrolment(t, userRef)
			tc.assert(t, inner, e, store.PutPending(ctx, e))
		})
	}
}

// proofFixture is what a ProveDevice case asserts against.
type proofFixture struct {
	inner *mfa.MemoryEnrolmentStore
	gen   id.ID
}

func TestEnrolmentStore_ProveDevice(t *testing.T) {
	t.Parallel()

	cs := newCiphers(t)
	at := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	until := at.Add(10 * time.Minute)

	type testCase struct {
		name   string
		cipher func(ctrl *gomock.Controller, gen id.ID) seal.Cipher
		code   []byte
		assert func(t *testing.T, f proofFixture, ok bool, err error)
	}

	stored := func(t *testing.T, f proofFixture) mfa.Enrolment {
		t.Helper()
		e, found, err := f.inner.Get(t.Context(), userRef)
		require.NoError(t, err)
		require.True(t, found)

		return e
	}

	cases := []testCase{
		{
			name: "the inner store holds the emailed code sealed, bound to generation and user",
			code: []byte(codeSentinel),
			assert: func(t *testing.T, f proofFixture, ok bool, err error) {
				require.NoError(t, err)
				require.True(t, ok)

				e := stored(t, f)
				require.NotNil(t, e.EmailCode)
				assert.NotContains(t, string(e.EmailCode), codeSentinel, "the inner store received the emailed code in plaintext")

				opened, keyID, err := cs.k2Only.Open(e.EmailCode, seal.MFAEmailCodeAAD(f.gen, userRef))
				require.NoError(t, err)
				assert.Equal(t, "k2", keyID)
				assert.Equal(t, []byte(codeSentinel), opened)

				other, err := id.NewV7Generator().NewID()
				require.NoError(t, err)
				for name, aad := range map[string][]byte{
					"another generation": seal.MFAEmailCodeAAD(other, userRef),
					"another user":       seal.MFAEmailCodeAAD(f.gen, "victim"),
					"the user's secret":  seal.MFASecretAAD(userRef),
					"no additional data": nil,
				} {
					_, _, err := cs.current.Open(e.EmailCode, aad)
					assert.ErrorIs(t, err, seal.ErrDecryptionFailed, "the code opened under %s", name)
				}

				assert.True(t, e.DeviceProvenAt.Equal(at))
				assert.True(t, e.EmailCodeUntil.Equal(until))
			},
		},
		{
			name: "no emailed code reaches the inner store as none, without consulting the cipher",
			cipher: func(ctrl *gomock.Controller, _ id.ID) seal.Cipher {
				return NewMockCipher(ctrl)
			},
			assert: func(t *testing.T, f proofFixture, ok bool, err error) {
				require.NoError(t, err)
				require.True(t, ok)
				assert.Nil(t, stored(t, f).EmailCode)
			},
		},
		{
			name: "a cipher that fails to seal the emailed code stores nothing",
			cipher: func(ctrl *gomock.Controller, gen id.ID) seal.Cipher {
				c := NewMockCipher(ctrl)
				c.EXPECT().Seal([]byte(codeSentinel), seal.MFAEmailCodeAAD(gen, userRef)).Return(nil, errCipherDown)

				return c
			},
			code: []byte(codeSentinel),
			assert: func(t *testing.T, f proofFixture, ok bool, err error) {
				require.ErrorIs(t, err, errCipherDown)
				assert.False(t, ok)
				assertNoLeak(t, err, string(userRef), codeSentinel)

				e := stored(t, f)
				assert.True(t, e.DeviceProvenAt.IsZero(), "no device proof is recorded")
				assert.Nil(t, e.EmailCode)
				assert.Zero(t, e.LastStep)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			inner := mfa.NewMemoryEnrolmentStore()
			e := pendingEnrolment(t, userRef)
			putSealed(t, inner, cs.current, e)

			c := cs.current
			if tc.cipher != nil {
				c = tc.cipher(ctrl, e.Generation)
			}

			store, err := seal.NewEnrolmentStore(inner, nil, c, seal.WithResealOnRead(false))
			require.NoError(t, err)
			p, isProof := store.(mfa.DeviceProofStore)
			require.True(t, isProof)

			ok, err := p.ProveDevice(t.Context(), userRef, e.Generation, 9, tc.code, until, at)
			tc.assert(t, proofFixture{inner: inner, gen: e.Generation}, ok, err)
		})
	}
}

// enrolmentFixture is what a Get case sets up and asserts against.
type enrolmentFixture struct {
	store    mfa.EnrolmentStore
	inner    mfa.EnrolmentStore
	resealer *MockEnrolmentResealer
}

func TestEnrolmentStore_Get(t *testing.T) {
	t.Parallel()

	cs := newCiphers(t)
	gone := mustCipher(t, seal.WithEncryptionKey("gone", keyThree))
	secret := []byte(mfaSentinel + string(userRef))

	// Every case reads at codeLive, before proveSealed's code expires, unless
	// it names a clock of its own or asks for the default one.
	type testCase struct {
		name         string
		opts         []seal.Option
		defaultClock bool
		cipher       func(ctrl *gomock.Controller) seal.Cipher
		inner        func(ctrl *gomock.Controller) mfa.EnrolmentStore
		setup        func(t *testing.T, f enrolmentFixture)
		ctx          func(ctx context.Context) context.Context
		assert       func(t *testing.T, f enrolmentFixture, e mfa.Enrolment, found bool, err error)
	}

	unreadable := func(want error) func(*testing.T, enrolmentFixture, mfa.Enrolment, bool, error) {
		return func(t *testing.T, _ enrolmentFixture, e mfa.Enrolment, found bool, err error) {
			t.Helper()
			require.ErrorIs(t, err, want)
			assert.False(t, found)
			assert.Equal(t, mfa.Enrolment{}, e)
			assertNoLeak(t, err, string(userRef), "gone")
		}
	}

	opened := func(t *testing.T, _ enrolmentFixture, e mfa.Enrolment, found bool, err error) {
		t.Helper()
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, secret, e.Secret)
	}

	cases := []testCase{
		{
			name: "an enrolment loads with its secret and every other field",
			setup: func(t *testing.T, f enrolmentFixture) {
				require.NoError(t, f.store.PutPending(t.Context(), pendingEnrolment(t, userRef)))
				ok, err := f.store.Confirm(t.Context(), userRef, 7, time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC))
				require.NoError(t, err)
				require.True(t, ok)
			},
			assert: func(t *testing.T, f enrolmentFixture, e mfa.Enrolment, found bool, err error) {
				require.NoError(t, err)
				require.True(t, found)
				assert.Equal(t, secret, e.Secret)

				want, _, err := f.inner.Get(t.Context(), userRef)
				require.NoError(t, err)
				want.Secret = secret
				assert.Equal(t, want, e)
				assert.Equal(t, int64(7), e.LastStep)
			},
		},
		{
			name: "no enrolment is absent, without consulting the cipher",
			cipher: func(ctrl *gomock.Controller) seal.Cipher {
				return NewMockCipher(ctrl)
			},
			assert: func(t *testing.T, _ enrolmentFixture, _ mfa.Enrolment, found bool, err error) {
				require.NoError(t, err)
				assert.False(t, found)
			},
		},
		{
			name: "an unreadable secret is an error, never not enrolled",
			setup: func(t *testing.T, f enrolmentFixture) {
				e := pendingEnrolment(t, userRef)
				tampered := bytes.Clone(putSealed(t, f.inner, cs.current, e))
				tampered[len(tampered)-1] ^= 0x01
				e.Secret = tampered
				require.NoError(t, f.inner.PutPending(t.Context(), e))
			},
			assert: unreadable(seal.ErrDecryptionFailed),
		},
		{
			name: "a secret copied from another user's enrolment does not open",
			setup: func(t *testing.T, f enrolmentFixture) {
				e := pendingEnrolment(t, userRef)
				e.Secret = putSealed(t, f.inner, cs.current, pendingEnrolment(t, "victim"))
				require.NoError(t, f.inner.PutPending(t.Context(), e))
			},
			assert: unreadable(seal.ErrDecryptionFailed),
		},
		{
			name: "a secret sealed under a key the ring no longer holds is an unknown key id",
			setup: func(t *testing.T, f enrolmentFixture) {
				putSealed(t, f.inner, gone, pendingEnrolment(t, userRef))
			},
			assert: func(t *testing.T, f enrolmentFixture, e mfa.Enrolment, found bool, err error) {
				unreadable(seal.ErrUnknownKeyID)(t, f, e, found, err)
				assert.NotErrorIs(t, err, seal.ErrDecryptionFailed)
			},
		},
		{
			name: "a secret sealed under the retired key is re-sealed under the active key",
			setup: func(t *testing.T, f enrolmentFixture) {
				old := putSealed(t, f.inner, cs.retired, pendingEnrolment(t, userRef))
				f.resealer.EXPECT().ResealEnrolmentSecret(gomock.Any(), userRef, old, gomock.Any()).DoAndReturn(
					func(_ context.Context, _ identity.UserID, _, resealed []byte) error {
						opened, keyID, err := cs.k2Only.Open(resealed, seal.MFASecretAAD(userRef))
						require.NoError(t, err)
						assert.Equal(t, "k2", keyID)
						assert.Equal(t, secret, opened)

						return nil
					})
			},
			assert: opened,
		},
		{
			name: "a secret sealed under the active key is not re-sealed",
			setup: func(t *testing.T, f enrolmentFixture) {
				putSealed(t, f.inner, cs.current, pendingEnrolment(t, userRef))
			},
			assert: opened,
		},
		{
			name: "a failed re-seal does not fail the read",
			setup: func(t *testing.T, f enrolmentFixture) {
				putSealed(t, f.inner, cs.retired, pendingEnrolment(t, userRef))
				f.resealer.EXPECT().ResealEnrolmentSecret(gomock.Any(), userRef, gomock.Any(), gomock.Any()).
					Return(errors.New("conditional update failed"))
			},
			assert: opened,
		},
		{
			name: "re-sealing switched off leaves the retired-key secret alone",
			opts: []seal.Option{seal.WithResealOnRead(false)},
			setup: func(t *testing.T, f enrolmentFixture) {
				putSealed(t, f.inner, cs.retired, pendingEnrolment(t, userRef))
			},
			assert: func(t *testing.T, f enrolmentFixture, e mfa.Enrolment, found bool, err error) {
				opened(t, f, e, found, err)

				_, keyID, err := cs.retired.Open(innerSecret(t, f.inner, userRef), seal.MFASecretAAD(userRef))
				require.NoError(t, err)
				assert.Equal(t, "k1", keyID)
			},
		},
		{
			name: "a cipher that cannot name its active key skips the re-seal, not the read",
			cipher: func(ctrl *gomock.Controller) seal.Cipher {
				c := NewMockCipher(ctrl)
				c.EXPECT().Open(gomock.Any(), seal.MFASecretAAD(userRef)).Return(secret, "k1", nil)
				c.EXPECT().ActiveKeyID().Return("", errCipherDown)

				return c
			},
			setup: func(t *testing.T, f enrolmentFixture) {
				putSealed(t, f.inner, cs.retired, pendingEnrolment(t, userRef))
			},
			assert: opened,
		},
		{
			name: "a failed re-seal Seal does not call the resealer",
			cipher: func(ctrl *gomock.Controller) seal.Cipher {
				c := NewMockCipher(ctrl)
				c.EXPECT().Open(gomock.Any(), seal.MFASecretAAD(userRef)).Return(secret, "k1", nil)
				c.EXPECT().ActiveKeyID().Return("k2", nil)
				c.EXPECT().Seal(secret, seal.MFASecretAAD(userRef)).Return(nil, errCipherDown)

				return c
			},
			setup: func(t *testing.T, f enrolmentFixture) {
				putSealed(t, f.inner, cs.retired, pendingEnrolment(t, userRef))
			},
			assert: opened,
		},
		{
			name: "an emailed code loads opened",
			setup: func(t *testing.T, f enrolmentFixture) {
				e := pendingEnrolment(t, userRef)
				putSealed(t, f.inner, cs.current, e)
				proveSealed(t, f.inner, cs.current, e.Generation, e.Generation)
			},
			assert: func(t *testing.T, f enrolmentFixture, e mfa.Enrolment, found bool, err error) {
				opened(t, f, e, found, err)
				assert.Equal(t, []byte(codeSentinel), e.EmailCode)
			},
		},
		{
			name: "Emailed code unreadable: a tampered code is an error, never not enrolled",
			setup: func(t *testing.T, f enrolmentFixture) {
				e := pendingEnrolment(t, userRef)
				putSealed(t, f.inner, cs.current, e)
				sealed, err := cs.current.Seal([]byte(codeSentinel), seal.MFAEmailCodeAAD(e.Generation, userRef))
				require.NoError(t, err)
				sealed[len(sealed)-1] ^= 0x01
				p, _ := f.inner.(mfa.DeviceProofStore)
				ok, err := p.ProveDevice(t.Context(), userRef, e.Generation, 9, sealed, time.Now().Add(time.Hour), time.Now())
				require.NoError(t, err)
				require.True(t, ok)
			},
			assert: unreadable(seal.ErrDecryptionFailed),
		},
		{
			name: "an emailed code sealed for another generation does not open",
			setup: func(t *testing.T, f enrolmentFixture) {
				earlier := pendingEnrolment(t, userRef)
				e := pendingEnrolment(t, userRef)
				putSealed(t, f.inner, cs.current, e)
				proveSealed(t, f.inner, cs.current, e.Generation, earlier.Generation)
			},
			assert: unreadable(seal.ErrDecryptionFailed),
		},
		{
			name: "an emailed code sealed under a key the ring no longer holds fails closed",
			setup: func(t *testing.T, f enrolmentFixture) {
				e := pendingEnrolment(t, userRef)
				putSealed(t, f.inner, cs.current, e)
				proveSealed(t, f.inner, gone, e.Generation, e.Generation)
			},
			assert: func(t *testing.T, f enrolmentFixture, e mfa.Enrolment, found bool, err error) {
				unreadable(seal.ErrUnknownKeyID)(t, f, e, found, err)
				assertNoLeak(t, err, codeSentinel)
			},
		},
		{
			// The code is not a sealed value at all: had the store tried to
			// open it, the mock cipher would have failed the case.
			name: "Expired code is not opened: an unopenable code at its expiry reads back as none, expiry kept",
			opts: []seal.Option{seal.WithClock(clockAt(codeUntil))},
			cipher: func(ctrl *gomock.Controller) seal.Cipher {
				c := NewMockCipher(ctrl)
				c.EXPECT().Open(gomock.Any(), seal.MFASecretAAD(userRef)).Return(secret, "k2", nil)
				c.EXPECT().ActiveKeyID().Return("k2", nil)

				return c
			},
			setup: func(t *testing.T, f enrolmentFixture) {
				e := pendingEnrolment(t, userRef)
				putSealed(t, f.inner, cs.current, e)
				p, _ := f.inner.(mfa.DeviceProofStore)
				ok, err := p.ProveDevice(t.Context(), userRef, e.Generation, 9, []byte("not a sealed value"),
					codeUntil, codeIssuedAt)
				require.NoError(t, err)
				require.True(t, ok)
			},
			assert: func(t *testing.T, f enrolmentFixture, e mfa.Enrolment, found bool, err error) {
				opened(t, f, e, found, err)
				assert.Nil(t, e.EmailCode)
				assert.True(t, e.EmailCodeUntil.Equal(codeUntil), "EmailCodeUntil is %v, want %v", e.EmailCodeUntil, codeUntil)
				assert.True(t, e.DeviceProvenAt.Equal(codeIssuedAt), "DeviceProvenAt is %v", e.DeviceProvenAt)
			},
		},
		{
			name: "Abandoned code after its key is removed: an expired code reads back as none, expiry kept",
			opts: []seal.Option{seal.WithClock(clockAt(codeUntil.Add(time.Hour)))},
			setup: func(t *testing.T, f enrolmentFixture) {
				e := pendingEnrolment(t, userRef)
				putSealed(t, f.inner, cs.current, e)
				proveSealed(t, f.inner, gone, e.Generation, e.Generation)
			},
			assert: func(t *testing.T, f enrolmentFixture, e mfa.Enrolment, found bool, err error) {
				opened(t, f, e, found, err)
				assert.Nil(t, e.EmailCode)
				assert.True(t, e.EmailCodeUntil.Equal(codeUntil), "EmailCodeUntil is %v, want %v", e.EmailCodeUntil, codeUntil)
			},
		},
		{
			name: "an expired code that would open is still not opened",
			opts: []seal.Option{seal.WithClock(clockAt(codeUntil))},
			setup: func(t *testing.T, f enrolmentFixture) {
				e := pendingEnrolment(t, userRef)
				putSealed(t, f.inner, cs.current, e)
				proveSealed(t, f.inner, cs.current, e.Generation, e.Generation)
			},
			assert: func(t *testing.T, f enrolmentFixture, e mfa.Enrolment, found bool, err error) {
				opened(t, f, e, found, err)
				assert.Nil(t, e.EmailCode)
				assert.True(t, e.EmailCodeUntil.Equal(codeUntil), "EmailCodeUntil is %v, want %v", e.EmailCodeUntil, codeUntil)
			},
		},
		{
			name: "a code one instant before its expiry is still opened",
			opts: []seal.Option{seal.WithClock(clockAt(codeUntil.Add(-time.Nanosecond)))},
			setup: func(t *testing.T, f enrolmentFixture) {
				e := pendingEnrolment(t, userRef)
				putSealed(t, f.inner, cs.current, e)
				proveSealed(t, f.inner, cs.current, e.Generation, e.Generation)
			},
			assert: func(t *testing.T, f enrolmentFixture, e mfa.Enrolment, found bool, err error) {
				opened(t, f, e, found, err)
				assert.Equal(t, []byte(codeSentinel), e.EmailCode)
			},
		},
		{
			// proveSealed's code expired long before the wall clock.
			name:         "the default clock is the wall clock: a code expired by it is not opened",
			defaultClock: true,
			setup: func(t *testing.T, f enrolmentFixture) {
				e := pendingEnrolment(t, userRef)
				putSealed(t, f.inner, cs.current, e)
				proveSealed(t, f.inner, gone, e.Generation, e.Generation)
			},
			assert: func(t *testing.T, f enrolmentFixture, e mfa.Enrolment, found bool, err error) {
				opened(t, f, e, found, err)
				assert.Nil(t, e.EmailCode)
			},
		},
		{
			name: "Emailed code is not rewritten on read: a retired-key code opens and stays as stored",
			setup: func(t *testing.T, f enrolmentFixture) {
				e := pendingEnrolment(t, userRef)
				old := putSealed(t, f.inner, cs.retired, e)
				proveSealed(t, f.inner, cs.retired, e.Generation, e.Generation)
				// Only the secret is handed to the resealer; the code never is.
				f.resealer.EXPECT().ResealEnrolmentSecret(gomock.Any(), userRef, old, gomock.Any()).Return(nil)
			},
			assert: func(t *testing.T, f enrolmentFixture, e mfa.Enrolment, found bool, err error) {
				after, _, getErr := f.inner.Get(t.Context(), userRef)
				require.NoError(t, getErr)

				opened(t, f, e, found, err)
				assert.Equal(t, []byte(codeSentinel), e.EmailCode)

				_, keyID, err := cs.retired.Open(after.EmailCode, seal.MFAEmailCodeAAD(e.Generation, userRef))
				require.NoError(t, err)
				assert.Equal(t, "k1", keyID, "the stored code stays sealed under the retired key")
			},
		},
		{
			name: "a cancelled read is an error, never not enrolled",
			inner: func(ctrl *gomock.Controller) mfa.EnrolmentStore {
				inner := NewMockEnrolmentStore(ctrl)
				inner.EXPECT().Get(gomock.Any(), userRef).DoAndReturn(
					func(ctx context.Context, _ identity.UserID) (mfa.Enrolment, bool, error) {
						return mfa.Enrolment{}, false, ctx.Err()
					})

				return inner
			},
			ctx: cancelled,
			assert: func(t *testing.T, _ enrolmentFixture, _ mfa.Enrolment, found bool, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.False(t, found)
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
			var inner mfa.EnrolmentStore = mfa.NewMemoryEnrolmentStore()
			if tc.inner != nil {
				inner = tc.inner(ctrl)
			}
			resealer := NewMockEnrolmentResealer(ctrl)

			opts := tc.opts
			if !tc.defaultClock {
				opts = append([]seal.Option{seal.WithClock(clockAt(codeLive))}, tc.opts...)
			}
			store, err := seal.NewEnrolmentStore(inner, resealer, c, opts...)
			require.NoError(t, err)

			f := enrolmentFixture{store: store, inner: inner, resealer: resealer}
			if tc.setup != nil {
				tc.setup(t, f)
			}
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			e, found, err := store.Get(ctx, userRef)
			tc.assert(t, f, e, found, err)
		})
	}
}

// TestEnrolmentStore_PassThrough covers the operations that carry no secret:
// each is a different call on the same wrapped store, so the case runs it.
func TestEnrolmentStore_PassThrough(t *testing.T) {
	t.Parallel()

	cs := newCiphers(t)
	at := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)

	type testCase struct {
		name  string
		setup func(t *testing.T, inner *mfa.MemoryEnrolmentStore) id.ID
		run   func(t *testing.T, store mfa.EnrolmentStore, inner *mfa.MemoryEnrolmentStore, gen id.ID)
	}

	pending := func(t *testing.T, inner *mfa.MemoryEnrolmentStore) id.ID {
		t.Helper()
		e := pendingEnrolment(t, userRef)
		putSealed(t, inner, cs.current, e)

		return e.Generation
	}
	confirmed := func(t *testing.T, inner *mfa.MemoryEnrolmentStore) id.ID {
		t.Helper()
		gen := pending(t, inner)
		ok, err := inner.Confirm(t.Context(), userRef, 3, at)
		require.NoError(t, err)
		require.True(t, ok)

		return gen
	}
	proofs := func(t *testing.T, store mfa.EnrolmentStore) mfa.DeviceProofStore {
		t.Helper()
		p, ok := store.(mfa.DeviceProofStore)
		require.True(t, ok)

		return p
	}

	cases := []testCase{
		{
			name:  "Confirm confirms the pending enrolment",
			setup: pending,
			run: func(t *testing.T, store mfa.EnrolmentStore, inner *mfa.MemoryEnrolmentStore, _ id.ID) {
				ok, err := store.Confirm(t.Context(), userRef, 3, at)
				require.NoError(t, err)
				assert.True(t, ok)

				e, _, err := inner.Get(t.Context(), userRef)
				require.NoError(t, err)
				assert.True(t, e.ConfirmedAt.Equal(at))
			},
		},
		{
			name: "Confirm reports no pending enrolment",
			run: func(t *testing.T, store mfa.EnrolmentStore, _ *mfa.MemoryEnrolmentStore, _ id.ID) {
				ok, err := store.Confirm(t.Context(), userRef, 3, at)
				require.NoError(t, err)
				assert.False(t, ok)
			},
		},
		{
			name:  "AcceptStep accepts a later step once",
			setup: confirmed,
			run: func(t *testing.T, store mfa.EnrolmentStore, _ *mfa.MemoryEnrolmentStore, _ id.ID) {
				ok, err := store.AcceptStep(t.Context(), userRef, 4)
				require.NoError(t, err)
				assert.True(t, ok)

				ok, err = store.AcceptStep(t.Context(), userRef, 4)
				require.NoError(t, err)
				assert.False(t, ok)
			},
		},
		{
			name:  "Delete removes the enrolment",
			setup: confirmed,
			run: func(t *testing.T, store mfa.EnrolmentStore, inner *mfa.MemoryEnrolmentStore, _ id.ID) {
				require.NoError(t, store.Delete(t.Context(), userRef))

				_, ok, err := inner.Get(t.Context(), userRef)
				require.NoError(t, err)
				assert.False(t, ok)
			},
		},
		{
			name:  "ProveDevice, ChargeEmailCode and Complete reach the inner store",
			setup: pending,
			run: func(t *testing.T, store mfa.EnrolmentStore, inner *mfa.MemoryEnrolmentStore, gen id.ID) {
				p := proofs(t, store)

				ok, err := p.ProveDevice(t.Context(), userRef, gen, 5, []byte("123456"), at.Add(time.Hour), at)
				require.NoError(t, err)
				require.True(t, ok)

				attempts, ok, err := p.ChargeEmailCode(t.Context(), userRef, gen, at)
				require.NoError(t, err)
				require.True(t, ok)
				assert.Equal(t, 1, attempts)

				ok, err = p.Complete(t.Context(), userRef, gen, at)
				require.NoError(t, err)
				assert.True(t, ok)

				e, _, err := inner.Get(t.Context(), userRef)
				require.NoError(t, err)
				assert.True(t, e.ConfirmedAt.Equal(at))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inner := mfa.NewMemoryEnrolmentStore()
			var gen id.ID
			if tc.setup != nil {
				gen = tc.setup(t, inner)
			}

			store, err := seal.NewEnrolmentStore(inner, nil, cs.current, seal.WithResealOnRead(false))
			require.NoError(t, err)

			tc.run(t, store, inner, gen)
		})
	}
}

// TestEnrolmentStore_PassThroughFailure pins that an inner failure on an
// operation carrying no secret comes back behind fixed text, still matching.
func TestEnrolmentStore_PassThroughFailure(t *testing.T) {
	t.Parallel()

	c := newCiphers(t).current

	type testCase struct {
		name   string
		expect func(inner *MockEnrolmentStore)
		run    func(ctx context.Context, store mfa.EnrolmentStore) error
		assert func(t *testing.T, err error)
	}

	failed := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, errCipherDown)
		assertNoLeak(t, err, string(userRef))
	}

	cases := []testCase{
		{
			name: "Confirm",
			expect: func(inner *MockEnrolmentStore) {
				inner.EXPECT().Confirm(gomock.Any(), userRef, int64(1), gomock.Any()).Return(false, errCipherDown)
			},
			run: func(ctx context.Context, store mfa.EnrolmentStore) error {
				_, err := store.Confirm(ctx, userRef, 1, time.Now())

				return err
			},
			assert: failed,
		},
		{
			name: "AcceptStep",
			expect: func(inner *MockEnrolmentStore) {
				inner.EXPECT().AcceptStep(gomock.Any(), userRef, int64(1)).Return(false, errCipherDown)
			},
			run: func(ctx context.Context, store mfa.EnrolmentStore) error {
				_, err := store.AcceptStep(ctx, userRef, 1)

				return err
			},
			assert: failed,
		},
		{
			name: "Delete",
			expect: func(inner *MockEnrolmentStore) {
				inner.EXPECT().Delete(gomock.Any(), userRef).Return(errCipherDown)
			},
			run: func(ctx context.Context, store mfa.EnrolmentStore) error {
				return store.Delete(ctx, userRef)
			},
			assert: failed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inner := NewMockEnrolmentStore(gomock.NewController(t))
			tc.expect(inner)

			store, err := seal.NewEnrolmentStore(inner, nil, c, seal.WithResealOnRead(false))
			require.NoError(t, err)

			tc.assert(t, tc.run(t.Context(), store))
		})
	}
}
