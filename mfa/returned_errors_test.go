package mfa_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/id"
)

// errMFAFixture is a dependency failure whose text quotes a value the library
// never saw (an address) and one it did (the user reference). Neither may
// reach the text of an error an mfa method returns.
var errMFAFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// pathStore is an enrolment store that also serves the enrolment path, built
// from the two generated doubles.
type pathStore struct {
	*MockEnrolmentStore
	*MockDeviceProofStore
}

// returnedErrorsDeps is what one row of TestMFAReturnedErrors works through.
type returnedErrorsDeps struct {
	store      *MockEnrolmentStore
	proofs     *MockDeviceProofStore
	method     *mfa.TOTP
	enrolments *MockEnrolmentRemover
	sessions   *MockSessionRevoker
	users      *MockUserLoader
	sender     *MockSender
	gen        id.ID
	secret     []byte
	now        time.Time
}

// redeemFailingEnroller is a consumer's Enroller whose RedeemEmailCode fails
// with its own error, as completingEnroller in enroller_test.go completes.
type redeemFailingEnroller struct {
	mfa.Enroller

	err error
}

func (e redeemFailingEnroller) RedeemEmailCode(context.Context, identity.UserID, id.ID, string) error {
	return e.err
}

func (d *returnedErrorsDeps) code(t *testing.T) string {
	t.Helper()

	return codeAt(t, d.secret, d.now, 6, 30*time.Second)
}

func (d *returnedErrorsDeps) reset(contact mfa.ContactResolver) mfa.ResetDeps {
	return mfa.ResetDeps{
		Enrolments: d.enrolments,
		Sessions:   d.sessions,
		Users:      d.users,
		Sender:     d.sender,
		Contact:    contact,
	}
}

// assertRedacted is what every row with a failing dependency asserts: the text
// is the library's own, the cause is still reachable, and the failure is not
// mistaken for any refusal the package defines.
func assertRedacted(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "alice@example.com")
	assert.NotContains(t, err.Error(), "u-123")
	assert.ErrorIs(t, err, errMFAFixture)

	for _, sentinel := range []error{
		mfa.ErrInvalidCode, mfa.ErrAlreadyEnrolled, mfa.ErrEmailCodeInvalid,
		mfa.ErrConfig, mfa.ErrSameChannel, mfa.ErrVerifyThrottled, mfa.ErrEnrolmentThrottled,
	} {
		assert.NotErrorIs(t, err, sentinel, "a dependency failure is not a refusal")
	}
}

func TestMFAReturnedErrors(t *testing.T) {
	t.Parallel()

	const user identity.UserID = "u-123"

	ada := &identity.Details{ID: user, Username: "alice@example.com"}

	type testCase struct {
		name    string
		arrange func(t *testing.T, d *returnedErrorsDeps)
		act     func(t *testing.T, ctx context.Context, d *returnedErrorsDeps) error
		assert  func(t *testing.T, err error)
	}

	confirmed := func(d *returnedErrorsDeps) mfa.Enrolment {
		return mfa.Enrolment{User: user, Secret: d.secret, ConfirmedAt: d.now.Add(-time.Hour), Generation: d.gen}
	}
	pending := func(d *returnedErrorsDeps) mfa.Enrolment {
		return mfa.Enrolment{User: user, Secret: d.secret, Generation: d.gen}
	}
	proven := func(d *returnedErrorsDeps) mfa.Enrolment {
		e := pending(d)
		e.DeviceProvenAt = d.now

		return e
	}

	begin := func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
		_, err := d.method.BeginEnrolment(ctx, user, "alice")

		return err
	}
	beginGeneration := func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
		_, _, err := d.method.BeginEnrolmentGeneration(ctx, user, "alice")

		return err
	}
	putPendingReturns := func(err error) func(*testing.T, *returnedErrorsDeps) {
		return func(_ *testing.T, d *returnedErrorsDeps) {
			d.store.EXPECT().PutPending(gomock.Any(), gomock.Any()).Return(err)
		}
	}
	// A store that wraps the sentinel with text of its own: the sentinel still
	// matches, the text does not come back.
	wrappedAlreadyEnrolled := fmt.Errorf("store: %w for alice@example.com (u-123)", mfa.ErrAlreadyEnrolled)
	assertWrappedAlreadyEnrolled := func(t *testing.T, err error) {
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "alice@example.com")
		assert.NotContains(t, err.Error(), "u-123")
		assert.ErrorIs(t, err, mfa.ErrAlreadyEnrolled)
		assert.ErrorIs(t, err, wrappedAlreadyEnrolled)
	}
	assertBareAlreadyEnrolled := func(t *testing.T, err error) {
		assert.Equal(t, mfa.ErrAlreadyEnrolled, err, "a bare sentinel comes back as itself") //nolint:testifylint // identity
		assert.True(t, err == mfa.ErrAlreadyEnrolled)                                        //nolint:errorlint // identity is the point
		assert.Equal(t, mfa.ErrAlreadyEnrolled.Error(), err.Error())
	}

	cases := []testCase{
		// TOTP.Verify
		{
			name: "verify: the enrolment store cannot read",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.store.EXPECT().Get(gomock.Any(), user).Return(mfa.Enrolment{}, false, errMFAFixture)
			},
			act: func(t *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return d.method.Verify(ctx, user, d.code(t))
			},
			assert: assertRedacted,
		},
		{
			name: "verify: the enrolment store cannot accept the step",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.store.EXPECT().Get(gomock.Any(), user).Return(confirmed(d), true, nil)
				d.store.EXPECT().AcceptStep(gomock.Any(), user, gomock.Any()).Return(false, errMFAFixture)
			},
			act: func(t *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return d.method.Verify(ctx, user, d.code(t))
			},
			assert: assertRedacted,
		},
		// TOTP.Enrolled
		{
			name: "enrolled: the enrolment store cannot read",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.store.EXPECT().Get(gomock.Any(), user).Return(mfa.Enrolment{}, false, errMFAFixture)
			},
			act: func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				_, err := d.method.Enrolled(ctx, user)

				return err
			},
			assert: assertRedacted,
		},
		// TOTP.BeginEnrolment and BeginEnrolmentGeneration
		{
			name:    "begin: the enrolment store cannot write the pending enrolment",
			arrange: putPendingReturns(errMFAFixture),
			act:     begin,
			assert:  assertRedacted,
		},
		{
			name:    "begin generation: the enrolment store cannot write the pending enrolment",
			arrange: putPendingReturns(errMFAFixture),
			act:     beginGeneration,
			assert:  assertRedacted,
		},
		{
			name:    "begin: a bare ErrAlreadyEnrolled from the store comes back as itself",
			arrange: putPendingReturns(mfa.ErrAlreadyEnrolled),
			act:     begin,
			assert:  assertBareAlreadyEnrolled,
		},
		{
			name:    "begin generation: a bare ErrAlreadyEnrolled from the store comes back as itself",
			arrange: putPendingReturns(mfa.ErrAlreadyEnrolled),
			act:     beginGeneration,
			assert:  assertBareAlreadyEnrolled,
		},
		{
			name:    "begin: a store's own error wrapping ErrAlreadyEnrolled still matches it",
			arrange: putPendingReturns(wrappedAlreadyEnrolled),
			act:     begin,
			assert:  assertWrappedAlreadyEnrolled,
		},
		// TOTP.ConfirmEnrolment
		{
			name: "confirm: the enrolment store cannot read",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.store.EXPECT().Get(gomock.Any(), user).Return(mfa.Enrolment{}, false, errMFAFixture)
			},
			act: func(t *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return d.method.ConfirmEnrolment(ctx, user, d.code(t))
			},
			assert: assertRedacted,
		},
		{
			name: "confirm: the enrolment store cannot confirm",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.store.EXPECT().Get(gomock.Any(), user).Return(pending(d), true, nil)
				d.store.EXPECT().Confirm(gomock.Any(), user, gomock.Any(), gomock.Any()).Return(false, errMFAFixture)
			},
			act: func(t *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return d.method.ConfirmEnrolment(ctx, user, d.code(t))
			},
			assert: assertRedacted,
		},
		// TOTP.RemoveEnrolment
		{
			name: "remove: the enrolment store cannot delete",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.store.EXPECT().Delete(gomock.Any(), user).Return(errMFAFixture)
			},
			act: func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return d.method.RemoveEnrolment(ctx, user)
			},
			assert: assertRedacted,
		},
		// TOTP.ProveDevice
		{
			name: "prove device: the enrolment store cannot read",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.store.EXPECT().Get(gomock.Any(), user).Return(mfa.Enrolment{}, false, errMFAFixture)
			},
			act: func(t *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				_, err := d.method.ProveDevice(ctx, user, d.gen, d.code(t), false, 0)

				return err
			},
			assert: assertRedacted,
		},
		{
			name: "prove device: the device-proof store cannot record the proof",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.store.EXPECT().Get(gomock.Any(), user).Return(pending(d), true, nil)
				d.proofs.EXPECT().
					ProveDevice(gomock.Any(), user, d.gen, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(false, errMFAFixture)
			},
			act: func(t *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				_, err := d.method.ProveDevice(ctx, user, d.gen, d.code(t), false, 0)

				return err
			},
			assert: assertRedacted,
		},
		// TOTP.CompleteEnrolment
		{
			name: "complete: the enrolment store cannot read",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.store.EXPECT().Get(gomock.Any(), user).Return(mfa.Enrolment{}, false, errMFAFixture)
			},
			act: func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return d.method.CompleteEnrolment(ctx, user, d.gen)
			},
			assert: assertRedacted,
		},
		{
			name: "complete: the device-proof store cannot complete",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.store.EXPECT().Get(gomock.Any(), user).Return(proven(d), true, nil)
				d.proofs.EXPECT().Complete(gomock.Any(), user, d.gen, gomock.Any()).Return(false, errMFAFixture)
			},
			act: func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return d.method.CompleteEnrolment(ctx, user, d.gen)
			},
			assert: assertRedacted,
		},
		// TOTP.RedeemEmailCode
		{
			name: "redeem: the device-proof store cannot charge the attempt",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.proofs.EXPECT().ChargeEmailCode(gomock.Any(), user, d.gen, gomock.Any()).Return(0, false, errMFAFixture)
			},
			act: func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return d.method.RedeemEmailCode(ctx, user, d.gen, "123456")
			},
			assert: assertRedacted,
		},
		{
			name: "redeem: the enrolment store cannot read",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.proofs.EXPECT().ChargeEmailCode(gomock.Any(), user, d.gen, gomock.Any()).Return(1, true, nil)
				d.store.EXPECT().Get(gomock.Any(), user).Return(mfa.Enrolment{}, false, errMFAFixture)
			},
			act: func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return d.method.RedeemEmailCode(ctx, user, d.gen, "123456")
			},
			assert: assertRedacted,
		},
		{
			name: "redeem: the device-proof store cannot complete",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				e := proven(d)
				e.EmailCode, e.EmailCodeUntil = []byte("123456"), d.now.Add(time.Minute)

				d.proofs.EXPECT().ChargeEmailCode(gomock.Any(), user, d.gen, gomock.Any()).Return(1, true, nil)
				d.store.EXPECT().Get(gomock.Any(), user).Return(e, true, nil)
				d.proofs.EXPECT().Complete(gomock.Any(), user, d.gen, gomock.Any()).Return(false, errMFAFixture)
			},
			act: func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return d.method.RedeemEmailCode(ctx, user, d.gen, "123456")
			},
			assert: assertRedacted,
		},
		// ResetEnrolment
		{
			name: "reset: the enrolment remover fails",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), user).Return(errMFAFixture)
			},
			act: func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return mfa.ResetEnrolment(ctx, user, d.reset(nil))
			},
			assert: assertRedacted,
		},
		{
			name: "reset: the session revoker fails",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil)
				d.sessions.EXPECT().DeleteByUser(gomock.Any(), user).Return(errMFAFixture)
			},
			act: func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return mfa.ResetEnrolment(ctx, user, d.reset(nil))
			},
			assert: assertRedacted,
		},
		{
			name: "reset: the user loader fails",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil)
				d.sessions.EXPECT().DeleteByUser(gomock.Any(), user).Return(nil)
				d.users.EXPECT().LoadByUserID(gomock.Any(), user).Return(nil, errMFAFixture)
			},
			act: func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return mfa.ResetEnrolment(ctx, user, d.reset(nil))
			},
			assert: assertRedacted,
		},
		{
			name: "reset: the contact resolver fails",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil)
				d.sessions.EXPECT().DeleteByUser(gomock.Any(), user).Return(nil)
				d.users.EXPECT().LoadByUserID(gomock.Any(), user).Return(ada, nil)
			},
			act: func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return mfa.ResetEnrolment(ctx, user, d.reset(
					func(context.Context, *identity.Details) (string, error) { return "", errMFAFixture }))
			},
			assert: assertRedacted,
		},
		{
			name: "reset: the sender fails",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.enrolments.EXPECT().RemoveEnrolment(gomock.Any(), user).Return(nil)
				d.sessions.EXPECT().DeleteByUser(gomock.Any(), user).Return(nil)
				d.users.EXPECT().LoadByUserID(gomock.Any(), user).Return(ada, nil)
				d.sender.EXPECT().Send(gomock.Any(), gomock.Any()).Return(errMFAFixture)
			},
			act: func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return mfa.ResetEnrolment(ctx, user, d.reset(nil))
			},
			assert: assertRedacted,
		},

		// VoidEmailCode passes the method's own error on: the method is the
		// consumer's, and its text is already the text they chose.
		{
			name:    "void: a consumer enroller's own error comes back as itself",
			arrange: func(*testing.T, *returnedErrorsDeps) {},
			act: func(_ *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return mfa.VoidEmailCode(ctx, redeemFailingEnroller{Enroller: d.method, err: errMFAFixture}, user, d.gen)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.True(t, err == errMFAFixture, "the enroller's error by identity") //nolint:errorlint // identity is the point
				assert.Equal(t, errMFAFixture.Error(), err.Error())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			gen, err := id.NewV7Generator().NewID()
			require.NoError(t, err)

			d := &returnedErrorsDeps{
				store:      NewMockEnrolmentStore(ctrl),
				proofs:     NewMockDeviceProofStore(ctrl),
				enrolments: NewMockEnrolmentRemover(ctrl),
				sessions:   NewMockSessionRevoker(ctrl),
				users:      NewMockUserLoader(ctrl),
				sender:     NewMockSender(ctrl),
				gen:        gen,
				secret:     []byte("12345678901234567890"),
				now:        time.Date(2026, 9, 24, 10, 0, 15, 0, time.UTC),
			}

			d.method, err = mfa.NewTOTP(pathStore{d.store, d.proofs}, "Example",
				mfa.WithClock(func() time.Time { return d.now }))
			require.NoError(t, err)

			tc.arrange(t, d)
			tc.assert(t, tc.act(t, t.Context(), d))
		})
	}
}
