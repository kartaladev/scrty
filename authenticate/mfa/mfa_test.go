package mfa_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
)

// stubMethod is a consumer's own method: it proves the port admits one that is
// not TOTP, and lets a test choose what the store underneath it answers.
type stubMethod struct {
	name     string
	channel  factor.Channel
	enrolled bool
	err      error

	// response is what Response reports; nil reports a valid form field.
	response *mfa.ResponseFormat
}

func (s *stubMethod) Name() string {
	if s.name == "" {
		return "stub"
	}

	return s.name
}

func (s *stubMethod) Channel() factor.Channel { return s.channel }

func (s *stubMethod) Enrolled(context.Context, identity.UserID) (bool, error) {
	return s.enrolled, s.err
}

func (s *stubMethod) Response() mfa.ResponseFormat {
	if s.response == nil {
		return mfa.FormField("code", 4<<10)
	}

	return *s.response
}

func (s *stubMethod) Verify(context.Context, identity.UserID, []byte) error { return s.err }

func TestMethodSatisfiesLookup(t *testing.T) {
	t.Parallel()

	// The assertion is on the interface type, not on one implementation of it:
	// a concrete type may satisfy both ports by coincidence, while what this
	// pins is that every Method is a policy lookup, with no adapter at all.
	assert.True(t,
		reflect.TypeFor[mfa.Method]().Implements(reflect.TypeFor[policy.MFAMethodLookup]()),
		"a Method is usable as a policy lookup without an adapter")

	var m mfa.Method = &stubMethod{channel: factor.AuthenticatorApp}

	_, ok := any(m).(policy.MFAMethodLookup)
	assert.True(t, ok)
}

func TestMFASentinels(t *testing.T) {
	t.Parallel()

	sentinels := []error{
		mfa.ErrInvalidCode,
		mfa.ErrAlreadyEnrolled,
		mfa.ErrSameChannel,
		mfa.ErrVerifyThrottled,
		mfa.ErrEmailCodeInvalid,
		mfa.ErrEnrolmentThrottled,
		mfa.ErrConfig,
	}

	for i, a := range sentinels {
		for j, b := range sentinels {
			// An emailed-code refusal is the invalid second-factor code
			// refusal; TestEmailCodeInvalidIsInvalidCode pins that pair.
			// Identity, not errors.Is: the pair is excluded by name.
			if i != j && (a != mfa.ErrEmailCodeInvalid || b != mfa.ErrInvalidCode) { //nolint:errorlint // sentinel identity
				assert.NotErrorIs(t, a, b)
			}
		}

		assert.Contains(t, a.Error(), "mfa: ")
	}
}

// TestEmailCodeInvalidIsInvalidCode pins that an emailed-code refusal is
// identifiable as the invalid second-factor code refusal, so a caller mapping
// ErrInvalidCode answers it the same way, while its own message still tells an
// operator which code was refused.
func TestEmailCodeInvalidIsInvalidCode(t *testing.T) {
	t.Parallel()

	require.ErrorIs(t, mfa.ErrEmailCodeInvalid, mfa.ErrInvalidCode)
	assert.NotErrorIs(t, mfa.ErrInvalidCode, mfa.ErrEmailCodeInvalid,
		"a device-code refusal is not an emailed-code one")
	assert.Contains(t, mfa.ErrEmailCodeInvalid.Error(), "emailed code")
}

func TestLookupsFor(t *testing.T) {
	t.Parallel()

	totp, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example")
	require.NoError(t, err)

	responding := func(f mfa.ResponseFormat) *mfa.ResponseFormat { return &f }
	named := func(name string) mfa.Method {
		return &stubMethod{name: name, channel: factor.Email}
	}

	type testCase struct {
		name    string
		methods []mfa.Method
		assert  func(t *testing.T, l []policy.MFAMethodLookup, err error)
	}

	configError := func(t *testing.T, l []policy.MFAMethodLookup, err error) {
		require.ErrorIs(t, err, mfa.ErrConfig)
		assert.Nil(t, l)
	}

	cases := []testCase{
		{
			name:    "TOTP and a consumer's method, in order",
			methods: []mfa.Method{totp, named("email-code")},
			assert: func(t *testing.T, l []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				require.Len(t, l, 2)
				assert.Equal(t, "totp", l[0].Name())
				assert.Equal(t, factor.AuthenticatorApp, l[0].Channel())
				assert.Equal(t, "email-code", l[1].Name())
				assert.Equal(t, factor.Email, l[1].Channel())
			},
		},
		{
			name: "a JSON method at the largest limit",
			methods: []mfa.Method{&stubMethod{
				name: "webauthn", channel: factor.Channel("security-key"),
				response: responding(mfa.JSONBody(1 << 20)),
			}},
			assert: func(t *testing.T, l []policy.MFAMethodLookup, err error) {
				require.NoError(t, err)
				assert.Len(t, l, 1)
			},
		},
		{name: "no methods", methods: nil, assert: configError},
		{name: "an empty set", methods: []mfa.Method{}, assert: configError},
		{name: "a nil method", methods: []mfa.Method{totp, nil}, assert: configError},
		{name: "a typed-nil TOTP", methods: []mfa.Method{(*mfa.TOTP)(nil)}, assert: configError},
		{name: "a typed-nil consumer method", methods: []mfa.Method{(*stubMethod)(nil)}, assert: configError},
		{
			name:    "an empty channel",
			methods: []mfa.Method{&stubMethod{name: "email-code", channel: ""}},
			assert:  configError,
		},
		{name: "an empty name", methods: []mfa.Method{&emptyNamedMethod{}}, assert: configError},
		{name: "an upper-case name", methods: []mfa.Method{named("TOTP")}, assert: configError},
		{name: "a name with a slash", methods: []mfa.Method{named("a/b")}, assert: configError},
		{name: "a name starting with a hyphen", methods: []mfa.Method{named("-x")}, assert: configError},
		{name: "a name with a space", methods: []mfa.Method{named("email code")}, assert: configError},
		{name: "two methods named totp", methods: []mfa.Method{totp, named("totp")}, assert: configError},
		{
			name: "a form field limit of zero",
			methods: []mfa.Method{&stubMethod{
				name: "email-code", channel: factor.Email, response: responding(mfa.FormField("code", 0)),
			}},
			assert: configError,
		},
		{
			name: "a form field limit above 1 MiB",
			methods: []mfa.Method{&stubMethod{
				name: "email-code", channel: factor.Email, response: responding(mfa.FormField("code", 1<<20+1)),
			}},
			assert: configError,
		},
		{
			name: "a form field with no name",
			methods: []mfa.Method{&stubMethod{
				name: "email-code", channel: factor.Email, response: responding(mfa.FormField("", 10)),
			}},
			assert: configError,
		},
		{
			name: "a negative JSON limit",
			methods: []mfa.Method{&stubMethod{
				name: "email-code", channel: factor.Email, response: responding(mfa.JSONBody(-1)),
			}},
			assert: configError,
		},
		{
			name: "the zero response format",
			methods: []mfa.Method{&stubMethod{
				name: "email-code", channel: factor.Email, response: responding(mfa.ResponseFormat{}),
			}},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, err := mfa.LookupsFor(tc.methods...)
			tc.assert(t, l, err)
		})
	}
}

// emptyNamedMethod reports an empty name, which stubMethod cannot: its empty
// name field stands for its default.
type emptyNamedMethod struct{ stubMethod }

func (*emptyNamedMethod) Name() string { return "" }

func (*emptyNamedMethod) Channel() factor.Channel { return factor.Email }

func TestLookupContract(t *testing.T) {
	t.Parallel()

	outage := errors.New("dial tcp: connection refused")

	type testCase struct {
		name   string
		method mfa.Method
		assert func(t *testing.T, enrolled bool, err error)
	}

	cases := []testCase{
		{
			name:   "a confirmed enrolment is true",
			method: &stubMethod{channel: factor.AuthenticatorApp, enrolled: true},
			assert: func(t *testing.T, enrolled bool, err error) {
				require.NoError(t, err)
				assert.True(t, enrolled)
			},
		},
		{
			name:   "no enrolment is false",
			method: &stubMethod{channel: factor.AuthenticatorApp, enrolled: false},
			assert: func(t *testing.T, enrolled bool, err error) {
				require.NoError(t, err)
				assert.False(t, enrolled)
			},
		},
		{
			name:   "a store outage is an error, never a false",
			method: &stubMethod{channel: factor.AuthenticatorApp, err: outage},
			assert: func(t *testing.T, enrolled bool, err error) {
				assert.ErrorIs(t, err, outage)
				assert.False(t, enrolled, "and the bool must not be read as an answer")
			},
		},
		{
			name: "an unreadable secret is an error",
			method: &stubMethod{
				channel: factor.AuthenticatorApp,
				err:     errors.New("cipher: message authentication failed"),
			},
			assert: func(t *testing.T, _ bool, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, err := mfa.LookupsFor(tc.method)
			require.NoError(t, err)
			require.Len(t, l, 1)

			enrolled, lookupErr := l[0].Enrolled(t.Context(), "u-1")
			tc.assert(t, enrolled, lookupErr)
		})
	}
}

func TestResponseFormat(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		format mfa.ResponseFormat
		assert func(t *testing.T, f mfa.ResponseFormat)
	}

	cases := []testCase{
		{
			name:   "a form field reports its kind, field and limit",
			format: mfa.FormField("code", 4096),
			assert: func(t *testing.T, f mfa.ResponseFormat) {
				assert.Equal(t, mfa.ResponseFormField, f.Kind())
				assert.Equal(t, "code", f.Field())
				assert.Equal(t, int64(4096), f.Limit())
			},
		},
		{
			name:   "a JSON body reports its kind and limit, and no field",
			format: mfa.JSONBody(16 << 10),
			assert: func(t *testing.T, f mfa.ResponseFormat) {
				assert.Equal(t, mfa.ResponseJSONBody, f.Kind())
				assert.Empty(t, f.Field())
				assert.Equal(t, int64(16384), f.Limit())
			},
		},
		{
			name:   "the zero format is neither kind",
			format: mfa.ResponseFormat{},
			assert: func(t *testing.T, f mfa.ResponseFormat) {
				assert.NotEqual(t, mfa.ResponseFormField, f.Kind())
				assert.NotEqual(t, mfa.ResponseJSONBody, f.Kind())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.format)
		})
	}
}

func TestUsernameAsAddress(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		details *identity.Details
		assert  func(t *testing.T, got string, err error)
	}

	cases := []testCase{
		{
			name:    "the username is returned unchanged",
			details: &identity.Details{ID: "u-1", Username: " Ada+MFA@Example.com", Name: "Ada"},
			assert: func(t *testing.T, got string, err error) {
				require.NoError(t, err)
				assert.Equal(t, " Ada+MFA@Example.com", got, "never trimmed, case-folded or parsed")
			},
		},
		{
			name:    "a username with a colon is returned as it is, for the method to refuse",
			details: &identity.Details{ID: "u-1", Username: "ada:example"},
			assert: func(t *testing.T, got string, err error) {
				require.NoError(t, err)
				assert.Equal(t, "ada:example", got)
			},
		},
		{
			name:    "an empty username is an error, not an empty address",
			details: &identity.Details{ID: "u-1"},
			assert: func(t *testing.T, got string, err error) {
				require.Error(t, err)
				assert.Empty(t, got)
			},
		},
		{
			name:    "no details is an error",
			details: nil,
			assert: func(t *testing.T, got string, err error) {
				require.Error(t, err)
				assert.Empty(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := mfa.UsernameAsAddress(t.Context(), tc.details)
			tc.assert(t, got, err)
		})
	}
}

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
		Enrolments: []mfa.EnrolmentRemover{d.enrolments},
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
				return d.method.Verify(ctx, user, []byte(d.code(t)))
			},
			assert: assertRedacted,
		},
		{
			name: "verify: the enrolment store cannot charge the attempt",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.store.EXPECT().Get(gomock.Any(), user).Return(confirmed(d), true, nil)
				d.store.EXPECT().ChargeVerifyAttempt(gomock.Any(), user, gomock.Any(), gomock.Any(), gomock.Any()).
					Return(time.Time{}, false, errMFAFixture)
			},
			act: func(t *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return d.method.Verify(ctx, user, []byte(d.code(t)))
			},
			assert: assertRedacted,
		},
		{
			name: "verify: the enrolment store cannot accept the step",
			arrange: func(_ *testing.T, d *returnedErrorsDeps) {
				d.store.EXPECT().Get(gomock.Any(), user).Return(confirmed(d), true, nil)
				d.store.EXPECT().ChargeVerifyAttempt(gomock.Any(), user, gomock.Any(), gomock.Any(), gomock.Any()).
					Return(time.Now(), true, nil)
				d.store.EXPECT().AcceptStep(gomock.Any(), user, gomock.Any(), gomock.Any()).Return(false, errMFAFixture)
			},
			act: func(t *testing.T, ctx context.Context, d *returnedErrorsDeps) error {
				return d.method.Verify(ctx, user, []byte(d.code(t)))
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
				d.store.EXPECT().Confirm(gomock.Any(), user, gomock.Any(), gomock.Any(), gomock.Any()).Return(false, errMFAFixture)
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
				mfa.WithClock(clockwork.NewFakeClockAt(d.now)))
			require.NoError(t, err)

			tc.arrange(t, d)
			tc.assert(t, tc.act(t, t.Context(), d))
		})
	}
}

// TestMFAConstructors_ErrorsAreConfigErrors pins that every construction
// failure of the TOTP method and the verification throttle matches ErrConfig,
// whatever parameter caused it.
func TestMFAConstructors_ErrorsAreConfigErrors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func() error
		assert func(t *testing.T, err error)
	}

	configError := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, mfa.ErrConfig)
	}

	totp := func(store mfa.EnrolmentStore, issuer string, opts ...mfa.Option) func() error {
		return func() error {
			_, err := mfa.NewTOTP(store, issuer, opts...)
			return err
		}
	}
	store := mfa.NewMemoryEnrolmentStore()

	cases := []testCase{
		{name: "totp: nil store", build: totp(nil, "Example"), assert: configError},
		{name: "totp: typed nil store", build: totp((*mfa.MemoryEnrolmentStore)(nil), "Example"), assert: configError},
		{name: "totp: empty issuer", build: totp(store, ""), assert: configError},
		{name: "totp: issuer containing ':'", build: totp(store, "Ex:ample"), assert: configError},
		{name: "totp: 7 digits", build: totp(store, "Example", mfa.WithDigits(7)), assert: configError},
		{name: "totp: zero period", build: totp(store, "Example", mfa.WithTimeStep(0)), assert: configError},
		{name: "totp: negative period", build: totp(store, "Example", mfa.WithTimeStep(-time.Second)), assert: configError},
		{name: "totp: nil logger", build: totp(store, "Example", mfa.WithLogger(nil)), assert: configError},
		{
			name:   "totp: nil identifier generator",
			build:  totp(store, "Example", mfa.WithIDGenerator((id.Generator)(nil))),
			assert: configError,
		},
		{
			name: "throttle: nil logger",
			build: func() error {
				_, err := mfa.NewVerifyThrottle(mfa.WithThrottleLogger(nil))
				return err
			},
			assert: configError,
		},
		{
			name: "throttle: nil clock",
			build: func() error {
				_, err := mfa.NewVerifyThrottle(mfa.WithThrottleClock(nil))
				return err
			},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.build())
		})
	}
}
