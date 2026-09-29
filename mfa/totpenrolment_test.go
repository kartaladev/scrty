package mfa_test

import (
	"context"
	"encoding/base32"
	"errors"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
)

// failingReader is a random source that cannot produce bytes.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy pool exhausted") }

// stubRequirement is the consumer's record of who must use a second factor. It
// is deliberately independent of any enrolment store, which is the property
// TestTOTPRemoveEnrolment exists to pin.
type stubRequirement struct{ required map[identity.UserID]bool }

func (s *stubRequirement) Required(_ context.Context, user identity.UserID) (bool, error) {
	return s.required[user], nil
}

func TestTOTPBeginEnrolment(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		label  string
		random io.Reader
		assert func(t *testing.T, p mfa.Provisioning, err error, stored bool)
	}

	refused := func(t *testing.T, p mfa.Provisioning, err error, stored bool) {
		require.Error(t, err)
		assert.False(t, stored)
		assert.Empty(t, p.Secret)
	}

	cases := []testCase{
		{
			name:  "the URI names the issuer, the label and the parameters",
			label: "ada@example.com",
			assert: func(t *testing.T, p mfa.Provisioning, err error, stored bool) {
				require.NoError(t, err)
				assert.True(t, stored)

				u, parseErr := url.Parse(p.URI)
				require.NoError(t, parseErr)

				assert.Equal(t, "otpauth", u.Scheme)
				assert.Equal(t, "totp", u.Host)
				assert.Equal(t, "/Example Payroll:ada@example.com", u.Path)
				assert.Equal(t, "Example Payroll", u.Query().Get("issuer"))
				assert.Equal(t, "SHA1", u.Query().Get("algorithm"))
				assert.Equal(t, "6", u.Query().Get("digits"))
				assert.Equal(t, "30", u.Query().Get("period"))
				assert.Equal(t, p.Secret, u.Query().Get("secret"))

				raw, decErr := base32.StdEncoding.WithPadding(base32.NoPadding).
					DecodeString(p.Secret)
				require.NoError(t, decErr)
				assert.Len(t, raw, 20, "20 bytes from the OS random source")

				assert.NotContains(t, p.URI, "u-1",
					"the label is the consumer's, never the user reference")
			},
		},
		{
			name:  "a label needing escaping survives",
			label: "ada+payroll@example.com",
			assert: func(t *testing.T, p mfa.Provisioning, err error, stored bool) {
				require.NoError(t, err)
				assert.True(t, stored)

				u, parseErr := url.Parse(p.URI)
				require.NoError(t, parseErr)
				assert.Equal(t, "/Example Payroll:ada+payroll@example.com", u.Path)
			},
		},
		{name: "an empty label is refused", label: "", assert: refused},
		{name: "a label with a colon is refused", label: "ada:example", assert: refused},
		{
			name:   "a random source failure stores nothing",
			label:  "ada@example.com",
			random: failingReader{},
			assert: func(t *testing.T, p mfa.Provisioning, err error, stored bool) {
				require.Error(t, err)
				assert.False(t, stored, "no pending enrolment may be written")
				assert.Empty(t, p.Secret)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			store := mfa.NewMemoryEnrolmentStore()

			opts := []mfa.TOTPOption{}
			if tc.random != nil {
				opts = append(opts, mfa.WithRandom(tc.random))
			}

			m, err := mfa.NewTOTP(store, "Example Payroll", opts...)
			require.NoError(t, err)

			p, beginErr := m.BeginEnrolment(ctx, "u-1", tc.label)

			_, stored, getErr := store.Get(ctx, "u-1")
			require.NoError(t, getErr)

			tc.assert(t, p, beginErr, stored)
		})
	}
}

func TestTOTPConfirmEnrolment(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		code   func(t *testing.T, secret string) string
		assert func(t *testing.T, m *mfa.TOTP, err error)
	}

	cases := []testCase{
		{
			name: "a valid code confirms",
			code: func(t *testing.T, secret string) string { return codeForSecret(t, secret, base) },
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				require.NoError(t, err)

				enrolled, lookupErr := m.Enrolled(t.Context(), "u-1")
				require.NoError(t, lookupErr)
				assert.True(t, enrolled)
			},
		},
		{
			name: "a wrong code does not",
			code: func(*testing.T, string) string { return "000000" },
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				assert.ErrorIs(t, err, mfa.ErrInvalidCode)

				enrolled, lookupErr := m.Enrolled(t.Context(), "u-1")
				require.NoError(t, lookupErr)
				assert.False(t, enrolled)
			},
		},
		{
			name: "a malformed code does not",
			code: func(*testing.T, string) string { return "12345a" },
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				assert.ErrorIs(t, err, mfa.ErrInvalidCode)

				enrolled, lookupErr := m.Enrolled(t.Context(), "u-1")
				require.NoError(t, lookupErr)
				assert.False(t, enrolled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			m, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example",
				mfa.WithClock(clockwork.NewFakeClockAt(base)))
			require.NoError(t, err)

			p, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
			require.NoError(t, err)

			pending, err := m.Enrolled(ctx, "u-1")
			require.NoError(t, err)
			require.False(t, pending, "a pending enrolment is not an enrolment")

			tc.assert(t, m, m.ConfirmEnrolment(ctx, "u-1", tc.code(t, p.Secret)))
		})
	}
}

// TestTOTPConfirmEnrolmentUnknown pins the two shapes that have no pending
// enrolment to confirm at all, which the table above always has.
func TestTOTPConfirmEnrolmentUnknown(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	m, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example",
		mfa.WithClock(clockwork.NewFakeClockAt(base)))
	require.NoError(t, err)

	assert.ErrorIs(t, m.ConfirmEnrolment(ctx, "nobody", "123456"), mfa.ErrInvalidCode)

	p, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	require.NoError(t, err)

	code := codeForSecret(t, p.Secret, base)
	require.NoError(t, m.ConfirmEnrolment(ctx, "u-1", code))
	assert.ErrorIs(t, m.ConfirmEnrolment(ctx, "u-1", code), mfa.ErrInvalidCode,
		"there is nothing pending to confirm a second time")
}

func TestTOTPBeginEnrolmentTwice(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(base)))
	require.NoError(t, err)

	first, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	require.NoError(t, err)

	second, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	require.NoError(t, err, "a pending enrolment is replaced")
	assert.NotEqual(t, first.Secret, second.Secret)

	require.NoError(t, m.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, second.Secret, base)))

	_, err = m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	assert.ErrorIs(t, err, mfa.ErrAlreadyEnrolled)

	// The existing authenticator still works: nothing was replaced.
	later := base.Add(time.Minute)

	m2, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(later)))
	require.NoError(t, err)
	assert.NoError(t, m2.Verify(ctx, "u-1", codeForSecret(t, second.Secret, later)))
}

func TestTOTPRemoveEnrolment(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(base)))
	require.NoError(t, err)

	p, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	require.NoError(t, err)
	require.NoError(t, m.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, p.Secret, base)))

	required := &stubRequirement{required: map[identity.UserID]bool{"u-1": true}}

	require.NoError(t, m.RemoveEnrolment(ctx, "u-1"))

	enrolled, err := m.Enrolled(ctx, "u-1")
	require.NoError(t, err)
	assert.False(t, enrolled)

	stillRequired, err := required.Required(ctx, "u-1")
	require.NoError(t, err)
	assert.True(t, stillRequired, "removing an enrolment cannot clear the requirement")

	require.NoError(t, m.RemoveEnrolment(ctx, "u-1"), "removing nothing is not an error")

	// And the user may enrol again, because nothing confirmed is left.
	_, err = m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	assert.NoError(t, err)
}
