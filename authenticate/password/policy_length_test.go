package password_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/password"
)

// forwardingEncoder is a consumer's encoder that wraps another and states no
// input limit of its own.
type forwardingEncoder struct{ inner password.Encoder }

func (e forwardingEncoder) Encode(input string) ([]byte, error) { return e.inner.Encode(input) }

func (e forwardingEncoder) Match(input string, encoded []byte) bool {
	return e.inner.Match(input, encoded)
}

// limitedEncoder also states its limit through MaxInputBytes.
type limitedEncoder struct {
	forwardingEncoder
	limit int
}

func (e limitedEncoder) MaxInputBytes() int { return e.limit }

func TestPolicy_Length(t *testing.T) {
	t.Parallel()

	bcrypt, err := password.NewBcryptEncoder(password.WithBcryptCost(10))
	require.NoError(t, err)

	fast := fastArgon2id(t)

	type testCase struct {
		name      string
		opts      []password.PolicyOption
		candidate string
		// change runs Change, with a recording write, instead of Check.
		change bool
		assert func(t *testing.T, err error, w *recordingWrite)
	}

	check := func(assert func(t *testing.T, err error)) func(t *testing.T, err error, _ *recordingWrite) {
		return func(t *testing.T, err error, _ *recordingWrite) { assert(t, err) }
	}

	wrapped := forwardingEncoder{inner: bcrypt}

	euro := func(n int) string { return strings.Repeat("€", n) } // 3 bytes each

	cases := []testCase{
		{
			name:      "fifteen three-byte characters pass a minimum of 15",
			candidate: euro(15),
			assert:    check(accepted),
		},
		{
			name:      "fourteen three-byte characters are too short, whatever their bytes",
			candidate: euro(14),
			assert:    check(rejectedBy(password.RuleTooShort)),
		},
		{
			name:      "an empty candidate is too short",
			opts:      []password.PolicyOption{password.MinLength(8)},
			candidate: "",
			assert:    check(rejectedBy(password.RuleTooShort)),
		},
		{
			name:      "a leading and a trailing space count, and are kept in the stored hash",
			opts:      []password.PolicyOption{password.WithEncoder(fast)},
			candidate: " thirteenchars ",
			change:    true,
			assert: func(t *testing.T, err error, w *recordingWrite) {
				require.NoError(t, err)
				require.Equal(t, 1, w.calls)
				assert.True(t, fast.Match(" thirteenchars ", w.hash), "the hash is of the candidate as given")
				assert.False(t, fast.Match("thirteenchars", w.hash), "the candidate was not trimmed")
			},
		},
		{
			name:      "the default maximum accepts 128 characters",
			candidate: strings.Repeat("x", 128),
			assert:    check(accepted),
		},
		{
			name:      "the default maximum refuses 129 characters",
			candidate: strings.Repeat("x", 129),
			assert:    check(rejectedBy(password.RuleTooLong)),
		},
		{
			name:      "a replaced maximum refuses beyond it",
			opts:      []password.PolicyOption{password.MaxLength(64)},
			candidate: strings.Repeat("x", 65),
			assert:    check(rejectedBy(password.RuleTooLong)),
		},
		{
			name:      "a raised maximum accepts beyond the default",
			opts:      []password.PolicyOption{password.MaxLength(256)},
			candidate: strings.Repeat("x", 200),
			assert:    check(accepted),
		},
		{
			name:      "a bcrypt policy refuses 30 three-byte characters as too long at the check",
			opts:      []password.PolicyOption{password.WithEncoder(bcrypt)},
			candidate: euro(30),
			assert:    check(rejectedBy(password.RuleTooLong)),
		},
		{
			name:      "a bcrypt policy accepts exactly 72 bytes",
			opts:      []password.PolicyOption{password.WithEncoder(bcrypt)},
			candidate: euro(24),
			assert:    check(accepted),
		},
		{
			name:      "an Argon2id policy has no byte limit below the maximum",
			opts:      []password.PolicyOption{password.WithEncoder(fast)},
			candidate: euro(30),
			assert:    check(accepted),
		},
		{
			name:      "a consumer encoder stating a limit has it refused as too long at the check",
			opts:      []password.PolicyOption{password.WithEncoder(limitedEncoder{wrapped, 72})},
			candidate: euro(30),
			assert:    check(rejectedBy(password.RuleTooLong)),
		},
		{
			name:      "a consumer encoder stating a limit accepts exactly that many bytes",
			opts:      []password.PolicyOption{password.WithEncoder(limitedEncoder{wrapped, 72})},
			candidate: euro(24),
			assert:    check(accepted),
		},
		{
			name:      "a consumer encoder stating a limit of zero has no limit",
			opts:      []password.PolicyOption{password.WithEncoder(limitedEncoder{wrapped, 0})},
			candidate: euro(30),
			assert:    check(accepted),
		},
		{
			name:      "a consumer encoder stating no limit leaves the check to accept what its encoder refuses",
			opts:      []password.PolicyOption{password.WithEncoder(wrapped)},
			candidate: euro(30),
			assert:    check(accepted),
		},
		{
			name:      "a change answers an encoder's too-long refusal as a too-long rejection, not a failure",
			opts:      []password.PolicyOption{password.WithEncoder(wrapped)},
			candidate: euro(30),
			change:    true,
			assert: func(t *testing.T, err error, w *recordingWrite) {
				rejectedBy(password.RuleTooLong)(t, err)
				assert.Zero(t, w.calls, "nothing is written")
			},
		},
		{
			name:      "a NUL byte is the bcrypt encoder's refusal, returned unchanged by a change",
			opts:      []password.PolicyOption{password.WithEncoder(bcrypt)},
			candidate: "pass\x00word-long-enough",
			change:    true,
			assert: func(t *testing.T, err error, w *recordingWrite) {
				require.ErrorIs(t, err, password.ErrContainsNUL)
				assert.Same(t, password.ErrContainsNUL, err, "returned as is, not wrapped")
				assert.Zero(t, w.calls, "nothing is written")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := password.NewPolicy(tc.opts...)
			require.NoError(t, err)

			w := &recordingWrite{}
			if tc.change {
				err = p.Change(t.Context(), checkUser(), tc.candidate, w.write)
			} else {
				err = p.Check(t.Context(), checkUser(), tc.candidate)
			}

			tc.assert(t, err, w)
		})
	}
}
