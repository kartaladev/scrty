package ratelimit_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/ratelimit"
)

// TestUnavailableMode_Declarations pins the two facts the public declarations
// carry on their own: the zero mode is the fail-closed one, so a consumer who
// configures nothing refuses during an outage, and the unavailable sentinel is
// its own error rather than an alias of a refusal or a wiring mistake.
func TestUnavailableMode_Declarations(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "the zero mode refuses",
			assert: func(t *testing.T) {
				var zero ratelimit.UnavailableMode
				assert.Equal(t, ratelimit.UnavailableRefuse, zero)
			},
		},
		{
			name: "the three modes are distinct",
			assert: func(t *testing.T) {
				assert.NotEqual(t, ratelimit.UnavailableRefuse, ratelimit.UnavailableFallBackToLocal)
				assert.NotEqual(t, ratelimit.UnavailableRefuse, ratelimit.UnavailableAllow)
				assert.NotEqual(t, ratelimit.UnavailableFallBackToLocal, ratelimit.UnavailableAllow)
			},
		},
		{
			name: "backend unavailable is its own sentinel",
			assert: func(t *testing.T) {
				assert.False(t, errors.Is(ratelimit.ErrBackendUnavailable, ratelimit.ErrConfig))
				assert.False(t, errors.Is(ratelimit.ErrBackendUnavailable, ratelimit.ErrThrottled))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t)
		})
	}
}

// TestUnavailableMode_String pins the names a log record or error message
// prints for each mode, and the stable form of a value that names none.
func TestUnavailableMode_String(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		mode   ratelimit.UnavailableMode
		assert func(t *testing.T, got string)
	}

	is := func(want string) func(t *testing.T, got string) {
		return func(t *testing.T, got string) { assert.Equal(t, want, got) }
	}

	cases := []testCase{
		{name: "refuse", mode: ratelimit.UnavailableRefuse, assert: is("refuse")},
		{name: "fall back to local", mode: ratelimit.UnavailableFallBackToLocal, assert: is("fall-back")},
		{name: "allow", mode: ratelimit.UnavailableAllow, assert: is("allow")},
		{name: "an unknown value prints its number", mode: ratelimit.UnavailableMode(7), assert: is("UnavailableMode(7)")},
		{name: "a negative value prints its number", mode: ratelimit.UnavailableMode(-1), assert: is("UnavailableMode(-1)")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.mode.String())
		})
	}
}
