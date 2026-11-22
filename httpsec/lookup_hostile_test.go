package httpsec_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
)

// walkBudget is the number of entries one classification examines before it
// gives up, as the http-error-propagation spec pins it.
const walkBudget = 1000

// hostileWithin bounds how long one hostile lookup may take. A walk of the
// whole budget takes well under a millisecond; a regression to an unbounded
// walk hangs, or takes seconds on the fan-out.
const hostileWithin = 2 * time.Second

// hostileSecret is the text every hostile fixture's Error returns, so a test
// can assert that no record quotes it.
const hostileSecret = "hostile-secret-text"

// cycleOne is a chain that contains itself through Unwrap() error.
type cycleOne struct{}

func (*cycleOne) Error() string   { return hostileSecret }
func (c *cycleOne) Unwrap() error { return c }

// cycleMany is a chain that contains itself through Unwrap() []error.
type cycleMany struct{}

func (*cycleMany) Error() string     { return hostileSecret }
func (c *cycleMany) Unwrap() []error { return []error{c} }

// isPanics is a link whose own Is method panics.
type isPanics struct{}

func (isPanics) Error() string { return hostileSecret }
func (isPanics) Is(error) bool { panic(isPanicMessage) }

// asPanics is a link whose own As method panics.
type asPanics struct{}

func (asPanics) Error() string { return hostileSecret }
func (asPanics) As(any) bool   { panic("the link's As panicked") }

// fanOut is depth levels of an error joined with itself: no cycle, but 2^depth
// paths for an unbounded walk.
func fanOut(depth int) error {
	err := errors.New(hostileSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// lookupWithin runs LookupStatus on its own goroutine and fails the test when
// it does not return within d or lets a panic escape, so a regression is a
// failure with a name instead of a hung suite. A stack overflow still kills
// the process: that is a fatal error, which nothing can recover.
func lookupWithin(t *testing.T, err error, d time.Duration) (int, bool) {
	t.Helper()

	type result struct {
		status   int
		ok       bool
		panicked bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				done <- result{panicked: true, value: recover()}
			}
		}()

		status, ok := httpsec.LookupStatus(err)
		returned = true
		done <- result{status: status, ok: ok}
	}()

	select {
	case r := <-done:
		require.False(t, r.panicked, "a panic escaped the lookup: %v", r.value)

		return r.status, r.ok
	case <-time.After(d):
		t.Fatalf("LookupStatus did not return within %v", d)

		return 0, false
	}
}

func TestLookupStatus_HostileChains(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    func() error
		assert func(t *testing.T, status int, ok bool)
	}

	unrecognised := func(t *testing.T, status int, ok bool) {
		t.Helper()
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.False(t, ok, "an aborted classification is not recognised")
	}
	answers := func(want int) func(t *testing.T, status int, ok bool) {
		return func(t *testing.T, status int, ok bool) {
			t.Helper()
			assert.Equal(t, want, status)
			assert.True(t, ok, "recognised")
		}
	}
	mfa := func() *httpsec.ChallengeError { return &httpsec.ChallengeError{Kind: policy.ChallengeMFA} }

	cases := []testCase{
		{
			name:   "self-cycle through Unwrap() error",
			err:    func() error { return &cycleOne{} },
			assert: unrecognised,
		},
		{
			name:   "self-cycle through Unwrap() []error",
			err:    func() error { return &cycleMany{} },
			assert: unrecognised,
		},
		{
			name:   "fan-out of 25 joined levels",
			err:    func() error { return fanOut(25) },
			assert: unrecognised,
		},
		{
			name:   "a link whose Is panics",
			err:    func() error { return errors.Join(isPanics{}, authorize.ErrAccessDenied) },
			assert: unrecognised,
		},
		{
			name:   "a link whose As panics",
			err:    func() error { return errors.Join(asPanics{}, authorize.ErrAccessDenied) },
			assert: unrecognised,
		},
		{
			// Its value-receiver Is would dereference the nil pointer.
			name: "typed-nil *password.RejectedError joined ahead of access denied",
			err: func() error {
				return errors.Join((*password.RejectedError)(nil), authorize.ErrAccessDenied)
			},
			assert: answers(http.StatusForbidden),
		},
		{
			name: "typed-nil *ChallengeError joined ahead of a challenge through As",
			err: func() error {
				return errors.Join((*httpsec.ChallengeError)(nil), asChallenge{ch: mfa()})
			},
			assert: answers(http.StatusUnauthorized),
		},
		{
			// The challenge is the budget's last entry.
			name:   "challenge at the budget's last entry is found",
			err:    func() error { return wrapLayers(mfa(), walkBudget-1) },
			assert: answers(http.StatusUnauthorized),
		},
		{
			name:   "challenge one entry past the budget",
			err:    func() error { return wrapLayers(mfa(), walkBudget) },
			assert: unrecognised,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			status, ok := lookupWithin(t, tc.err(), hostileWithin)
			tc.assert(t, status, ok)
		})
	}
}
