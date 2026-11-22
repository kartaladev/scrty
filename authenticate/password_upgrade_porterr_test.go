package authenticate_test

// TestPortErrors_PasswordUpgrade replaces slog.Default() for its duration, so
// it does not run in parallel, and it restores the logger it found.
//
// The hostile errors are the ones firstof_porterr_test.go declares.

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
)

// errUpgradeEncodeDown is the plain failure the parity run's encoder returns.
var errUpgradeEncodeDown = errors.New("encoder: entropy exhausted")

// upgradeOutcome is what one PasswordUpgrade.Result after a verified login
// produced, and what it logged.
type upgradeOutcome struct {
	ok                       bool
	user, replaced, upgraded bool // whether each came back non-empty

	// failures are the "could not be upgraded" records on the provider's
	// logger, reduced to their level and reason.
	failures []string

	// aborts are the sanitizer's records on the provider's logger, and
	// defaultAborts those on slog.Default().
	aborts        []map[string]any
	defaultAborts int
}

// upgradeThroughEncoder logs in with a password whose stored hash is outdated,
// then asks the handle for its upgrade, with the encoder failing that
// encoding with encodeErr. When cancelAfterLogin is set the request's context
// is cancelled between the login and Result, as when the request has ended.
// It fails the test when Result hangs or lets a panic escape.
func upgradeThroughEncoder(t *testing.T, encodeErr error, cancelAfterLogin bool) upgradeOutcome {
	t.Helper()

	defaults := defaultRecords(t)

	inner := cheapEncoder(t)
	enc := &upgradingEncoder{Encoder: inner, needs: true, encodeFail: encodeErr}
	stored := storedUser(t, inner, true)

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUsername(gomock.Any(), "ada").Return(stored, nil)

	buf := &syncBuffer{}
	auth, err := authenticate.NewUsernamePasswordAuthenticator(users,
		authenticate.WithPasswordEncoder(enc),
		authenticate.WithPasswordLogger(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ctx, u := authenticate.RequestPasswordUpgrade(ctx)

	_, err = auth.Authenticate(ctx, identity.NewUsernamePassword("ada", []byte(storedPassword)))
	require.NoError(t, err, "precondition: the password verifies")

	if cancelAfterLogin {
		cancel()
	}

	type result struct {
		out      upgradeOutcome
		returned bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		var r result

		defer func() {
			if !r.returned {
				r.value = recover()
			}

			done <- r
		}()

		user, replaced, upgraded, ok := u.Result()
		r.out = upgradeOutcome{ok: ok, user: user != nil, replaced: len(replaced) > 0, upgraded: len(upgraded) > 0}
		r.returned = true
	}()

	var r result

	select {
	case r = <-done:
		require.True(t, r.returned, "a hostile encoder error escaped Result as a panic: %v", r.value)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile encoder error hung Result")
	}

	out := r.out

	for _, rec := range jsonRecords(t, buf.Bytes()) {
		switch rec["msg"] {
		case "password hash could not be upgraded":
			level, _ := rec["level"].(string)
			reason, _ := rec["reason"].(string)
			out.failures = append(out.failures, level+" "+reason)
		case msgPortErrAborted:
			out.aborts = append(out.aborts, rec)
		}
	}

	for _, rec := range jsonRecords(t, defaults.Bytes()) {
		if rec["msg"] == msgPortErrAborted {
			out.defaultAborts++
		}
	}

	return out
}

// TestPortErrors_PasswordUpgrade pins that an encoder failing the upgrade's
// encoding with an error whose chain cannot be walked is answered as a plain
// encoding failure is: no upgrade, the user and the replaced hash dropped,
// the same one error-level failure record, and no hang or panic. The
// sanitizer writes one abort record, to the provider's own logger and none
// to slog.Default().
func TestPortErrors_PasswordUpgrade(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name string
		err  error

		// cancel cancels the request's context between the login and Result.
		cancel bool

		assert func(t *testing.T, plain, got upgradeOutcome)
	}

	// sameAsPlain asserts the outcome a plain encoding failure has.
	sameAsPlain := func(t *testing.T, plain, got upgradeOutcome) {
		t.Helper()

		assert.Equal(t, plain.ok, got.ok, "never an upgrade")
		assert.Equal(t, plain.user, got.user)
		assert.Equal(t, plain.replaced, got.replaced)
		assert.Equal(t, plain.upgraded, got.upgraded)
		assert.Equal(t, plain.failures, got.failures, "the same one failure record")
		assert.Zero(t, got.defaultAborts, "nothing on slog.Default(): the provider has its own logger")
	}

	// aborted asserts the plain outcome and one abort record with reason on the
	// provider's logger, quoting nothing of the encoder's error.
	aborted := func(reason string) func(t *testing.T, plain, got upgradeOutcome) {
		return func(t *testing.T, plain, got upgradeOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)

			require.Len(t, got.aborts, 1, "one abort record, on the provider's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			for k, v := range got.aborts[0] {
				s, _ := v.(string)
				assert.NotContains(t, s, firstOfPortErrSecret, "attribute %q quotes the encoder's error", k)
			}
		}
	}

	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: &foCycleOne{}, assert: aborted("budget")},
		// In-process, not a child: nothing on this path uses the stdlib walk that overflows on it.
		{name: "a cycle through Unwrap() []error", err: &foCycleMany{}, assert: aborted("budget")},
		{
			name:   "a join that fans out",
			err:    foFanOut(errors.New(firstOfPortErrSecret), firstOfFanOutDepth),
			assert: aborted("budget"),
		},
		{name: "a link whose Unwrap panics", err: foUnwrapPanics{value: "boom " + firstOfPortErrSecret}, assert: aborted("panic")},
		{name: "a link whose Unwrap panics with nil", err: foUnwrapPanics{value: nil}, assert: aborted("panic")},
		{name: "a cycle after the request's context was cancelled", err: &foCycleOne{}, cancel: true, assert: aborted("budget")},
		{
			name: "a typed-nil root walks to the end and is answered as a plain failure",
			err:  (*foTypedNil)(nil),
			assert: func(t *testing.T, plain, got upgradeOutcome) {
				t.Helper()

				sameAsPlain(t, plain, got)
				assert.Empty(t, got.aborts, "a walk that completes writes nothing")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plain := upgradeThroughEncoder(t, errUpgradeEncodeDown, tc.cancel)
			require.False(t, plain.ok, "precondition: a failed encoding is no upgrade")
			require.Equal(t, []string{"ERROR password-upgrade"}, plain.failures, "precondition")
			require.Empty(t, plain.aborts, "a plain failure writes no abort record")
			require.Zero(t, plain.defaultAborts)

			tc.assert(t, plain, upgradeThroughEncoder(t, tc.err, tc.cancel))
		})
	}
}
