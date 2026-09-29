package mfa_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
)

// TestRequiredUserFailsClosed runs the whole path a lost enrolment travels:
// the consumer's requirement lookup, this package's enrolment lookup, and the
// real requirement policy behind a real engine. A stub standing in for the
// policy would prove only that the stub denies.
func TestRequiredUserFailsClosed(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	outage := errors.New("dial tcp: connection refused")
	unreadable := errors.New("cipher: message authentication failed")

	type testCase struct {
		name   string
		store  func(t *testing.T, healthy mfa.EnrolmentStore) mfa.EnrolmentStore
		assert func(t *testing.T, d policy.Decision)
	}

	cases := []testCase{
		{
			name: "the enrolment was removed",
			store: func(t *testing.T, healthy mfa.EnrolmentStore) mfa.EnrolmentStore {
				require.NoError(t, healthy.Delete(t.Context(), "u-1"))

				return healthy
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.ErrorIs(t, d.Reason, policy.ErrMFAEnrollmentRequired)
			},
		},
		{
			name: "the enrolment store is down",
			store: func(*testing.T, mfa.EnrolmentStore) mfa.EnrolmentStore {
				return failingEnrolmentStore{err: outage}
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.ErrorIs(t, d.Reason, outage)
			},
		},
		{
			name: "the stored secret cannot be opened",
			store: func(*testing.T, mfa.EnrolmentStore) mfa.EnrolmentStore {
				return failingEnrolmentStore{err: unreadable}
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.ErrorIs(t, d.Reason, unreadable)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			// A user who is enrolled and required to use MFA.
			healthy := mfa.NewMemoryEnrolmentStore()

			setup, err := mfa.NewTOTP(healthy, "Example",
				mfa.WithClock(clockwork.NewFakeClockAt(base)))
			require.NoError(t, err)

			p, err := setup.BeginEnrolment(ctx, "u-1", "ada@example.com")
			require.NoError(t, err)
			require.NoError(t, setup.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, p.Secret, base)))

			// Now break the enrolment, leaving the requirement alone.
			method, err := mfa.NewTOTP(tc.store(t, healthy), "Example",
				mfa.WithClock(clockwork.NewFakeClockAt(base)))
			require.NoError(t, err)

			lookup, err := mfa.LookupFor(method)
			require.NoError(t, err)

			required := &stubRequirement{required: map[identity.UserID]bool{"u-1": true}}

			pol, err := policy.NewMFARequirementPolicy(required, []policy.MFAMethodLookup{lookup})
			require.NoError(t, err)

			engine, err := policy.NewEngine(pol)
			require.NoError(t, err)

			d := engine.EvaluatePhase(ctx, policy.PostAuthentication, &policy.Input{
				User:        "u-1",
				Username:    "ada",
				FirstFactor: factor.Password,
				Now:         base,
			})

			assert.Equal(t, policy.Deny, d.Outcome,
				"a required user with no usable enrolment is refused, never completed on "+
					"the first factor")
			require.Error(t, d.Reason)
			tc.assert(t, d)
		})
	}
}

// TestRequireForAllLocksOutUnenrolled pins the documented limit: with MFA
// required of everyone, a user who never enrolled is refused, and this change
// gives them no way to enrol through that refusal.
func TestRequireForAllLocksOutUnenrolled(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	method, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example",
		mfa.WithClock(clockwork.NewFakeClockAt(base)))
	require.NoError(t, err)

	lookup, err := mfa.LookupFor(method)
	require.NoError(t, err)

	// Required of everyone, and this user never enrolled. There is no per-user
	// requirement lookup at all, which is what require-for-all permits.
	pol, err := policy.NewMFARequirementPolicy(nil, []policy.MFAMethodLookup{lookup}, policy.WithMFARequiredForAll())
	require.NoError(t, err)

	engine, err := policy.NewEngine(pol)
	require.NoError(t, err)

	d := engine.EvaluatePhase(ctx, policy.PostAuthentication, &policy.Input{
		User:        "u-new",
		Username:    "newcomer",
		FirstFactor: factor.Password,
		Now:         base,
	})

	assert.Equal(t, policy.Deny, d.Outcome)
	require.Error(t, d.Reason)
	assert.ErrorIs(t, d.Reason, policy.ErrMFAEnrollmentRequired)
}
