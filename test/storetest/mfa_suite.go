package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
)

// mfaUser is the user most enrolment cases enrol. Its case and trailing space
// catch a store that folds or trims the reference.
const mfaUser identity.UserID = "Alice@Example.COM "

// pendingEnrolment returns a pending enrolment for user on generation n,
// carrying secret.
func pendingEnrolment(user identity.UserID, secret string, n int) mfa.Enrolment {
	return mfa.Enrolment{
		User:      user,
		Secret:    []byte(secret),
		CreatedAt: suiteStart.Add(time.Duration(n) * time.Minute),
	}
}

// assertEnrolment requires the user's stored enrolment to be present and to
// equal want in every field this contract covers.
func assertEnrolment(ctx context.Context, t *testing.T, s mfa.EnrolmentStore, want mfa.Enrolment) {
	t.Helper()

	got, ok, err := s.Get(ctx, want.User)
	require.NoError(t, err)
	require.True(t, ok, "the enrolment of %q must be present", want.User)
	assert.Equal(t, want.User, got.User, "the user reference must round-trip byte for byte")
	assert.Equal(t, want.Secret, got.Secret)
	assertTimeEqual(t, want.ConfirmedAt, got.ConfirmedAt, "ConfirmedAt")
	assert.Equal(t, want.LastStep, got.LastStep, "LastStep")
	assertTimeEqual(t, want.CreatedAt, got.CreatedAt, "CreatedAt")
	// Generation, DeviceProvenAt, EmailCode, EmailCodeUntil and
	// EmailCodeAttempts are the device-proof enrolment path's fields. They
	// are asserted by the enrolment-path suite extension, not here.
}

// assertNotEnrolled requires the store to hold no enrolment for user.
func assertNotEnrolled(ctx context.Context, t *testing.T, s mfa.EnrolmentStore, user identity.UserID) {
	t.Helper()

	got, ok, err := s.Get(ctx, user)
	require.NoError(t, err)
	assert.False(t, ok, "%q must not be enrolled", user)
	assert.Zero(t, got, "an absent enrolment is the zero value")
}

// confirmEnrolment begins and confirms an enrolment for user at step, and
// returns what the store should then hold.
func confirmEnrolment(
	ctx context.Context, t *testing.T, s mfa.EnrolmentStore, user identity.UserID, step int64,
) mfa.Enrolment {
	t.Helper()

	e := pendingEnrolment(user, "secret-of-"+string(user), 1)
	require.NoError(t, s.PutPending(ctx, e))
	at := suiteStart.Add(time.Hour)
	confirmed, err := s.Confirm(ctx, user, step, at)
	require.NoError(t, err)
	require.True(t, confirmed, "a pending enrolment must confirm")

	e.ConfirmedAt = at
	e.LastStep = step
	return e
}

// RunEnrolmentStoreSuite checks an mfa.EnrolmentStore against the contract
// the TOTP method relies on: an absent enrolment is reported as absent, never
// as an error; a begin is stored pending with no step spent, whatever it is
// given; a pending enrolment is replaced by the next begin, and a
// confirmed one is never replaced; Confirm succeeds once and records its time
// and step; AcceptStep succeeds only on a confirmed enrolment and only for a
// step strictly after the recorded one; users are matched byte for byte; and
// deleting is not an error when there is nothing to delete.
//
// newStore is called once per case and must return an empty store. The store
// takes every instant from its caller, so it needs no clock.
func RunEnrolmentStoreSuite(t *testing.T, newStore func(t *testing.T) mfa.EnrolmentStore) {
	t.Helper()

	cases := []suiteCase[mfa.EnrolmentStore]{
		{
			name: "a user with no enrolment is absent, without an error",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *fakeClock) {
				assertNotEnrolled(ctx, t, s, mfaUser)
			},
		},
		{
			// A begin starts unconfirmed with no step spent whatever it is
			// handed, so a caller cannot begin an enrolment already confirmed.
			name: "a begin is stored pending with no step spent, whatever confirmation and step it is given",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *fakeClock) {
				given := pendingEnrolment(mfaUser, "secret-1", 1)
				given.ConfirmedAt = suiteStart.Add(time.Hour)
				given.LastStep = 1000
				require.NoError(t, s.PutPending(ctx, given))

				assertEnrolment(ctx, t, s, pendingEnrolment(mfaUser, "secret-1", 1))
			},
		},
		{
			// Replacing a pending enrolment is a store's other write path, and
			// it starts afresh as a first begin does.
			name: "a second begin while pending replaces it, pending with no step spent whatever it is given",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *fakeClock) {
				require.NoError(t, s.PutPending(ctx, pendingEnrolment(mfaUser, "secret-1", 1)))

				given := pendingEnrolment(mfaUser, "secret-2", 2)
				given.ConfirmedAt = suiteStart.Add(time.Hour)
				given.LastStep = 1000
				require.NoError(t, s.PutPending(ctx, given))

				assertEnrolment(ctx, t, s, pendingEnrolment(mfaUser, "secret-2", 2))
			},
		},
		{
			name: "a begin over a confirmed enrolment is refused and leaves it unchanged",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *fakeClock) {
				confirmed := confirmEnrolment(ctx, t, s, mfaUser, 1000)

				err := s.PutPending(ctx, pendingEnrolment(mfaUser, "attacker-secret", 2))
				require.ErrorIs(t, err, mfa.ErrAlreadyEnrolled)

				assertEnrolment(ctx, t, s, confirmed)
			},
		},
		{
			name: "confirming records its time and step, and a second confirm is refused",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *fakeClock) {
				confirmed := confirmEnrolment(ctx, t, s, mfaUser, 1000)
				assertEnrolment(ctx, t, s, confirmed)

				again, err := s.Confirm(ctx, mfaUser, 2000, suiteStart.Add(2*time.Hour))
				require.NoError(t, err)
				assert.False(t, again, "a confirmed enrolment has nothing pending to confirm")

				assertEnrolment(ctx, t, s, confirmed)
			},
		},
		{
			name: "confirming with no enrolment is refused and enrols no one",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *fakeClock) {
				confirmed, err := s.Confirm(ctx, mfaUser, 1000, suiteStart)
				require.NoError(t, err)
				assert.False(t, confirmed)

				assertNotEnrolled(ctx, t, s, mfaUser)
			},
		},
		{
			name: "a step is not accepted for a pending or absent enrolment",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *fakeClock) {
				e := pendingEnrolment(mfaUser, "secret-1", 1)
				require.NoError(t, s.PutPending(ctx, e))

				for _, user := range []identity.UserID{mfaUser, "nobody"} {
					accepted, err := s.AcceptStep(ctx, user, 1001)
					require.NoError(t, err)
					assert.False(t, accepted, "no confirmed enrolment for %q", user)
				}

				assertEnrolment(ctx, t, s, e)
				assertNotEnrolled(ctx, t, s, "nobody")
			},
		},
		{
			name: "a step is accepted only when it is after the recorded one",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *fakeClock) {
				e := confirmEnrolment(ctx, t, s, mfaUser, 1000)

				// A refused step records nothing: the recorded step after each
				// call is the highest accepted so far, so a refused earlier
				// step can never reopen a spent later one.
				for _, call := range []struct {
					step     int64
					want     bool
					recorded int64
				}{
					{1001, true, 1001},
					{1001, false, 1001},
					{1000, false, 1001},
					{1001, false, 1001},
					{1002, true, 1002},
				} {
					accepted, err := s.AcceptStep(ctx, mfaUser, call.step)
					require.NoError(t, err)
					assert.Equal(t, call.want, accepted, "step %d", call.step)

					e.LastStep = call.recorded
					assertEnrolment(ctx, t, s, e)
				}
			},
		},
		{
			name: "enrolment times keep at least microsecond precision",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *fakeClock) {
				begun := pendingEnrolment(mfaUser, "secret-1", 0)
				begun.CreatedAt = preciseStart
				require.NoError(t, s.PutPending(ctx, begun))
				at := preciseStart.Add(time.Minute)
				confirmed, err := s.Confirm(ctx, mfaUser, 1000, at)
				require.NoError(t, err)
				require.True(t, confirmed)

				got, ok, err := s.Get(ctx, mfaUser)
				require.NoError(t, err)
				require.True(t, ok)
				assertTimeMicro(t, begun.CreatedAt, got.CreatedAt, "CreatedAt")
				assertTimeMicro(t, at, got.ConfirmedAt, "ConfirmedAt")
			},
		},
		{
			name: "users differing only in case are enrolled separately",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *fakeClock) {
				confirmed := confirmEnrolment(ctx, t, s, mfaUser, 1000)
				folded := pendingEnrolment("alice@example.com", "secret-of-folded", 2)
				require.NoError(t, s.PutPending(ctx, folded), "another user's enrolment is not this user's")

				assertEnrolment(ctx, t, s, confirmed)
				assertEnrolment(ctx, t, s, folded)
			},
		},
		{
			name: "deleting removes that user's enrolment, and deleting an absent one is not an error",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *fakeClock) {
				confirmEnrolment(ctx, t, s, mfaUser, 1000)
				other := pendingEnrolment("bob", "secret-of-bob", 1)
				require.NoError(t, s.PutPending(ctx, other))

				require.NoError(t, s.Delete(ctx, mfaUser))
				require.NoError(t, s.Delete(ctx, mfaUser))
				require.NoError(t, s.Delete(ctx, "nobody"))

				assertNotEnrolled(ctx, t, s, mfaUser)
				assertEnrolment(ctx, t, s, other)
				require.NoError(t, s.PutPending(ctx, pendingEnrolment(mfaUser, "secret-3", 3)),
					"a deleted enrolment no longer blocks a begin")
			},
		},
	}

	runSuite(t, cases, withoutClock(newStore))
}
