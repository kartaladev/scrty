package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/id"
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

// pendingOn returns a pending enrolment for user on generation n, carrying
// secret and begun on the enrolment generation gen.
func pendingOn(user identity.UserID, secret string, n int, gen id.ID) mfa.Enrolment {
	e := pendingEnrolment(user, secret, n)
	e.Generation = gen
	return e
}

// assertEnrolment requires the user's stored enrolment to be present and to
// equal want in every field: the ones mfa.EnrolmentStore writes, and the
// enrolment path's, which mfa.DeviceProofStore writes and PutPending and
// Confirm clear. An emailed code of nil and one of no bytes are both none.
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
	assert.Equal(t, want.Generation, got.Generation, "Generation")
	assertTimeEqual(t, want.DeviceProvenAt, got.DeviceProvenAt, "DeviceProvenAt")
	if len(want.EmailCode) == 0 {
		assert.Empty(t, got.EmailCode, "EmailCode must be none")
	} else {
		assert.Equal(t, want.EmailCode, got.EmailCode, "EmailCode")
	}
	assertTimeEqual(t, want.EmailCodeUntil, got.EmailCodeUntil, "EmailCodeUntil")
	assert.Equal(t, want.EmailCodeAttempts, got.EmailCodeAttempts, "EmailCodeAttempts")
	assert.Equal(t, want.VerifyAttempts, got.VerifyAttempts, "VerifyAttempts")
	assertTimeEqual(t, want.VerifyWindowUntil, got.VerifyWindowUntil, "VerifyWindowUntil")
}

// The charging window the verification-attempt cases use: the default limit
// and window, so a case reads as the TOTP method charges.
const (
	verifyLimit  = 5
	verifyWindow = 15 * time.Minute
)

// chargeVerify charges one TOTP verification attempt for mfaUser at at with
// the cases' limit and window, requires it to succeed, and returns the end of
// the window it was charged in.
func chargeVerify(ctx context.Context, t *testing.T, s mfa.EnrolmentStore, at time.Time) time.Time {
	t.Helper()

	until, ok, err := s.ChargeVerifyAttempt(ctx, mfaUser, at, verifyLimit, verifyWindow)
	require.NoError(t, err)
	require.True(t, ok, "a charge at %v must succeed", at)
	return until
}

// verifyAttemptCases are the enrolment suite's cases for charging and giving
// back TOTP verification attempts, each named after the scenario it proves.
func verifyAttemptCases() []suiteCase[mfa.EnrolmentStore] {
	return []suiteCase[mfa.EnrolmentStore]{
		{
			name: "The window ends at its end instant",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
				confirmEnrolment(ctx, t, s, mfaUser, 1000)
				for range verifyLimit {
					until := chargeVerify(ctx, t, s, suiteStart)
					assertTimeEqual(t, suiteStart.Add(verifyWindow), until, "window end")
				}
				_, ok, err := s.ChargeVerifyAttempt(ctx, mfaUser, suiteStart.Add(14*time.Minute), verifyLimit, verifyWindow)
				require.NoError(t, err)
				assert.False(t, ok, "a sixth charge inside the window must be refused")

				until, ok, err := s.ChargeVerifyAttempt(ctx, mfaUser, suiteStart.Add(verifyWindow), verifyLimit, verifyWindow)
				require.NoError(t, err)
				require.True(t, ok, "a charge at the window's end instant opens a new window")
				assertTimeEqual(t, suiteStart.Add(2*verifyWindow), until, "new window end")

				got, _, err := s.Get(ctx, mfaUser)
				require.NoError(t, err)
				assert.Equal(t, 1, got.VerifyAttempts, "the new window counts one")
				assertTimeEqual(t, suiteStart.Add(2*verifyWindow), got.VerifyWindowUntil, "VerifyWindowUntil")
			},
		},
		{
			name: "A charge after an idle gap opens a window from the charge",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
				confirmEnrolment(ctx, t, s, mfaUser, 1000)
				chargeVerify(ctx, t, s, suiteStart)

				at := suiteStart.Add(verifyWindow + 7*time.Minute)
				until := chargeVerify(ctx, t, s, at)
				assertTimeEqual(t, at.Add(verifyWindow), until, "window end")

				got, _, err := s.Get(ctx, mfaUser)
				require.NoError(t, err)
				assert.Equal(t, 1, got.VerifyAttempts, "the new window counts one")
				assertTimeEqual(t, at.Add(verifyWindow), got.VerifyWindowUntil, "VerifyWindowUntil")
			},
		},
		{
			name: "Pending enrolment is not charged",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
				e := pendingEnrolment(mfaUser, "secret", 0)
				require.NoError(t, s.PutPending(ctx, e))

				_, ok, err := s.ChargeVerifyAttempt(ctx, mfaUser, suiteStart, verifyLimit, verifyWindow)
				require.NoError(t, err)
				assert.False(t, ok, "a pending enrolment is not charged")
				assertEnrolment(ctx, t, s, e)

				_, ok, err = s.ChargeVerifyAttempt(ctx, "nobody", suiteStart, verifyLimit, verifyWindow)
				require.NoError(t, err)
				assert.False(t, ok, "an absent enrolment is not charged")
				assertNotEnrolled(ctx, t, s, "nobody")
			},
		},
		{
			name: "The window end a charge returns is the one a give-back matches",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
				confirmEnrolment(ctx, t, s, mfaUser, 1000)
				until := chargeVerify(ctx, t, s, preciseStart)
				assert.True(t, until.Equal(preciseStart.Add(verifyWindow).Truncate(time.Microsecond)),
					"window end is %v, want the charge instant plus the window, truncated to the microsecond", until)

				got, _, err := s.Get(ctx, mfaUser)
				require.NoError(t, err)
				assertTimeEqual(t, until, got.VerifyWindowUntil, "VerifyWindowUntil is the end the charge returned")
				assert.Equal(t, 1, got.VerifyAttempts)

				ok, err := s.RefundVerifyAttempt(ctx, mfaUser, until)
				require.NoError(t, err)
				assert.True(t, ok, "a give-back naming the returned window end must match")

				got, _, err = s.Get(ctx, mfaUser)
				require.NoError(t, err)
				assert.Zero(t, got.VerifyAttempts, "the give-back restores the count")
			},
		},
		{
			name: "Give-back in the window it was charged in",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
				confirmEnrolment(ctx, t, s, mfaUser, 1000)
				until := chargeVerify(ctx, t, s, suiteStart)
				chargeVerify(ctx, t, s, suiteStart.Add(time.Minute))

				ok, err := s.RefundVerifyAttempt(ctx, mfaUser, until)
				require.NoError(t, err)
				assert.True(t, ok, "a give-back naming the current window must succeed")

				got, _, err := s.Get(ctx, mfaUser)
				require.NoError(t, err)
				assert.Equal(t, 1, got.VerifyAttempts, "the give-back lowers the count by one")
				assertTimeEqual(t, until, got.VerifyWindowUntil, "a give-back keeps the window")
			},
		},
		{
			name: "Give-back after the window was replaced",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
				confirmEnrolment(ctx, t, s, mfaUser, 1000)
				first := chargeVerify(ctx, t, s, suiteStart)
				second := chargeVerify(ctx, t, s, suiteStart.Add(verifyWindow))

				ok, err := s.RefundVerifyAttempt(ctx, mfaUser, first)
				require.NoError(t, err)
				assert.False(t, ok, "a give-back naming a replaced window must be refused")

				got, _, err := s.Get(ctx, mfaUser)
				require.NoError(t, err)
				assert.Equal(t, 1, got.VerifyAttempts, "a refused give-back leaves the count")
				assertTimeEqual(t, second, got.VerifyWindowUntil, "a refused give-back leaves the window")
			},
		},
		{
			name: "Give-back at zero",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
				confirmEnrolment(ctx, t, s, mfaUser, 1000)
				until := chargeVerify(ctx, t, s, suiteStart)
				ok, err := s.RefundVerifyAttempt(ctx, mfaUser, until)
				require.NoError(t, err)
				require.True(t, ok, "the charge must be given back once")

				ok, err = s.RefundVerifyAttempt(ctx, mfaUser, until)
				require.NoError(t, err)
				assert.False(t, ok, "a give-back with nothing charged must be refused")

				got, _, err := s.Get(ctx, mfaUser)
				require.NoError(t, err)
				assert.Zero(t, got.VerifyAttempts, "the count stays zero")
			},
		},
		{
			name: "A new begin clears the count",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
				confirmEnrolment(ctx, t, s, mfaUser, 1000)
				for range 3 {
					chargeVerify(ctx, t, s, suiteStart)
				}
				require.NoError(t, s.Delete(ctx, mfaUser))

				// The begin is handed a count and a window, as a caller
				// replaying a read enrolment would, and keeps neither.
				given := pendingEnrolment(mfaUser, "secret-2", 2)
				given.VerifyAttempts = 3
				given.VerifyWindowUntil = suiteStart.Add(verifyWindow)
				require.NoError(t, s.PutPending(ctx, given))
				assertEnrolment(ctx, t, s, pendingEnrolment(mfaUser, "secret-2", 2))
			},
		},
	}
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

// The enrolment suite's cases that need mfa.DeviceProofStore to seed. The
// enrolment suite runs them when the store implements the port and logs them
// as not run otherwise; RunDeviceProofSuite, which requires the port, always
// runs them, so a store behind that suite cannot pass them unchecked.
const (
	newGenerationCase    = "A new pending enrolment starts a new generation"
	confirmKeepsStepCase = "Confirmation keeps a later device-proof step"
)

// assertNewGeneration is the case newGenerationCase: a begin over a proven
// enrolment whose code took a charge reads back on the new generation with no
// device proof, no code, no expiry and no attempts.
//
//nolint:revive // context-as-argument: the table-test assert signature puts t before ctx.
func assertNewGeneration(
	t *testing.T, ctx context.Context, s mfa.EnrolmentStore, p mfa.DeviceProofStore, _ *clockwork.FakeClock,
) {
	begunOn(ctx, t, s, suiteID(1))
	proveDevice(ctx, t, p, suiteID(1), 1000, emailCode)
	_, charged, err := p.ChargeEmailCode(ctx, mfaUser, suiteID(1), chargeAt)
	require.NoError(t, err)
	require.True(t, charged, "the proven code must take a charge")

	next := pendingOn(mfaUser, "secret-2", 2, suiteID(2))
	require.NoError(t, s.PutPending(ctx, next))

	assertEnrolment(ctx, t, s, next)
}

// assertConfirmKeepsStep is the case confirmKeepsStepCase: a confirmation at
// a step earlier than the device proof's clears the emailed code, keeps the
// later step, and so leaves that step spent.
//
//nolint:revive // context-as-argument: the table-test assert signature puts t before ctx.
func assertConfirmKeepsStep(
	t *testing.T, ctx context.Context, s mfa.EnrolmentStore, p mfa.DeviceProofStore, _ *clockwork.FakeClock,
) {
	begunOn(ctx, t, s, suiteID(1))
	e := proveDevice(ctx, t, p, suiteID(1), 1001, emailCode)

	at := suiteStart.Add(time.Hour)
	confirmed, err := s.Confirm(ctx, mfaUser, 1000, at)
	require.NoError(t, err)
	require.True(t, confirmed, "Confirmation keeps a later device-proof step: Confirm must report true")

	e.ConfirmedAt, e.EmailCode = at, nil
	assertEnrolment(ctx, t, s, e)

	accepted, err := s.AcceptStep(ctx, mfaUser, 1001)
	require.NoError(t, err)
	assert.False(t, accepted, "the device-proof step 1001 is spent and must not be accepted again")
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
// It also holds the store to charging TOTP verification attempts: only a
// confirmed enrolment is charged; a window ends at its end instant, and a
// charge then opens a new one counting one; a give-back lowers the count only
// in the window it names and never below zero; and a begin starts with no
// count and no window. That at most the limit of concurrent charges succeed
// is RunVerifyChargeRace's to prove.
//
// For a store that also implements mfa.DeviceProofStore, two more cases hold
// the begin and the confirmation to the enrolment path: a begin starts a new
// generation and clears the device proof, the emailed code, its expiry and
// its attempts; and a confirmation clears the emailed code and never lowers a
// step a device proof recorded. They need ProveDevice to seed, so for a store
// without it they are logged as not run; RunDeviceProofSuite runs them too,
// with the rest of that port, and fails a store without it.
//
// newStore is called once per case and must return an empty store. The store
// takes every instant from its caller, so it needs no clock.
func RunEnrolmentStoreSuite(t *testing.T, newStore func(t *testing.T) mfa.EnrolmentStore) {
	t.Helper()

	cases := []suiteCase[mfa.EnrolmentStore]{
		{
			name: "a user with no enrolment is absent, without an error",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
				assertNotEnrolled(ctx, t, s, mfaUser)
			},
		},
		{
			// A begin starts unconfirmed with no step spent whatever it is
			// handed, so a caller cannot begin an enrolment already confirmed.
			name: "a begin is stored pending with no step spent, whatever confirmation and step it is given",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
				confirmed := confirmEnrolment(ctx, t, s, mfaUser, 1000)

				err := s.PutPending(ctx, pendingEnrolment(mfaUser, "attacker-secret", 2))
				require.ErrorIs(t, err, mfa.ErrAlreadyEnrolled)

				assertEnrolment(ctx, t, s, confirmed)
			},
		},
		{
			name: "confirming records its time and step, and a second confirm is refused",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
				confirmed, err := s.Confirm(ctx, mfaUser, 1000, suiteStart)
				require.NoError(t, err)
				assert.False(t, confirmed)

				assertNotEnrolled(ctx, t, s, mfaUser)
			},
		},
		{
			name: "a step is not accepted for a pending or absent enrolment",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
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
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
				confirmed := confirmEnrolment(ctx, t, s, mfaUser, 1000)
				folded := pendingEnrolment("alice@example.com", "secret-of-folded", 2)
				require.NoError(t, s.PutPending(ctx, folded), "another user's enrolment is not this user's")

				assertEnrolment(ctx, t, s, confirmed)
				assertEnrolment(ctx, t, s, folded)
			},
		},
		{
			name: "deleting removes that user's enrolment, and deleting an absent one is not an error",
			assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
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
		optionalCase(false, newGenerationCase, assertNewGeneration),
		optionalCase(false, confirmKeepsStepCase, assertConfirmKeepsStep),
	}
	cases = append(cases, verifyAttemptCases()...)

	runSuite(t, cases, withoutClock(newStore))
}
