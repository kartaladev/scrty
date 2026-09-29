package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/id"
)

// DeviceProofEnrolmentStore is what RunDeviceProofSuite and the enrolment
// path's races need: an enrolment store that also implements the device-proof
// port, both on one value.
type DeviceProofEnrolmentStore interface {
	mfa.EnrolmentStore
	mfa.DeviceProofStore
}

// RequireDeviceProof returns s as a DeviceProofEnrolmentStore, and fails t at
// once, naming the missing port and the store's type, when s does not
// implement mfa.DeviceProofStore. It lets a factory typed on
// mfa.EnrolmentStore, such as a wrapper's constructor that returns the
// interface, feed RunDeviceProofSuite without a type assertion of its own.
func RequireDeviceProof(t testing.TB, s mfa.EnrolmentStore) DeviceProofEnrolmentStore {
	t.Helper()

	p, ok := s.(DeviceProofEnrolmentStore)
	if !ok {
		t.Fatalf("storetest: store %T does not implement mfa.DeviceProofStore, which the enrolment path needs", s)
	}
	return p
}

// The instants and the code the device-proof cases write: a device proven at
// provenAt issues emailCode, good until codeUntil, and a charge at chargeAt
// finds it outstanding.
var (
	provenAt  = suiteStart.Add(time.Minute)
	chargeAt  = suiteStart.Add(2 * time.Minute)
	codeUntil = suiteStart.Add(10 * time.Minute)
	emailCode = []byte("314159")
)

// begunOn begins mfaUser's enrolment on generation gen and returns what the
// store should then hold.
func begunOn(ctx context.Context, t *testing.T, s mfa.EnrolmentStore, gen id.ID) mfa.Enrolment {
	t.Helper()

	e := pendingOn(mfaUser, "secret-1", 1, gen)
	require.NoError(t, s.PutPending(ctx, e))
	return e
}

// proveDevice proves the device of mfaUser's enrolment, begun by begunOn on
// gen, at step issuing code, requires the proof to succeed, and returns what
// the store should then hold. A nil code issues none, and no expiry with it.
func proveDevice(
	ctx context.Context, t *testing.T, s mfa.DeviceProofStore, gen id.ID, step int64, code []byte,
) mfa.Enrolment {
	t.Helper()

	var until time.Time
	if code != nil {
		until = codeUntil
	}
	proven, err := s.ProveDevice(ctx, mfaUser, gen, step, code, until, provenAt)
	require.NoError(t, err)
	require.True(t, proven, "the device of a pending enrolment on generation %v must prove", gen)

	e := pendingOn(mfaUser, "secret-1", 1, gen)
	e.LastStep, e.DeviceProvenAt = step, provenAt
	e.EmailCode, e.EmailCodeUntil = code, until
	return e
}

// refuseProof requires a device proof of mfaUser's enrolment on gen at step
// to be refused, naming the case.
func refuseProof(ctx context.Context, t *testing.T, s mfa.DeviceProofStore, gen id.ID, step int64, row string) {
	t.Helper()

	proven, err := s.ProveDevice(ctx, mfaUser, gen, step, []byte("999999"), codeUntil, provenAt)
	require.NoError(t, err)
	assert.False(t, proven, "%s: ProveDevice must report false", row)
}

// refuseCompletion requires a completion of mfaUser's enrolment on gen to be
// refused, naming the case.
func refuseCompletion(ctx context.Context, t *testing.T, s mfa.DeviceProofStore, gen id.ID, row string) {
	t.Helper()

	completed, err := s.Complete(ctx, mfaUser, gen, chargeAt)
	require.NoError(t, err)
	assert.False(t, completed, "%s: Complete must report false", row)
}

// refuseCharge requires a charge against mfaUser's emailed code on gen at at
// to be refused with a count of 0, naming the case.
func refuseCharge(ctx context.Context, t *testing.T, s mfa.DeviceProofStore, gen id.ID, at time.Time, row string) {
	t.Helper()

	count, charged, err := s.ChargeEmailCode(ctx, mfaUser, gen, at)
	require.NoError(t, err)
	assert.False(t, charged, "%s: ChargeEmailCode must report false", row)
	assert.Zero(t, count, "%s: a refused charge reports a count of 0", row)
}

// RunDeviceProofSuite holds a store implementing mfa.DeviceProofStore to the
// security-state-stores requirement "Enrolment device proof, completion and
// emailed-code attempts are decided by the write": a device proof records its
// step, time, code and expiry only on the pending enrolment's current
// generation, once, at a later step; a completion confirms only a proven
// enrolment on its generation, once, clearing the code and keeping its expiry;
// a charge counts an attempt only against an outstanding, unexpired code on
// its generation, at most mfa.MaxEmailCodeFailures times; and the nil
// generation matches nothing, even an enrolment stored without one. Every
// refused write changes nothing. The cases are sequential; RunCompleteRace and
// RunChargeRace hold the same writes under contention.
//
// newStore is called once per case and must return an empty store. The store
// takes every instant from its caller, so it needs no clock. A factory whose
// store is typed as mfa.EnrolmentStore passes it through RequireDeviceProof.
func RunDeviceProofSuite(t *testing.T, newStore func(t *testing.T) DeviceProofEnrolmentStore) {
	t.Helper()

	g1, g2 := suiteID(1), suiteID(2)

	cases := []suiteCase[DeviceProofEnrolmentStore]{
		{
			name: "a proof on the current generation records its step, time, code and expiry, with no attempt charged",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				begunOn(ctx, t, s, g1)
				e := proveDevice(ctx, t, s, g1, 1000, emailCode)

				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			name: "Device proof on a stale generation",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				begunOn(ctx, t, s, g1)
				e := pendingOn(mfaUser, "secret-2", 2, g2)
				require.NoError(t, s.PutPending(ctx, e))

				refuseProof(ctx, t, s, g1, 1000, "Device proof on a stale generation")

				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			name: "Device proven twice",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				begunOn(ctx, t, s, g1)
				e := proveDevice(ctx, t, s, g1, 1000, emailCode)

				refuseProof(ctx, t, s, g1, 1001, "Device proven twice")

				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			// A begin records no step, so the recorded step is 0: a proof at
			// 0 is at it, not after it.
			name: "a proof at a step not later than the recorded one is refused",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				e := begunOn(ctx, t, s, g1)

				refuseProof(ctx, t, s, g1, 0, "a proof at a step not later than the recorded one")

				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			name: "a proof on a confirmed enrolment is refused",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				e := begunOn(ctx, t, s, g1)
				at := suiteStart.Add(time.Hour)
				confirmed, err := s.Confirm(ctx, mfaUser, 1000, at)
				require.NoError(t, err)
				require.True(t, confirmed)

				refuseProof(ctx, t, s, g1, 1001, "a proof on a confirmed enrolment")

				e.ConfirmedAt, e.LastStep = at, 1000
				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			// The zero identifier is what an enrolment begun outside the
			// enrolment path carries, and what a caller passes when it has
			// no generation. A durable store that writes it as a value (the
			// all-zero UUID) and compares it as one matches the two, and lets
			// such an enrolment be proven, completed and charged.
			//
			// Only the proof is really exercised here: the enrolment is
			// never proven, so Complete and ChargeEmailCode would refuse it
			// as unproven even on a store that matches the nil generation,
			// and their two refusals below pin only that nothing changes.
			// An adapter wanting them held to the nil generation too can
			// seed a proven enrolment with no generation through its
			// harness's Raw and complete and charge it with id.Nil.
			name: "nil generation",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				e := begunOn(ctx, t, s, id.Nil)

				refuseProof(ctx, t, s, id.Nil, 1000, "nil generation")
				assertEnrolment(ctx, t, s, e)
				refuseCompletion(ctx, t, s, id.Nil, "nil generation")
				assertEnrolment(ctx, t, s, e)
				refuseCharge(ctx, t, s, id.Nil, chargeAt, "nil generation")
				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			name: "Completion before device proof",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				e := begunOn(ctx, t, s, g1)

				refuseCompletion(ctx, t, s, g1, "Completion before device proof")

				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			name: "A newer begin invalidates an earlier proof",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				begunOn(ctx, t, s, g1)
				proveDevice(ctx, t, s, g1, 1000, emailCode)
				e := pendingOn(mfaUser, "secret-2", 2, g2)
				require.NoError(t, s.PutPending(ctx, e))

				refuseCompletion(ctx, t, s, g1, "A newer begin invalidates an earlier proof")

				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			// The newer generation is proven here, so only the generation
			// named keeps the completion from confirming it.
			name: "a completion naming an earlier generation of a proven enrolment is refused",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				begunOn(ctx, t, s, g1)
				require.NoError(t, s.PutPending(ctx, pendingOn(mfaUser, "secret-1", 1, g2)))
				e := proveDevice(ctx, t, s, g2, 1000, emailCode)

				refuseCompletion(ctx, t, s, g1, "a completion naming an earlier generation")

				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			name: "a completion on the proven generation confirms it once, clears the code and keeps its expiry",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				begunOn(ctx, t, s, g1)
				e := proveDevice(ctx, t, s, g1, 1000, emailCode)

				completed, err := s.Complete(ctx, mfaUser, g1, chargeAt)
				require.NoError(t, err)
				require.True(t, completed, "a proven enrolment must complete on its generation")

				e.ConfirmedAt, e.EmailCode = chargeAt, nil
				assertEnrolment(ctx, t, s, e)

				refuseCompletion(ctx, t, s, g1, "a second completion")
				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			// "Concurrent charges against one code", one charge after another.
			name: "charges against one code count up to the cap and are then refused, the code kept",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				begunOn(ctx, t, s, g1)
				e := proveDevice(ctx, t, s, g1, 1000, emailCode)

				for want := 1; want <= mfa.MaxEmailCodeFailures; want++ {
					count, charged, err := s.ChargeEmailCode(ctx, mfaUser, g1, chargeAt)
					require.NoError(t, err)
					assert.True(t, charged, "charge %d of %d must succeed", want, mfa.MaxEmailCodeFailures)
					assert.Equal(t, want, count, "the count after charge %d", want)
				}

				refuseCharge(ctx, t, s, g1, chargeAt, "a charge past the cap")

				e.EmailCodeAttempts = mfa.MaxEmailCodeFailures
				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			name: "Expired code is not charged",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				begunOn(ctx, t, s, g1)
				e := proveDevice(ctx, t, s, g1, 1000, emailCode)

				refuseCharge(ctx, t, s, g1, codeUntil.Add(time.Minute), "Expired code is not charged")

				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			// A code stops being accepted at its expiry, not after it.
			name: "Code charged at its expiry instant",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				begunOn(ctx, t, s, g1)
				e := proveDevice(ctx, t, s, g1, 1000, emailCode)

				refuseCharge(ctx, t, s, g1, codeUntil, "Code charged at its expiry instant")

				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			name: "a charge with no code issued is refused",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				begunOn(ctx, t, s, g1)
				e := proveDevice(ctx, t, s, g1, 1000, nil)

				refuseCharge(ctx, t, s, g1, chargeAt, "a charge with no code issued")

				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			// proveDevice leaves EmailCodeUntil at the zero time when code is
			// nil, so a charge refused there could be caught by the expiry
			// condition alone. Proving with an expiry that is still open at
			// chargeAt isolates the missing code: only "email_code IS NOT
			// NULL" can be refusing the charge below.
			name: "a charge after a proof that issued no code is refused",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				begunOn(ctx, t, s, g1)
				proven, err := s.ProveDevice(ctx, mfaUser, g1, 1000, nil, codeUntil, provenAt)
				require.NoError(t, err)
				require.True(t, proven, "a proof issuing no code must still record the device proof")

				e := pendingOn(mfaUser, "secret-1", 1, g1)
				e.LastStep, e.DeviceProvenAt = 1000, provenAt
				e.EmailCodeUntil = codeUntil

				refuseCharge(ctx, t, s, g1, chargeAt, "a charge after a proof that issued no code")

				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			name: "a charge before device proof, or naming another generation, is refused",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				e := begunOn(ctx, t, s, g1)
				refuseCharge(ctx, t, s, g1, chargeAt, "a charge before device proof")
				assertEnrolment(ctx, t, s, e)

				e = proveDevice(ctx, t, s, g1, 1000, emailCode)
				refuseCharge(ctx, t, s, g2, chargeAt, "a charge naming another generation")
				assertEnrolment(ctx, t, s, e)
			},
		},
		{
			name: "a charge after completion is refused",
			assert: func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, _ *clockwork.FakeClock) {
				begunOn(ctx, t, s, g1)
				e := proveDevice(ctx, t, s, g1, 1000, emailCode)
				completed, err := s.Complete(ctx, mfaUser, g1, chargeAt)
				require.NoError(t, err)
				require.True(t, completed)

				refuseCharge(ctx, t, s, g1, chargeAt, "a charge after completion")

				e.ConfirmedAt, e.EmailCode = chargeAt, nil
				assertEnrolment(ctx, t, s, e)
			},
		},
		// The enrolment suite's cases that need this port to seed, run here
		// too so a store is held to them whether or not the enrolment
		// suite could run them.
		{name: newGenerationCase, assert: withDeviceProof(assertNewGeneration)},
		{name: confirmKeepsStepCase, assert: withDeviceProof(assertConfirmKeepsStep)},
	}

	runSuite(t, cases, withoutClock(newStore))
}

// withDeviceProof adapts a case written against the two ports apart to a
// store holding both.
func withDeviceProof(
	assert func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, p mfa.DeviceProofStore, clock *clockwork.FakeClock),
) func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, clock *clockwork.FakeClock) {
	return func(t *testing.T, ctx context.Context, s DeviceProofEnrolmentStore, clock *clockwork.FakeClock) {
		assert(t, ctx, s, s, clock)
	}
}
