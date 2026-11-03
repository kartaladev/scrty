package mfa_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// blockingConfirmStore is the real in-memory store, device-proof port included,
// with one seam: Confirm announces it was reached, then waits to be released
// before the real Confirm decides. Every outcome is the store's own. It is
// local to this file because a generated mock of EnrolmentStore would not carry
// the device-proof port a real proof has to pass through. A second seam,
// beforeProve, runs what must land after a proof's read and before its write.
type blockingConfirmStore struct {
	*mfa.MemoryEnrolmentStore

	reached     chan struct{}
	release     chan struct{}
	reachOnce   sync.Once
	beforeProve func()
}

func (s *blockingConfirmStore) ProveDevice(
	ctx context.Context, user identity.UserID, gen id.ID, step int64, code []byte, codeUntil, at time.Time,
) (bool, error) {
	if s.beforeProve != nil {
		s.beforeProve()
	}

	return s.MemoryEnrolmentStore.ProveDevice(ctx, user, gen, step, code, codeUntil, at)
}

func (s *blockingConfirmStore) Confirm(
	ctx context.Context, user identity.UserID, gen id.ID, step int64, at time.Time,
) (bool, error) {
	s.reachOnce.Do(func() { close(s.reached) })
	<-s.release

	return s.MemoryEnrolmentStore.Confirm(ctx, user, gen, step, at)
}

// proofTiming says where the device proof lands relative to ConfirmEnrolment.
type proofTiming int

const (
	proofNever proofTiming = iota
	proofBeforeRead
	proofWhileConfirmBlocked
	proofAfterConfirm
	proofWriteAfterConfirm
)

// confirmRaceOutcome is what one interleaving left behind.
type confirmRaceOutcome struct {
	reachedConfirm bool
	proofWhileHeld bool
	proofErr       error
	confirmErr     error

	// emailed is the code the proof handed back to send, if any.
	emailed string

	// held is the enrolment as the proof left it while Confirm was held, and
	// confirmed is the enrolment as a confirmation left it before the proof's
	// write.
	held      mfa.Enrolment
	confirmed mfa.Enrolment

	// stored is the enrolment once the confirmation and any proof are done.
	stored mfa.Enrolment

	// redeemTried and redeemErr record presenting the code the proof emailed,
	// and final is the enrolment after that.
	redeemTried bool
	redeemErr   error
	final       mfa.Enrolment

	// completeErr is the outcome of completing a proof that issued no code.
	completeErr error
}

// TestConfirmEnrolment_DeviceProofBetweenReadAndConfirm lands a device proof of
// the same generation at each point around the single-call confirmation. Once a
// proof has issued an emailed code, only that code may complete the enrolment,
// wherever the proof landed relative to the confirmation's read.
func TestConfirmEnrolment_DeviceProofBetweenReadAndConfirm(t *testing.T) {
	t.Parallel()

	const (
		user         = identity.UserID("u-1")
		emailCodeTTL = 10 * time.Minute
	)

	now := time.Date(2026, 11, 3, 10, 0, 15, 0, time.UTC)

	// outcomeReflectsProof is the same check for every row. A proof that issued
	// a code leaves the single-call confirmation refused and the enrolment
	// pending with that code outstanding; with no proof recorded, the
	// confirmation stands.
	outcomeReflectsProof := func(t *testing.T, got confirmRaceOutcome) {
		t.Helper()

		if got.stored.EmailCodeUntil.IsZero() {
			assert.NoError(t, got.confirmErr, "with no proof recorded the confirmation stands")
			assert.False(t, got.stored.ConfirmedAt.IsZero(), "with no proof recorded the enrolment is confirmed")

			return
		}

		assert.ErrorIs(t, got.confirmErr, mfa.ErrInvalidCode,
			"a confirmation must be refused once a proof has issued an emailed code")
		assert.True(t, got.stored.ConfirmedAt.IsZero(),
			"the enrolment must stay pending until the emailed code is redeemed")
		assert.NotNil(t, got.stored.EmailCode, "the emailed code must stay outstanding")
	}

	// confirmedOnce holds whichever way the outcome goes: exactly one caller is
	// told it confirmed, and nothing rewrites a confirmation already made.
	confirmedOnce := func(t *testing.T, got confirmRaceOutcome) {
		t.Helper()

		successes := 0
		if got.confirmErr == nil {
			successes++
		}

		if got.redeemTried && got.redeemErr == nil {
			successes++
		}

		assert.Equal(t, 1, successes, "exactly one of the confirmation and the redemption succeeds")
		assert.False(t, got.final.ConfirmedAt.IsZero(), "the enrolment ends up confirmed")

		if !got.stored.ConfirmedAt.IsZero() {
			assert.True(t, got.final.ConfirmedAt.Equal(got.stored.ConfirmedAt),
				"a later step must not rewrite the confirmation")
		}
	}

	type testCase struct {
		name     string
		timing   proofTiming
		emailOff bool
		assert   func(t *testing.T, got confirmRaceOutcome)
	}

	cases := []testCase{
		{
			name:   "Out-of-band enrolment with no device proof",
			timing: proofNever,
			assert: func(t *testing.T, got confirmRaceOutcome) {
				require.True(t, got.reachedConfirm, "the double was not reached")
				outcomeReflectsProof(t, got)
				confirmedOnce(t, got)
				assert.True(t, got.stored.ConfirmedAt.Equal(now), "the enrolment is confirmed at the clock's time")
				assert.Equal(t, now.Unix()/30, got.stored.LastStep, "the confirming step is recorded")
				assert.True(t, got.stored.DeviceProvenAt.IsZero(), "no device proof is recorded")
			},
		},
		{
			name:   "proof lands before the read",
			timing: proofBeforeRead,
			assert: func(t *testing.T, got confirmRaceOutcome) {
				require.NoError(t, got.proofErr, "the proof did not land")
				require.False(t, got.reachedConfirm, "the read should have refused before the write")
				outcomeReflectsProof(t, got)
				confirmedOnce(t, got)
			},
		},
		{
			name:   "proof lands between the read and Confirm",
			timing: proofWhileConfirmBlocked,
			assert: func(t *testing.T, got confirmRaceOutcome) {
				require.True(t, got.reachedConfirm, "the double was not reached")
				require.NoError(t, got.proofErr, "the proof did not land")
				require.True(t, got.proofWhileHeld, "the proof did not land while Confirm was held")
				outcomeReflectsProof(t, got)
				confirmedOnce(t, got)
			},
		},
		{
			name:   "proof lands after the confirmation",
			timing: proofAfterConfirm,
			assert: func(t *testing.T, got confirmRaceOutcome) {
				require.True(t, got.reachedConfirm, "the double was not reached")
				require.ErrorIs(t, got.proofErr, mfa.ErrInvalidCode, "a confirmed enrolment takes no proof")
				outcomeReflectsProof(t, got)
				confirmedOnce(t, got)
			},
		},
		{
			name:     "Device proof lands during a confirmation with email confirmation off",
			timing:   proofWhileConfirmBlocked,
			emailOff: true,
			assert: func(t *testing.T, got confirmRaceOutcome) {
				require.True(t, got.reachedConfirm, "the double was not reached")
				require.NoError(t, got.proofErr, "the proof did not land")
				require.True(t, got.proofWhileHeld, "the proof did not land while Confirm was held")
				assert.Empty(t, got.emailed, "email confirmation is off, so no code is issued")
				assert.ErrorIs(t, got.confirmErr, mfa.ErrInvalidCode,
					"a confirmation must be refused once a proof is recorded, code or no code")
				assert.Equal(t, got.held, got.stored, "a refused confirmation changes nothing")
				assert.NoError(t, got.completeErr, "the enrolment path can still complete the proof")
				assert.False(t, got.final.ConfirmedAt.IsZero(), "the path's completion confirms the enrolment")
			},
		},
		{
			name:   "Device proof lands after a single-call confirmation",
			timing: proofWriteAfterConfirm,
			assert: func(t *testing.T, got confirmRaceOutcome) {
				require.True(t, got.reachedConfirm, "the confirmation did not run before the proof's write")
				require.NoError(t, got.confirmErr, "the confirmation landed first, so it stands")
				assert.ErrorIs(t, got.proofErr, mfa.ErrInvalidCode, "a confirmed enrolment takes no proof")
				assert.Empty(t, got.emailed, "a refused proof hands back no code to send")
				assert.True(t, got.stored.DeviceProvenAt.IsZero(), "no device proof is recorded")
				assert.Empty(t, got.stored.EmailCode, "no emailed code is stored")
				assert.True(t, got.stored.EmailCodeUntil.IsZero(), "no emailed code expiry is stored")
				assert.False(t, got.stored.ConfirmedAt.IsZero(), "the enrolment stays confirmed")
				assert.Equal(t, got.confirmed, got.stored, "the confirmation time and step are unchanged")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			clock := clockwork.NewFakeClockAt(now)
			inner := mfa.NewMemoryEnrolmentStore()
			store := &blockingConfirmStore{
				MemoryEnrolmentStore: inner,
				reached:              make(chan struct{}),
				release:              make(chan struct{}),
			}
			release := sync.OnceFunc(func() { close(store.release) })
			defer release()

			m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clock))
			require.NoError(t, err)

			p, gen, err := m.BeginEnrolmentGeneration(ctx, user, "alice")
			require.NoError(t, err)

			code := codeForSecret(t, p.Secret, now)

			var got confirmRaceOutcome

			prove := func() {
				got.emailed, got.proofErr = m.ProveDevice(ctx, user, gen, code, !tc.emailOff, emailCodeTTL)
			}

			// confirmAroundProof runs the confirmation on its own goroutine,
			// with the proof landing where the row says.
			confirmAroundProof := func() {
				if tc.timing == proofBeforeRead {
					prove()
				}

				confirmDone := make(chan error, 1)
				go func() { confirmDone <- m.ConfirmEnrolment(ctx, user, code) }()

				// Once Confirm is reached it holds until released, so these two
				// are never ready together.
				returned := false
				select {
				case <-store.reached:
					got.reachedConfirm = true
				case got.confirmErr = <-confirmDone:
					returned = true
				}

				if tc.timing == proofWhileConfirmBlocked && got.reachedConfirm {
					prove()

					mid, ok, getErr := inner.Get(ctx, user)
					require.NoError(t, getErr)
					require.True(t, ok)

					select {
					case early := <-confirmDone:
						require.Failf(t, "ConfirmEnrolment returned while its Confirm was held", "returned: %v", early)
					default:
					}

					got.held = mid
					got.proofWhileHeld = !mid.DeviceProvenAt.IsZero() && mid.ConfirmedAt.IsZero()
				}

				release()

				if !returned {
					got.confirmErr = <-confirmDone
				}

				if tc.timing == proofAfterConfirm {
					prove()
				}
			}

			// confirmDuringProof lands the confirmation after the proof's read
			// and before its write. It presents the previous step's code, which
			// the window admits, so the proof's own step is still later than the
			// recorded one and only the confirmation can refuse it.
			confirmDuringProof := func() {
				release()

				store.beforeProve = func() {
					got.reachedConfirm = true
					got.confirmErr = m.ConfirmEnrolment(ctx, user, codeForSecret(t, p.Secret, now.Add(-30*time.Second)))

					var (
						ok     bool
						getErr error
					)
					got.confirmed, ok, getErr = inner.Get(ctx, user)
					require.NoError(t, getErr)
					require.True(t, ok)
				}

				prove()
			}

			if tc.timing == proofWriteAfterConfirm {
				confirmDuringProof()
			} else {
				confirmAroundProof()
			}

			var ok bool
			got.stored, ok, err = inner.Get(ctx, user)
			require.NoError(t, err)
			require.True(t, ok)
			got.final = got.stored

			t.Logf("generation current=%t confirmed=%t device_proven=%t code_issued=%t code_outstanding=%t confirm_err=%v",
				got.stored.Generation == gen, !got.stored.ConfirmedAt.IsZero(), !got.stored.DeviceProvenAt.IsZero(),
				!got.stored.EmailCodeUntil.IsZero(), got.stored.EmailCode != nil, got.confirmErr)

			if got.emailed != "" {
				clock.Advance(time.Second)

				got.redeemTried = true
				got.redeemErr = m.RedeemEmailCode(ctx, user, gen, got.emailed)

				got.final, ok, err = inner.Get(ctx, user)
				require.NoError(t, err)
				require.True(t, ok)

				t.Logf("redeem_err=%v confirmed=%t", got.redeemErr, !got.final.ConfirmedAt.IsZero())
			}

			if tc.emailOff {
				got.completeErr = m.CompleteEnrolment(ctx, user, gen)

				got.final, ok, err = inner.Get(ctx, user)
				require.NoError(t, err)
				require.True(t, ok)
			}

			tc.assert(t, got)
		})
	}
}

// TestConfirmEnrolment_AfterNewBegin pins a documented limit, not a guarantee:
// a new begin starts a new generation and clears the device proof and the
// emailed code, so the single-call ConfirmEnrolment then needs only a valid
// code for the new secret. It carries no mailbox proof of its own, which is why
// it must never be reachable from a session the enrolment path confines.
func TestConfirmEnrolment_AfterNewBegin(t *testing.T) {
	t.Parallel()

	const (
		user         = identity.UserID("u-1")
		emailCodeTTL = 10 * time.Minute
	)

	now := time.Date(2026, 11, 3, 10, 0, 15, 0, time.UTC)

	type testCase struct {
		name   string
		assert func(t *testing.T, err error, first, stored mfa.Enrolment)
	}

	cases := []testCase{
		{
			name: "A new begin clears the proof the confirmation would have met",
			assert: func(t *testing.T, err error, first, stored mfa.Enrolment) {
				require.NoError(t, err)
				assert.NotEqual(t, first.Generation, stored.Generation, "the second begin is a new generation")
				assert.False(t, stored.ConfirmedAt.IsZero(), "the enrolment is confirmed on the new generation")
				assert.True(t, stored.DeviceProvenAt.IsZero(), "no device proof remains")
				assert.Empty(t, stored.EmailCode, "no emailed code remains")
				assert.True(t, stored.EmailCodeUntil.IsZero(), "no emailed code expiry remains")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			store := mfa.NewMemoryEnrolmentStore()

			m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(now)))
			require.NoError(t, err)

			p, gen, err := m.BeginEnrolmentGeneration(ctx, user, "alice")
			require.NoError(t, err)

			emailed, err := m.ProveDevice(ctx, user, gen, codeForSecret(t, p.Secret, now), true, emailCodeTTL)
			require.NoError(t, err)
			require.NotEmpty(t, emailed, "the proof issues an emailed code")

			first, ok, err := store.Get(ctx, user)
			require.NoError(t, err)
			require.True(t, ok)

			p2, _, err := m.BeginEnrolmentGeneration(ctx, user, "alice")
			require.NoError(t, err)

			err = m.ConfirmEnrolment(ctx, user, codeForSecret(t, p2.Secret, now))

			stored, ok, getErr := store.Get(ctx, user)
			require.NoError(t, getErr)
			require.True(t, ok)

			tc.assert(t, err, first, stored)
		})
	}
}
