package storetest_test

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/storetest"
)

// mfaDefect is one deliberate flaw an mfaStore can carry.
type mfaDefect string

const (
	mfaConforming mfaDefect = "conforming"
	// AcceptStep records every step presented and reports whether it was
	// later than the one recorded before, so a refused earlier step moves the
	// recorded one backwards and reopens a spent one.
	mfaAcceptStepMovesBack mfaDefect = "accept-step-moves-back"
	// A begin over a pending enrolment copies the confirmation time and step
	// it is given, where a begin with none to replace starts afresh.
	mfaReplaceKeepsGiven mfaDefect = "replace-keeps-given"

	// Complete confirms a proven pending enrolment whatever generation it
	// names, so a proof made for one begin completes a later one.
	mfaGenerationBlindComplete mfaDefect = "generation-blind-complete"
	// Confirm records the step it is given, lowering a later one a device
	// proof recorded, so the proving code can be replayed.
	mfaStepOverwritingConfirm mfaDefect = "step-overwriting-confirm"
	// Confirm leaves the emailed code stored on the confirmed enrolment.
	mfaConfirmKeepsCode mfaDefect = "confirm-keeps-code"
	// ChargeEmailCode charges however many attempts were charged before.
	mfaChargeWithoutCap mfaDefect = "charge-without-cap"
	// ChargeEmailCode charges a code whatever its expiry.
	mfaChargeIgnoresExpiry mfaDefect = "charge-ignores-expiry"
	// Complete clears the code's expiry with the code, erasing the record
	// that the proof issued one.
	mfaCompleteClearsExpiry mfaDefect = "complete-clears-code-expiry"
	// The nil generation is stored and compared as a value, as a durable
	// store writing id.Nil as the all-zero UUID and binding it as one would:
	// an enrolment begun with no generation is matched by a write naming
	// none.
	mfaNilGenerationMatches mfaDefect = "nil-generation-matches"
	// A begin over a pending enrolment keeps its device proof, emailed code,
	// expiry and attempts, as a gorm struct update skipping zero fields
	// would.
	mfaPutPendingKeepsProof mfaDefect = "put-pending-keeps-proof"
	// A begin over a pending enrolment keeps the attempts charged against
	// the previous generation's code, clearing everything else, so the new
	// generation's code starts part-spent.
	mfaPutPendingKeepsAttempts mfaDefect = "put-pending-keeps-attempts"
	// Complete decides by a read and writes after it, as a SELECT followed by
	// an unconditional UPDATE, so concurrent completions all win.
	mfaCompleteReadThenWrite mfaDefect = "complete-read-then-write"
	// ChargeEmailCode reads the count, then writes it plus one, so concurrent
	// charges all pass the cap.
	mfaChargeReadThenWrite mfaDefect = "charge-read-then-write"
	// ChargeEmailCode clears the code with the charge that reaches the cap,
	// so exactly the allowed charges win but the code is gone after them,
	// where it must stay stored until completion or a new begin.
	mfaChargeClearsCodeAtCap mfaDefect = "charge-clears-code-at-cap"
)

// mfaStore is an enrolment store over process memory, written apart from the
// shipped store so a defect can reach state the shipped store never exposes.
// Without a defect it conforms.
type mfaStore struct {
	defect mfaDefect

	mu         sync.Mutex
	enrolments map[identity.UserID]mfa.Enrolment
}

var _ storetest.DeviceProofEnrolmentStore = (*mfaStore)(nil)

func newMFAStore(defect mfaDefect) *mfaStore {
	return &mfaStore{defect: defect, enrolments: make(map[identity.UserID]mfa.Enrolment)}
}

func (s *mfaStore) Get(_ context.Context, user identity.UserID) (mfa.Enrolment, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	e.Secret = bytes.Clone(e.Secret)
	e.EmailCode = bytes.Clone(e.EmailCode)
	return e, ok, nil
}

func (s *mfaStore) PutPending(_ context.Context, e mfa.Enrolment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, replacing := s.enrolments[e.User]
	if replacing && !existing.ConfirmedAt.IsZero() {
		return mfa.ErrAlreadyEnrolled
	}
	stored := mfa.Enrolment{
		User: e.User, Secret: bytes.Clone(e.Secret), CreatedAt: e.CreatedAt, Generation: e.Generation,
	}
	if replacing && s.defect == mfaReplaceKeepsGiven {
		stored.ConfirmedAt, stored.LastStep = e.ConfirmedAt, e.LastStep
	}
	if replacing && s.defect == mfaPutPendingKeepsProof {
		stored.DeviceProvenAt = existing.DeviceProvenAt
		stored.EmailCode, stored.EmailCodeUntil = existing.EmailCode, existing.EmailCodeUntil
		stored.EmailCodeAttempts = existing.EmailCodeAttempts
	}
	if replacing && s.defect == mfaPutPendingKeepsAttempts {
		stored.EmailCodeAttempts = existing.EmailCodeAttempts
	}
	s.enrolments[e.User] = stored
	return nil
}

func (s *mfaStore) Confirm(_ context.Context, user identity.UserID, step int64, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	if !ok || !e.ConfirmedAt.IsZero() {
		return false, nil
	}
	e.ConfirmedAt, e.LastStep = at, max(e.LastStep, step)
	if s.defect == mfaStepOverwritingConfirm {
		e.LastStep = step
	}
	if s.defect != mfaConfirmKeepsCode {
		e.EmailCode = nil
	}
	s.enrolments[user] = e
	return true, nil
}

func (s *mfaStore) AcceptStep(_ context.Context, user identity.UserID, step int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	if !ok || e.ConfirmedAt.IsZero() {
		return false, nil
	}
	if s.defect == mfaAcceptStepMovesBack {
		old := e.LastStep
		e.LastStep = step
		s.enrolments[user] = e
		return old < step, nil
	}
	if e.LastStep >= step {
		return false, nil
	}
	e.LastStep = step
	s.enrolments[user] = e
	return true, nil
}

func (s *mfaStore) Delete(_ context.Context, user identity.UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.enrolments, user)
	return nil
}

// onGeneration reports whether e is pending on gen. The nil generation
// matches nothing, unless the store carries mfaNilGenerationMatches.
func (s *mfaStore) onGeneration(e mfa.Enrolment, gen id.ID) bool {
	if gen == id.Nil && s.defect != mfaNilGenerationMatches {
		return false
	}
	return e.Generation == gen && e.ConfirmedAt.IsZero()
}

func (s *mfaStore) ProveDevice(
	_ context.Context, user identity.UserID, gen id.ID,
	step int64, code []byte, codeUntil, at time.Time,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	if !ok || !s.onGeneration(e, gen) || !e.DeviceProvenAt.IsZero() || step <= e.LastStep {
		return false, nil
	}
	e.LastStep, e.DeviceProvenAt = step, at
	e.EmailCode, e.EmailCodeUntil, e.EmailCodeAttempts = bytes.Clone(code), codeUntil, 0
	s.enrolments[user] = e
	return true, nil
}

func (s *mfaStore) Complete(_ context.Context, user identity.UserID, gen id.ID, at time.Time) (bool, error) {
	s.mu.Lock()
	e, ok := s.enrolments[user]
	if ok && s.defect == mfaGenerationBlindComplete {
		gen = e.Generation
	}
	if !ok || !s.onGeneration(e, gen) || e.DeviceProvenAt.IsZero() {
		s.mu.Unlock()
		return false, nil
	}
	if s.defect == mfaCompleteReadThenWrite {
		// The window between the read and the write that a real store's
		// round trips open.
		s.mu.Unlock()
		time.Sleep(time.Millisecond)
		s.mu.Lock()
	}
	defer s.mu.Unlock()

	e.ConfirmedAt, e.EmailCode = at, nil
	if s.defect == mfaCompleteClearsExpiry {
		e.EmailCodeUntil = time.Time{}
	}
	s.enrolments[user] = e
	return true, nil
}

func (s *mfaStore) ChargeEmailCode(
	_ context.Context, user identity.UserID, gen id.ID, at time.Time,
) (int, bool, error) {
	s.mu.Lock()
	e, ok := s.enrolments[user]
	refused := !ok || !s.onGeneration(e, gen) || e.DeviceProvenAt.IsZero() || e.EmailCode == nil ||
		(!at.Before(e.EmailCodeUntil) && s.defect != mfaChargeIgnoresExpiry) ||
		(e.EmailCodeAttempts >= mfa.MaxEmailCodeFailures && s.defect != mfaChargeWithoutCap)
	if refused {
		s.mu.Unlock()
		return 0, false, nil
	}
	if s.defect == mfaChargeReadThenWrite {
		s.mu.Unlock()
		time.Sleep(time.Millisecond)
		s.mu.Lock()
	}
	defer s.mu.Unlock()

	e.EmailCodeAttempts++
	if s.defect == mfaChargeClearsCodeAtCap && e.EmailCodeAttempts == mfa.MaxEmailCodeFailures {
		e.EmailCode = nil
	}
	s.enrolments[user] = e
	return e.EmailCodeAttempts, true, nil
}

// The suite cases the enrolment-path variants must fail at, as the suites
// name them.
const (
	newGenerationCase    = "A new pending enrolment starts a new generation"
	confirmKeepsStepCase = "Confirmation keeps a later device-proof step"
)

// enrolmentPathVariants are the variants of the enrolment path's suite
// extension: the device-proof suite, the enrolment suite's device-proof cases
// and the session suite's enrolment fields.
var enrolmentPathVariants = []brokenVariant{
	deviceProofVariant(mfaConforming, "", ""),
	deviceProofVariant(mfaGenerationBlindComplete,
		"a completion naming an earlier generation of a proven enrolment is refused",
		"a completion naming an earlier generation: Complete must report false"),
	deviceProofVariant(mfaChargeWithoutCap,
		"charges against one code count up to the cap and are then refused, the code kept",
		"a charge past the cap: ChargeEmailCode must report false"),
	deviceProofVariant(mfaChargeIgnoresExpiry, "Expired code is not charged",
		"Expired code is not charged: ChargeEmailCode must report false"),
	deviceProofVariant(mfaCompleteClearsExpiry,
		"a completion on the proven generation confirms it once, clears the code and keeps its expiry",
		"EmailCodeUntil is"),
	deviceProofVariant(mfaNilGenerationMatches, "nil generation",
		"nil generation: ProveDevice must report false"),
	mfaVariant(mfaStepOverwritingConfirm, confirmKeepsStepCase),
	mfaVariant(mfaConfirmKeepsCode, confirmKeepsStepCase),
	mfaVariant(mfaPutPendingKeepsProof, newGenerationCase),
	// The device-proof suite requires the port, so it runs the begin's
	// device-proof case where the enrolment suite may only log it as not
	// run.
	deviceProofVariant(mfaPutPendingKeepsAttempts, newGenerationCase, "EmailCodeAttempts"),
	{
		// The shipped memory store implements the port, so the port is
		// hidden here as a store written against mfa.EnrolmentStore alone
		// would lack it. The check runs before any case, so the run is
		// wrapped in a subtest for the guard to find the failure by name.
		name: "mfa-device-proof-port-missing",
		run: func(t *testing.T) {
			t.Run("missing port", func(t *testing.T) {
				storetest.RunDeviceProofSuite(t, func(t *testing.T) storetest.DeviceProofEnrolmentStore {
					t.Helper()
					return storetest.RequireDeviceProof(t, enrolmentOnlyStore{mfa.NewMemoryEnrolmentStore()})
				})
			})
		},
		failsCase: "missing port",
		failsWith: "does not implement mfa.DeviceProofStore",
	},
	sessionVariant(sessionSaveDropsEnrolmentDeadline, "Enrolment-only session round trip"),
	sessionVariant(sessionSaveKeepsEnrolmentMarker, "Marker cleared on upgrade"),
	sessionVariant(sessionLoadDropsEnrolmentGeneration, "Enrolment-only session round trip"),
}

func deviceProofVariant(d mfaDefect, failsCase, failsWith string) brokenVariant {
	return brokenVariant{
		name: "deviceproof-" + string(d),
		run: func(t *testing.T) {
			storetest.RunDeviceProofSuite(t, func(t *testing.T) storetest.DeviceProofEnrolmentStore {
				t.Helper()
				return newMFAStore(d)
			})
		},
		failsCase: failsCase,
		failsWith: failsWith,
	}
}

// enrolmentOnlyStore is an enrolment store without the device-proof port.
type enrolmentOnlyStore struct{ mfa.EnrolmentStore }
