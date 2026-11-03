package storetest_test

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/internal/storefix"
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
	// Confirm confirms a pending enrolment whatever generation it names, so
	// a code checked against one begin's secret confirms a later begin's.
	mfaGenerationBlindConfirm mfaDefect = "generation-blind-confirm"
	// AcceptStep accepts a step whatever generation it names, so a code
	// checked against a removed secret counts for the re-enrolment.
	mfaGenerationBlindAccept mfaDefect = "generation-blind-accept"
	// Store ignoring the device proof: Confirm confirms a proven enrolment, so
	// a proof landing after a stale read goes round the emailed code.
	mfaConfirmIgnoresProof mfaDefect = "store-ignoring-the-device-proof"
	// Store honouring only a live emailed code: Confirm refuses a proven
	// enrolment only while its code is unexpired, so waiting out the code goes
	// round it.
	mfaConfirmHonoursOnlyLiveCode mfaDefect = "store-honouring-only-a-live-emailed-code"
	// Confirm refuses a proven enrolment only while its code has attempts
	// left, so spending them goes round it.
	mfaConfirmHonoursOnlyUnspentCode mfaDefect = "store-honouring-only-an-unspent-emailed-code"
	// Confirm refuses a proven enrolment only when the proof issued a code, so
	// a proof with email confirmation off does not block it.
	mfaConfirmHonoursOnlyIssuedCode mfaDefect = "store-honouring-only-an-issued-emailed-code"
	// Store confirming by reading and then writing: Confirm checks the proof,
	// lets go of its lock, then writes without the condition, as a SELECT
	// followed by an unconditional UPDATE, so a proof landing between the two
	// and the confirmation both report success. Called one after the other it
	// conforms, so only the race can catch it.
	mfaConfirmReadThenWrite mfaDefect = "store-confirming-by-reading-and-then-writing"
	// Store whose refusal still writes: Confirm of a proven enrolment reports
	// false, and clears the emailed code the path still needs.
	mfaConfirmRefusalWrites mfaDefect = "store-whose-refusal-still-writes"
	// ProveDevice proves a confirmed enrolment on its generation, so a proof
	// landing after a confirmation stores a code nothing can redeem.
	mfaProofOnConfirmed mfaDefect = "proof-on-confirmed"
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

	// ChargeVerifyAttempt counts every charge in the window, however many
	// were charged before.
	mfaVerifyChargeWithoutCap mfaDefect = "verify-charge-without-cap"
	// ChargeVerifyAttempt reads the count, then writes it plus one, so
	// concurrent charges all pass the limit.
	mfaVerifyChargeReadThenWrite mfaDefect = "verify-charge-read-then-write"
	// ChargeVerifyAttempt never opens a new window, so an ended one keeps
	// counting.
	mfaVerifyWindowNeverEnds mfaDefect = "verify-window-never-ends"
	// ChargeVerifyAttempt opens the new window from the old window's end, not
	// from the charge, so after an idle gap the window is already over.
	mfaVerifyWindowAnchoredOnOldEnd mfaDefect = "verify-window-anchored-on-old-end"
	// RefundVerifyAttempt lowers the count whatever window it names.
	mfaVerifyRefundIgnoresWindow mfaDefect = "verify-refund-ignores-window"
	// ChargeVerifyAttempt charges a pending enrolment as if confirmed.
	mfaVerifyChargesPending mfaDefect = "verify-charges-pending"
	// RefundVerifyAttempt lowers the count past zero.
	mfaVerifyRefundBelowZero mfaDefect = "verify-refund-below-zero"
	// mfaVerifyRefundZeroesCount gives a charge back by resetting the count
	// to zero instead of lowering it by one.
	mfaVerifyRefundZeroesCount mfaDefect = "verify-refund-zeroes-count"
	// ChargeVerifyAttempt returns and stores the window end as computed,
	// without the truncation to the microsecond a durable store applies.
	mfaVerifyWindowEndUntruncated mfaDefect = "verify-window-end-untruncated"
	// A begin stores the verification attempts and window it is given, where
	// it must start with none.
	mfaPutPendingKeepsGivenVerifyAttempts mfaDefect = "put-pending-keeps-given-verify-attempts"
)

// mfaStore is an enrolment store over process memory, written apart from the
// shipped store so a defect can reach state the shipped store never exposes.
// Without a defect it conforms.
type mfaStore struct {
	defect mfaDefect

	mu         sync.Mutex
	enrolments map[identity.UserID]mfa.Enrolment

	// proofs, when set, holds an mfaConfirmReadThenWrite store's Confirm between
	// its check and its write until a proof of that user lands, or its context
	// ends, so a confirmation that passed the check always overlaps the proof
	// racing it. Each channel closes when its user's proof is written.
	proofs map[identity.UserID]chan struct{}
}

var _ storetest.DeviceProofEnrolmentStore = (*mfaStore)(nil)

func newMFAStore(defect mfaDefect) *mfaStore {
	return &mfaStore{defect: defect, enrolments: make(map[identity.UserID]mfa.Enrolment)}
}

// newHeldConfirmStore returns an mfaConfirmReadThenWrite store whose window
// between check and write stays open until the proof racing it has landed.
func newHeldConfirmStore() *mfaStore {
	s := newMFAStore(mfaConfirmReadThenWrite)
	s.proofs = make(map[identity.UserID]chan struct{})
	return s
}

// proofLanded returns the channel closed when user's proof is written, and nil
// for a store that holds nothing. The caller holds s.mu.
func (s *mfaStore) proofLanded(user identity.UserID) chan struct{} {
	if s.proofs == nil {
		return nil
	}
	landed, ok := s.proofs[user]
	if !ok {
		landed = make(chan struct{})
		s.proofs[user] = landed
	}
	return landed
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
	if s.defect == mfaPutPendingKeepsGivenVerifyAttempts {
		stored.VerifyAttempts, stored.VerifyWindowUntil = e.VerifyAttempts, e.VerifyWindowUntil
	}
	s.enrolments[e.User] = stored
	return nil
}

func (s *mfaStore) Confirm(
	ctx context.Context, user identity.UserID, gen id.ID, step int64, at time.Time,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	if !ok || !e.ConfirmedAt.IsZero() {
		return false, nil
	}
	if s.defect != mfaGenerationBlindConfirm && !s.onGeneration(e, gen) {
		return false, nil
	}
	refused := !e.DeviceProvenAt.IsZero()
	switch s.defect {
	case mfaConfirmIgnoresProof:
		refused = false
	case mfaConfirmHonoursOnlyLiveCode:
		refused = at.Before(e.EmailCodeUntil)
	case mfaConfirmHonoursOnlyUnspentCode:
		refused = e.EmailCode != nil && e.EmailCodeAttempts < mfa.MaxEmailCodeAttempts
	case mfaConfirmHonoursOnlyIssuedCode:
		refused = !e.EmailCodeUntil.IsZero()
	default:
	}
	if refused {
		if s.defect == mfaConfirmRefusalWrites {
			e.EmailCode = nil
			s.enrolments[user] = e
		}
		return false, nil
	}
	if s.defect == mfaConfirmReadThenWrite {
		e = s.afterConfirmWindow(ctx, user)
	}
	e.ConfirmedAt, e.LastStep = at, max(e.LastStep, step)
	s.enrolments[user] = e
	return true, nil
}

// afterConfirmWindow is the window between the read and the write that a real
// store's round trips open: it lets go of s.mu, waits for the proof when the
// store holds for one, and returns the row as it now stands, which an
// unconditional UPDATE would write over. The caller holds s.mu, and holds it
// again on return.
func (s *mfaStore) afterConfirmWindow(ctx context.Context, user identity.UserID) mfa.Enrolment {
	landed := s.proofLanded(user)
	s.mu.Unlock()
	if landed != nil {
		select {
		case <-landed:
		case <-ctx.Done():
		}
	}
	s.mu.Lock()
	return s.enrolments[user]
}

func (s *mfaStore) AcceptStep(_ context.Context, user identity.UserID, gen id.ID, step int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	if !ok || e.ConfirmedAt.IsZero() {
		return false, nil
	}
	if s.defect != mfaGenerationBlindAccept &&
		(e.Generation != gen || (gen == id.Nil && s.defect != mfaNilGenerationMatches)) {
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
	onGen := ok && s.onGeneration(e, gen)
	if ok && s.defect == mfaProofOnConfirmed {
		onGen = gen != id.Nil && e.Generation == gen
	}
	if !onGen || !e.DeviceProvenAt.IsZero() || step <= e.LastStep {
		return false, nil
	}
	e.LastStep, e.DeviceProvenAt = step, at
	e.EmailCode, e.EmailCodeUntil, e.EmailCodeAttempts = bytes.Clone(code), codeUntil, 0
	s.enrolments[user] = e
	if landed := s.proofLanded(user); landed != nil {
		close(landed)
	}
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
		(e.EmailCodeAttempts >= mfa.MaxEmailCodeAttempts && s.defect != mfaChargeWithoutCap)
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
	if s.defect == mfaChargeClearsCodeAtCap && e.EmailCodeAttempts == mfa.MaxEmailCodeAttempts {
		e.EmailCode = nil
	}
	s.enrolments[user] = e
	return e.EmailCodeAttempts, true, nil
}

func (s *mfaStore) ChargeVerifyAttempt(
	_ context.Context, user identity.UserID, at time.Time, limit int, window time.Duration,
) (time.Time, bool, error) {
	s.mu.Lock()
	e, ok := s.enrolments[user]
	if !ok || (e.ConfirmedAt.IsZero() && s.defect != mfaVerifyChargesPending) {
		s.mu.Unlock()
		return time.Time{}, false, nil
	}
	old := e.VerifyWindowUntil
	ended := e.VerifyWindowUntil.IsZero() || !at.Before(e.VerifyWindowUntil)
	if s.defect == mfaVerifyWindowNeverEnds {
		ended = e.VerifyWindowUntil.IsZero()
	}
	if !ended && e.VerifyAttempts >= limit && s.defect != mfaVerifyChargeWithoutCap {
		s.mu.Unlock()
		return time.Time{}, false, nil
	}
	if s.defect == mfaVerifyChargeReadThenWrite {
		// The window between the read and the write that a real store's
		// round trips open; the write then stores what was read plus one.
		s.mu.Unlock()
		time.Sleep(time.Millisecond)
		s.mu.Lock()
	}
	defer s.mu.Unlock()

	if ended {
		e.VerifyAttempts, e.VerifyWindowUntil = 1, at.Add(window).Truncate(time.Microsecond)
		if s.defect == mfaVerifyWindowEndUntruncated {
			e.VerifyWindowUntil = at.Add(window)
		}
		if s.defect == mfaVerifyWindowAnchoredOnOldEnd && !old.IsZero() {
			e.VerifyWindowUntil = old.Add(window).Truncate(time.Microsecond)
		}
	} else {
		e.VerifyAttempts++
	}
	s.enrolments[user] = e
	return e.VerifyWindowUntil, true, nil
}

func (s *mfaStore) RefundVerifyAttempt(_ context.Context, user identity.UserID, until time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	if !ok ||
		(e.VerifyAttempts <= 0 && s.defect != mfaVerifyRefundBelowZero) ||
		(!e.VerifyWindowUntil.Equal(until) && s.defect != mfaVerifyRefundIgnoresWindow) {
		return false, nil
	}
	e.VerifyAttempts--
	if s.defect == mfaVerifyRefundZeroesCount {
		e.VerifyAttempts = 0
	}
	s.enrolments[user] = e
	return true, nil
}

// The suite cases the enrolment-path variants must fail at, as the suites
// name them.
const (
	newGenerationCase        = "A new pending enrolment starts a new generation"
	confirmKeepsStepCase     = "Confirmation keeps a later device-proof step"
	confirmRefusedNoCodeCase = "Confirmation refused after a device proof with no emailed code"
	confirmRefusedDeadCase   = "Confirmation refused when the emailed code has expired or run out of attempts"
	proofOnConfirmedCase     = "Device proof on a confirmed enrolment"
	confirmProofCase         = "a confirmation and a device proof of one generation never both succeed"
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
	mfaVariant(mfaGenerationBlindConfirm, "confirm naming a replaced generation is refused"),
	mfaVariant(mfaGenerationBlindAccept, "accept naming a removed generation is refused"),
	mfaVariant(mfaConfirmIgnoresProof, confirmKeepsStepCase),
	deviceProofVariant(mfaConfirmIgnoresProof, confirmKeepsStepCase, "Confirm must report false"),
	mfaVariant(mfaConfirmHonoursOnlyLiveCode, confirmRefusedDeadCase),
	deviceProofVariant(mfaConfirmHonoursOnlyLiveCode, confirmKeepsStepCase, "Confirm must report false"),
	mfaVariant(mfaConfirmHonoursOnlyUnspentCode, confirmRefusedDeadCase),
	mfaVariant(mfaConfirmHonoursOnlyIssuedCode, confirmRefusedNoCodeCase),
	mfaVariant(mfaProofOnConfirmed, proofOnConfirmedCase),
	// RunDeviceProofSuite holds a store to these three on its own, so a store
	// behind it cannot pass them by being run only through that suite.
	deviceProofVariant(mfaConfirmHonoursOnlyIssuedCode, confirmRefusedNoCodeCase, "Confirm must report false"),
	deviceProofVariant(mfaConfirmHonoursOnlyUnspentCode, confirmRefusedDeadCase, "Confirm must report false"),
	deviceProofVariant(mfaProofOnConfirmed, proofOnConfirmedCase, "ProveDevice must report false"),
	mfaVariant(mfaConfirmRefusalWrites, confirmKeepsStepCase),
	deviceProofVariant(mfaConfirmRefusalWrites, confirmKeepsStepCase, "EmailCode"),
	deviceProofVariant(mfaConfirmRefusalWrites, confirmRefusedDeadCase, "EmailCode"),
	// The sequential suites pass a confirmation that reads and then writes, as
	// the calls never overlap there, which is what the race below is for.
	mfaVariant(mfaConfirmReadThenWrite, ""),
	deviceProofVariant(mfaConfirmReadThenWrite, "", ""),
	confirmProofVariant("race-confirm-proof-memory", mfa.NewMemoryEnrolmentStore, "", ""),
	confirmProofVariant("race-confirm-proof-conforming", mfaRaceStore(mfaConforming), "", ""),
	confirmProofVariant("race-confirm-proof-read-then-write", newHeldConfirmStore, confirmProofCase,
		"more than one successful confirmation or device proof: 2 of 2 racers won"),
	{
		// A store written against mfa.EnrolmentStore alone has no device
		// proofs, so a Confirm with no proof condition conforms: the cases
		// that would seed a proof are logged as not run, not failed.
		name: "mfa-enrolment-only-store-with-no-proof-condition",
		run: func(t *testing.T) {
			storetest.RunEnrolmentStoreSuite(t, func(t *testing.T) mfa.EnrolmentStore {
				t.Helper()
				return enrolmentOnlyStore{newMFAStore(mfaConfirmIgnoresProof)}
			})
		},
	},
	mfaVariant(mfaPutPendingKeepsProof, newGenerationCase),
	mfaVariant(mfaVerifyChargeWithoutCap, "The window ends at its end instant"),
	mfaVariant(mfaVerifyWindowNeverEnds, "The window ends at its end instant"),
	mfaVariant(mfaVerifyWindowAnchoredOnOldEnd, "A charge after an idle gap opens a window from the charge"),
	mfaVariant(mfaVerifyRefundIgnoresWindow, "Give-back after the window was replaced"),
	mfaVariant(mfaVerifyChargesPending, "Pending enrolment is not charged"),
	mfaVariant(mfaVerifyRefundBelowZero, "Give-back at zero"),
	mfaVariant(mfaVerifyRefundZeroesCount, "Give-back in the window it was charged in"),
	mfaVariant(mfaVerifyWindowEndUntruncated, "The window end a charge returns is the one a give-back matches"),
	mfaVariant(mfaPutPendingKeepsGivenVerifyAttempts, "A new begin clears the count"),
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
	sessionVariant(sessionCreateDropsMarker, "marker round trip"),
	sessionVariant(sessionSaveSetsMarker, "a save does not set the marker"),
	sessionVariant(sessionSaveClearsMarker, "a save does not clear the marker"),
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

// confirmProofVariant races a confirmation against a device proof through
// storefix's race inputs on a store newStore makes, shared by both instances,
// with a pool only as wide as the race's default of 2 racers. An empty
// failsCase is a conforming run, which the race must pass.
func confirmProofVariant[S storetest.DeviceProofEnrolmentStore](
	name string, newStore func() S, failsCase, failsWith string,
) brokenVariant {
	return brokenVariant{
		name: name,
		run: func(t *testing.T) {
			h := sharedHarness(newStore)
			h.PoolSize = 2
			storetest.RunConfirmProofRace(t, h, storefix.ConfirmProofRace[S]())
		},
		failsCase: failsCase,
		failsWith: failsWith,
	}
}

// enrolmentOnlyStore is an enrolment store without the device-proof port.
type enrolmentOnlyStore struct{ mfa.EnrolmentStore }
