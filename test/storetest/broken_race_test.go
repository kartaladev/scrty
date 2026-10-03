package storetest_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// raceTable is the state the instances of one in-process single-use store
// share, as replicas share a database.
type raceTable struct {
	used sync.Map // key -> struct{}

	// mu guards the read and the write of the defective forms, which touch
	// used separately, so the race detector sees no data race: their defect
	// is in the logic.
	mu sync.Mutex
}

// raceStore is one instance of an in-process single-use store over a shared
// table. Its conforming form decides a use with one atomic compare-and-swap on
// the table, so it holds across instances. Its read-then-write form reads,
// yields, then writes, as a durable store would with a SELECT followed by an
// unconditional UPDATE. Its instance-mutex form does the same under a lock of
// its own instance, which serialises the callers of one instance and no
// others, as a process-wide mutex serialises one replica.
type raceStore struct {
	defect raceDefect
	table  *raceTable

	instance sync.Mutex
}

type raceDefect string

const (
	raceConforming    raceDefect = "conforming"
	raceReadThenWrite raceDefect = "read-then-write"
	raceInstanceMutex raceDefect = "instance-mutex"
	raceBlocks        raceDefect = "blocks"
	raceIgnoresCtx    raceDefect = "ignores-context"
	raceRefusesAll    raceDefect = "refuses-all"
	raceFails         raceDefect = "fails"
)

func (s *raceStore) use(ctx context.Context, key string) (bool, error) {
	switch s.defect {
	case raceRefusesAll:
		return false, nil
	case raceFails:
		return false, errors.New("connection reset")
	case raceBlocks:
		// A call waiting on a lock it never gets, until the caller gives up.
		<-ctx.Done()
		return false, ctx.Err()
	case raceIgnoresCtx:
		// A call that never returns, whatever its context says.
		select {}
	case raceReadThenWrite:
		return s.readThenWrite(key), nil
	case raceInstanceMutex:
		s.instance.Lock()
		defer s.instance.Unlock()
		return s.readThenWrite(key), nil
	default:
		_, used := s.table.used.LoadOrStore(key, struct{}{})
		return !used, nil
	}
}

// readThenWrite reads whether key is used, yields, and marks it used.
func (s *raceStore) readThenWrite(key string) bool {
	s.table.mu.Lock()
	_, used := s.table.used.Load(key)
	s.table.mu.Unlock()
	if used {
		return false
	}
	// The window between the read and the write that a real store's round
	// trips open.
	time.Sleep(time.Millisecond)
	s.table.mu.Lock()
	s.table.used.Store(key, struct{}{})
	s.table.mu.Unlock()
	return true
}

// raceHarness is a fake harness whose New and NewReplica return instances of
// d over one shared table.
func raceHarness(d raceDefect) storetest.DurableHarness[*raceStore] {
	table := &raceTable{}
	return fakeHarness(func(*testing.T) *raceStore { return &raceStore{defect: d, table: table} })
}

func raceOver() storetest.Race[*raceStore] {
	return storetest.Race[*raceStore]{
		Seed: func(_ context.Context, _ *testing.T, _ *raceStore, i int) string {
			return "record-" + strconv.Itoa(i)
		},
		Attempt: func(ctx context.Context, s *raceStore, key string, _ int) (bool, error) {
			return s.use(ctx, key)
		},
	}
}

type raceSuite func(t *testing.T, h storetest.DurableHarness[*raceStore], r storetest.Race[*raceStore])

func raceVariant(name string, suite raceSuite, d raceDefect, failsCase, failsWith string) brokenVariant {
	return brokenVariant{
		name: "race-" + name + "-" + string(d),
		run: func(t *testing.T) {
			suite(t, raceHarness(d), raceOver())
		},
		failsCase: failsCase,
		failsWith: failsWith,
	}
}

// blockedVariant is a consume race whose attempts never return by
// themselves, raced with a short timeout so the guard sees the suite fail
// rather than wait out its default.
func blockedVariant(d raceDefect) brokenVariant {
	return brokenVariant{
		name: "race-consume-" + string(d),
		run: func(t *testing.T) {
			r := raceOver()
			r.Records, r.Timeout = 2, 50*time.Millisecond
			storetest.RunConsumeRace(t, raceHarness(d), r)
		},
		failsCase: consumeCase,
		failsWith: "the race timeout of 50ms",
	}
}

const (
	consumeCase  = "exactly one consumption wins per record"
	insertCase   = "exactly one insert wins per record"
	stepCase     = "exactly one acceptance of a step wins per record"
	completeCase = "exactly one completion wins per record"
	chargeCase   = "exactly the allowed number of charges win per code"

	verifyChargeCase = "exactly the limit of verification charges win per enrolment"
)

// sharedHarness is a fake harness whose New and NewReplica both return one
// store, made once per run, as two instances on one database share its
// state. It is as wide as the charge race's default of 20 racers.
func sharedHarness[S any](newStore func() S) storetest.DurableHarness[S] {
	var (
		once   sync.Once
		shared S
	)
	h := fakeHarness(func(*testing.T) S {
		once.Do(func() { shared = newStore() })
		return shared
	})
	h.PoolSize = 20
	return h
}

// enrolmentRace names which of the enrolment path's writes a variant races.
type enrolmentRace int

const (
	completeRace enrolmentRace = iota
	chargeRace
)

// enrolmentRaceVariant races completions or charges through storefix's race
// inputs against a store newStore makes, shared by both instances. An empty
// failsCase is a conforming run, which the race must pass.
func enrolmentRaceVariant[S storetest.DeviceProofEnrolmentStore](
	name string, race enrolmentRace, newStore func() S, failsCase, failsWith string,
) brokenVariant {
	return brokenVariant{
		name: name,
		run: func(t *testing.T) {
			if race == completeRace {
				storetest.RunCompleteRace(t, sharedHarness(newStore), storefix.CompleteRace[S]())
				return
			}
			storetest.RunChargeRace(t, sharedHarness(newStore), storefix.ChargeRace[S]())
		},
		failsCase: failsCase,
		failsWith: failsWith,
	}
}

// mfaRaceStore returns a maker of an mfaStore carrying d.
func mfaRaceStore(d mfaDefect) func() *mfaStore {
	return func() *mfaStore { return newMFAStore(d) }
}

// enrolmentRaceVariants race the enrolment path's writes: the shipped memory
// store and the conforming fake must pass, and the fakes deciding by a read,
// or leaving the wrong state behind, must fail.
var enrolmentRaceVariants = []brokenVariant{
	enrolmentRaceVariant("race-complete-memory", completeRace, mfa.NewMemoryEnrolmentStore, "", ""),
	enrolmentRaceVariant("race-complete-conforming", completeRace, mfaRaceStore(mfaConforming), "", ""),
	enrolmentRaceVariant("race-complete-read-then-write", completeRace, mfaRaceStore(mfaCompleteReadThenWrite),
		completeCase, "more than one successful completion"),
	enrolmentRaceVariant("race-charge-memory", chargeRace, mfa.NewMemoryEnrolmentStore, "", ""),
	enrolmentRaceVariant("race-charge-conforming", chargeRace, mfaRaceStore(mfaConforming), "", ""),
	enrolmentRaceVariant("race-charge-read-then-write", chargeRace, mfaRaceStore(mfaChargeReadThenWrite),
		chargeCase, "more than 5 successful charge"),
	// Exactly the allowed charges win, so only the check of each record
	// after the race finds the code gone.
	enrolmentRaceVariant("race-charge-clears-code-at-cap", chargeRace, mfaRaceStore(mfaChargeClearsCodeAtCap),
		chargeCase, "EmailCode must still be stored after the race"),
	{
		name: "race-verify-charge-memory",
		run: func(t *testing.T) {
			storetest.RunVerifyChargeRace(t, sharedHarness(mfa.NewMemoryEnrolmentStore),
				storefix.VerifyChargeRace[*mfa.MemoryEnrolmentStore]())
		},
	},
	{
		name: "race-verify-charge-conforming",
		run: func(t *testing.T) {
			storetest.RunVerifyChargeRace(t, sharedHarness(mfaRaceStore(mfaConforming)),
				storefix.VerifyChargeRace[*mfaStore]())
		},
	},
	{
		name: "race-verify-charge-read-then-write",
		run: func(t *testing.T) {
			storetest.RunVerifyChargeRace(t, sharedHarness(mfaRaceStore(mfaVerifyChargeReadThenWrite)),
				storefix.VerifyChargeRace[*mfaStore]())
		},
		failsCase: verifyChargeCase,
		failsWith: "more than 5 successful verification charge",
	},
	{
		// A single-use store lets one charge through where five are
		// allowed: the race counts wins both ways.
		name: "race-charge-single-winner",
		run: func(t *testing.T) {
			h := raceHarness(raceConforming)
			h.PoolSize = 20
			storetest.RunChargeRace(t, h, raceOver())
		},
		failsCase: chargeCase,
		failsWith: "fewer than 5 successful charge: 1 of 20 racers won",
	},
}

// raceVariants are the race suites' variants: the single-use races' below,
// then the enrolment path's.
var raceVariants = append([]brokenVariant{
	raceVariant("consume", storetest.RunConsumeRace[*raceStore], raceConforming, "", ""),
	raceVariant("consume", storetest.RunConsumeRace[*raceStore], raceReadThenWrite,
		consumeCase, "more than one successful consumption"),
	raceVariant("consume", storetest.RunConsumeRace[*raceStore], raceInstanceMutex,
		consumeCase, "more than one successful consumption"),
	raceVariant("consume", storetest.RunConsumeRace[*raceStore], raceRefusesAll,
		consumeCase, "no successful consumption"),
	raceVariant("consume", storetest.RunConsumeRace[*raceStore], raceFails,
		consumeCase, "failed with an unexpected error"),
	raceVariant("insert", storetest.RunLinkInsertRace[*raceStore], raceConforming, "", ""),
	raceVariant("insert", storetest.RunLinkInsertRace[*raceStore], raceReadThenWrite,
		insertCase, "more than one successful insert"),
	raceVariant("step", storetest.RunStepAcceptRace[*raceStore], raceConforming, "", ""),
	raceVariant("step", storetest.RunStepAcceptRace[*raceStore], raceReadThenWrite,
		stepCase, "more than one successful acceptance of a step"),
	raceVariant("step", storetest.RunStepAcceptRace[*raceStore], raceInstanceMutex,
		stepCase, "more than one successful acceptance of a step"),
	blockedVariant(raceBlocks),
	blockedVariant(raceIgnoresCtx),
	{
		// The input check runs before any case, so the run is wrapped in a
		// subtest for the guard to find the failure by name.
		name: "race-consume-narrow-pool",
		run: func(t *testing.T) {
			t.Run("narrow pool", func(t *testing.T) {
				h := raceHarness(raceConforming)
				h.PoolSize = 2
				storetest.RunConsumeRace(t, h, raceOver())
			})
		},
		failsCase: "narrow pool",
		failsWith: "storetest: a pool of 2 connections cannot exercise a race of 8 racers",
	},
}, enrolmentRaceVariants...)
