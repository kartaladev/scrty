package storetest_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// The recovery stores' suites and races are proven here against in-process
// fakes: a conforming form, which every suite must pass, and forms carrying
// one defect each, which the suite guarding that defect must fail. The
// conforming form passing shows the defective ones fail for their defect and
// not for something else about the fake.

// codeDefect names the one defect a codeFake carries.
type codeDefect string

const (
	codeConforming          codeDefect = "conforming"
	codeSpendReadThenWrite  codeDefect = "spend-read-then-write"
	codeReplaceMerges       codeDefect = "replace-merges"
	codeMatchSpends         codeDefect = "match-spends"
	codeSpendAcrossUsers    codeDefect = "spend-across-users"
	codeRemainingCountsAll  codeDefect = "remaining-counts-spent"
	codeDeleteCountsUnspent codeDefect = "delete-counts-unspent"
)

// codeTable is the state the instances of one fake code store share, as
// replicas share a database.
type codeTable struct {
	mu   sync.Mutex
	sets map[identity.UserID]map[string]time.Time // hash -> spent at, zero while unspent
}

// codeFake is one instance of an in-process CodeStore over a shared table.
type codeFake struct {
	defect codeDefect
	table  *codeTable
}

func newCodeFake(d codeDefect) *codeFake {
	return &codeFake{defect: d, table: &codeTable{sets: map[identity.UserID]map[string]time.Time{}}}
}

func (s *codeFake) ReplaceSet(_ context.Context, user identity.UserID, hashes [][]byte, _ time.Time) error {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	set := s.table.sets[user]
	if s.defect != codeReplaceMerges || set == nil {
		set = map[string]time.Time{}
	}
	for _, h := range hashes {
		set[string(h)] = time.Time{}
	}
	s.table.sets[user] = set

	return nil
}

func (s *codeFake) Match(_ context.Context, user identity.UserID, hash []byte) (bool, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	spent, ok := s.table.sets[user][string(hash)]
	if ok && spent.IsZero() && s.defect == codeMatchSpends {
		s.table.sets[user][string(hash)] = time.Now()
	}

	return ok && spent.IsZero(), nil
}

func (s *codeFake) Spend(ctx context.Context, user identity.UserID, hash []byte, at time.Time) (bool, error) {
	switch s.defect {
	case codeSpendReadThenWrite:
		// A read, the window a real store's round trips open, then an
		// unconditional write, as a SELECT followed by an UPDATE with no
		// "not yet spent" guard.
		ok, err := s.Match(ctx, user, hash)
		if err != nil || !ok {
			return false, err
		}
		time.Sleep(time.Millisecond)
		s.table.mu.Lock()
		s.table.sets[user][string(hash)] = at
		s.table.mu.Unlock()

		return true, nil
	case codeSpendAcrossUsers:
		s.table.mu.Lock()
		defer s.table.mu.Unlock()
		for _, set := range s.table.sets {
			if spent, ok := set[string(hash)]; ok && spent.IsZero() {
				set[string(hash)] = at
				return true, nil
			}
		}

		return false, nil
	default:
		s.table.mu.Lock()
		defer s.table.mu.Unlock()
		spent, ok := s.table.sets[user][string(hash)]
		if !ok || !spent.IsZero() {
			return false, nil
		}
		s.table.sets[user][string(hash)] = at

		return true, nil
	}
}

func (s *codeFake) Remaining(_ context.Context, user identity.UserID) (int, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	n := 0
	for _, spent := range s.table.sets[user] {
		if spent.IsZero() || s.defect == codeRemainingCountsAll {
			n++
		}
	}

	return n, nil
}

func (s *codeFake) DeleteUser(_ context.Context, user identity.UserID) (int, error) {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()

	n := 0
	for _, spent := range s.table.sets[user] {
		if spent.IsZero() || s.defect != codeDeleteCountsUnspent {
			n++
		}
	}
	delete(s.table.sets, user)

	return n, nil
}

// recordDefect names the one defect a recordFake carries.
type recordDefect string

const (
	recordConforming               recordDefect = "conforming"
	recordCompleteReadThenWrite    recordDefect = "complete-read-then-write"
	recordCompleteIgnoresNotBefore recordDefect = "complete-ignores-not-before"
	recordCompleteAfterCancel      recordDefect = "complete-after-cancel"
	recordLatestIsEarliest         recordDefect = "latest-is-earliest"
	recordCancelPendingAllUsers    recordDefect = "cancel-pending-all-users"
	recordFindSharesRefs           recordDefect = "find-shares-refs"
	recordInsertReplaces           recordDefect = "insert-replaces"
)

// errRecordTaken refuses an insert under an identifier already held.
var errRecordTaken = errors.New("fake: the record identifier is taken")

// recordFake is an in-process RecordStore carrying one defect.
type recordFake struct {
	defect recordDefect

	mu      sync.Mutex
	records map[id.ID]*recovery.Record
}

func newRecordFake(d recordDefect) *recordFake {
	return &recordFake{defect: d, records: map[id.ID]*recovery.Record{}}
}

func copyRec(r *recovery.Record) *recovery.Record {
	c := *r
	c.Proven = slices.Clone(r.Proven)
	c.Reported = slices.Clone(r.Reported)

	return &c
}

func pendingRec(r *recovery.Record) bool { return r.CompletedAt.IsZero() && r.CancelledAt.IsZero() }

func (s *recordFake) Insert(_ context.Context, r recovery.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.records[r.ID]; ok && s.defect != recordInsertReplaces {
		return errRecordTaken
	}
	s.records[r.ID] = copyRec(&r)

	return nil
}

func (s *recordFake) Find(_ context.Context, rid id.ID) (*recovery.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.records[rid]
	if !ok {
		return nil, recovery.ErrRecordNotFound
	}
	if s.defect == recordFindSharesRefs {
		c := *r
		return &c, nil
	}

	return copyRec(r), nil
}

func (s *recordFake) Complete(_ context.Context, rid id.ID, at time.Time) (bool, error) {
	if s.defect == recordCompleteReadThenWrite {
		// A read, the window, then an unconditional write.
		s.mu.Lock()
		r, ok := s.records[rid]
		completable := ok && pendingRec(r) && !at.Before(r.NotBefore)
		s.mu.Unlock()
		if !completable {
			return false, nil
		}
		time.Sleep(time.Millisecond)
		s.mu.Lock()
		r.CompletedAt = at
		s.mu.Unlock()

		return true, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.records[rid]
	if !ok {
		return false, nil
	}
	switch {
	case s.defect == recordCompleteAfterCancel && !r.CompletedAt.IsZero():
		return false, nil
	case s.defect != recordCompleteAfterCancel && !pendingRec(r):
		return false, nil
	case s.defect != recordCompleteIgnoresNotBefore && at.Before(r.NotBefore):
		return false, nil
	}
	r.CompletedAt = at

	return true, nil
}

func (s *recordFake) Cancel(_ context.Context, rid id.ID, at time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.records[rid]
	if !ok || !pendingRec(r) {
		return 0, nil
	}
	r.CancelledAt = at

	return 1, nil
}

func (s *recordFake) CancelPending(_ context.Context, user identity.UserID, at time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for _, r := range s.records {
		if (r.User == user || s.defect == recordCancelPendingAllUsers) && pendingRec(r) {
			r.CancelledAt = at
			n++
		}
	}

	return n, nil
}

func (s *recordFake) LatestCompletion(_ context.Context, user identity.UserID) (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var pick time.Time
	for _, r := range s.records {
		if r.User != user || r.CompletedAt.IsZero() {
			continue
		}
		later := r.CompletedAt.After(pick)
		if s.defect == recordLatestIsEarliest {
			later = pick.IsZero() || r.CompletedAt.Before(pick)
		}
		if later {
			pick = r.CompletedAt
		}
	}

	return pick, !pick.IsZero(), nil
}

var (
	_ recovery.CodeStore   = (*codeFake)(nil)
	_ recovery.RecordStore = (*recordFake)(nil)
)

// recoveryBackend is the subtest every recovery variant runs its suite under,
// so the guard finds the failed case beneath it.
const recoveryBackend = "fake"

// codeSuiteVariant runs the saved-code suite against a fresh fake carrying d
// per case.
func codeSuiteVariant(d codeDefect, failsCase string) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name: "recovery-code-" + string(d),
		Run: func(t *testing.T) {
			t.Run(recoveryBackend, func(t *testing.T) {
				storetest.RunRecoveryCodeStoreSuite(t, func(*testing.T, clock.Clock) recovery.CodeStore {
					return newCodeFake(d)
				})
			})
		},
		FailsCase: failsCase,
	}
}

// recordSuiteVariant runs the record suite against a fresh fake carrying d
// per case.
func recordSuiteVariant(d recordDefect, failsCase string) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name: "recovery-record-" + string(d),
		Run: func(t *testing.T) {
			t.Run(recoveryBackend, func(t *testing.T) {
				storetest.RunRecoveryRecordStoreSuite(t, func(*testing.T, clock.Clock) recovery.RecordStore {
					return newRecordFake(d)
				})
			})
		},
		FailsCase: failsCase,
	}
}

// spendRace races spends of one code per user through storefix's race, over
// two instances of a fake sharing one table.
func spendRace(t *testing.T, d codeDefect) {
	table := newCodeFake(d).table
	h := fakeHarness(func(*testing.T) *codeFake { return &codeFake{defect: d, table: table} })
	storetest.RunConsumeRace(t, h, storefix.RecoverySpendRace[*codeFake]())
}

// recordRace races completions against cancellations of one record each,
// through storefix's race, over one fake both instances share.
func recordRace(t *testing.T, d recordDefect) {
	storetest.RunConsumeRace(t, sharedHarness(func() *recordFake { return newRecordFake(d) }),
		storefix.RecoveryRecordRace[*recordFake]())
}

// raceWinsCase is the case of the single-winner race the recovery races run
// through.
const raceWinsCase = "exactly one consumption wins per record"

// recoveryVariants are the recovery variants the guard must see fail.
var recoveryVariants = []storefix.BrokenVariant{
	codeSuiteVariant(codeReplaceMerges, "replacement is whole: no old code, spent or not, survives"),
	codeSuiteVariant(codeMatchSpends, "match writes nothing: three matches, then the code is still spendable"),
	codeSuiteVariant(codeSpendAcrossUsers, "another user's hash is refused and the owner's code stays unspent"),
	codeSuiteVariant(codeRemainingCountsAll, "a spent code neither matches nor spends again"),
	codeSuiteVariant(codeDeleteCountsUnspent,
		"delete user removes every code, spent or not, and reports how many"),
	codeSuiteVariant(codeSpendReadThenWrite,
		"concurrent spends: exactly one of 8 succeeds, the rest look like an unknown code"),
	recordSuiteVariant(recordCompleteIgnoresNotBefore,
		"completing before the completable instant is refused and the record stays pending"),
	recordSuiteVariant(recordCompleteAfterCancel, "cancel then complete: the completion is refused"),
	recordSuiteVariant(recordLatestIsEarliest, "the latest completion is the latest among the user's records"),
	recordSuiteVariant(recordCancelPendingAllUsers,
		"CancelPending cancels only the user's pending records and counts them"),
	recordSuiteVariant(recordFindSharesRefs, "a found record is the caller's own copy"),
	recordSuiteVariant(recordInsertReplaces, "inserting an existing identifier is an error"),
	// A read-then-write completion is not a suite variant: in the suite's
	// single-record race a cancellation often takes the record before any
	// completion reads it, so the defect shows only some runs. The record race
	// below, over 50 records at once, catches it every run.
	{
		Name: "recovery-spend-race-" + string(codeSpendReadThenWrite),
		Run: func(t *testing.T) {
			t.Run(recoveryBackend, func(t *testing.T) { spendRace(t, codeSpendReadThenWrite) })
		},
		FailsCase: raceWinsCase,
		FailsWith: "more than one successful consumption",
	},
	{
		Name: "recovery-record-race-" + string(recordCompleteReadThenWrite),
		Run: func(t *testing.T) {
			t.Run(recoveryBackend, func(t *testing.T) { recordRace(t, recordCompleteReadThenWrite) })
		},
		FailsCase: raceWinsCase,
		FailsWith: "more than one successful consumption",
	},
}

// recoveryBrokenVar names the variant TestBrokenRecoveryConformance runs.
const recoveryBrokenVar = "STORETEST_BROKEN_RECOVERY"

// TestBrokenRecoveryConformance is the child half of
// TestRecoverySuitesCatchBrokenStores.
func TestBrokenRecoveryConformance(t *testing.T) {
	storefix.RunBrokenChild(t, recoveryBrokenVar, "TestRecoverySuitesCatchBrokenStores", recoveryVariants)
}

// TestRecoverySuitesCatchBrokenStores checks that each recovery suite and race
// fails against every fake carrying the defect it guards, at the case
// guarding it.
func TestRecoverySuitesCatchBrokenStores(t *testing.T) {
	t.Parallel()

	storefix.CatchBrokenVariants(t, recoveryBrokenVar, "TestBrokenRecoveryConformance", recoveryBackend,
		recoveryVariants)
}

// TestRecoveryFakesConform runs every recovery suite and race against the
// conforming fakes, which must pass: the defective forms differ from them by
// their defect alone.
func TestRecoveryFakesConform(t *testing.T) {
	t.Parallel()

	t.Run("code suite", func(t *testing.T) {
		storetest.RunRecoveryCodeStoreSuite(t, func(*testing.T, clock.Clock) recovery.CodeStore {
			return newCodeFake(codeConforming)
		})
	})
	t.Run("record suite", func(t *testing.T) {
		storetest.RunRecoveryRecordStoreSuite(t, func(*testing.T, clock.Clock) recovery.RecordStore {
			return newRecordFake(recordConforming)
		})
	})
	t.Run("spend race", func(t *testing.T) { spendRace(t, codeConforming) })
	t.Run("record race", func(t *testing.T) { recordRace(t, recordConforming) })
	t.Run("memory spend race", func(t *testing.T) {
		storetest.RunConsumeRace(t, sharedHarness(recovery.NewMemoryCodeStore),
			storefix.RecoverySpendRace[*recovery.MemoryCodeStore]())
	})
	t.Run("memory record race", func(t *testing.T) {
		storetest.RunConsumeRace(t, sharedHarness(recovery.NewMemoryRecordStore),
			storefix.RecoveryRecordRace[*recovery.MemoryRecordStore]())
	})
}
