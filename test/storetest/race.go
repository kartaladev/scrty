package storetest

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/kartaladev/scrty/mfa"
)

// The race suites' defaults. Many records, not one: a single contended row
// serialises on the database's row lock, which hides a read-then-write
// implementation almost every run, while fifty independent rows raced at once
// expose it.
const (
	defaultRaceRecords = 50
	defaultRaceRacers  = 8

	// defaultChargeRacers is the default racer count of RunChargeRace and
	// RunVerifyChargeRace: enough more than the cap they allow
	// (mfa.MaxEmailCodeFailures, mfa.DefaultVerifyAttemptLimit) that a store
	// charging past it under contention wins visibly more often than it may.
	defaultChargeRacers = 20

	// defaultRaceTimeout bounds a race whose Race.Timeout is zero. A healthy
	// race of the default size ends in well under a second; the bound is
	// there so a blocked call fails its record instead of hanging the test
	// binary until go test's -timeout.
	defaultRaceTimeout = 30 * time.Second
)

// Race describes the contended operation a race suite runs: how to create a
// record, and one racing call against it. Seed and Attempt are required, and
// a race missing either fails at once, naming it.
type Race[S any] struct {
	// Records is how many independent records are raced for. Zero means the
	// default of 50.
	Records int

	// Racers is how many callers race for each record, and so how many
	// connections the pool must be able to open at once
	// (DurableHarness.PoolSize). Zero means the race's default: 8, or 20 for
	// RunChargeRace and RunVerifyChargeRace. Fewer racers than one more than
	// the wins the race allows per record are refused, naming that minimum,
	// as they could never show a store letting too many win: two for the
	// single-winner races, mfa.MaxEmailCodeFailures+1 for RunChargeRace, and
	// mfa.DefaultVerifyAttemptLimit+1 for RunVerifyChargeRace.
	Racers int

	// Timeout bounds the racing. Every racer's context carries a deadline
	// this far from the start of the race, and a racer that returns after it
	// fails its record, whatever it returned. A racer that has not returned
	// by twice the timeout, because its call ignores the context, is
	// abandoned and fails its record too, so the suite reports rather than
	// hangs. The abandoned call still holds its store instance: a harness
	// whose cleanup waits for every connection to return (pgxpool.Pool.Close
	// does) must bound that wait, or the test hangs in cleanup instead.
	// Zero means the default of 30 seconds; a negative timeout is refused.
	Timeout time.Duration

	// Seed creates record i, 0 <= i < Records, and returns the key the racers
	// contend on. It runs before any racer starts, one record after another,
	// and may fail t.
	Seed func(ctx context.Context, t *testing.T, s S, i int) string

	// Attempt makes one racing call for key as racer number racer,
	// 0 <= racer < Racers; a link insert, for example, inserts for a user of
	// its own per racer. It reports won when the call succeeded, and
	// (false, nil) when the store refused it as already used, already
	// existing or already accepted. Any error is unexpected and fails the
	// suite. It runs on its own goroutine, so it must not call t.
	Attempt func(ctx context.Context, s S, key string, racer int) (won bool, err error)

	// Check, when set, asserts what record key holds once its race is over:
	// the end state a race whose winners were counted right may still get
	// wrong, such as a count that took the right wins but stored another
	// number. It runs after every racer of every record has returned, one
	// record after another, on the store Seed wrote through, and may fail t.
	// It does not run when a racer was abandoned at the timeout, as that
	// racer may still be writing. Nil means only the winners are checked.
	Check func(ctx context.Context, t *testing.T, s S, key string)
}

// RunConsumeRace holds a single-use store, such as one-time tokens or
// handoffs, to atomic consumption: Racers callers consume each of Records
// independent records at once, released together off one barrier, and every
// record must be consumed exactly once. Attempt consumes key and maps the
// store's "not found" refusal to (false, nil).
//
// Racers alternate between the store h.New returns and the one
// h.NewReplica returns, two instances on one database with their own
// connection pools, so a store that serialises under a lock of one instance
// fails. Both instances live in the test's process, so a lock shared by the
// whole process (a package-level mutex) is not caught; real replicas are
// separate processes, where such a lock guards only one of them. Records are
// seeded through h.New's store.
//
// It fails at once, naming the input, when h or r is missing one, and when
// h.PoolSize is narrower than r.Racers, since racers queueing for a
// connection reach the database one after another and prove nothing.
func RunConsumeRace[S any](t *testing.T, h DurableHarness[S], r Race[S]) {
	t.Helper()

	runRace(t, h, r, consumeRule)
}

// RunLinkInsertRace holds a store with unique inserts, such as external
// identity links, to deciding uniqueness by the write: Racers callers insert
// the same record at once for each of Records independent records, and
// exactly one insert of each must succeed. Attempt inserts key, typically for
// a user of its own per racer, and maps the store's "already exists" refusal
// to (false, nil); an upsert that reports every insert as a success fails.
//
// Its inputs are checked as RunConsumeRace checks them.
func RunLinkInsertRace[S any](t *testing.T, h DurableHarness[S], r Race[S]) {
	t.Helper()

	runRace(t, h, r, insertRule)
}

// RunStepAcceptRace holds an MFA enrolment store to accepting each TOTP time
// step once: Racers callers record the same step at once for each of Records
// independent confirmed enrolments, and exactly one recording of each must
// succeed. Seed confirms an enrolment below the step Attempt records, and
// Attempt returns what AcceptStep reports.
//
// Its inputs are checked as RunConsumeRace checks them.
func RunStepAcceptRace[S any](t *testing.T, h DurableHarness[S], r Race[S]) {
	t.Helper()

	runRace(t, h, r, stepRule)
}

// RunCompleteRace holds an MFA enrolment store to completing each enrolment
// generation once: Racers callers complete the same proven generation at
// once for each of Records independent pending enrolments, and exactly one
// completion of each must succeed. Seed begins an enrolment on a generation
// of its own and proves its device, and returns a key Attempt can recover
// both the user and the generation from; Attempt returns what
// mfa.DeviceProofStore.Complete reports. storefix.CompleteRace is such a race.
//
// Its inputs are checked as RunConsumeRace checks them.
func RunCompleteRace[S any](t *testing.T, h DurableHarness[S], r Race[S]) {
	t.Helper()

	runRace(t, h, r, completeRule)
}

// RunChargeRace holds an MFA enrolment store to capping the attempts charged
// against one emailed code: Racers callers charge the same outstanding code
// at once for each of Records independent proven enrolments, and exactly
// mfa.MaxEmailCodeFailures charges of each must succeed, however many race.
// Seed begins an enrolment, proves its device with an emailed code that is
// still outstanding when Attempt charges it, and returns a key Attempt can
// recover the user and the generation from; Attempt reports the bool
// mfa.DeviceProofStore.ChargeEmailCode returns. storefix.ChargeRace is such
// a race.
//
// Racers defaults to 20 here, so a zero Racers needs a pool of 20
// connections, and must otherwise be at least mfa.MaxEmailCodeFailures+1, so
// a store with no cap can win more charges than allowed. Its inputs are
// otherwise checked as RunConsumeRace checks them.
func RunChargeRace[S any](t *testing.T, h DurableHarness[S], r Race[S]) {
	t.Helper()

	runRace(t, h, r, chargeRule)
}

// RunVerifyChargeRace holds an MFA enrolment store to capping the TOTP
// verification attempts charged in one window: Racers callers charge the same
// confirmed enrolment at once for each of Records independent enrolments, and
// exactly mfa.DefaultVerifyAttemptLimit charges of each must succeed, however
// many race. Seed stores and confirms an enrolment and returns its user
// reference; Attempt reports the bool mfa.EnrolmentStore.ChargeVerifyAttempt
// returns with that limit. storefix.VerifyChargeRace is such a race.
//
// Racers defaults to 20 here, so a zero Racers needs a pool of 20
// connections, and must otherwise be at least
// mfa.DefaultVerifyAttemptLimit+1, so a store with no cap can win more
// charges than allowed. Its inputs are otherwise checked as RunConsumeRace
// checks them.
func RunVerifyChargeRace[S any](t *testing.T, h DurableHarness[S], r Race[S]) {
	t.Helper()

	runRace(t, h, r, verifyChargeRule)
}

// raceRule is what one race suite requires of each record: the subtest name
// it reports under, the noun its failures call the operation, how many
// racers of a record must win (zero means one), and the racer count a zero
// Race.Racers means (zero means defaultRaceRacers).
type raceRule struct {
	name, noun string
	wins       int
	racers     int
}

// The rules of the race suites.
var (
	consumeRule  = raceRule{name: "exactly one consumption wins per record", noun: "consumption"}
	insertRule   = raceRule{name: "exactly one insert wins per record", noun: "insert"}
	stepRule     = raceRule{name: "exactly one acceptance of a step wins per record", noun: "acceptance of a step"}
	completeRule = raceRule{name: "exactly one completion wins per record", noun: "completion"}
	chargeRule   = raceRule{
		name:   "exactly the allowed number of charges win per code",
		noun:   "charge",
		wins:   mfa.MaxEmailCodeFailures,
		racers: defaultChargeRacers,
	}
	verifyChargeRule = raceRule{
		name:   "exactly the limit of verification charges win per enrolment",
		noun:   "verification charge",
		wins:   mfa.DefaultVerifyAttemptLimit,
		racers: defaultChargeRacers,
	}
)

// minRacers is the fewest racers that can show rule broken: one more than
// the wins it allows, so a store letting every racer win wins too many.
func (rule raceRule) minRacers() int {
	return rule.wins + 1
}

// withDefaults returns rule with its zero wins and racers made explicit.
func (rule raceRule) withDefaults() raceRule {
	if rule.wins == 0 {
		rule.wins = 1
	}
	if rule.racers == 0 {
		rule.racers = defaultRaceRacers
	}
	return rule
}

// raceParams are a race's record and racer counts and its timeout, with the
// defaults applied.
type raceParams struct {
	records, racers int
	timeout         time.Duration
}

// requireRace fails t at once when h or r is missing an input or the pool is
// too narrow for the racers, or when r.Racers is below rule's minimum, and
// returns the race's parameters with the defaults applied, a zero r.Racers
// taking rule.racers. rule must have its defaults applied.
func requireRace[S any](t testing.TB, h DurableHarness[S], r Race[S], rule raceRule) raceParams {
	t.Helper()

	h.requireWith(t,
		input{"Race.Seed", r.Seed != nil},
		input{"Race.Attempt", r.Attempt != nil},
	)

	p := raceParams{records: r.Records, racers: r.Racers, timeout: r.Timeout}
	switch {
	case p.records == 0:
		p.records = defaultRaceRecords
	case p.records < 0:
		t.Fatalf("storetest: Race.Records must be positive, or zero for the default of %d", defaultRaceRecords)
	}
	switch {
	case p.racers == 0:
		p.racers = rule.racers
	case p.racers < rule.minRacers():
		t.Fatalf("storetest: Race.Racers must be at least %d, or zero for the default of %d",
			rule.minRacers(), rule.racers)
	}
	switch {
	case p.timeout == 0:
		p.timeout = defaultRaceTimeout
	case p.timeout < 0:
		t.Fatalf("storetest: Race.Timeout must be positive, or zero for the default of %s", defaultRaceTimeout)
	}

	requirePool(t, h.PoolSize, p.racers)

	return p
}

// raceOutcome is what one racer's attempt returned, once it has.
type raceOutcome struct {
	returned bool
	won      bool
	err      error
}

// runRace is the engine the race suites share. In a subtest named name, it
// seeds every record through h.New's store, starts every racer of every
// record, even racers on that store and odd ones on h.NewReplica's, waits
// until all of them are blocked on one barrier, and releases them together
// by closing it. Once every racer has returned, or twice the timeout has
// passed, it fails for each record with any racer error or racer that did
// not return in time, and for each record whose winners are not exactly
// rule.wins, calling the operation rule.noun. When every racer returned, it
// then runs r.Check, if set, on each record through h.New's store.
func runRace[S any](t *testing.T, h DurableHarness[S], r Race[S], rule raceRule) {
	t.Helper()

	rule = rule.withDefaults()
	p := requireRace(t, h, r, rule)

	t.Run(rule.name, func(t *testing.T) {
		// Racers alternate between two instances on one database, by racer
		// index, so single use must hold across replicas and not only
		// under a lock of one instance. Records are seeded through the
		// first.
		stores := [2]S{h.New(t), h.NewReplica(t)}

		keys := make([]string, p.records)
		for i := range keys {
			keys[i] = r.Seed(t.Context(), t, stores[0], i)
		}

		ctx, cancel := context.WithTimeout(t.Context(), p.timeout)
		defer cancel()

		// mu guards outcomes: a racer abandoned at the deadline may still
		// write its slot while the outcomes are read.
		var mu sync.Mutex
		outcomes := make([][]raceOutcome, p.records)
		start := make(chan struct{})
		var ready, done sync.WaitGroup
		for i := range outcomes {
			outcomes[i] = make([]raceOutcome, p.racers)
			for racer := range p.racers {
				ready.Add(1)
				done.Go(func() {
					ready.Done()
					<-start
					won, err := r.Attempt(ctx, stores[racer%2], keys[i], racer)
					if ctx.Err() != nil {
						late := fmt.Errorf("the attempt returned after the race timeout of %s (won=%t)", p.timeout, won)
						err = errors.Join(late, err)
					}
					mu.Lock()
					outcomes[i][racer] = raceOutcome{returned: true, won: won, err: err}
					mu.Unlock()
				})
			}
		}
		ready.Wait()
		close(start)

		finished := make(chan struct{})
		go func() {
			done.Wait()
			close(finished)
		}()
		abandon := time.NewTimer(2 * p.timeout)
		defer abandon.Stop()
		allReturned := false
		select {
		case <-finished:
			allReturned = true
		case <-abandon.C:
		}

		mu.Lock()
		for i, record := range outcomes {
			for racer, o := range record {
				if !o.returned {
					record[racer].err = fmt.Errorf(
						"the attempt had not returned by twice the race timeout of %s and was abandoned", p.timeout)
				}
			}
			reportRecord(t, i, keys[i], rule, record)
		}
		mu.Unlock()

		if r.Check == nil || !allReturned {
			return
		}
		for _, key := range keys {
			r.Check(t.Context(), t, stores[0], key)
		}
	})
}

// reportRecord fails t for one record's outcomes: for any racer error, and
// unless exactly rule.wins racers won.
func reportRecord(t *testing.T, i int, key string, rule raceRule, record []raceOutcome) {
	t.Helper()

	wins, failed := 0, 0
	var first error
	for _, o := range record {
		if o.won {
			wins++
		}
		if o.err != nil {
			if failed == 0 {
				first = o.err
			}
			failed++
		}
	}

	if failed > 0 {
		t.Errorf("record %d (key %q): %d of %d racers failed with an unexpected error, the first: %v",
			i, key, failed, len(record), first)
	}
	switch {
	case wins > rule.wins:
		t.Errorf("record %d (key %q): more than %s successful %s: %d of %d racers won",
			i, key, countWord(rule.wins), rule.noun, wins, len(record))
	case wins == 0:
		t.Errorf("record %d (key %q): no successful %s: none of %d racers won", i, key, rule.noun, len(record))
	case wins < rule.wins:
		t.Errorf("record %d (key %q): fewer than %s successful %s: %d of %d racers won",
			i, key, countWord(rule.wins), rule.noun, wins, len(record))
	}
}

// countWord spells one as a word, as the single-winner races always have,
// and any other count in digits.
func countWord(n int) string {
	if n == 1 {
		return "one"
	}
	return strconv.Itoa(n)
}
