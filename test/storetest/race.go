package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// The race suites' defaults. Many records, not one: a single contended row
// serialises on the database's row lock, which hides a read-then-write
// implementation almost every run, while fifty independent rows raced at once
// expose it.
const (
	defaultRaceRecords = 50
	defaultRaceRacers  = 8

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
	// (DurableHarness.PoolSize). Zero means the default of 8; one is refused,
	// as a single caller races nobody.
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

	runRace(t, h, r, "exactly one consumption wins per record", "consumption")
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

	runRace(t, h, r, "exactly one insert wins per record", "insert")
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

	runRace(t, h, r, "exactly one acceptance of a step wins per record", "acceptance of a step")
}

// raceParams are a race's record and racer counts and its timeout, with the
// defaults applied.
type raceParams struct {
	records, racers int
	timeout         time.Duration
}

// requireRace fails t at once when h or r is missing an input or the pool is
// too narrow for the racers, and returns the race's parameters with the
// defaults applied.
func requireRace[S any](t testing.TB, h DurableHarness[S], r Race[S]) raceParams {
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
		p.racers = defaultRaceRacers
	case p.racers < 2:
		t.Fatalf("storetest: Race.Racers must be at least 2, or zero for the default of %d", defaultRaceRacers)
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
// not return in time, and for each record without exactly one winner,
// calling the operation noun.
func runRace[S any](t *testing.T, h DurableHarness[S], r Race[S], name, noun string) {
	t.Helper()

	p := requireRace(t, h, r)

	t.Run(name, func(t *testing.T) {
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
		select {
		case <-finished:
		case <-abandon.C:
		}

		mu.Lock()
		defer mu.Unlock()
		for i, record := range outcomes {
			for racer, o := range record {
				if !o.returned {
					record[racer].err = fmt.Errorf(
						"the attempt had not returned by twice the race timeout of %s and was abandoned", p.timeout)
				}
			}
			reportRecord(t, i, keys[i], noun, record)
		}
	})
}

// reportRecord fails t for one record's outcomes: for any racer error, and
// unless exactly one racer won.
func reportRecord(t *testing.T, i int, key, noun string, record []raceOutcome) {
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
	case wins > 1:
		t.Errorf("record %d (key %q): more than one successful %s: %d of %d racers won",
			i, key, noun, wins, len(record))
	case wins == 0:
		t.Errorf("record %d (key %q): no successful %s: none of %d racers won", i, key, noun, len(record))
	}
}
