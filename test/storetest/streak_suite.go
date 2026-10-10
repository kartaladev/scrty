package storetest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
)

// StreakStore is what the failure-streak suite drives: a login-attempt store
// that also keeps consecutive-failure streaks.
type StreakStore interface {
	policy.AttemptStore
	policy.FailureStreakStore
}

// The streak suite's fixed values.
const (
	// streakLimit is the cap the suite's cases add against.
	streakLimit = 5

	// streakRetention is how long a count below the cap lasts without a new
	// failure, which places the suite's cutoffs.
	streakRetention = 30 * 24 * time.Hour

	// The race's shape: raceStreakRacers adds at once on a streak of
	// raceStreakStart, under a cap of raceStreakLimit that they cross.
	raceStreakStart  = 90
	raceStreakLimit  = 100
	raceStreakRacers = 20

	// raceStreakRecords is how many identifiers are raced for at once. More
	// than one, so a read-then-write store is exposed even where a single
	// contended row would serialise on its lock.
	raceStreakRecords = 8

	// The reset storm's shape: per identifier (stormRecords of them),
	// stormResetters goroutines Reset in a loop while stormAdders goroutines
	// each add stormAddsEach failures.
	stormRecords   = 4
	stormResetters = 3
	stormAdders    = 6
	stormAddsEach  = 200

	// stormTimeout bounds a reset storm, whose value is its volume of
	// row-serialised calls. Healthy, a storm ends in about a second, but on a
	// CPU-starved CI runner its database can take tens of seconds, so its hang
	// guard is wider than defaultRaceTimeout. It still only exists so a blocked
	// call fails instead of hanging the binary.
	stormTimeout = 2 * time.Minute
)

var (
	// streakSince is the cutoff an add or a read at suiteStart is judged
	// against.
	streakSince = suiteStart.Add(-streakRetention)

	// streakOld is a failure that was recent when it was added, against the
	// cutoff of its own instant (streakOldSince), and is behind streakSince.
	streakOld      = streakSince.Add(-time.Hour)
	streakOldSince = streakOld.Add(-streakRetention)
)

// addStreak adds a failure for username at each instant, against since and
// limit, and returns the streak after the last.
func addStreak(
	ctx context.Context, t *testing.T, s policy.FailureStreakStore,
	username string, since time.Time, limit int, at ...time.Time,
) policy.FailureStreak {
	t.Helper()

	var got policy.FailureStreak
	for _, when := range at {
		var err error
		got, _, err = s.AddStreakFailure(ctx, username, when, since, limit)
		require.NoError(t, err, "add a streak failure for %q at %v", username, when)
	}

	return got
}

// repeat returns n copies of at.
func repeat(at time.Time, n int) []time.Time {
	out := make([]time.Time, n)
	for i := range out {
		out[i] = at
	}

	return out
}

// readStreak reads username's streak against since.
func readStreak(
	ctx context.Context, t *testing.T, s policy.FailureStreakStore, username string, since time.Time,
) policy.FailureStreak {
	t.Helper()

	got, err := s.FailureStreak(ctx, username, since)
	require.NoError(t, err, "read the streak of %q", username)

	return got
}

// assertStreak requires got to hold failures, newest and heldAt, comparing
// instants by Equal so a store returning another location still conforms. A
// zero heldAt requires the streak not to be held.
func assertStreak(t *testing.T, got policy.FailureStreak, failures int, newest, heldAt time.Time) {
	t.Helper()

	assert.Equal(t, failures, got.Failures, "failures")
	assertTimeEqual(t, newest, got.Newest, "Newest")
	if heldAt.IsZero() {
		assert.False(t, got.Held(), "the streak must not be held, HeldAt is %v", got.HeldAt)
		return
	}
	assertTimeEqual(t, heldAt, got.HeldAt, "HeldAt")
}

// assertStreakEmpty requires got to be the zero streak.
func assertStreakEmpty(t *testing.T, got policy.FailureStreak) {
	t.Helper()

	assert.Zero(t, got.Failures, "failures")
	assert.True(t, got.Newest.IsZero(), "Newest is %v, want zero", got.Newest)
	assert.False(t, got.Held(), "the streak must not be held, HeldAt is %v", got.HeldAt)
}

// RunFailureStreakSuite checks a store that is both a policy.AttemptStore and
// a policy.FailureStreakStore against the contract the lockout cap relies on:
//
//   - a streak counts from one and advances by one per add;
//   - one that is not held and whose newest failure is at or before the
//     cutoff restarts at one when added to, and reads as empty;
//   - the add that brings the count to the limit or above, on a streak not
//     yet held, sets the hold and is the only add to report it, including
//     when the limit is lowered below a count already reached; the hold is
//     never moved, and a held streak never restarts or reads as empty;
//   - the newest failure never moves backwards, and the restart is judged
//     against the stored newest failure, not a late add's instant;
//   - Reset clears the streak, the hold and the failure log together, is not
//     an error for an identifier with no streak, and the next add counts one;
//   - identifiers are matched byte for byte, never folded, and one holding a
//     NUL byte is either refused on add, with an error that does not echo it,
//     and then reads as no streak with a nil error, or kept as given, never
//     altered into another;
//   - the cutoff is inclusive on add: a newest failure exactly at it restarts
//     the streak;
//   - a purge refuses a zero cutoff and deletes nothing, and otherwise removes
//     exactly the streaks that are not held and whose newest failure is
//     strictly before its cutoff.
//
// newStore is called once per case and must return an empty store. The store
// takes every instant from its caller, so it needs no clock.
func RunFailureStreakSuite(t *testing.T, newStore func(t *testing.T) StreakStore) {
	t.Helper()

	cases := []suiteCase[StreakStore]{
		{
			name: "counts from one",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				got, setHold, err := s.AddStreakFailure(ctx, "ada", suiteStart, streakSince, streakLimit)
				require.NoError(t, err)
				assert.False(t, setHold, "one failure does not reach the limit")
				assertStreak(t, got, 1, suiteStart, time.Time{})
				assertStreak(t, readStreak(ctx, t, s, "ada", streakSince), 1, suiteStart, time.Time{})
			},
		},
		{
			name: "advances by one per add",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				last := suiteStart.Add(2 * time.Second)
				got := addStreak(ctx, t, s, "ada", streakSince, streakLimit,
					suiteStart, suiteStart.Add(time.Second), last)
				assertStreak(t, got, 3, last, time.Time{})
				assertStreak(t, readStreak(ctx, t, s, "ada", streakSince), 3, last, time.Time{})
			},
		},
		{
			name: "a streak inactive past the cutoff restarts at one",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				before := addStreak(ctx, t, s, "ada", streakOldSince, streakLimit, repeat(streakOld, 4)...)
				require.Equal(t, 4, before.Failures, "the old failures counted while they were recent")

				got, setHold, err := s.AddStreakFailure(ctx, "ada", suiteStart, streakSince, streakLimit)
				require.NoError(t, err)
				assert.False(t, setHold)
				assertStreak(t, got, 1, suiteStart, time.Time{})
			},
		},
		{
			// The cutoff is inclusive: a newest failure exactly at it is
			// inactive, so the add restarts the streak rather than continuing it.
			name: "a streak whose newest failure is exactly at the cutoff restarts at one",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				before := addStreak(ctx, t, s, "ada", streakOldSince, streakLimit, streakOld)
				require.Equal(t, 1, before.Failures)

				at := suiteStart
				got, setHold, err := s.AddStreakFailure(ctx, "ada", at, streakOld, streakLimit)
				require.NoError(t, err)
				assert.False(t, setHold)
				assertStreak(t, got, 1, at, time.Time{})
			},
		},
		{
			name: "a streak inactive past the cutoff reads as empty",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				addStreak(ctx, t, s, "ada", streakOldSince, streakLimit, streakOld, streakOld)

				assertStreakEmpty(t, readStreak(ctx, t, s, "ada", streakSince))
				assertStreakEmpty(t, readStreak(ctx, t, s, "ada", streakOld))
				assertStreak(t, readStreak(ctx, t, s, "ada", streakOldSince), 2, streakOld, time.Time{})
			},
		},
		{
			name: "the add reaching the limit sets the hold, once, and it never moves",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				var setters []int
				for i := range streakLimit + 1 {
					_, setHold, err := s.AddStreakFailure(ctx, "ada",
						suiteStart.Add(time.Duration(i)*time.Second), streakSince, streakLimit)
					require.NoError(t, err)
					if setHold {
						setters = append(setters, i+1)
					}
				}

				assert.Equal(t, []int{streakLimit}, setters, "only the add reaching the limit reports setting the hold")
				heldAt := suiteStart.Add((streakLimit - 1) * time.Second)
				assertStreak(t, readStreak(ctx, t, s, "ada", streakSince),
					streakLimit+1, suiteStart.Add(streakLimit*time.Second), heldAt)
			},
		},
		{
			name: "a held streak never restarts or reads as empty",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				addStreak(ctx, t, s, "ada", streakOldSince, streakLimit, repeat(streakOld, streakLimit)...)

				assertStreak(t, readStreak(ctx, t, s, "ada", streakSince), streakLimit, streakOld, streakOld)

				got, setHold, err := s.AddStreakFailure(ctx, "ada", suiteStart, streakSince, streakLimit)
				require.NoError(t, err)
				assert.False(t, setHold, "a held streak's hold is not set again")
				assertStreak(t, got, streakLimit+1, suiteStart, streakOld)
			},
		},
		{
			// A deployment lowers its cap below a count a streak has already
			// reached without being held. Its next failure holds it, and that
			// add reports so, though its count is not equal to the limit.
			name: "a streak above a lowered limit is held by its next add",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				const generous = 100

				before := addStreak(ctx, t, s, "ada", streakSince, generous, repeat(suiteStart, 7)...)
				require.False(t, before.Held(), "seven failures do not reach a limit of %d", generous)

				at := suiteStart.Add(time.Second)
				got, setHold, err := s.AddStreakFailure(ctx, "ada", at, streakSince, streakLimit)
				require.NoError(t, err)
				assert.True(t, setHold, "the add that first finds the streak at or above the limit sets the hold")
				assertStreak(t, got, 8, at, at)
			},
		},
		{
			// Adds can land out of order. A late add still counts, but the
			// newest failure stays where it is, and the restart is judged
			// against the stored newest failure, not the late add's instant.
			name: "the newest failure never moves backwards",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				addStreak(ctx, t, s, "ada", streakSince, streakLimit, suiteStart, suiteStart.Add(-time.Minute))
				assertStreak(t, readStreak(ctx, t, s, "ada", streakSince), 2, suiteStart, time.Time{})

				got, setHold, err := s.AddStreakFailure(ctx, "ada", streakOld, streakSince, streakLimit)
				require.NoError(t, err)
				assert.False(t, setHold)
				assertStreak(t, got, 3, suiteStart, time.Time{})
			},
		},
		{
			name: "Reset clears the streak, the hold and the failure log, and the next add counts one",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				held := addStreak(ctx, t, s, "ada", streakSince, streakLimit, repeat(suiteStart, streakLimit)...)
				require.True(t, held.Held())
				require.NoError(t, s.RecordFailure(ctx, "ada", suiteStart))

				require.NoError(t, s.Reset(ctx, "ada"))

				assertStreakEmpty(t, readStreak(ctx, t, s, "ada", streakSince))
				assertStreakEmpty(t, readStreak(ctx, t, s, "ada", streakOldSince))
				assertFailureCount(ctx, t, s, "ada", streakSince, 0)

				at := suiteStart.Add(time.Second)
				got, setHold, err := s.AddStreakFailure(ctx, "ada", at, streakSince, streakLimit)
				require.NoError(t, err)
				assert.False(t, setHold)
				assertStreak(t, got, 1, at, time.Time{})
			},
		},
		{
			name: "Reset of an identifier with no streak is not an error",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				require.NoError(t, s.Reset(ctx, "ada"))
				assertStreakEmpty(t, readStreak(ctx, t, s, "ada", streakSince))
			},
		},
		{
			name: "identifiers are matched exactly, never folded",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				addStreak(ctx, t, s, "Ada", streakSince, streakLimit, suiteStart)
				addStreak(ctx, t, s, "ada ", streakSince, streakLimit, suiteStart, suiteStart)

				assertStreakEmpty(t, readStreak(ctx, t, s, "ada", streakSince))
				assertStreak(t, readStreak(ctx, t, s, "Ada", streakSince), 1, suiteStart, time.Time{})
				assertStreak(t, readStreak(ctx, t, s, "ada ", streakSince), 2, suiteStart, time.Time{})

				require.NoError(t, s.Reset(ctx, "ada"))
				assertStreak(t, readStreak(ctx, t, s, "Ada", streakSince), 1, suiteStart, time.Time{})
				assertStreak(t, readStreak(ctx, t, s, "ada ", streakSince), 2, suiteStart, time.Time{})
			},
		},
		{
			// A PostgreSQL text column cannot hold a NUL byte. A store may
			// refuse such an identifier on add, with an error that does not
			// echo it, and then reads it as no streak with a nil error; or it
			// may keep it exactly. It may never alter it into another one.
			name: "an identifier holding a NUL byte is refused or kept as given, never altered",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				const canary = "canary-5d1f"
				username := "ada\x00" + canary

				_, _, addErr := s.AddStreakFailure(ctx, username, suiteStart, streakSince, streakLimit)
				got, readErr := s.FailureStreak(ctx, username, streakSince)
				if addErr == nil {
					require.NoError(t, readErr, "an added identifier must be readable")
					assertStreak(t, got, 1, suiteStart, time.Time{})
				} else {
					assert.NotContains(t, addErr.Error(), canary, "the refusal must not echo the identifier")
					// A refused identifier reads as no streak, not as an error:
					// the policy goes on to allow on a read error, so it must
					// not see one for an identifier the store cannot hold.
					require.NoError(t, readErr, "a refused identifier must read as no streak")
					assertStreakEmpty(t, got)
				}

				for _, altered := range []string{"ada", canary, "ada" + canary, "ada " + canary} {
					assertStreakEmpty(t, readStreak(ctx, t, s, altered, streakSince))
				}
			},
		},
		{
			name: "a purge with a zero cutoff is refused and deletes nothing",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				addStreak(ctx, t, s, "ada", streakOldSince, streakLimit, streakOld)

				n, err := s.DeleteStreaksBefore(ctx, time.Time{})
				require.ErrorIs(t, err, policy.ErrRetainSinceRequired)
				assert.Zero(t, n)
				assertStreak(t, readStreak(ctx, t, s, "ada", streakOldSince), 1, streakOld, time.Time{})
			},
		},
		{
			name: "a purge removes inactive streaks strictly before its cutoff, and keeps holds and recent streaks",
			assert: func(t *testing.T, ctx context.Context, s StreakStore, _ *clockwork.FakeClock) {
				addStreak(ctx, t, s, "old", streakOldSince, streakLimit, streakOld, streakOld)
				addStreak(ctx, t, s, "held", streakOldSince, streakLimit, repeat(streakOld, streakLimit)...)
				addStreak(ctx, t, s, "edge", streakSince.Add(-streakRetention), streakLimit, streakSince)
				addStreak(ctx, t, s, "recent", streakSince, streakLimit, suiteStart)

				n, err := s.DeleteStreaksBefore(ctx, streakSince)
				require.NoError(t, err)
				assert.Equal(t, 1, n, "only the inactive streak that is not held goes")

				assertStreakEmpty(t, readStreak(ctx, t, s, "old", streakOldSince))
				assertStreak(t, readStreak(ctx, t, s, "held", streakSince), streakLimit, streakOld, streakOld)
				assertStreak(t, readStreak(ctx, t, s, "edge", streakSince.Add(-time.Second)),
					1, streakSince, time.Time{})
				assertStreak(t, readStreak(ctx, t, s, "recent", streakSince), 1, suiteStart, time.Time{})
			},
		},
	}

	runSuite(t, cases, withoutClock(newStore))
}

// RunFailureStreakRace adds raceStreakRacers (20) failures at once to a
// streak of raceStreakStart (90), under a limit of raceStreakLimit (100), and
// requires the count to be exact (110), the streak held, and exactly one add
// to report setting the hold. It races several identifiers' streaks at once
// on one store, so a store that reads and then writes in two steps loses
// counts or reports the hold more than once.
//
// It also races adds for identifiers with no streak, which must count exactly
// and report the hold once; adds racing Resets, after which a final Reset and
// add must leave {Failures: 1}; and a reset storm (stormResetters Reset loops
// per identifier against stormAdders*stormAddsEach adds), in which no add may
// fail.
//
// newStore is called once and must return an empty store that can serve
// raceStreakRecords*raceStreakRacers (160) calls at once.
func RunFailureStreakRace(t *testing.T, newStore func(t *testing.T) StreakStore) {
	t.Helper()

	t.Run("concurrent adds across the limit count exactly and set the hold once", func(t *testing.T) {
		ctx := t.Context()
		s := newStore(t)

		usernames := make([]string, raceStreakRecords)
		for i := range usernames {
			usernames[i] = fmt.Sprintf("racer-%d", i)
			seeded := addStreak(ctx, t, s, usernames[i], streakSince, raceStreakLimit,
				repeat(suiteStart, raceStreakStart)...)
			require.Equal(t, raceStreakStart, seeded.Failures, "the seeded streak of %q", usernames[i])
		}

		type result struct {
			setHold bool
			err     error
		}
		results := make([][]result, raceStreakRecords)
		for i := range results {
			results[i] = make([]result, raceStreakRacers)
		}

		raceCtx, cancel := context.WithTimeout(ctx, defaultRaceTimeout)
		defer cancel()

		start := make(chan struct{})
		var wg sync.WaitGroup
		for i, username := range usernames {
			for r := range raceStreakRacers {
				wg.Go(func() {
					<-start
					_, setHold, err := s.AddStreakFailure(raceCtx, username,
						suiteStart.Add(time.Second), streakSince, raceStreakLimit)
					results[i][r] = result{setHold: setHold, err: err}
				})
			}
		}
		close(start)
		wg.Wait()

		for i, username := range usernames {
			var setters int
			for r, res := range results[i] {
				if !assert.NoError(t, res.err, "racer %d of %q", r, username) {
					continue
				}
				if res.setHold {
					setters++
				}
			}
			assert.Equal(t, 1, setters, "exactly one add of %q reports setting the hold", username)

			got := readStreak(ctx, t, s, username, streakSince)
			assert.Equal(t, raceStreakStart+raceStreakRacers, got.Failures, "the count of %q is exact", username)
			assert.True(t, got.Held(), "%q is held", username)
		}
	})

	t.Run("concurrent adds to fresh identifiers count exactly and set the hold once", func(t *testing.T) {
		ctx := t.Context()
		s := newStore(t)

		type result struct {
			setHold bool
			err     error
		}
		results := make([][]result, raceStreakRecords)
		for i := range results {
			results[i] = make([]result, raceStreakRacers)
		}

		raceCtx, cancel := context.WithTimeout(ctx, defaultRaceTimeout)
		defer cancel()

		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range raceStreakRecords {
			username := fmt.Sprintf("fresh-%d", i)
			for r := range raceStreakRacers {
				wg.Go(func() {
					<-start
					_, setHold, err := s.AddStreakFailure(raceCtx, username,
						suiteStart, streakSince, streakLimit)
					results[i][r] = result{setHold: setHold, err: err}
				})
			}
		}
		close(start)
		wg.Wait()

		for i := range raceStreakRecords {
			username := fmt.Sprintf("fresh-%d", i)
			var setters int
			for r, res := range results[i] {
				if !assert.NoError(t, res.err, "racer %d of %q", r, username) {
					continue
				}
				if res.setHold {
					setters++
				}
			}
			assert.Equal(t, 1, setters, "exactly one add of %q reports setting the hold", username)

			got := readStreak(ctx, t, s, username, streakSince)
			assert.Equal(t, raceStreakRacers, got.Failures, "the count of %q is exact", username)
			assert.True(t, got.Held(), "%q is held", username)
		}
	})

	t.Run("adds racing resets leave a streak that counts on from one", func(t *testing.T) {
		ctx := t.Context()
		s := newStore(t)

		raceCtx, cancel := context.WithTimeout(ctx, stormTimeout)
		defer cancel()

		start := make(chan struct{})
		var adders, resetters sync.WaitGroup
		errs := make(chan error, stormRecords*stormAdders*stormAddsEach+stormRecords*stormResetters)
		done := make(chan struct{})
		for i := range stormRecords {
			username := fmt.Sprintf("reset-race-%d", i)
			for range stormAdders {
				adders.Go(func() {
					<-start
					for range stormAddsEach {
						got, _, err := s.AddStreakFailure(raceCtx, username,
							suiteStart, streakSince, raceStreakLimit)
						if err != nil {
							errs <- err
						} else if got.Failures < 1 {
							errs <- fmt.Errorf("an add returned %d failures", got.Failures)
						}
					}
				})
			}
			for range stormResetters {
				resetters.Go(func() {
					<-start
					for {
						select {
						case <-done:
							return
						default:
						}
						if err := s.Reset(raceCtx, username); err != nil {
							errs <- err
							return
						}
					}
				})
			}
		}
		close(start)
		adders.Wait()
		close(done)
		resetters.Wait()
		close(errs)
		for err := range errs {
			assert.NoError(t, err)
		}

		for i := range stormRecords {
			username := fmt.Sprintf("reset-race-%d", i)
			require.NoError(t, s.Reset(ctx, username))
			assertStreakEmpty(t, readStreak(ctx, t, s, username, streakSince))
			assertStreak(t, addStreak(ctx, t, s, username, streakSince, raceStreakLimit, suiteStart),
				1, suiteStart, time.Time{})
		}
	})

	t.Run("an add racing a reset storm never fails", func(t *testing.T) {
		ctx := t.Context()
		s := newStore(t)

		raceCtx, cancel := context.WithTimeout(ctx, stormTimeout)
		defer cancel()

		start := make(chan struct{})
		var adders, resetters sync.WaitGroup
		errs := make(chan error, stormRecords*stormAdders*stormAddsEach+stormRecords*stormResetters)
		done := make(chan struct{})
		for i := range stormRecords {
			username := fmt.Sprintf("storm-%d", i)
			for range stormResetters {
				resetters.Go(func() {
					<-start
					for {
						select {
						case <-done:
							return
						default:
						}
						if err := s.Reset(raceCtx, username); err != nil {
							errs <- err
							return
						}
					}
				})
			}
			for range stormAdders {
				adders.Go(func() {
					<-start
					for range stormAddsEach {
						if _, _, err := s.AddStreakFailure(raceCtx, username,
							suiteStart, streakSince, raceStreakLimit); err != nil {
							errs <- err
						}
					}
				})
			}
		}
		close(start)
		adders.Wait()
		close(done)
		resetters.Wait()
		close(errs)
		for err := range errs {
			assert.NoError(t, err, "an add must not fail while resets create and delete its streak")
		}
	})
}
