package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fullRace returns a race with every input present. Its functions are never
// called: the input check looks only at whether they are there.
func fullRace() Race[struct{}] {
	return Race[struct{}]{
		Seed: func(context.Context, *testing.T, struct{}, int) string { return "" },
		Attempt: func(context.Context, struct{}, string, int) (bool, error) {
			return false, nil
		},
	}
}

func TestRaceInputs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// rule is the race suite whose defaults apply; the zero rule is
		// the single-winner races' (consume, insert, step, complete).
		rule    raceRule
		harness func(h *DurableHarness[struct{}])
		race    func(r *Race[struct{}])
		assert  func(t *testing.T, failures []string, p raceParams)
	}

	noChange := func(*DurableHarness[struct{}]) {}
	failsWith := func(want string) func(t *testing.T, failures []string, _ raceParams) {
		return func(t *testing.T, failures []string, _ raceParams) {
			require.Equal(t, []string{want}, failures)
		}
	}

	cases := []testCase{
		{
			name:    "a complete race runs 50 records of 8 racers within 30s by default",
			harness: noChange,
			race:    func(*Race[struct{}]) {},
			assert: func(t *testing.T, failures []string, p raceParams) {
				assert.Empty(t, failures)
				assert.Equal(t, raceParams{records: 50, racers: 8, timeout: 30 * time.Second}, p)
			},
		},
		{
			name:    "records, racers and the timeout are overridable",
			harness: func(h *DurableHarness[struct{}]) { h.PoolSize = 4 },
			race:    func(r *Race[struct{}]) { r.Records, r.Racers, r.Timeout = 3, 4, time.Second },
			assert: func(t *testing.T, failures []string, p raceParams) {
				assert.Empty(t, failures)
				assert.Equal(t, raceParams{records: 3, racers: 4, timeout: time.Second}, p)
			},
		},
		{
			name:    "a missing replica fails naming it",
			harness: func(h *DurableHarness[struct{}]) { h.NewReplica = nil },
			race:    func(*Race[struct{}]) {},
			assert:  failsWith("storetest: DurableHarness.NewReplica is required"),
		},
		{
			name:    "a missing seed fails naming it",
			harness: noChange,
			race:    func(r *Race[struct{}]) { r.Seed = nil },
			assert:  failsWith("storetest: Race.Seed is required"),
		},
		{
			name:    "a missing attempt fails naming it",
			harness: noChange,
			race:    func(r *Race[struct{}]) { r.Attempt = nil },
			assert:  failsWith("storetest: Race.Attempt is required"),
		},
		{
			name:    "missing harness and race inputs fail once, naming every one",
			harness: func(h *DurableHarness[struct{}]) { h.Raw = nil },
			race:    func(r *Race[struct{}]) { r.Seed = nil },
			assert:  failsWith("storetest: DurableHarness.Raw, Race.Seed are required"),
		},
		{
			name:    "a pool of 2 for the default 8 racers fails stating it cannot exercise the race",
			harness: func(h *DurableHarness[struct{}]) { h.PoolSize = 2 },
			race:    func(*Race[struct{}]) {},
			assert:  failsWith("storetest: a pool of 2 connections cannot exercise a race of 8 racers"),
		},
		{
			name:    "the pool is checked against overridden racers",
			harness: func(h *DurableHarness[struct{}]) { h.PoolSize = 16 },
			race:    func(r *Race[struct{}]) { r.Racers = 17 },
			assert:  failsWith("storetest: a pool of 16 connections cannot exercise a race of 17 racers"),
		},
		{
			name:    "negative records fail",
			harness: noChange,
			race:    func(r *Race[struct{}]) { r.Records = -1 },
			assert:  failsWith("storetest: Race.Records must be positive, or zero for the default of 50"),
		},
		{
			name:    "a negative timeout fails",
			harness: noChange,
			race:    func(r *Race[struct{}]) { r.Timeout = -time.Second },
			assert:  failsWith("storetest: Race.Timeout must be positive, or zero for the default of 30s"),
		},
		{
			name:    "a single racer fails, as it races nobody",
			harness: noChange,
			race:    func(r *Race[struct{}]) { r.Racers = 1 },
			assert:  failsWith("storetest: Race.Racers must be at least 2, or zero for the default of 8"),
		},
		{
			name:    "a charge race runs 50 records of 20 racers within 30s by default",
			rule:    chargeRule,
			harness: func(h *DurableHarness[struct{}]) { h.PoolSize = 20 },
			race:    func(*Race[struct{}]) {},
			assert: func(t *testing.T, failures []string, p raceParams) {
				assert.Empty(t, failures)
				assert.Equal(t, raceParams{records: 50, racers: 20, timeout: 30 * time.Second}, p)
			},
		},
		{
			name:    "a charge race's default 20 racers fail a pool of 16",
			rule:    chargeRule,
			harness: noChange,
			race:    func(*Race[struct{}]) {},
			assert:  failsWith("storetest: a pool of 16 connections cannot exercise a race of 20 racers"),
		},
		{
			name:    "a charge race's racers are overridable",
			rule:    chargeRule,
			harness: noChange,
			race:    func(r *Race[struct{}]) { r.Racers = 6 },
			assert: func(t *testing.T, failures []string, p raceParams) {
				assert.Empty(t, failures)
				assert.Equal(t, raceParams{records: 50, racers: 6, timeout: 30 * time.Second}, p)
			},
		},
		{
			name:    "a charge race of 5 racers fails naming its minimum of 6, as 5 racers cannot exceed 5 wins",
			rule:    chargeRule,
			harness: noChange,
			race:    func(r *Race[struct{}]) { r.Racers = 5 },
			assert:  failsWith("storetest: Race.Racers must be at least 6, or zero for the default of 20"),
		},
		{
			name:    "a charge race's single racer fails naming its minimum of 6 and its default of 20",
			rule:    chargeRule,
			harness: noChange,
			race:    func(r *Race[struct{}]) { r.Racers = 1 },
			assert:  failsWith("storetest: Race.Racers must be at least 6, or zero for the default of 20"),
		},
		{
			name:    "a completion race runs 8 racers by default, as the scenario of 8 callers does",
			rule:    completeRule,
			harness: noChange,
			race:    func(*Race[struct{}]) {},
			assert: func(t *testing.T, failures []string, p raceParams) {
				assert.Empty(t, failures)
				assert.Equal(t, raceParams{records: 50, racers: 8, timeout: 30 * time.Second}, p)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h, r := fullHarness(), fullRace()
			tc.harness(&h)
			tc.race(&r)

			var p raceParams
			rule := tc.rule.withDefaults()
			failures := runRecorded(t, func(tb testing.TB) { p = requireRace(tb, h, r, rule) })
			tc.assert(t, failures, p)
		})
	}
}
