package storetest

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingTB stands in for testing.TB while an input check runs, so what the
// check reports is observed by the real test instead of ending it. Its Fatalf
// ends only the goroutine that calls it (runtime.Goexit, as testing.T's does),
// so a check must run under runRecorded. Methods it does not override go to
// the real test it embeds.
type recordingTB struct {
	testing.TB

	failures []string
}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

func (r *recordingTB) Fatalf(format string, args ...any) {
	r.Errorf(format, args...)
	runtime.Goexit()
}

func (r *recordingTB) Fatal(args ...any) {
	r.failures = append(r.failures, fmt.Sprint(args...))
	runtime.Goexit()
}

func (r *recordingTB) FailNow() {
	r.failures = append(r.failures, "FailNow")
	runtime.Goexit()
}

// runRecorded runs check against a fresh recorder on its own goroutine and
// returns what the recorder was told. The goroutine is what lets a Fatalf end
// the check without ending the calling test.
func runRecorded(t *testing.T, check func(tb testing.TB)) []string {
	t.Helper()

	rec := &recordingTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		check(rec)
	}()
	<-done

	return rec.failures
}

// fullHarness returns a harness with every input present. Its functions are
// never called: the input check looks only at whether they are there.
func fullHarness() DurableHarness[struct{}] {
	return DurableHarness[struct{}]{
		Harness:    Harness[struct{}]{New: func(*testing.T) struct{} { return struct{}{} }},
		NewReplica: func(*testing.T) struct{} { return struct{}{} },
		Raw:        &sql.DB{},
		Begin: func(*testing.T) (context.Context, func() error, func() error) {
			return context.Background(), nil, nil
		},
		BeginResolved: func(*testing.T) (struct{}, context.Context, func() error, func() error) {
			return struct{}{}, context.Background(), nil, nil
		},
		BeginForeign: func(*testing.T) (context.Context, func() error) {
			return context.Background(), nil
		},
		PoolSize: 16,
	}
}

func TestDurableHarnessRequire(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		harness func() DurableHarness[struct{}]
		assert  func(t *testing.T, failures []string)
	}

	missing := func(field string, drop func(h *DurableHarness[struct{}])) testCase {
		return testCase{
			name: "missing " + field + " fails naming it",
			harness: func() DurableHarness[struct{}] {
				h := fullHarness()
				drop(&h)
				return h
			},
			assert: func(t *testing.T, failures []string) {
				require.Equal(t, []string{"storetest: " + field + " is required"}, failures)
			},
		}
	}

	cases := []testCase{
		{
			name:    "a harness with every input passes",
			harness: fullHarness,
			assert: func(t *testing.T, failures []string) {
				assert.Empty(t, failures)
			},
		},
		missing("Harness.New", func(h *DurableHarness[struct{}]) { h.New = nil }),
		missing("DurableHarness.NewReplica", func(h *DurableHarness[struct{}]) { h.NewReplica = nil }),
		missing("DurableHarness.Raw", func(h *DurableHarness[struct{}]) { h.Raw = nil }),
		missing("DurableHarness.Begin", func(h *DurableHarness[struct{}]) { h.Begin = nil }),
		missing("DurableHarness.BeginResolved", func(h *DurableHarness[struct{}]) { h.BeginResolved = nil }),
		missing("DurableHarness.BeginForeign", func(h *DurableHarness[struct{}]) { h.BeginForeign = nil }),
		missing("DurableHarness.PoolSize", func(h *DurableHarness[struct{}]) { h.PoolSize = 0 }),
		{
			name:    "an empty harness fails once, naming every missing input",
			harness: func() DurableHarness[struct{}] { return DurableHarness[struct{}]{} },
			assert: func(t *testing.T, failures []string) {
				require.Equal(t, []string{
					"storetest: Harness.New, DurableHarness.NewReplica, DurableHarness.Raw, DurableHarness.Begin, " +
						"DurableHarness.BeginResolved, DurableHarness.BeginForeign, " +
						"DurableHarness.PoolSize are required",
				}, failures)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := tc.harness()
			tc.assert(t, runRecorded(t, func(tb testing.TB) { h.Require(tb) }))
		})
	}
}

func TestRequirePool(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		pool   int
		racers int
		assert func(t *testing.T, failures []string)
	}

	cases := []testCase{
		{
			name:   "a pool of 2 for 8 racers fails stating it cannot exercise the race",
			pool:   2,
			racers: 8,
			assert: func(t *testing.T, failures []string) {
				require.Equal(t, []string{
					"storetest: a pool of 2 connections cannot exercise a race of 8 racers",
				}, failures)
			},
		},
		{
			name:   "a pool one narrower than the racers fails",
			pool:   7,
			racers: 8,
			assert: func(t *testing.T, failures []string) {
				require.Equal(t, []string{
					"storetest: a pool of 7 connections cannot exercise a race of 8 racers",
				}, failures)
			},
		},
		{
			name:   "a pool as wide as the racers passes",
			pool:   8,
			racers: 8,
			assert: func(t *testing.T, failures []string) {
				assert.Empty(t, failures)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, runRecorded(t, func(tb testing.TB) { requirePool(tb, tc.pool, tc.racers) }))
		})
	}
}
