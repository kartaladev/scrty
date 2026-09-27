package storetest

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fullAmbient returns probes with every input present. They are never
// called: the input check looks only at whether they are there.
func fullAmbient() Ambient[struct{}] {
	return Ambient[struct{}]{
		Write:   func(context.Context, struct{}, int) error { return nil },
		Present: func(*testing.T, *sql.DB, int) bool { return false },
		Refuse:  func(context.Context, struct{}) error { return nil },
		Refusal: errors.New("refused"),
	}
}

func TestAmbientInputs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		harness func(h *DurableHarness[struct{}])
		ambient func(a *Ambient[struct{}])
		assert  func(t *testing.T, failures []string)
	}

	noChange := func(*DurableHarness[struct{}]) {}
	failsWith := func(want string) func(t *testing.T, failures []string) {
		return func(t *testing.T, failures []string) {
			require.Equal(t, []string{want}, failures)
		}
	}
	missing := func(field string, drop func(a *Ambient[struct{}])) testCase {
		return testCase{
			name:    "a missing " + field + " fails naming it",
			harness: noChange,
			ambient: drop,
			assert:  failsWith("storetest: " + field + " is required"),
		}
	}

	cases := []testCase{
		{
			name:    "complete probes pass",
			harness: noChange,
			ambient: func(*Ambient[struct{}]) {},
			assert: func(t *testing.T, failures []string) {
				assert.Empty(t, failures)
			},
		},
		{
			name:    "missing out-of-band access fails naming it",
			harness: func(h *DurableHarness[struct{}]) { h.Raw = nil },
			ambient: func(*Ambient[struct{}]) {},
			assert:  failsWith("storetest: DurableHarness.Raw is required"),
		},
		{
			name:    "a missing resolver transaction fails naming it",
			harness: func(h *DurableHarness[struct{}]) { h.BeginResolved = nil },
			ambient: func(*Ambient[struct{}]) {},
			assert:  failsWith("storetest: DurableHarness.BeginResolved is required"),
		},
		missing("Ambient.Write", func(a *Ambient[struct{}]) { a.Write = nil }),
		missing("Ambient.Present", func(a *Ambient[struct{}]) { a.Present = nil }),
		missing("Ambient.Refuse", func(a *Ambient[struct{}]) { a.Refuse = nil }),
		missing("Ambient.Refusal", func(a *Ambient[struct{}]) { a.Refusal = nil }),
		{
			name:    "empty probes on an empty harness fail once, naming every input",
			harness: func(h *DurableHarness[struct{}]) { *h = DurableHarness[struct{}]{} },
			ambient: func(a *Ambient[struct{}]) { *a = Ambient[struct{}]{} },
			assert: failsWith("storetest: Harness.New, DurableHarness.NewReplica, DurableHarness.Raw, DurableHarness.Begin, " +
				"DurableHarness.BeginResolved, DurableHarness.BeginForeign, DurableHarness.PoolSize, " +
				"Ambient.Write, Ambient.Present, Ambient.Refuse, Ambient.Refusal are required"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h, a := fullHarness(), fullAmbient()
			tc.harness(&h)
			tc.ambient(&a)

			tc.assert(t, runRecorded(t, func(tb testing.TB) { requireAmbient(tb, h, a) }))
		})
	}
}
