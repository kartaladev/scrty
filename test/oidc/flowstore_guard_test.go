package oidctest_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
	oidctest "github.com/kartaladev/scrty/test/oidc"
)

// flowDefectVar names the environment variable that selects the single
// deliberate flaw the flow store under test carries. One defect per process,
// so the suite's verdict is attributable to it alone.
const flowDefectVar = "SCRTY_OIDC_FLOW_DEFECT"

// flowDefect is one deliberate flaw a flow store can carry.
type flowDefect string

const (
	flowDefectNone flowDefect = ""
	// Complete removes the flow before judging the call, so a refused call
	// spends it.
	flowDefectBurnsBeforeCompare flowDefect = "burns-before-compare"
	// Complete decides "still there" by a read released before its delete.
	flowDefectReadThenWrite flowDefect = "read-then-write"
	// Complete never compares the provider.
	flowDefectIgnoresProvider flowDefect = "ignores-provider"
	// Complete accepts an empty state as matching any flow.
	flowDefectEmptyStateMatches flowDefect = "empty-state-matches"
	// Complete never judges expiry.
	flowDefectIgnoresExpiry flowDefect = "ignores-expiry"
	// Complete never removes a completed flow.
	flowDefectCompletesTwice flowDefect = "completes-twice"
	// DeleteExpired treats a zero cutoff as a real one.
	flowDefectAcceptsZeroCutoff flowDefect = "accepts-zero-cutoff"
	// DeleteExpired removes a flow whose expiry equals the cutoff, not just
	// the ones strictly before it.
	flowDefectDeletesAtCutoff flowDefect = "deletes-at-cutoff"
)

// everyFlowDefect is every flaw the guard expects the suite to catch. A
// non-constant-time state comparison is left out: no black-box suite can
// observe it.
var everyFlowDefect = []flowDefect{
	flowDefectBurnsBeforeCompare,
	flowDefectReadThenWrite,
	flowDefectIgnoresProvider,
	flowDefectEmptyStateMatches,
	flowDefectIgnoresExpiry,
	flowDefectCompletesTwice,
	flowDefectAcceptsZeroCutoff,
	flowDefectDeletesAtCutoff,
}

// brokenFlowStore is a flow store over process memory carrying exactly one
// deliberate defect. It is written on its own rather than wrapped around the
// shipped store, so the suite, not an inherited correctness, decides.
type brokenFlowStore struct {
	d   flowDefect
	now func() time.Time

	mu    sync.Mutex
	flows map[string]oidc.Flow

	// arrived counts the completions that have reached the window between
	// their read and their delete, so the read-then-write race shows on every
	// run.
	arrived atomic.Int64
}

var _ oidc.FlowStore = (*brokenFlowStore)(nil)

func newBrokenFlowStore(d flowDefect, now func() time.Time) *brokenFlowStore {
	return &brokenFlowStore{d: d, now: now, flows: make(map[string]oidc.Flow)}
}

// meet blocks until want callers have reached it, or until a short deadline
// passes so that a lone caller is not held up.
func (s *brokenFlowStore) meet(want int64) {
	if s.arrived.Add(1) >= want {
		return
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for s.arrived.Load() < want && time.Now().Before(deadline) {
		runtime.Gosched()
	}
}

func (s *brokenFlowStore) Begin(_ context.Context, f oidc.Flow) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows[h] = f
	return h, nil
}

// accepts judges a call against f, honouring the store's defect.
func (s *brokenFlowStore) accepts(f oidc.Flow, provider, state string) bool {
	providerOK := f.Provider == provider || s.d == flowDefectIgnoresProvider
	stateOK := (state != "" && state == f.State) || (state == "" && s.d == flowDefectEmptyStateMatches)
	liveOK := s.now().Before(f.ExpiresAt) || s.d == flowDefectIgnoresExpiry
	return providerOK && stateOK && liveOK
}

func (s *brokenFlowStore) Complete(_ context.Context, handle, provider, state string) (oidc.Flow, error) {
	if s.d == flowDefectReadThenWrite {
		s.mu.Lock()
		f, ok := s.flows[handle]
		s.mu.Unlock()
		if !ok || !s.accepts(f, provider, state) {
			return oidc.Flow{}, oidc.ErrInvalidState
		}
		s.meet(2)
		s.mu.Lock()
		delete(s.flows, handle)
		s.mu.Unlock()
		return f, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.flows[handle]
	if s.d == flowDefectBurnsBeforeCompare {
		delete(s.flows, handle)
	}
	if !ok || !s.accepts(f, provider, state) {
		return oidc.Flow{}, oidc.ErrInvalidState
	}
	if s.d != flowDefectCompletesTwice {
		delete(s.flows, handle)
	}
	return f, nil
}

func (s *brokenFlowStore) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	if before.IsZero() && s.d != flowDefectAcceptsZeroCutoff {
		return 0, oidc.ErrRetainSinceRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for h, f := range s.flows {
		expired := f.ExpiresAt.Before(before)
		if s.d == flowDefectDeletesAtCutoff {
			// The defect treats "at or before" as expired, not "strictly before".
			expired = !f.ExpiresAt.After(before)
		}
		// The defect reads a zero cutoff as "no cutoff": everything goes.
		if before.IsZero() || expired {
			delete(s.flows, h)
			removed++
		}
	}
	return removed, nil
}

// TestBrokenFlowStoreConformance runs the suite against a store carrying the
// defect named by the environment, and is the child half of
// TestFlowStoreSuiteIsLoadBearing. Without a defect named it skips.
func TestBrokenFlowStoreConformance(t *testing.T) {
	d, named := os.LookupEnv(flowDefectVar)
	if !named {
		t.Skipf("no defect named in %s; run through TestFlowStoreSuiteIsLoadBearing", flowDefectVar)
	}

	t.Logf("defect under test: %q", d)

	oidctest.RunFlowStoreSuite(t, func(t *testing.T, now func() time.Time) oidc.FlowStore {
		t.Helper()
		return newBrokenFlowStore(flowDefect(d), now)
	})
}

// TestFlowStoreSuiteIsLoadBearing checks the suite itself: a store carrying
// any defect above must fail it, and a store carrying none must pass. Each
// defect runs in its own process because a failing suite reports through its
// own *testing.T, which cannot be substituted.
func TestFlowStoreSuiteIsLoadBearing(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		defect flowDefect
		assert func(t *testing.T, err error, output string)
	}

	cases := make([]testCase, 0, len(everyFlowDefect)+1)
	cases = append(cases, testCase{
		name:   "a store with no defect passes",
		defect: flowDefectNone,
		assert: func(t *testing.T, err error, output string) {
			require.NoError(t, err,
				"the suite rejected a conforming store, so every defect below fails for the wrong reason:\n%s",
				output)
		},
	})
	for _, d := range everyFlowDefect {
		cases = append(cases, testCase{
			name:   string(d) + " is caught",
			defect: d,
			assert: func(t *testing.T, err error, output string) {
				require.Error(t, err,
					"the suite passed a flow store whose %s defect breaks the contract the callback relies on:\n%s",
					d, output)
			},
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			output, err := runFlowSuiteInProcess(t, tc.defect)
			tc.assert(t, err, output)
		})
	}
}

// runFlowSuiteInProcess re-executes this test binary, running only the child
// test against a store carrying d, and returns its combined output.
func runFlowSuiteInProcess(t *testing.T, d flowDefect) (string, error) {
	t.Helper()

	//nolint:gosec // G204: this test binary re-executed with fixed arguments
	cmd := exec.CommandContext(t.Context(), os.Args[0],
		"-test.run=^TestBrokenFlowStoreConformance$", "-test.count=1", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), flowDefectVar+"="+string(d))

	out, err := cmd.CombinedOutput()

	assert.NotContains(t, string(out), "SKIP",
		"the child skipped rather than running the suite, so nothing was checked")

	return string(out), err
}
