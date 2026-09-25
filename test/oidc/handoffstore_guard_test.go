package oidctest_test

import (
	"context"
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

// handoffDefectVar names the environment variable that selects the single
// deliberate flaw the handoff store under test carries. One defect per
// process, so the suite's verdict is attributable to it alone.
const handoffDefectVar = "SCRTY_OIDC_HANDOFF_DEFECT"

// handoffDefect is one deliberate flaw a handoff store can carry.
type handoffDefect string

const (
	handoffDefectNone handoffDefect = ""
	// Consume succeeds on a record that is already consumed.
	handoffDefectConsumeTwice handoffDefect = "consume-twice"
	// Consume decides "unconsumed" by a read released before its write.
	handoffDefectReadThenWrite handoffDefect = "read-then-write"
	// DeleteExpired treats a zero cutoff as a real one.
	handoffDefectAcceptsZeroCutoff handoffDefect = "accepts-zero-cutoff"
	// FindByTokenID hands back the store's own record.
	handoffDefectFindReturnsSharedPointer handoffDefect = "find-returns-shared-pointer"
)

// everyHandoffDefect is every flaw the guard expects the suite to catch.
var everyHandoffDefect = []handoffDefect{
	handoffDefectConsumeTwice,
	handoffDefectReadThenWrite,
	handoffDefectAcceptsZeroCutoff,
	handoffDefectFindReturnsSharedPointer,
}

// brokenHandoffStore is a handoff store over process memory carrying exactly
// one deliberate defect. It is written on its own rather than wrapped around
// the shipped store, so the suite, not an inherited correctness, decides.
type brokenHandoffStore struct {
	d   handoffDefect
	now func() time.Time

	mu      sync.Mutex
	records map[string]*oidc.HandoffRecord

	// arrived counts the consumes that have reached the window between their
	// read and their write, so the read-then-write race shows on every run.
	arrived atomic.Int64
}

var _ oidc.HandoffStore = (*brokenHandoffStore)(nil)

func newBrokenHandoffStore(d handoffDefect, now func() time.Time) *brokenHandoffStore {
	return &brokenHandoffStore{d: d, now: now, records: make(map[string]*oidc.HandoffRecord)}
}

// meet blocks until want callers have reached it, or until a short deadline
// passes so that a lone caller is not held up.
func (s *brokenHandoffStore) meet(want int64) {
	if s.arrived.Add(1) >= want {
		return
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for s.arrived.Load() < want && time.Now().Before(deadline) {
		runtime.Gosched()
	}
}

func cloneBrokenHandoffRecord(rec oidc.HandoffRecord) *oidc.HandoffRecord {
	rec.SecretHash = append([]byte(nil), rec.SecretHash...)
	if rec.ConsumedAt != nil {
		at := *rec.ConsumedAt
		rec.ConsumedAt = &at
	}
	return &rec
}

func (s *brokenHandoffStore) Insert(_ context.Context, rec oidc.HandoffRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records[rec.TokenID] = cloneBrokenHandoffRecord(rec)
	return nil
}

func (s *brokenHandoffStore) FindByTokenID(_ context.Context, tokenID string) (*oidc.HandoffRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[tokenID]
	if !ok {
		return nil, oidc.ErrHandoffNotFound
	}
	if s.d == handoffDefectFindReturnsSharedPointer {
		return rec, nil
	}
	return cloneBrokenHandoffRecord(*rec), nil
}

func (s *brokenHandoffStore) Consume(_ context.Context, tokenID string, at time.Time) error {
	if s.d == handoffDefectReadThenWrite {
		s.mu.Lock()
		rec, ok := s.records[tokenID]
		spent := ok && rec.ConsumedAt != nil
		s.mu.Unlock()
		if !ok || spent {
			return oidc.ErrHandoffNotFound
		}
		s.meet(2)
		s.mu.Lock()
		rec.ConsumedAt = &at
		s.mu.Unlock()
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[tokenID]
	if !ok || (rec.ConsumedAt != nil && s.d != handoffDefectConsumeTwice) {
		return oidc.ErrHandoffNotFound
	}
	rec.ConsumedAt = &at
	return nil
}

func (s *brokenHandoffStore) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	if before.IsZero() && s.d != handoffDefectAcceptsZeroCutoff {
		return 0, oidc.ErrRetainSinceRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	removed := 0
	for k, rec := range s.records {
		expired := !now.Before(rec.ExpiresAt)
		// The defect reads a zero cutoff as "no cutoff": everything expired goes.
		if expired && (before.IsZero() || rec.ExpiresAt.Before(before)) {
			delete(s.records, k)
			removed++
		}
	}
	return removed, nil
}

// TestBrokenHandoffStoreConformance runs the suite against a store carrying
// the defect named by the environment, and is the child half of
// TestHandoffStoreSuiteIsLoadBearing. Without a defect named it skips.
func TestBrokenHandoffStoreConformance(t *testing.T) {
	d, named := os.LookupEnv(handoffDefectVar)
	if !named {
		t.Skipf("no defect named in %s; run through TestHandoffStoreSuiteIsLoadBearing", handoffDefectVar)
	}

	t.Logf("defect under test: %q", d)

	oidctest.RunHandoffStoreSuite(t, func(t *testing.T, now func() time.Time) oidc.HandoffStore {
		t.Helper()
		return newBrokenHandoffStore(handoffDefect(d), now)
	})
}

// TestHandoffStoreSuiteIsLoadBearing checks the suite itself: a store
// carrying any defect above must fail it, and a store carrying none must pass.
// Each defect runs in its own process because a failing suite reports through
// its own *testing.T, which cannot be substituted.
func TestHandoffStoreSuiteIsLoadBearing(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		defect handoffDefect
		assert func(t *testing.T, err error, output string)
	}

	cases := make([]testCase, 0, len(everyHandoffDefect)+1)
	cases = append(cases, testCase{
		name:   "a store with no defect passes",
		defect: handoffDefectNone,
		assert: func(t *testing.T, err error, output string) {
			require.NoError(t, err,
				"the suite rejected a conforming store, so every defect below fails for the wrong reason:\n%s",
				output)
		},
	})
	for _, d := range everyHandoffDefect {
		cases = append(cases, testCase{
			name:   string(d) + " is caught",
			defect: d,
			assert: func(t *testing.T, err error, output string) {
				require.Error(t, err,
					"the suite passed a handoff store whose %s defect breaks the contract redemption relies on:\n%s",
					d, output)
			},
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			output, err := runHandoffSuiteInProcess(t, tc.defect)
			tc.assert(t, err, output)
		})
	}
}

// runHandoffSuiteInProcess re-executes this test binary, running only the
// child test against a store carrying d, and returns its combined output.
func runHandoffSuiteInProcess(t *testing.T, d handoffDefect) (string, error) {
	t.Helper()

	//nolint:gosec // G204: this test binary re-executed with fixed arguments
	cmd := exec.CommandContext(t.Context(), os.Args[0],
		"-test.run=^TestBrokenHandoffStoreConformance$", "-test.count=1", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), handoffDefectVar+"="+string(d))

	out, err := cmd.CombinedOutput()

	assert.NotContains(t, string(out), "SKIP",
		"the child skipped rather than running the suite, so nothing was checked")

	return string(out), err
}
