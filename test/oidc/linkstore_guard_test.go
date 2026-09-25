package oidctest_test

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
	oidctest "github.com/kartaladev/scrty/test/oidc"
)

// linkDefectVar names the environment variable that selects the single
// deliberate flaw the link store under test carries. One defect per process,
// so the suite's verdict is attributable to it and to nothing else.
const linkDefectVar = "SCRTY_OIDC_LINK_DEFECT"

// linkDefect is one deliberate flaw a link store can carry.
type linkDefect string

const (
	linkDefectNone linkDefect = ""
	// Insert overwrites an existing link instead of refusing it.
	linkDefectOverwritesOnInsert linkDefect = "overwrites-on-insert"
	// Insert decides the collision by a read released before the write, so
	// concurrent inserts of one key all succeed.
	linkDefectReadThenWrite linkDefect = "read-then-write"
	// The key is provider and subject only, so one subject at two issuers
	// collides.
	linkDefectIgnoresIssuer linkDefect = "ignores-issuer"
	// DeleteByUser matches the user reference case-insensitively.
	linkDefectCaseFoldsReference linkDefect = "case-folds-reference"
	// DeleteByUser removes the links but reports none.
	linkDefectNoDeleteCount linkDefect = "no-delete-count"
)

// everyLinkDefect is every flaw the guard expects the suite to catch. A
// defect that is not listed here is a defect no run exercises.
var everyLinkDefect = []linkDefect{
	linkDefectOverwritesOnInsert,
	linkDefectReadThenWrite,
	linkDefectIgnoresIssuer,
	linkDefectCaseFoldsReference,
	linkDefectNoDeleteCount,
}

// brokenLinkStore is a LinkStore over process memory carrying exactly one
// deliberate defect. It is written on its own rather than wrapped around the
// shipped store, so that the suite, not an inherited correctness, decides the
// verdict.
type brokenLinkStore struct {
	d linkDefect

	mu    sync.Mutex
	links map[[3]string]oidc.Link

	// arrived counts the inserts that have reached the window between their
	// read and their write, so the read-then-write race shows on every run
	// rather than only when the scheduler allows.
	arrived atomic.Int64
}

var _ oidc.LinkStore = (*brokenLinkStore)(nil)

func newBrokenLinkStore(d linkDefect) *brokenLinkStore {
	return &brokenLinkStore{d: d, links: make(map[[3]string]oidc.Link)}
}

func (s *brokenLinkStore) key(provider, issuer, subject string) [3]string {
	if s.d == linkDefectIgnoresIssuer {
		issuer = ""
	}
	return [3]string{provider, issuer, subject}
}

// meet blocks until want callers have reached it, or until a short deadline
// passes so that a lone caller is not held up.
func (s *brokenLinkStore) meet(want int64) {
	if s.arrived.Add(1) >= want {
		return
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for s.arrived.Load() < want && time.Now().Before(deadline) {
		runtime.Gosched()
	}
}

func (s *brokenLinkStore) FindByExternal(_ context.Context, provider, issuer, subject string) (*oidc.Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	l, ok := s.links[s.key(provider, issuer, subject)]
	if !ok {
		return nil, oidc.ErrLinkNotFound
	}
	return &l, nil
}

func (s *brokenLinkStore) Insert(_ context.Context, l oidc.Link) error {
	k := s.key(l.Provider, l.Issuer, l.Subject)

	if s.d == linkDefectReadThenWrite {
		s.mu.Lock()
		_, taken := s.links[k]
		s.mu.Unlock()
		if taken {
			return oidc.ErrLinkExists
		}
		s.meet(2)
		s.mu.Lock()
		s.links[k] = l
		s.mu.Unlock()
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, taken := s.links[k]; taken && s.d != linkDefectOverwritesOnInsert {
		return oidc.ErrLinkExists
	}
	s.links[k] = l
	return nil
}

func (s *brokenLinkStore) DeleteByUser(_ context.Context, user identity.UserID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for k, l := range s.links {
		match := l.UserID == user
		if s.d == linkDefectCaseFoldsReference {
			match = strings.EqualFold(string(l.UserID), string(user))
		}
		if match {
			delete(s.links, k)
			n++
		}
	}
	if s.d == linkDefectNoDeleteCount {
		return 0, nil
	}
	return n, nil
}

// TestBrokenLinkStoreConformance runs the suite against a store carrying the
// defect named by the environment, and is the child half of
// TestLinkStoreSuiteIsLoadBearing. Without a defect named it skips.
func TestBrokenLinkStoreConformance(t *testing.T) {
	d, named := os.LookupEnv(linkDefectVar)
	if !named {
		t.Skipf("no defect named in %s; run through TestLinkStoreSuiteIsLoadBearing", linkDefectVar)
	}

	t.Logf("defect under test: %q", d)

	oidctest.RunLinkStoreSuite(t, func(t *testing.T) oidc.LinkStore {
		t.Helper()
		return newBrokenLinkStore(linkDefect(d))
	})
}

// TestLinkStoreSuiteIsLoadBearing checks the suite itself: a store carrying
// any defect above must fail it, and a store carrying none must pass. Each
// defect runs in its own process because a failing suite reports through its
// own *testing.T, which cannot be substituted.
func TestLinkStoreSuiteIsLoadBearing(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		defect linkDefect
		assert func(t *testing.T, err error, output string)
	}

	cases := make([]testCase, 0, len(everyLinkDefect)+1)
	cases = append(cases, testCase{
		name:   "a store with no defect passes",
		defect: linkDefectNone,
		assert: func(t *testing.T, err error, output string) {
			require.NoError(t, err,
				"the suite rejected a conforming store, so every defect below fails for the wrong reason:\n%s",
				output)
		},
	})
	for _, d := range everyLinkDefect {
		cases = append(cases, testCase{
			name:   string(d) + " is caught",
			defect: d,
			assert: func(t *testing.T, err error, output string) {
				require.Error(t, err,
					"the suite passed a link store whose %s defect breaks the contract the broker relies on:\n%s",
					d, output)
			},
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			output, err := runLinkSuiteInProcess(t, tc.defect)
			tc.assert(t, err, output)
		})
	}
}

// runLinkSuiteInProcess re-executes this test binary, running only the child
// test against a store carrying d, and returns its combined output.
func runLinkSuiteInProcess(t *testing.T, d linkDefect) (string, error) {
	t.Helper()

	//nolint:gosec // G204: this test binary re-executed with fixed arguments
	cmd := exec.CommandContext(t.Context(), os.Args[0],
		"-test.run=^TestBrokenLinkStoreConformance$", "-test.count=1", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), linkDefectVar+"="+string(d))

	out, err := cmd.CombinedOutput()

	assert.NotContains(t, string(out), "SKIP",
		"the child skipped rather than running the suite, so nothing was checked")

	return string(out), err
}
