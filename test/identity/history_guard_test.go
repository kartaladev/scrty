package identitytest_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	identitytest "github.com/kartaladev/scrty/test/identity"
)

// historyDefectVar names the environment variable that selects the single
// deliberate flaw the history under test carries. One defect per process, so
// the suite's verdict is attributable to it and to nothing else.
const historyDefectVar = "SCRTY_HISTORY_DEFECT"

// historyDefect is one deliberate flaw a password.History implementation can
// carry.
type historyDefect string

const (
	historyDefectNone historyDefect = ""
	// RecentPasswords returns entries oldest first instead of newest first.
	historyDefectOldestFirst historyDefect = "oldest-first"
	// RetirePassword never removes an entry beyond keep.
	historyDefectNeverPrunes historyDefect = "never-prunes"
	// RetirePassword records the same bytes as the newest entry again, rather
	// than adding nothing.
	historyDefectIgnoresSameBytes historyDefect = "ignores-same-bytes"
	// RetirePassword adds nothing when any stored entry, not only the newest,
	// holds the same bytes.
	historyDefectDedupAnywhere historyDefect = "dedup-anywhere"
	// RetirePassword adds nothing when the oldest entry, rather than the
	// newest, holds the same bytes.
	historyDefectDedupAgainstOldest historyDefect = "dedup-against-oldest"
	// RetirePassword with keep == 0 leaves the stored entries untouched.
	historyDefectIgnoresKeepZero historyDefect = "ignores-keep-zero"
	// RetirePassword keeps the caller's buffer rather than a copy, so the
	// caller reusing it rewrites the stored entry.
	historyDefectKeepsCallerBuffer historyDefect = "keeps-caller-buffer"
	// RecentPasswords returns the stored buffers rather than copies, so a
	// caller writing to a returned hash rewrites the stored entry.
	historyDefectSharesReturnedBuffer historyDefect = "shares-returned-buffer"
	// ForgetPasswords removes nothing.
	historyDefectForgetNoop historyDefect = "forget-noop"
	// ForgetPasswords removes every user's entries, not only the named one's.
	historyDefectForgetEveryone historyDefect = "forget-everyone"
	// A rollback applies the transaction's writes instead of discarding them.
	historyDefectRollbackKeeps historyDefect = "rollback-keeps"
	// A commit discards the transaction's writes instead of applying them.
	historyDefectCommitDiscards historyDefect = "commit-discards"
	// A read through a transaction's context ignores the transaction, and
	// reads only what is committed.
	historyDefectReadsIgnoreTx historyDefect = "reads-ignore-tx"
	// A commit writes back every user the transaction read, as it read them,
	// so a transaction that only read undoes what another writer committed
	// meanwhile.
	historyDefectCommitWritesReads historyDefect = "commit-writes-reads"
	// Begin answers ErrHookUnsupported, as an implementation with no
	// transaction support would.
	historyDefectMissingBegin historyDefect = "missing-begin"
	// Begin returns a nil context, with a usable commit and rollback.
	historyDefectNilTxContext historyDefect = "nil-tx-context"
	// Begin returns a nil commit.
	historyDefectNilCommit historyDefect = "nil-commit"
	// Begin returns a nil rollback.
	historyDefectNilRollback historyDefect = "nil-rollback"
	// A forget made inside a transaction is seen through its own context, but
	// is never logged for commit to replay, so committing it changes nothing.
	historyDefectTxForgetNotLogged historyDefect = "tx-forget-not-logged"
	// A forget made inside a transaction is applied straight to the shared
	// records immediately, bypassing the transaction it was made through.
	historyDefectTxForgetLeaks historyDefect = "tx-forget-leaks"
	// RetirePassword returns early without pruning when the retired bytes
	// match the newest entry already stored.
	historyDefectDedupSkipsPrune historyDefect = "dedup-skips-prune"
)

// everyHistoryDefect is every flaw the guard expects RunPasswordHistory to
// catch by case assertion. A defect that is not listed here is a defect no
// run exercises. The defects of Begin itself are the preflight's, and
// TestPasswordHistoryRequiresUsableBegin checks them.
var everyHistoryDefect = []historyDefect{
	historyDefectOldestFirst,
	historyDefectNeverPrunes,
	historyDefectIgnoresSameBytes,
	historyDefectDedupAnywhere,
	historyDefectDedupAgainstOldest,
	historyDefectIgnoresKeepZero,
	historyDefectKeepsCallerBuffer,
	historyDefectSharesReturnedBuffer,
	historyDefectForgetNoop,
	historyDefectForgetEveryone,
	historyDefectRollbackKeeps,
	historyDefectCommitDiscards,
	historyDefectReadsIgnoreTx,
	historyDefectCommitWritesReads,
	historyDefectTxForgetNotLogged,
	historyDefectTxForgetLeaks,
	historyDefectDedupSkipsPrune,
}

// brokenHistory implements password.History and identitytest.HistoryHarness
// over process memory, carrying exactly one deliberate defect. It is written
// on its own rather than wrapped around InMemoryHistory, so that
// RunPasswordHistory — not an inherited correctness — is what decides the
// verdict. With no defect it follows the same transaction model as
// InMemoryHistory: a private view per transaction, and a log of writes
// replayed on commit, with the transaction's lock always taken first.
type brokenHistory struct {
	d historyDefect

	mu     sync.Mutex
	byUser map[identity.UserID][][]byte // oldest first
}

func newBrokenHistory(d historyDefect) *brokenHistory {
	return &brokenHistory{d: d, byUser: make(map[identity.UserID][][]byte)}
}

// brokenHistoryTxKey is the context key under which brokenHistory.Begin
// stores the transaction its methods read and write through.
type brokenHistoryTxKey struct{}

// brokenHistoryWrite is one retire or forget a transaction made.
type brokenHistoryWrite struct {
	user   identity.UserID
	forget bool
	hash   []byte
	keep   int
}

type brokenHistoryTx struct {
	base *brokenHistory

	mu     sync.Mutex
	view   map[identity.UserID][][]byte
	writes []brokenHistoryWrite
}

func (s *brokenHistory) txFrom(ctx context.Context) *brokenHistoryTx {
	tx, _ := ctx.Value(brokenHistoryTxKey{}).(*brokenHistoryTx)

	return tx
}

// viewLocked is called with tx.mu held, which is taken before base.mu.
func (tx *brokenHistoryTx) viewLocked(user identity.UserID) [][]byte {
	entries, touched := tx.view[user]
	if !touched {
		tx.base.mu.Lock()
		entries = slices.Clone(tx.base.byUser[user])
		tx.base.mu.Unlock()

		tx.view[user] = entries
	}

	return entries
}

func (s *brokenHistory) Begin(
	ctx context.Context,
) (txCtx context.Context, commit, rollback func() error, err error) {
	if s.d == historyDefectMissingBegin {
		return nil, nil, nil, identitytest.ErrHookUnsupported
	}

	tx := &brokenHistoryTx{base: s, view: make(map[identity.UserID][][]byte)}
	txCtx = context.WithValue(ctx, brokenHistoryTxKey{}, tx)

	var once sync.Once

	end := func(apply bool) func() error {
		return func() error {
			once.Do(func() {
				if !apply {
					return
				}

				tx.mu.Lock()
				defer tx.mu.Unlock()

				s.mu.Lock()
				defer s.mu.Unlock()

				if s.d == historyDefectCommitWritesReads {
					for user, entries := range tx.view {
						s.byUser[user] = entries
					}

					return
				}

				for _, w := range tx.writes {
					s.writeLocked(w)
				}
			})

			return nil
		}
	}

	commit = end(s.d != historyDefectCommitDiscards)
	// The rollback-keeps defect applies the transaction's writes on rollback
	// too, as a rollback that fails to discard them would.
	rollback = end(s.d == historyDefectRollbackKeeps)

	switch s.d {
	case historyDefectNilTxContext:
		txCtx = nil
	case historyDefectNilCommit:
		commit = nil
	case historyDefectNilRollback:
		rollback = nil
	}

	return txCtx, commit, rollback, nil
}

func (s *brokenHistory) RecentPasswords(
	ctx context.Context, user identity.UserID, n int,
) ([][]byte, error) {
	var entries [][]byte

	if tx := s.txFrom(ctx); tx != nil && s.d != historyDefectReadsIgnoreTx {
		tx.mu.Lock()
		entries = tx.viewLocked(user)
		tx.mu.Unlock()
	} else {
		s.mu.Lock()
		entries = slices.Clone(s.byUser[user])
		s.mu.Unlock()
	}

	if n <= 0 || len(entries) == 0 {
		return nil, nil
	}

	ordered := make([][]byte, len(entries))
	for i, hash := range entries {
		if s.d != historyDefectSharesReturnedBuffer {
			hash = bytes.Clone(hash)
		}

		ordered[i] = hash
	}

	if s.d != historyDefectOldestFirst {
		slices.Reverse(ordered)
	}

	if len(ordered) > n {
		ordered = ordered[:n]
	}

	return ordered, nil
}

func (s *brokenHistory) RetirePassword(
	ctx context.Context, user identity.UserID, hash []byte, keep int,
) error {
	if s.d != historyDefectKeepsCallerBuffer {
		hash = bytes.Clone(hash)
	}

	s.write(ctx, brokenHistoryWrite{user: user, hash: hash, keep: keep})

	return nil
}

func (s *brokenHistory) ForgetPasswords(ctx context.Context, user identity.UserID) error {
	s.write(ctx, brokenHistoryWrite{user: user, forget: true})

	return nil
}

func (s *brokenHistory) write(ctx context.Context, w brokenHistoryWrite) {
	if tx := s.txFrom(ctx); tx != nil {
		// The leak defect applies a forget to the shared records right away,
		// ahead of tx.mu, rather than waiting for commit to replay it.
		if w.forget && s.d == historyDefectTxForgetLeaks {
			s.mu.Lock()
			s.writeLocked(w)
			s.mu.Unlock()
		}

		tx.mu.Lock()
		defer tx.mu.Unlock()

		if w.forget {
			tx.view[w.user] = nil

			// The not-logged defect stops here: the view is updated, so a
			// read through this transaction sees the forget, but nothing is
			// appended to tx.writes for commit to replay.
			if s.d == historyDefectTxForgetNotLogged {
				return
			}
		} else {
			tx.view[w.user] = s.retire(tx.viewLocked(w.user), w.hash, w.keep)
		}

		tx.writes = append(tx.writes, w)

		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.writeLocked(w)
}

// writeLocked is called with s.mu held.
func (s *brokenHistory) writeLocked(w brokenHistoryWrite) {
	switch {
	case !w.forget:
		s.byUser[w.user] = s.retire(s.byUser[w.user], w.hash, w.keep)
	case s.d == historyDefectForgetNoop:
	case s.d == historyDefectForgetEveryone:
		clear(s.byUser)
	default:
		delete(s.byUser, w.user)
	}
}

// retire returns entries, oldest first, with hash retired and pruned to keep,
// never modifying entries itself.
func (s *brokenHistory) retire(entries [][]byte, hash []byte, keep int) [][]byte {
	if keep <= 0 && s.d != historyDefectIgnoresKeepZero {
		return nil
	}

	out := slices.Clone(entries)
	if !s.alreadyNewest(out, hash) {
		out = append(out, hash)
	} else if s.d == historyDefectDedupSkipsPrune {
		// A same-bytes retire that adds nothing must still prune to a keep
		// that has since shrunk; this defect returns before that check runs.
		return out
	}

	if s.d != historyDefectNeverPrunes && keep > 0 && len(out) > keep {
		out = out[len(out)-keep:]
	}

	return out
}

// alreadyNewest reports whether retiring hash adds nothing to entries.
func (s *brokenHistory) alreadyNewest(entries [][]byte, hash []byte) bool {
	if len(entries) == 0 {
		return false
	}

	switch s.d {
	case historyDefectIgnoresSameBytes:
		return false
	case historyDefectDedupAnywhere:
		return slices.ContainsFunc(entries, func(e []byte) bool { return bytes.Equal(e, hash) })
	case historyDefectDedupAgainstOldest:
		return bytes.Equal(entries[0], hash)
	default:
		return bytes.Equal(entries[len(entries)-1], hash)
	}
}

var _ identitytest.HistoryHarness = (*brokenHistory)(nil)

// TestBrokenHistoryConformance runs RunPasswordHistory against a history
// carrying the defect named by the environment, and is the child half of
// TestPasswordHistorySuiteIsLoadBearing. Without a defect named it skips: a
// plain run of this package has nothing to prove here.
func TestBrokenHistoryConformance(t *testing.T) {
	d, named := os.LookupEnv(historyDefectVar)
	if !named {
		t.Skipf("no defect named in %s; run through TestPasswordHistorySuiteIsLoadBearing", historyDefectVar)
	}

	t.Logf("history defect under test: %q", d)

	identitytest.RunPasswordHistory(t, func(t *testing.T) identitytest.HistoryHarness {
		t.Helper()

		return newBrokenHistory(historyDefect(d))
	})
}

// TestPasswordHistorySuiteIsLoadBearing checks RunPasswordHistory itself: for
// every defect above, a history carrying it must fail the suite, and a
// history carrying none must pass.
//
// It is the only thing that keeps the password-history part honest. Each
// defect runs in its own process because a failing suite reports through its
// own *testing.T, which cannot be substituted.
func TestPasswordHistorySuiteIsLoadBearing(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		defect historyDefect
		assert func(t *testing.T, err error, output string)
	}

	cases := make([]testCase, 0, len(everyHistoryDefect)+1)

	cases = append(cases, testCase{
		name:   "a history with no defect passes",
		defect: historyDefectNone,
		assert: func(t *testing.T, err error, output string) {
			require.NoError(t, err,
				"the suite rejected a conforming history, so every defect below fails for the "+
					"wrong reason:\n%s", output)
		},
	})

	for _, d := range everyHistoryDefect {
		cases = append(cases, testCase{
			name:   string(d) + " is caught",
			defect: d,
			assert: func(t *testing.T, err error, output string) {
				require.Error(t, err,
					"the suite passed a history whose %s defect breaks a contract the port "+
						"relies on:\n%s", d, output)
				// A failed run is not enough: a defect that trips the preflight is
				// reported as a missing hook, and the case written for it never runs.
				assert.NotContains(t, output, "identitytest: required hook",
					"the %s defect stopped the run at the preflight, so no case was shown to "+
						"catch it:\n%s", d, output)
				assert.Contains(t, output, "--- FAIL: TestBrokenHistoryConformance/",
					"no case of the suite failed by assertion for the %s defect:\n%s", d, output)
			},
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			output, err := runHistorySuiteInProcess(t, tc.defect)
			tc.assert(t, err, output)
		})
	}
}

// TestPasswordHistoryRequiresUsableBegin checks that a harness whose Begin is
// missing, or returns no context, commit or rollback, fails the run before a
// single case runs, with a message naming the hook and what it lacked.
func TestPasswordHistoryRequiresUsableBegin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		defect historyDefect
		assert func(t *testing.T, err error, output string)
	}

	refusedWith := func(message string) func(t *testing.T, err error, output string) {
		return func(t *testing.T, err error, output string) {
			require.Error(t, err, "a harness with an unusable Begin passed the suite")
			assert.Contains(t, output, message,
				"the failure must name the hook and what it lacked, or the implementer is left to guess")
			assert.Zero(t, strings.Count(output, "=== RUN   TestBrokenHistoryConformance/"),
				"cases ran although Begin was unusable")
		}
	}

	cases := []testCase{
		{
			name:   "a missing Begin",
			defect: historyDefectMissingBegin,
			assert: refusedWith("identitytest: required hook Begin is missing"),
		},
		{
			name:   "a Begin returning no context",
			defect: historyDefectNilTxContext,
			assert: refusedWith("identitytest: hook Begin returned no transaction context"),
		},
		{
			name:   "a Begin returning no commit",
			defect: historyDefectNilCommit,
			assert: refusedWith("identitytest: hook Begin returned no commit function"),
		},
		{
			name:   "a Begin returning no rollback",
			defect: historyDefectNilRollback,
			assert: refusedWith("identitytest: hook Begin returned no rollback function"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			output, err := runHistorySuiteInProcess(t, tc.defect, "-test.v")
			tc.assert(t, err, output)
		})
	}
}

// runHistorySuiteInProcess re-executes this test binary, running only the
// child test against a history carrying d, and returns its combined output.
// Extra test flags, such as -test.v, are passed to the child.
func runHistorySuiteInProcess(t *testing.T, d historyDefect, flags ...string) (string, error) {
	t.Helper()

	args := append([]string{
		"-test.run=^TestBrokenHistoryConformance$", "-test.count=1", "-test.timeout=5m",
	}, flags...)

	//nolint:gosec // G204: this test binary re-executed with fixed arguments
	cmd := exec.CommandContext(t.Context(), os.Args[0], args...)
	cmd.Env = append(os.Environ(), historyDefectVar+"="+string(d))

	out, err := cmd.CombinedOutput()

	assert.NotContains(t, string(out), "SKIP",
		"the child skipped rather than running the suite, so nothing was checked")

	return string(out), err
}
