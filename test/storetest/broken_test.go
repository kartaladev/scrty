package storetest_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/test/storetest"
)

// brokenVar names the environment variable that selects the one broken
// variant the child test runs a suite against. One variant per process, so
// the suite's verdict is attributable to that variant alone.
const brokenVar = "STORETEST_BROKEN"

// brokenVariant is a store carrying one deliberate defect, the suite it must
// fail, and the case that must catch it. A variant with no failing case is a
// conforming store the suite must pass, which shows the defects below fail
// for their defect and not for something else about the test store.
type brokenVariant struct {
	name      string
	run       func(t *testing.T)
	failsCase string
	// failsWith, when set, is text the child's output must carry: the
	// violation the failing case reports.
	failsWith string
}

// brokenVariants is every variant the guard runs: the portable suites' below,
// the enrolment path's (enrolmentPathVariants), then the durable suites'
// (durableVariants).
var brokenVariants = slices.Concat(portableVariants, enrolmentPathVariants, durableVariants)

// portableVariants are the portable suites' variants.
var portableVariants = []brokenVariant{
	{
		name: "session-save-inserts",
		run: func(t *testing.T) {
			storetest.RunSessionStoreSuite(t, func(t *testing.T, now func() time.Time) session.Store {
				t.Helper()
				return saveInsertsStore{session.NewMemoryStore(session.WithMemoryStoreClock(now))}
			})
		},
		failsCase: "saving a deleted session is not found and does not bring it back",
	},
	sessionVariant(sessionConforming, ""),
	sessionVariant(sessionCountIdleOnly, "the active count is exactly the user's unexpired sessions"),
	sessionVariant(sessionSavePartial, "a saved session loads with every field saved, its user and provider included"),
	sessionVariant(sessionCreateSharesData, "a created, saved or loaded session is the caller's own copy"),
	sessionVariant(sessionLoadSharesData, "a created, saved or loaded session is the caller's own copy"),
	sessionVariant(sessionSaveKeepsUnset, "a save that clears the data and provider fields loads them cleared"),
	sessionVariant(sessionLoadNoneAsPending, "a federated session loads with its provider fields unchanged"),
	sessionVariant(sessionLoadTruncatesSeconds, "session times keep at least microsecond precision"),
	sessionVariant(sessionLoadRoundsMicro, ""),
	sessionVariant(sessionSaveKeepsMFATime, "a save moves the second-factor time to the one saved"),
	sessionVariant(sessionCreateReplacesInvalidUTF8,
		"session data holding invalid UTF-8 is refused or round-trips, never altered"),
	sessionVariant(sessionCreateStripsNUL, "session data holding a NUL byte is refused or round-trips, never altered"),
	sessionVariant(sessionCreateStripsNULFromUser,
		"a user reference holding a NUL byte is refused or round-trips, never altered"),
	sessionVariant(sessionCreateRefusesText, ""),
	sessionVariant(sessionSaveReplacesInvalidUTF8,
		"a saved session's data holding invalid UTF-8 is refused or round-trips, never altered"),
	sessionVariant(sessionSaveRefusesText, ""),
	sessionVariant(sessionSaveStripsNUL,
		"a saved session's data holding a NUL byte is refused or round-trips, never altered"),
	sessionVariant(sessionSaveStripsNULFromUser,
		"a saved session's user reference holding a NUL byte is refused or round-trips, never altered"),
	sessionVariant(sessionSaveRefusesTextAfterPartialWrite,
		"a saved session's data holding a NUL byte is refused or round-trips, never altered"),
	{
		name: "session-" + string(sessionCreateRefusesEchoing),
		run: func(t *testing.T) {
			storetest.RunSessionStoreSuite(t, func(t *testing.T, now func() time.Time) session.Store {
				t.Helper()
				return newSessionStore(sessionCreateRefusesEchoing, now)
			})
		},
		failsCase: "session data holding a NUL byte is refused or round-trips, never altered",
		failsWith: "the refusal must not echo the value",
	},
	oneTimeVariant(oneTimeConforming, ""),
	oneTimeVariant(oneTimeConsumeMovesTime,
		"a second consume is not found and keeps the first consumption time"),
	oneTimeVariant(oneTimeReapAcceptsZero, "a purge with a zero cutoff is refused and deletes nothing"),
	oneTimeVariant(oneTimeReapInclusive,
		"a purge removes exactly this purpose's records expired by the clock and issued before the cutoff"),
	oneTimeVariant(oneTimeInsertKeepsSlices, "an inserted record is not changed by the caller writing to its buffers"),
	oneTimeVariant(oneTimeFindRefusesExpiredBySystem,
		"a record is found whatever its expiry, by the system clock or the store's"),
	oneTimeVariant(oneTimeFindRefusesExpiredByStore,
		"a record is found whatever its expiry, by the system clock or the store's"),
	oneTimeVariant(oneTimeFindSharesBinding, "a found record is the caller's own copy"),
	oneTimeVariant(oneTimeCountSkipsExpiredByStore,
		"the recent-issue count is exact, counting a record issued at since, spent ones and expired ones"),
	oneTimeVariant(oneTimeCountSkipsExpiredBySystem,
		"the recent-issue count is exact, counting a record issued at since, spent ones and expired ones"),
	oneTimeVariant(oneTimeConsumeRefusesExpiredBySystem,
		"consuming records when, expired or not, and changes nothing else"),
	oneTimeVariant(oneTimeConsumeRefusesExpiredByStore,
		"consuming records when, expired or not, and changes nothing else"),
	{
		name: "onetime-reaper-required-but-missing",
		run: func(t *testing.T) {
			storetest.RunOneTimeStoreSuite(t, func(t *testing.T, now func() time.Time) onetime.Store {
				t.Helper()
				return withoutOneTimeReaper{onetime.NewMemoryStore(onetime.WithMemoryStoreClock(now))}
			}, storetest.RequireReaper())
		},
		failsCase: "a purge with a zero cutoff is refused and deletes nothing",
		failsWith: "store does not implement onetime.Reaper, which RequireReaper demands",
	},
	attemptVariant(attemptConforming, ""),
	attemptVariant(attemptCountInclusive, "the failure count is exact and excludes a failure recorded at since"),
	attemptVariant(attemptReapInclusive,
		"a purge removes exactly the failures recorded strictly before the cutoff, for every identifier"),
	attemptVariant(attemptStripsNUL, "a username holding a NUL byte is refused or counted as given, never altered"),
	attemptVariant(attemptRefusesNUL, ""),
	{
		name: "attempts-reaper-required-but-missing",
		run: func(t *testing.T) {
			storetest.RunAttemptStoreSuite(t, func(t *testing.T) policy.AttemptStore {
				t.Helper()
				return policy.NewMemoryAttemptStore()
			}, storetest.RequireReaper())
		},
		failsCase: "a purge with a zero cutoff is refused and deletes nothing",
		failsWith: "store does not implement policy.AttemptReaper, which RequireReaper demands",
	},
	{
		name: "signingkey-loadall-unordered",
		run: func(t *testing.T) {
			storetest.RunSigningKeyStoreSuite(t, func(t *testing.T) signingkey.KeyStore {
				t.Helper()
				return loadAllNewestFirstStore{signingkey.NewInMemoryKeyStore()}
			})
		},
		failsCase: "keys load oldest first by creation time, whatever order they were stored in",
	},
	{
		name: "mfa-putpending-overwrites-confirmed",
		run: func(t *testing.T) {
			storetest.RunEnrolmentStoreSuite(t, func(t *testing.T) mfa.EnrolmentStore {
				t.Helper()
				return putPendingOverwritesStore{mfa.NewMemoryEnrolmentStore()}
			})
		},
		failsCase: "a begin over a confirmed enrolment is refused and leaves it unchanged",
	},
	{
		name: "mfa-putpending-verbatim",
		run: func(t *testing.T) {
			storetest.RunEnrolmentStoreSuite(t, func(t *testing.T) mfa.EnrolmentStore {
				t.Helper()
				return putPendingVerbatimStore{mfa.NewMemoryEnrolmentStore()}
			})
		},
		failsCase: "a begin is stored pending with no step spent, whatever confirmation and step it is given",
	},
	mfaVariant(mfaConforming, ""),
	mfaVariant(mfaAcceptStepMovesBack, "a step is accepted only when it is after the recorded one"),
	mfaVariant(mfaReplaceKeepsGiven,
		"a second begin while pending replaces it, pending with no step spent whatever it is given"),
	{
		name: "apikey-revoke-moves-time",
		run: func(t *testing.T) {
			storetest.RunAPIKeyStoreSuite(t, func(t *testing.T) apikey.Store {
				t.Helper()
				return revokeMovesTimeStore{apikey.NewMemoryStore()}
			})
		},
		failsCase: "revoking records when, and a second revoke keeps the first time",
	},
	apiKeyVariant(apiKeyConforming, ""),
	apiKeyVariant(apiKeyTouchKeepsFirst, "touching records the latest use and changes nothing else"),
	apiKeyVariant(apiKeyPutKeepsSlices, "a stored key is not changed by the caller writing to what it put"),
	apiKeyVariant(apiKeyGetSharesSlices, "a stored key is not changed by the caller writing to what it read"),
	apiKeyVariant(apiKeyListSharesSlices, "a stored key is not changed by the caller writing to what it listed"),
	apiKeyVariant(apiKeyGetDropsExpired, "expired keys are still found and listed"),
	apiKeyVariant(apiKeyListDropsExpired, "expired keys are still found and listed"),
	apiKeyVariant(apiKeyPutDropsUse, "a stored key is found with every field unchanged"),
	apiKeyVariant(apiKeyGetTruncatesMillis, "key times keep at least microsecond precision"),
	apiKeyVariant(apiKeyPutRefusesNoScopes, "a key with nil or empty scopes is stored and found with none"),
	apiKeyVariant(apiKeyPutAltersText, "a scope holding invalid UTF-8 is refused or round-trips, never altered"),
	apiKeyVariant(apiKeyPutRefusesText, ""),
}

func sessionVariant(d sessionDefect, failsCase string) brokenVariant {
	return brokenVariant{
		name: "session-" + string(d),
		run: func(t *testing.T) {
			storetest.RunSessionStoreSuite(t, func(t *testing.T, now func() time.Time) session.Store {
				t.Helper()
				return newSessionStore(d, now)
			})
		},
		failsCase: failsCase,
	}
}

func mfaVariant(d mfaDefect, failsCase string) brokenVariant {
	return brokenVariant{
		name: "mfa-" + string(d),
		run: func(t *testing.T) {
			storetest.RunEnrolmentStoreSuite(t, func(t *testing.T) mfa.EnrolmentStore {
				t.Helper()
				return newMFAStore(d)
			})
		},
		failsCase: failsCase,
	}
}

func apiKeyVariant(d apiKeyDefect, failsCase string) brokenVariant {
	return brokenVariant{
		name: "apikey-" + string(d),
		run: func(t *testing.T) {
			storetest.RunAPIKeyStoreSuite(t, func(t *testing.T) apikey.Store {
				t.Helper()
				return newAPIKeyStore(d)
			})
		},
		failsCase: failsCase,
	}
}

func attemptVariant(d attemptDefect, failsCase string) brokenVariant {
	return brokenVariant{
		name: "attempts-" + string(d),
		run: func(t *testing.T) {
			storetest.RunAttemptStoreSuite(t, func(t *testing.T) policy.AttemptStore {
				t.Helper()
				return newAttemptStore(d)
			}, storetest.RequireReaper())
		},
		failsCase: failsCase,
	}
}

// loadAllNewestFirstStore returns its keys in the reverse of the order the
// contract requires.
type loadAllNewestFirstStore struct{ signingkey.KeyStore }

func (s loadAllNewestFirstStore) LoadAll(ctx context.Context) ([]signingkey.Record, error) {
	recs, err := s.KeyStore.LoadAll(ctx)
	slices.Reverse(recs)
	return recs, err
}

func oneTimeVariant(d oneTimeDefect, failsCase string) brokenVariant {
	return brokenVariant{
		name: "onetime-" + string(d),
		run: func(t *testing.T) {
			storetest.RunOneTimeStoreSuite(t, func(t *testing.T, now func() time.Time) onetime.Store {
				t.Helper()
				return newOneTimeStore(d, now)
			}, storetest.RequireReaper())
		},
		failsCase: failsCase,
	}
}

// saveInsertsStore re-creates a session its Save does not find, so a request
// that raced a logout writes the revoked session back.
type saveInsertsStore struct{ *session.MemoryStore }

func (s saveInsertsStore) Save(ctx context.Context, sess *session.Session) error {
	err := s.MemoryStore.Save(ctx, sess)
	if errors.Is(err, session.ErrSessionNotFound) {
		return s.Create(ctx, sess)
	}
	return err
}

// withoutOneTimeReaper hides the reaper of the store it wraps, as a store
// that never implemented one.
type withoutOneTimeReaper struct{ onetime.Store }

// putPendingVerbatimStore stores a begin as given, so a caller handing it a
// confirmation time and a spent step starts an enrolment already confirmed.
type putPendingVerbatimStore struct{ *mfa.MemoryEnrolmentStore }

func (s putPendingVerbatimStore) PutPending(ctx context.Context, e mfa.Enrolment) error {
	if err := s.MemoryEnrolmentStore.PutPending(ctx, e); err != nil || e.ConfirmedAt.IsZero() {
		return err
	}
	_, err := s.Confirm(ctx, e.User, e.LastStep, e.ConfirmedAt)
	return err
}

// putPendingOverwritesStore replaces a confirmed enrolment on a new begin,
// silently swapping a working second factor for one an attacker provisioned.
type putPendingOverwritesStore struct{ *mfa.MemoryEnrolmentStore }

func (s putPendingOverwritesStore) PutPending(ctx context.Context, e mfa.Enrolment) error {
	err := s.MemoryEnrolmentStore.PutPending(ctx, e)
	if errors.Is(err, mfa.ErrAlreadyEnrolled) {
		if err := s.Delete(ctx, e.User); err != nil {
			return err
		}
		return s.MemoryEnrolmentStore.PutPending(ctx, e)
	}
	return err
}

// revokeMovesTimeStore overwrites a revoked key's revocation time on every
// later revoke.
type revokeMovesTimeStore struct{ *apikey.MemoryStore }

func (s revokeMovesTimeStore) Revoke(ctx context.Context, keyID id.ID, at time.Time) error {
	rec, err := s.Get(ctx, keyID)
	if err != nil {
		return err
	}
	rec.RevokedAt = &at
	return s.Put(ctx, rec)
}

// TestBrokenStoreConformance runs one suite against the broken variant named
// by the environment, and is the child half of TestSuitesCatchBrokenStores.
// Without a variant named it skips.
func TestBrokenStoreConformance(t *testing.T) {
	name, named := os.LookupEnv(brokenVar)
	if !named {
		t.Skipf("no variant named in %s; run through TestSuitesCatchBrokenStores", brokenVar)
	}

	for _, v := range brokenVariants {
		if v.name == name {
			t.Logf("variant under test: %q", name)
			v.run(t)
			return
		}
	}
	t.Fatalf("no broken variant is named %q", name)
}

// failedCase matches a failed case of the child test in its output.
var failedCase = regexp.MustCompile(`--- FAIL: TestBrokenStoreConformance/(\S+)`)

// TestSuitesCatchBrokenStores checks the suites themselves: each must fail
// against every broken variant of its store, at the case that guards the
// broken behaviour. A suite never seen failing proves nothing. Each variant
// runs in its own process, because a failing suite reports through its own
// *testing.T and would fail this test with it.
func TestSuitesCatchBrokenStores(t *testing.T) {
	t.Parallel()

	for _, v := range brokenVariants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()

			//nolint:gosec // G204: this test binary re-executed with fixed arguments
			cmd := exec.CommandContext(t.Context(), os.Args[0],
				"-test.run=^TestBrokenStoreConformance$", "-test.count=1", "-test.v", "-test.timeout=5m")
			cmd.Env = append(os.Environ(), brokenVar+"="+v.name)
			out, err := cmd.CombinedOutput()
			output := string(out)

			require.NotContains(t, output, "--- SKIP: TestBrokenStoreConformance",
				"the child skipped rather than running the suite, so nothing was checked")

			if v.failsCase == "" {
				require.NoError(t, err, "the suite rejected a conforming store:\n%s", output)
				return
			}

			require.Error(t, err, "the suite passed a store carrying the %s defect:\n%s", v.name, output)
			var failed []string
			for _, m := range failedCase.FindAllStringSubmatch(output, -1) {
				failed = append(failed, m[1])
			}
			t.Logf("cases failed by %s: %v", v.name, failed)
			assert.Contains(t, failed, strings.ReplaceAll(v.failsCase, " ", "_"),
				"the suite failed, but not at the case that guards this defect:\n%s", output)
			if v.failsWith != "" {
				assert.Contains(t, output, v.failsWith, "the failure does not report the violation")
			}
		})
	}
}
