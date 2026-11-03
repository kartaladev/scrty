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
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/apikey"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/test/storetest"
	"github.com/kartaladev/scrty/token/onetime"
	"github.com/kartaladev/scrty/token/signingkey"
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
			storetest.RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store {
				t.Helper()
				return saveInsertsStore{must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk.(clock.Timed))))}
			})
		},
		failsCase: "saving a deleted session is not found and does not bring it back",
	},
	sessionVariant(sessionConforming, ""),
	sessionVariant(sessionCountIdleOnly, "the active count is exactly the user's unexpired sessions"),
	sessionVariant(sessionCountSuperseded, "renewed sign-in counts once"),
	sessionVariant(sessionActivityPastAbsolute,
		"activity write never stores an idle deadline past the stored absolute deadline"),
	sessionVariant(sessionActivityStrict, "activity write at the threshold is written"),
	sessionVariant(sessionExceptDeletesAll,
		"deleting by user except one removes the user's other sessions, expired ones included, and keeps that one"),
	sessionVariant(sessionExceptKeepsOnlyNamed,
		"named session inside its window keeps its successor and ends an unrelated session"),
	sessionVariant(sessionExceptKeepsWholeFamily, "named current session ends its superseded predecessor"),
	sessionVariant(sessionExceptKeepsWholeFamily, "a named session whose family has no current member is kept alone"),
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
	sessionVariant(sessionWholeRecordActivity, "activity write leaves other fields"),
	sessionVariant(sessionSupersedeIgnoresSupersededSuccessor,
		"re-rotation observing a successor already superseded is refused and writes nothing"),
	sessionVariant(sessionSupersedeIgnoresGoneSuccessor,
		"re-rotation observing a successor no longer stored is refused and writes nothing"),
	sessionVariant(sessionSupersedeIgnoresPresentation,
		"supersession requiring an unpresented successor is refused once it was presented"),
	sessionVariant(sessionSupersedeRefusesRequired,
		"supersession requiring an unpresented successor supersedes one never presented"),
	sessionVariant(sessionSupersedeAdvancedBeforeConflict,
		"a stale observation is a renewal conflict even when the successor moved on"),
	sessionVariant(sessionSupersedeKnockedOut,
		"knocked-out successor renewed as if fresh is a renewal conflict and writes nothing"),
	sessionVariant(sessionCreateAcceptsNoFamily,
		"creating a session with no family is refused and stores nothing"),
	sessionVariant(sessionSupersedeKeepsOwnDeadline, "a superseded record keeps the retention deadline"),
	sessionVariant(sessionSupersedeUsesSuccessorDeadline, "a superseded record keeps the retention deadline"),
	sessionVariant(sessionSupersedePreviousKeepsOwnDeadline,
		"re-rotation supersedes the previous successor with a window that has ended"),
	sessionVariant(sessionSupersedeRewritesFamily,
		"earlier superseded sessions are untouched by later supersessions"),
	sessionVariant(sessionSupersedeAlwaysRequiresUnpresented,
		"re-rotation not requiring an unpresented successor supersedes one presented"),
	sessionVariant(sessionSupersedeRetainsEveryFamily,
		"a supersession leaves another family's superseded session unchanged"),
	sessionVariant(sessionSupersedeRetainsUnsuperseded,
		"a supersession leaves an unsuperseded member of the family unchanged"),
	sessionVariant(sessionSaveMovesAuthenticatedAt, "save keeps the authentication time"),
	sessionVariant(sessionSupersedeLowersDeadline, "a supersession never lowers a retention deadline"),
	sessionVariant(sessionSupersedeRaisesEachDeadline,
		"a supersession keeps the record's own deadlines apart from its retention"),
	sessionVariant(sessionSupersedeRaisesDeadlines,
		"a supersession keeps the record's own deadlines apart from its retention"),
	sessionVariant(sessionSupersedePreviousLowers, "a knocked-out successor keeps the later retention deadline"),
	sessionVariant(sessionLoadSupersededByDeadlines,
		"a superseded record loads past its own deadlines until its retention deadline"),
	sessionVariant(sessionSweepSupersededByDeadlines,
		"a superseded record is swept after its retention deadline, not by its own deadlines"),
	sessionVariant(sessionSaveMovesRetention,
		"a stale save of a superseded record changes neither its deadlines nor its retention"),
	sessionVariant(sessionSupersedeDropsStrictMark, "a supersession without grace is loaded marked as strict"),
	sessionVariant(sessionSupersedeDropsStrictMark,
		"a strict rotation through one manager makes a rotation of the old identifier through another a renewal conflict"),
	sessionVariant(sessionSaveWritesStrictMark, "saving a session never writes the strict mark"),
	sessionVariant(sessionSaveOntoStrictRow, "saving a strictly superseded session is refused"),
	sessionVariant(sessionCreateWritesStrictMark, "creating a session never writes the strict mark"),
	sessionVariant(sessionSupersedeMarksPreviousSuccessor,
		"a strict supersession through an observed successor marks Old and leaves the knocked-out successor unmarked"),
	sessionVariant(sessionSupersedeMarkSticky, "a later supersession overwrites the strict mark of an earlier one"),
	sessionVariant(sessionSupersedeAcceptsEarlyRetention,
		"a retention deadline before the window is refused and writes nothing"),
	sessionVariant(sessionSupersedeAcceptsNoFamilySuccessor,
		"a successor with no family is refused and writes nothing"),
	sessionVariant(sessionCreateAcceptsNoFamilyStart,
		"creating a session with no family start time is refused and stores nothing"),
	sessionVariant(sessionSupersedeAcceptsNoFamilyStart,
		"a successor with no family start time is refused and writes nothing"),
	sessionVariant(sessionDeleteKeepsFamilyMember, "deleting a session removes it from its family"),
	sessionVariant(sessionMarkPresentedSuperseded,
		"marking a superseded session's first presentation returns the superseded-session error and writes nothing"),
	sessionVariant(sessionSuccessorGoneAsUsed, "successor deleted reads as unused"),
	sessionVariant(sessionSuccessorReadsStaleRecord, "a record past its retention deadline is not stored, swept or not"),
	sessionVariant(sessionSuccessorIgnoresStaleness, "a successor past its own deadlines, unswept, reads as unused"),
	sessionVariant(sessionListFoldsCase, "listing returns only the user's own sessions, matching the reference exactly"),
	sessionVariant(sessionSaveWritesBinding, "a save keeps the key binding"),
	sessionVariant(sessionListIgnoresUser,
		"listing returns only the user's own sessions, matching the reference exactly"),
	sessionVariant(sessionListIncludesSuperseded,
		"listing returns one live head per family, without superseded or expired members"),
	sessionVariant(sessionListIncludesExpired,
		"listing judges expiry by the time the caller passes, not the store's clock"),
	sessionVariant(sessionSaveWritesMetadata, "a save keeps the sign-in metadata and the CSRF token"),
	sessionVariant(sessionSaveWritesCSRFToken, "a save keeps the sign-in metadata and the CSRF token"),
	sessionVariant(sessionSupersedeDropsSignInState,
		"a supersession inserts its successor with the successor's sign-in state"),
	{
		name: "session-" + string(sessionCreateRefusesEchoing),
		run: func(t *testing.T) {
			storetest.RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store {
				t.Helper()
				return newSessionStore(sessionCreateRefusesEchoing, clk)
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
	oneTimeVariant(oneTimeBoundedCountsThenInserts, "bounded inserts for one subject never exceed the limit"),
	oneTimeVariant(oneTimeBoundedWritesRefused,
		"a bounded insert counts as the recent-issue count does, and a refused one writes nothing"),
	oneTimeVariant(oneTimeBoundedCountsEverySubject, "bounded inserts count each subject on its own"),
	{
		name: "onetime-reaper-required-but-missing",
		run: func(t *testing.T) {
			storetest.RunOneTimeStoreSuite(t, func(t *testing.T, clk clock.Clock) onetime.Store {
				t.Helper()
				return withoutOneTimeReaper{must.Must(onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk)))}
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
				return withoutAttemptReaper{must.Must(lockout.NewMemoryAttemptStore())}
			}, storetest.RequireReaper())
		},
		failsCase: "a purge with a zero cutoff is refused and deletes nothing",
		failsWith: "store does not implement lockout.AttemptReaper, which RequireReaper demands",
	},
	{
		name: "signingkey-loadall-unordered",
		run: func(t *testing.T) {
			storetest.RunSigningKeyStoreSuite(t, func(t *testing.T) signingkey.KeyStore {
				t.Helper()
				return loadAllNewestFirstStore{signingkey.NewMemoryKeyStore()}
			})
		},
		failsCase: "keys load oldest first by creation time, whatever order they were stored in",
	},
	signingKeyDeleteVariant("signingkey-delete-removes-nothing", func() signingkey.KeyStore {
		return deleteRemovesNothingStore{signingkey.NewMemoryKeyStore()}
	}, "deleting removes only the named keys, and they are not loaded"),
	signingKeyDeleteVariant("signingkey-delete-removes-every-record", func() signingkey.KeyStore {
		return deleteRemovesEveryRecordStore{signingkey.NewMemoryKeyStore()}
	}, "deleting removes only the named keys, and they are not loaded"),
	signingKeyDeleteVariant("signingkey-delete-refuses-many", func() signingkey.KeyStore {
		return deleteRefusesManyStore{signingkey.NewMemoryKeyStore()}
	}, "a delete naming more keys than a statement can bind removes every named key"),
	signingKeyDeleteVariant("signingkey-delete-drops-past-the-bound", func() signingkey.KeyStore {
		return deleteDropsPastTheBoundStore{signingkey.NewMemoryKeyStore()}
	}, "a delete naming more keys than a statement can bind removes every named key"),
	signingKeyDeleteVariant("signingkey-delete-loses-the-last-of-the-first-batch", func() signingkey.KeyStore {
		return deleteLosesLastOfFirstBatchStore{signingkey.NewMemoryKeyStore()}
	}, "a delete naming more keys than a statement can bind removes every named key"),
	signingKeyDeleteVariant("signingkey-delete-missing-is-an-error", func() signingkey.KeyStore {
		return deleteMissingFailsStore{signingkey.NewMemoryKeyStore()}
	}, "deleting a missing key is not an error"),
	signingKeyDeleteVariant("signingkey-delete-nothing-empties-the-store", func() signingkey.KeyStore {
		return deleteNothingEmptiesStore{signingkey.NewMemoryKeyStore()}
	}, "delete with no keys is a no-op"),
	signingKeyDeleteVariant("signingkey-delete-unstorable-is-an-error", func() signingkey.KeyStore {
		return deleteRefusesUnstorableStore{signingkey.NewMemoryKeyStore()}
	}, "a key id no store could hold is missing, and does not stop the others going"),
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
	apiKeyVariant(apiKeyRevokeReportsEvery, "revoke reports whether this call revoked the key"),
	apiKeyVariant(apiKeyRevokeReadsThenWrites, "concurrent revokes of one live key report a revocation exactly once"),
}

func sessionVariant(d sessionDefect, failsCase string) brokenVariant {
	return brokenVariant{
		name: "session-" + string(d),
		run: func(t *testing.T) {
			newStore := func(t *testing.T, clk clock.Clock) session.Store {
				t.Helper()
				return newSessionStore(d, clk)
			}
			storetest.RunSessionStoreSuite(t, newStore)
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

// signingKeyDeleteVariant runs the signing-key suite over a store with one
// defect in its Delete.
func signingKeyDeleteVariant(name string, build func() signingkey.KeyStore, failsCase string) brokenVariant {
	return brokenVariant{
		name: name,
		run: func(t *testing.T) {
			storetest.RunSigningKeyStoreSuite(t, func(t *testing.T) signingkey.KeyStore {
				t.Helper()
				return build()
			})
		},
		failsCase: failsCase,
	}
}

// deleteRemovesNothingStore reports a delete it never made.
type deleteRemovesNothingStore struct{ signingkey.KeyStore }

func (deleteRemovesNothingStore) Delete(context.Context, ...string) error { return nil }

// deleteRemovesEveryRecordStore removes the whole table, whatever it is asked to
// remove.
type deleteRemovesEveryRecordStore struct{ signingkey.KeyStore }

func (s deleteRemovesEveryRecordStore) Delete(ctx context.Context, kids ...string) error {
	if len(kids) == 0 {
		return nil
	}
	recs, err := s.LoadAll(ctx)
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if err := s.KeyStore.Delete(ctx, rec.Kid); err != nil {
			return err
		}
	}
	return nil
}

// postgresBindLimit is how many bound parameters PostgreSQL accepts in a statement.
const postgresBindLimit = 65535

// deleteRefusesManyStore binds a parameter per key identifier, so a call naming
// more than the database accepts fails, and a store past that size never shrinks.
type deleteRefusesManyStore struct{ signingkey.KeyStore }

func (s deleteRefusesManyStore) Delete(ctx context.Context, kids ...string) error {
	if len(kids) > postgresBindLimit {
		return errors.New("extended protocol limited to 65535 parameters")
	}
	return s.KeyStore.Delete(ctx, kids...)
}

// deleteDropsPastTheBoundStore quietly ignores the key identifiers past the limit.
type deleteDropsPastTheBoundStore struct{ signingkey.KeyStore }

func (s deleteDropsPastTheBoundStore) Delete(ctx context.Context, kids ...string) error {
	return s.KeyStore.Delete(ctx, kids[:min(len(kids), postgresBindLimit)]...)
}

// deleteLosesLastOfFirstBatchStore splits a long delete into batches at the limit
// and loses the last key identifier of the first.
type deleteLosesLastOfFirstBatchStore struct{ signingkey.KeyStore }

func (s deleteLosesLastOfFirstBatchStore) Delete(ctx context.Context, kids ...string) error {
	if len(kids) <= postgresBindLimit {
		return s.KeyStore.Delete(ctx, kids...)
	}
	rest := slices.Concat(kids[:postgresBindLimit-1], kids[postgresBindLimit:])
	return s.KeyStore.Delete(ctx, rest...)
}

// deleteMissingFailsStore treats a key already gone as a failure, so one
// replica's delete fails another's.
type deleteMissingFailsStore struct{ signingkey.KeyStore }

func (s deleteMissingFailsStore) Delete(ctx context.Context, kids ...string) error {
	recs, err := s.LoadAll(ctx)
	if err != nil {
		return err
	}
	for _, kid := range kids {
		if !slices.ContainsFunc(recs, func(rec signingkey.Record) bool { return rec.Kid == kid }) {
			return errors.New("no such key")
		}
	}
	return s.KeyStore.Delete(ctx, kids...)
}

// deleteNothingEmptiesStore reads no key identifiers as every key.
type deleteNothingEmptiesStore struct{ signingkey.KeyStore }

func (s deleteNothingEmptiesStore) Delete(ctx context.Context, kids ...string) error {
	if len(kids) > 0 {
		return s.KeyStore.Delete(ctx, kids...)
	}
	recs, err := s.LoadAll(ctx)
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if err := s.KeyStore.Delete(ctx, rec.Kid); err != nil {
			return err
		}
	}
	return nil
}

// deleteRefusesUnstorableStore passes a key identifier it could never have
// stored on to its database, whose refusal then fails the whole delete.
type deleteRefusesUnstorableStore struct{ signingkey.KeyStore }

func (s deleteRefusesUnstorableStore) Delete(ctx context.Context, kids ...string) error {
	for _, kid := range kids {
		if strings.IndexByte(kid, 0) >= 0 || !utf8.ValidString(kid) {
			return errors.New("invalid byte sequence")
		}
	}
	return s.KeyStore.Delete(ctx, kids...)
}

func oneTimeVariant(d oneTimeDefect, failsCase string) brokenVariant {
	return brokenVariant{
		name: "onetime-" + string(d),
		run: func(t *testing.T) {
			storetest.RunOneTimeStoreSuite(t, func(t *testing.T, clk clock.Clock) onetime.Store {
				t.Helper()
				return newOneTimeStore(d, clk)
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
	if errors.Is(err, session.ErrNotFound) {
		return s.Create(ctx, sess)
	}
	return err
}

// withoutAttemptReaper hides the reaper of the attempt store it wraps, as a
// store that never implemented one.
type withoutAttemptReaper struct{ policy.AttemptStore }

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
	_, err := s.Confirm(ctx, e.User, e.Generation, e.LastStep, e.ConfirmedAt)
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

func (s revokeMovesTimeStore) Revoke(ctx context.Context, keyID id.ID, at time.Time) (bool, error) {
	rec, err := s.Get(ctx, keyID)
	if err != nil {
		return false, err
	}
	live := rec.RevokedAt == nil
	rec.RevokedAt = &at
	return live, s.Put(ctx, rec)
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
