package storetest

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

// The purpose and subject most one-time records carry. The subject has mixed
// case and a trailing space, so a store that folds or trims it is caught.
const (
	oneTimePurpose = "verify-email"
	oneTimeSubject = "Alice@Example.COM "
	oneTimeTTL     = 15 * time.Minute
)

// oneTimeToken returns the suite's n-th record, bound and unspent, issued at
// issued and expiring oneTimeTTL later.
func oneTimeToken(n int, issued time.Time) onetime.Token {
	secret := sha256.Sum256(fmt.Appendf(nil, "secret-%d", n))
	binding := sha256.Sum256([]byte("binding"))

	return onetime.Token{
		ID:          suiteID(n),
		Purpose:     oneTimePurpose,
		Subject:     oneTimeSubject,
		SecretHash:  secret[:],
		BindingHash: binding[:],
		IssuedAt:    issued,
		ExpiresAt:   issued.Add(oneTimeTTL),
	}
}

// assertOneTimeToken compares a found record with the one inserted.
func assertOneTimeToken(t *testing.T, want onetime.Token, got *onetime.Token) {
	t.Helper()

	require.NotNil(t, got, "a found record must not be nil")
	assert.Equal(t, want.ID, got.ID)
	assert.Equal(t, want.Purpose, got.Purpose)
	assert.Equal(t, want.Subject, got.Subject, "the subject must round-trip byte for byte")
	assert.Equal(t, want.SecretHash, got.SecretHash)
	if want.BindingHash == nil {
		assert.Nil(t, got.BindingHash, "an absent binding must stay absent, not become empty")
	} else {
		assert.Equal(t, want.BindingHash, got.BindingHash)
	}
	assertTimeEqual(t, want.IssuedAt, got.IssuedAt, "IssuedAt")
	assertTimeEqual(t, want.ExpiresAt, got.ExpiresAt, "ExpiresAt")
	assertTimeEqual(t, want.ConsumedAt, got.ConsumedAt, "ConsumedAt")
}

// insertOneTime stores every record, failing the case at the first error.
func insertOneTime(ctx context.Context, t *testing.T, s onetime.Store, toks ...onetime.Token) {
	t.Helper()

	for _, tok := range toks {
		require.NoError(t, s.Insert(ctx, tok), "insert %s", tok.ID)
	}
}

// assertOneTimeFound requires each record to be found unchanged.
func assertOneTimeFound(ctx context.Context, t *testing.T, s onetime.Store, toks ...onetime.Token) {
	t.Helper()

	for _, want := range toks {
		got, err := s.FindByID(ctx, want.ID)
		if assert.NoError(t, err, "record %s must still be found", want.ID) {
			assertOneTimeToken(t, want, got)
		}
	}
}

// RunOneTimeStoreSuite checks a onetime.Store against the contract the
// one-time token manager relies on: records round-trip unchanged, an absent
// binding included, and are the caller's own copies; Insert never replaces;
// Consume succeeds once, whatever the record's expiry, keeps the first
// consumption time, and refuses an unknown or zero identifier as not found;
// and the recent-issue count is exact at its boundary and counts expired
// records.
//
// When the store also implements onetime.Reaper, the suite checks that a zero
// cutoff is refused and deletes nothing, and that a purge removes exactly the
// records of its purpose that are expired by the store's clock and were
// issued strictly before the cutoff. A store without a reaper is reported in
// the log and those cases do not run, since the reaper is optional in the
// contract; under RequireReaper they fail instead.
//
// newStore is called once per case and must return an empty store that reads
// time from clk. Only the reaper may consult it: the suite also advances it past
// the records' expiry around finding, consuming and counting, which judge no
// expiry.
//
// Stored times may be truncated or rounded to the microsecond, as the
// PostgreSQL stores do, and are compared by instant.
func RunOneTimeStoreSuite(
	t *testing.T, newStore func(t *testing.T, clk clock.Clock) onetime.Store, opts ...SuiteOption,
) {
	t.Helper()

	type oneTimeCase = suiteCase[onetime.Store]

	cfg := newSuiteConfig(opts)

	cases := []oneTimeCase{
		{
			name: "an inserted record is found unchanged",
			assert: func(t *testing.T, ctx context.Context, s onetime.Store, _ *clockwork.FakeClock) {
				tok := oneTimeToken(1, suiteStart)
				require.NoError(t, s.Insert(ctx, tok))

				assertOneTimeFound(ctx, t, s, tok)
			},
		},
		{
			name: "an unbound record is found with no binding",
			assert: func(t *testing.T, ctx context.Context, s onetime.Store, _ *clockwork.FakeClock) {
				tok := oneTimeToken(1, suiteStart)
				tok.BindingHash = nil
				require.NoError(t, s.Insert(ctx, tok))

				assertOneTimeFound(ctx, t, s, tok)
			},
		},
		{
			name: "a found record is the caller's own copy",
			assert: func(t *testing.T, ctx context.Context, s onetime.Store, _ *clockwork.FakeClock) {
				tok := oneTimeToken(1, suiteStart)
				require.NoError(t, s.Insert(ctx, tok))

				got, err := s.FindByID(ctx, tok.ID)
				require.NoError(t, err)
				require.NotNil(t, got)
				clear(got.SecretHash)
				clear(got.BindingHash)
				got.Subject = "mallory"
				got.ConsumedAt = suiteStart

				assertOneTimeFound(ctx, t, s, oneTimeToken(1, suiteStart))
			},
		},
		{
			name: "an inserted record is not changed by the caller writing to its buffers",
			assert: func(t *testing.T, ctx context.Context, s onetime.Store, _ *clockwork.FakeClock) {
				tok := oneTimeToken(1, suiteStart)
				require.NoError(t, s.Insert(ctx, tok))
				clear(tok.SecretHash)
				clear(tok.BindingHash)

				assertOneTimeFound(ctx, t, s, oneTimeToken(1, suiteStart))
			},
		},
		{
			name: "record times keep at least microsecond precision",
			assert: func(t *testing.T, ctx context.Context, s onetime.Store, _ *clockwork.FakeClock) {
				tok := oneTimeToken(1, preciseStart)
				require.NoError(t, s.Insert(ctx, tok))
				tok.ConsumedAt = preciseStart.Add(time.Minute)
				require.NoError(t, s.Consume(ctx, tok.ID, tok.ConsumedAt))

				got, err := s.FindByID(ctx, suiteID(1))
				require.NoError(t, err)
				assertTimeMicro(t, tok.IssuedAt, got.IssuedAt, "IssuedAt")
				assertTimeMicro(t, tok.ExpiresAt, got.ExpiresAt, "ExpiresAt")
				assertTimeMicro(t, tok.ConsumedAt, got.ConsumedAt, "ConsumedAt")
			},
		},
		{
			// Expiry is the manager's to judge, so neither the system clock nor
			// the store's may hide a record expired by it.
			name: "a record is found whatever its expiry, by the system clock or the store's",
			assert: func(t *testing.T, ctx context.Context, s onetime.Store, clock *clockwork.FakeClock) {
				longAgo := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
				expiredBySystem := oneTimeToken(1, longAgo)
				expiredByStore := oneTimeToken(2, suiteStart)
				insertOneTime(ctx, t, s, expiredBySystem, expiredByStore)
				clock.Advance((expiredByStore.ExpiresAt.Add(time.Hour)).Sub(clock.Now()))

				assertOneTimeFound(ctx, t, s, expiredBySystem, expiredByStore)
			},
		},
		{
			name: "a duplicate insert errors and leaves the original unchanged",
			assert: func(t *testing.T, ctx context.Context, s onetime.Store, _ *clockwork.FakeClock) {
				original := oneTimeToken(1, suiteStart)
				require.NoError(t, s.Insert(ctx, original))

				usurper := oneTimeToken(1, suiteStart.Add(time.Minute))
				usurper.Subject = "mallory"
				require.Error(t, s.Insert(ctx, usurper), "inserting over a stored identifier must fail")

				assertOneTimeFound(ctx, t, s, original)
			},
		},
		{
			name: "finding an unknown record is not found",
			assert: func(t *testing.T, ctx context.Context, s onetime.Store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Insert(ctx, oneTimeToken(1, suiteStart)))

				for _, unknown := range []id.ID{suiteID(2), id.Nil} {
					_, err := s.FindByID(ctx, unknown)
					require.ErrorIs(t, err, onetime.ErrTokenNotFound, "record %s", unknown)
				}
			},
		},
		{
			// Expiry is the manager's to judge, before it consumes, so neither
			// the system clock nor the store's may refuse a record expired by it.
			name: "consuming records when, expired or not, and changes nothing else",
			assert: func(t *testing.T, ctx context.Context, s onetime.Store, clock *clockwork.FakeClock) {
				// The store's clock starts before any record was issued, so the
				// first record is expired by the system clock alone.
				longAgo := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
				clock.Advance((longAgo.Add(-time.Hour)).Sub(clock.Now()))
				expiredBySystem := oneTimeToken(2, longAgo)
				insertOneTime(ctx, t, s, oneTimeToken(1, suiteStart), expiredBySystem)

				at := suiteStart.Add(time.Minute)
				require.NoError(t, s.Consume(ctx, suiteID(1), at))
				require.NoError(t, s.Consume(ctx, expiredBySystem.ID, at),
					"a record expired by the system clock is consumed")

				want := oneTimeToken(1, suiteStart)
				want.ConsumedAt = at
				expiredBySystem.ConsumedAt = at
				assertOneTimeFound(ctx, t, s, want, expiredBySystem)

				expiredByStore := oneTimeToken(3, suiteStart)
				require.NoError(t, s.Insert(ctx, expiredByStore))
				clock.Advance((expiredByStore.ExpiresAt.Add(time.Hour)).Sub(clock.Now()))
				require.NoError(t, s.Consume(ctx, expiredByStore.ID, at),
					"a record expired by the store's clock is consumed")

				expiredByStore.ConsumedAt = at
				assertOneTimeFound(ctx, t, s, expiredByStore)
			},
		},
		{
			name: "a second consume is not found and keeps the first consumption time",
			assert: func(t *testing.T, ctx context.Context, s onetime.Store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Insert(ctx, oneTimeToken(1, suiteStart)))

				first := suiteStart.Add(time.Minute)
				require.NoError(t, s.Consume(ctx, suiteID(1), first))
				require.ErrorIs(t, s.Consume(ctx, suiteID(1), first.Add(time.Minute)), onetime.ErrTokenNotFound,
					"a spent record must not be consumed again")

				want := oneTimeToken(1, suiteStart)
				want.ConsumedAt = first
				assertOneTimeFound(ctx, t, s, want)
			},
		},
		{
			name: "consuming an unknown or zero identifier is not found and spends nothing",
			assert: func(t *testing.T, ctx context.Context, s onetime.Store, _ *clockwork.FakeClock) {
				tok := oneTimeToken(1, suiteStart)
				require.NoError(t, s.Insert(ctx, tok))

				for _, unknown := range []id.ID{suiteID(2), id.Nil} {
					require.ErrorIs(t, s.Consume(ctx, unknown, suiteStart), onetime.ErrTokenNotFound,
						"record %s", unknown)
				}
				assertOneTimeFound(ctx, t, s, tok)
			},
		},
		{
			// What is counted is how often the subject asked, so a record
			// expired inside the window still counts: leaving it out would let
			// a subject wait out their tokens' expiry and ask again unlimited.
			// That is why the reaper keeps such records.
			name: "the recent-issue count is exact, counting a record issued at since, spent ones and expired ones",
			assert: func(t *testing.T, ctx context.Context, s onetime.Store, clock *clockwork.FakeClock) {
				since := suiteStart.Add(time.Hour)
				otherSubject := oneTimeToken(5, since.Add(time.Minute))
				otherSubject.Subject = "alice@example.com"
				otherPurpose := oneTimeToken(6, since.Add(time.Minute))
				otherPurpose.Purpose = "reset-password"
				expiredBySystem := oneTimeToken(7, since.Add(2*time.Minute))
				expiredBySystem.ExpiresAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
				insertOneTime(ctx, t, s,
					oneTimeToken(1, since.Add(-time.Second)),
					oneTimeToken(2, since),
					oneTimeToken(3, since.Add(time.Minute)),
					otherSubject,
					otherPurpose,
					expiredBySystem,
				)
				require.NoError(t, s.Consume(ctx, suiteID(3), since.Add(2*time.Minute)))
				clock.Advance((since.Add(oneTimeTTL + time.Hour)).Sub(clock.Now()))

				n, err := s.CountRecentBySubject(ctx, oneTimePurpose, oneTimeSubject, since)
				require.NoError(t, err)
				assert.Equal(t, 3, n,
					"issued at since counts, before it does not, spent ones and ones expired by either clock count")

				n, err = s.CountRecentBySubject(ctx, oneTimePurpose, "nobody", since)
				require.NoError(t, err)
				assert.Zero(t, n)
			},
		},
		optionalCase(
			cfg.requireReaper,
			"a purge with a zero cutoff is refused and deletes nothing",
			func(t *testing.T, ctx context.Context, s onetime.Store, reaper onetime.Reaper, clock *clockwork.FakeClock) {
				toks := []onetime.Token{oneTimeToken(1, suiteStart), oneTimeToken(2, suiteStart)}
				insertOneTime(ctx, t, s, toks...)
				clock.Advance((suiteStart.Add(24 * time.Hour)).Sub(clock.Now()))

				n, err := reaper.DeleteExpiredBefore(ctx, oneTimePurpose, time.Time{})
				require.ErrorIs(t, err, onetime.ErrRetainSinceRequired)
				assert.Zero(t, n)
				assertOneTimeFound(ctx, t, s, toks...)
			},
		),
		optionalCase(
			cfg.requireReaper,
			"a purge removes exactly this purpose's records expired by the clock and issued before the cutoff",
			func(t *testing.T, ctx context.Context, s onetime.Store, reaper onetime.Reaper, clock *clockwork.FakeClock) {
				cutoff := suiteStart.Add(time.Hour)
				now := suiteStart.Add(2 * time.Hour)

				expiringNow := oneTimeToken(3, suiteStart.Add(20*time.Minute))
				expiringNow.ExpiresAt = now
				issuedAtCutoff := oneTimeToken(4, cutoff)
				issuedAfter := oneTimeToken(5, cutoff.Add(10*time.Minute))
				live := oneTimeToken(6, suiteStart.Add(30*time.Minute))
				live.ExpiresAt = now.Add(time.Second)
				otherPurpose := oneTimeToken(7, suiteStart)
				otherPurpose.Purpose = "reset-password"
				insertOneTime(ctx, t, s,
					oneTimeToken(1, suiteStart),
					oneTimeToken(2, suiteStart.Add(10*time.Minute)),
					expiringNow, issuedAtCutoff, issuedAfter, live, otherPurpose)
				clock.Advance((now).Sub(clock.Now()))

				n, err := reaper.DeleteExpiredBefore(ctx, oneTimePurpose, cutoff)
				require.NoError(t, err)
				assert.Equal(t, 3, n, "expired at or before now, issued strictly before the cutoff, this purpose")

				for _, gone := range []id.ID{suiteID(1), suiteID(2), suiteID(3)} {
					_, err := s.FindByID(ctx, gone)
					assert.ErrorIs(t, err, onetime.ErrTokenNotFound, "record %s must be purged", gone)
				}
				assertOneTimeFound(ctx, t, s, issuedAtCutoff, issuedAfter, live, otherPurpose)
			},
		),
	}

	runSuite(t, cases, newStore)
}
