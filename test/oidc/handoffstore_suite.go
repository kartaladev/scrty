package oidctest

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
)

// handoffSuiteIssued is when every record in the suite was issued. It is whole
// seconds so a durable store that truncates sub-second precision still
// compares equal.
var handoffSuiteIssued = time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

// handoffSuiteNow is the store's clock in every case: an hour after issue, so
// every record the suite writes has expired by it and only the cutoff decides
// what a purge removes.
var handoffSuiteNow = handoffSuiteIssued.Add(time.Hour)

// handoffSuiteRacers is how many concurrent consumes of one record the race
// row starts.
const handoffSuiteRacers = 8

// handoffSuiteID derives the id a record for tokenID is stored under: unique
// per token id and non-zero, as a durable store's own primary key requires
// (see oidc.HandoffRecord.ID). It is a pure function of tokenID, so every
// call for the same tokenID agrees, including the calls handoffSuiteRecord
// makes to build the record a case compares a find against.
func handoffSuiteID(tokenID string) id.ID {
	sum := sha256.Sum256([]byte("handoff-id-of-" + tokenID))
	var v id.ID
	copy(v[:], sum[:16])

	return v
}

// handoffSuiteRecord returns a record for tokenID, issued at
// handoffSuiteIssued and expiring a minute later.
func handoffSuiteRecord(tokenID string) oidc.HandoffRecord {
	sum := sha256.Sum256([]byte("secret-of-" + tokenID))

	return oidc.HandoffRecord{
		ID:         handoffSuiteID(tokenID),
		TokenID:    tokenID,
		SecretHash: sum[:],
		UserID:     "u-1",
		Provider:   "corp",
		Issuer:     "https://corp.example",
		SessionID:  "sid-1",
		IDToken:    "header.payload.signature",
		Next:       "/home",
		CreatedAt:  handoffSuiteIssued,
		ExpiresAt:  handoffSuiteIssued.Add(time.Minute),
	}
}

// assertHandoffRecord compares a stored record with the one inserted, reading
// times by instant so a store that returns another location still conforms.
func assertHandoffRecord(t *testing.T, want oidc.HandoffRecord, got *oidc.HandoffRecord) {
	t.Helper()

	require.NotNil(t, got, "a found record must not be nil")
	assert.Equal(t, want.ID, got.ID)
	assert.Equal(t, want.TokenID, got.TokenID)
	assert.Equal(t, want.SecretHash, got.SecretHash)
	assert.Equal(t, want.UserID, got.UserID, "the user reference must round-trip unchanged")
	assert.Equal(t, want.Provider, got.Provider)
	assert.Equal(t, want.Issuer, got.Issuer)
	assert.Equal(t, want.SessionID, got.SessionID)
	assert.Equal(t, want.IDToken, got.IDToken)
	assert.Equal(t, want.Next, got.Next)
	if len(want.AMR) == 0 {
		assert.Empty(t, got.AMR, "a record stored without amr must read back with none")
	} else {
		assert.Equal(t, want.AMR, got.AMR, "the asserted amr must round-trip in order")
	}
	assert.Equal(t, want.ACR, got.ACR, "the asserted acr must round-trip unchanged")
	assert.True(t, want.CreatedAt.Equal(got.CreatedAt), "created at %v, want %v", got.CreatedAt, want.CreatedAt)
	assert.True(t, want.ExpiresAt.Equal(got.ExpiresAt), "expires at %v, want %v", got.ExpiresAt, want.ExpiresAt)
	if want.ConsumedAt == nil {
		assert.Nil(t, got.ConsumedAt, "an unconsumed record must read back unconsumed")
	} else if assert.NotNil(t, got.ConsumedAt, "a consumed record must read back consumed") {
		assert.True(t, want.ConsumedAt.Equal(*got.ConsumedAt),
			"consumed at %v, want %v", *got.ConsumedAt, *want.ConsumedAt)
	}
}

// RunHandoffStoreSuite checks a HandoffStore against the contract the handoff
// manager relies on: records round-trip unchanged and are the caller's own
// copies; a missing record is ErrHandoffNotFound; Consume succeeds once for an
// unconsumed record and exactly once among eight racing callers; and
// DeleteExpired removes only records expired before the cutoff, refusing a
// zero cutoff with ErrRetainSinceRequired and deleting nothing.
//
// newStore is called once per case and must return an empty store whose clock
// is now, for an adapter that has a use for one. DeleteExpired must not
// consult it: expiry is judged against the cutoff it is given alone, so a
// durable adapter with no clock of its own may simply ignore now.
//
// A consumer implementing HandoffStore over their own tables calls this from
// a test in their own module:
//
//	func TestMyHandoffStoreConformance(t *testing.T) {
//	    oidctest.RunHandoffStoreSuite(t, func(t *testing.T, clk clock.Clock) oidc.HandoffStore {
//	        return newMyHandoffStore(t, clk)
//	    })
//	}
func RunHandoffStoreSuite(t *testing.T, newStore func(t *testing.T, clk clock.Clock) oidc.HandoffStore) {
	t.Helper()

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, s oidc.HandoffStore)
	}

	// textCase inserts the record handoffSuiteRecord returns, changed by with
	// to carry text a PostgreSQL column cannot hold, marked by canary. The
	// store either refuses it, with an error that does not echo it, and stores
	// nothing; or stores it and finds it byte for byte. Anything else altered
	// the consumer's value.
	textCase := func(name, canary string, with func(*oidc.HandoffRecord)) testCase {
		return testCase{
			name: name,
			assert: func(t *testing.T, ctx context.Context, s oidc.HandoffStore) {
				want := handoffSuiteRecord("tok-a")
				with(&want)

				if err := s.Insert(ctx, want); err != nil {
					assert.NotContains(t, err.Error(), canary, "the refusal must not echo the value")
					_, err := s.FindByTokenID(ctx, "tok-a")
					assert.ErrorIs(t, err, oidc.ErrHandoffNotFound, "a refused record must not be stored")

					return
				}

				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assertHandoffRecord(t, want, got)
			},
		}
	}

	cases := []testCase{
		{
			name: "an inserted record is found unchanged",
			assert: func(t *testing.T, ctx context.Context, s oidc.HandoffStore) {
				require.NoError(t, s.Insert(ctx, handoffSuiteRecord("tok-a")))

				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assertHandoffRecord(t, handoffSuiteRecord("tok-a"), got)
			},
		},
		{
			name: "asserted assurance is found unchanged, in order",
			assert: func(t *testing.T, ctx context.Context, s oidc.HandoffStore) {
				want := handoffSuiteRecord("tok-a")
				want.AMR = []string{"pwd", "mfa"}
				want.ACR = "urn:corp:loa:2"
				require.NoError(t, s.Insert(ctx, want))

				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assertHandoffRecord(t, want, got)
			},
		},
		{
			name: "a record stored with an empty amr list reads back with none",
			assert: func(t *testing.T, ctx context.Context, s oidc.HandoffStore) {
				want := handoffSuiteRecord("tok-a")
				want.AMR = []string{}
				require.NoError(t, s.Insert(ctx, want))

				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assertHandoffRecord(t, want, got)
			},
		},
		textCase("an amr holding a NUL byte is refused or round-trips, never altered",
			"canary-a41b", func(rec *oidc.HandoffRecord) { rec.AMR = []string{"pwd", "x\x00canary-a41b"} }),
		textCase("an amr holding invalid UTF-8 is refused or round-trips, never altered",
			"canary-b52c", func(rec *oidc.HandoffRecord) { rec.AMR = []string{"caf\xe9 canary-b52c"} }),
		textCase("an acr holding a NUL byte is refused or round-trips, never altered",
			"canary-c63d", func(rec *oidc.HandoffRecord) { rec.ACR = "x\x00canary-c63d" }),
		textCase("an acr holding invalid UTF-8 is refused or round-trips, never altered",
			"canary-d74e", func(rec *oidc.HandoffRecord) { rec.ACR = "caf\xe9 canary-d74e" }),
		{
			name: "a found record's amr is the caller's own copy",
			assert: func(t *testing.T, ctx context.Context, s oidc.HandoffStore) {
				want := handoffSuiteRecord("tok-a")
				want.AMR = []string{"pwd", "mfa"}
				require.NoError(t, s.Insert(ctx, want))

				first, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				require.NotNil(t, first)
				first.AMR[0] = "tampered"

				again, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assertHandoffRecord(t, want, again)
			},
		},
		{
			name: "a found record is the caller's own copy",
			assert: func(t *testing.T, ctx context.Context, s oidc.HandoffStore) {
				require.NoError(t, s.Insert(ctx, handoffSuiteRecord("tok-a")))

				first, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				require.NotNil(t, first)
				clear(first.SecretHash)
				first.UserID = "u-2"
				spent := handoffSuiteIssued
				first.ConsumedAt = &spent

				again, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assertHandoffRecord(t, handoffSuiteRecord("tok-a"), again)
			},
		},
		{
			name: "a missing token id is not found, and a present one still is",
			assert: func(t *testing.T, ctx context.Context, s oidc.HandoffStore) {
				require.NoError(t, s.Insert(ctx, handoffSuiteRecord("tok-a")))

				_, err := s.FindByTokenID(ctx, "tok-missing")
				require.ErrorIs(t, err, oidc.ErrHandoffNotFound)

				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assertHandoffRecord(t, handoffSuiteRecord("tok-a"), got)
			},
		},
		{
			name: "consuming an unconsumed record succeeds and records when",
			assert: func(t *testing.T, ctx context.Context, s oidc.HandoffStore) {
				require.NoError(t, s.Insert(ctx, handoffSuiteRecord("tok-a")))

				at := handoffSuiteIssued.Add(10 * time.Second)
				require.NoError(t, s.Consume(ctx, "tok-a", at))

				want := handoffSuiteRecord("tok-a")
				want.ConsumedAt = &at
				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assertHandoffRecord(t, want, got)
			},
		},
		{
			name: "a second consume is not found and keeps the first consume time",
			assert: func(t *testing.T, ctx context.Context, s oidc.HandoffStore) {
				require.NoError(t, s.Insert(ctx, handoffSuiteRecord("tok-a")))

				at := handoffSuiteIssued.Add(10 * time.Second)
				require.NoError(t, s.Consume(ctx, "tok-a", at))
				require.ErrorIs(t, s.Consume(ctx, "tok-a", at.Add(time.Second)), oidc.ErrHandoffNotFound,
					"a consumed record must not be consumed again")

				want := handoffSuiteRecord("tok-a")
				want.ConsumedAt = &at
				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assertHandoffRecord(t, want, got)
			},
		},
		{
			name: "consuming a missing record is not found, and another record still consumes",
			assert: func(t *testing.T, ctx context.Context, s oidc.HandoffStore) {
				require.NoError(t, s.Insert(ctx, handoffSuiteRecord("tok-a")))

				require.ErrorIs(t, s.Consume(ctx, "tok-missing", handoffSuiteIssued), oidc.ErrHandoffNotFound)
				require.NoError(t, s.Consume(ctx, "tok-a", handoffSuiteIssued))
			},
		},
		{
			name: "eight concurrent consumes of one record: exactly one succeeds",
			assert: func(t *testing.T, ctx context.Context, s oidc.HandoffStore) {
				require.NoError(t, s.Insert(ctx, handoffSuiteRecord("tok-a")))

				var (
					start = make(chan struct{})
					wg    sync.WaitGroup
					errs  = make([]error, handoffSuiteRacers)
				)
				for i := range handoffSuiteRacers {
					wg.Go(func() {
						<-start
						errs[i] = s.Consume(ctx, "tok-a", handoffSuiteIssued.Add(time.Duration(i+1)*time.Second))
					})
				}
				close(start)
				wg.Wait()

				won, lost := 0, 0
				for i, err := range errs {
					switch {
					case err == nil:
						won++
					case errors.Is(err, oidc.ErrHandoffNotFound):
						lost++
					default:
						t.Errorf("consume %d failed with %v, not the not-found outcome", i, err)
					}
				}
				assert.Equal(t, 1, won,
					"exactly one racing consume may succeed: more means single use was decided by a read "+
						"another caller raced")
				assert.Equal(t, handoffSuiteRacers-1, lost)
			},
		},
		{
			name: "deleting expired records removes only those before the cutoff and reports the count",
			assert: func(t *testing.T, ctx context.Context, s oidc.HandoffStore) {
				early := handoffSuiteRecord("tok-early") // expires issued+1m
				late := handoffSuiteRecord("tok-late")
				late.ExpiresAt = handoffSuiteIssued.Add(5 * time.Minute)
				for _, rec := range []oidc.HandoffRecord{early, late} {
					require.NoError(t, s.Insert(ctx, rec))
				}

				n, err := s.DeleteExpired(ctx, handoffSuiteIssued.Add(2*time.Minute))
				require.NoError(t, err)
				assert.Equal(t, 1, n, "the count is of the records removed")

				_, err = s.FindByTokenID(ctx, "tok-early")
				require.ErrorIs(t, err, oidc.ErrHandoffNotFound, "a record expired before the cutoff must go")
				got, err := s.FindByTokenID(ctx, "tok-late")
				require.NoError(t, err, "a record expired after the cutoff must stay")
				assertHandoffRecord(t, late, got)
			},
		},
		{
			name: "a zero cutoff is refused and deletes nothing; a real cutoff then purges",
			assert: func(t *testing.T, ctx context.Context, s oidc.HandoffStore) {
				for _, tok := range []string{"tok-a", "tok-b"} {
					require.NoError(t, s.Insert(ctx, handoffSuiteRecord(tok)))
				}

				n, err := s.DeleteExpired(ctx, time.Time{})
				require.ErrorIs(t, err, oidc.ErrRetainSinceRequired)
				assert.Zero(t, n)
				for _, tok := range []string{"tok-a", "tok-b"} {
					got, err := s.FindByTokenID(ctx, tok)
					require.NoError(t, err, "a refused purge must delete nothing")
					assertHandoffRecord(t, handoffSuiteRecord(tok), got)
				}

				n, err = s.DeleteExpired(ctx, handoffSuiteIssued.Add(5*time.Minute))
				require.NoError(t, err)
				assert.Equal(t, 2, n)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			tc.assert(t, t.Context(), newStore(t, clockwork.NewFakeClockAt(handoffSuiteNow)))
		})
	}
}
