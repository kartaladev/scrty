package storetest

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/token/onetime"
)

const (
	// ProviderRaceRacers is how many callers the provider's single-winner races release
	// together per record, and so the least DurableHarness.PoolSize they accept.
	ProviderRaceRacers = 32

	// meetingRaceRecords is how many records a race of two operations runs, each record
	// one meeting of the two. A meeting is decided by a very short window, so it takes
	// many of them; more callers per record would hide a lost write, because a revocation
	// arriving later puts back what a racing create overwrote.
	meetingRaceRecords = 512

	// codeTokenPurpose is the token/onetime purpose of an authorization code (T2).
	codeTokenPurpose = "oidc-provider.code" //nolint:gosec // a purpose's name, and no credential
)

// The names the provider's races report under.
const (
	AdvanceRaceName          = "exactly one advance wins per pending request"
	CodeSpendRaceName        = "exactly one spend wins per code"
	AssertionRecordRaceName  = "exactly one record wins per assertion identifier"
	RevocationCreateRaceName = "a revocation racing a grant's create is kept"
	RevokedOnceRaceName      = "a revocation raced from many callers tells one it revoked the grant"
	EndReportedOnceRaceName  = "an end raced from many callers reports each grant once"
	EndCreateRaceName        = "a sign-in's end racing its code's exchange leaves the grant revoked"
	TouchRaceName            = "a touch racing a longer one leaves the longer deadline"

	// The pairs RunGrantOrderRaces meets, each reported under its own name.
	GrantOrderEndRevokeUserRaceName   = "an end racing a user's revocation fails neither"
	GrantOrderEndRevokeClientRaceName = "an end racing a client's revocation fails neither"
	GrantOrderEndsRaceName            = "two ends racing fail neither"
	GrantOrderRevokeUsersRaceName     = "two of a user's revocations racing fail neither"
	GrantOrderRevokeClientsRaceName   = "two of a client's revocations racing fail neither"

	// The pairs holding different sets, one of a user's grants and the other those of
	// one client of them.
	GrantOrderEndSetsRaceName        = "an end racing a client's revocation over different sets fails neither"
	GrantOrderRevokeUserSetsRaceName = "a user's revocation racing a client's over different sets fails neither"
)

// raceDigest is the digest a race holds for key.
func raceDigest(key string) []byte {
	sum := sha256.Sum256([]byte(key))

	return sum[:]
}

// raceN recovers the number a race seeded its key from.
func raceN(key string) int {
	n, _ := strconv.Atoi(key)

	return n
}

// RunAdvanceRace holds a pending-request store to spending a stage by the write:
// ProviderRaceRacers callers move each record from StageLogin to StageConsent at once,
// and exactly one of each must succeed, every other caller receiving
// oidcprovider.ErrNotFound. Its inputs are checked as RunConsumeRace checks them, so
// harness.PoolSize must be at least ProviderRaceRacers.
func RunAdvanceRace(t *testing.T, harness DurableHarness[oidcprovider.PendingRequestStore]) {
	t.Helper()

	signIn := opSignIn("u-1", 1)

	runRace(t, harness, Race[oidcprovider.PendingRequestStore]{
		Seed: func(ctx context.Context, t *testing.T, s oidcprovider.PendingRequestStore, i int) string {
			t.Helper()
			key := "pending-" + strconv.Itoa(i)
			r := pendingRecord(1)
			r.ID, r.HandleDigest = suiteID(80000+i), raceDigest(key)
			require.NoError(t, s.Create(ctx, r))

			return key
		},
		Attempt: func(ctx context.Context, s oidcprovider.PendingRequestStore, key string, _ int) (bool, error) {
			err := s.Advance(ctx, raceDigest(key), oidcprovider.StageLogin, oidcprovider.StageConsent, &signIn)
			if errors.Is(err, oidcprovider.ErrNotFound) {
				return false, nil
			}

			return err == nil, err
		},
		Check: func(ctx context.Context, t *testing.T, s oidcprovider.PendingRequestStore, key string) {
			t.Helper()
			got, err := s.Load(ctx, raceDigest(key))
			require.NoError(t, err)
			assert.Equal(t, oidcprovider.StageConsent, got.Stage)
			assert.NotNil(t, got.SignIn, "the winner's sign-in must be stored")
		},
	}, raceRule{name: AdvanceRaceName, noun: "advance", racers: ProviderRaceRacers})
}

// RunCodeSpendRace holds the store a provider spends its codes in to spending each
// once: ProviderRaceRacers callers consume each token of the provider's purpose at once,
// and exactly one of each must succeed, every other caller receiving
// onetime.ErrTokenNotFound. Its inputs are checked as RunConsumeRace checks them.
func RunCodeSpendRace(t *testing.T, harness DurableHarness[onetime.Store]) {
	t.Helper()

	const firstToken = 70000

	runRace(t, harness, Race[onetime.Store]{
		Seed: func(ctx context.Context, t *testing.T, s onetime.Store, i int) string {
			t.Helper()
			n := firstToken + i
			require.NoError(t, s.Insert(ctx, onetime.Token{
				ID:         suiteID(n),
				Purpose:    codeTokenPurpose,
				Subject:    opClient,
				SecretHash: raceDigest(strconv.Itoa(n)),
				IssuedAt:   suiteStart,
				ExpiresAt:  suiteStart.Add(time.Minute),
			}))

			return strconv.Itoa(n)
		},
		Attempt: func(ctx context.Context, s onetime.Store, key string, _ int) (bool, error) {
			err := s.Consume(ctx, suiteID(raceN(key)), suiteStart)
			if errors.Is(err, onetime.ErrTokenNotFound) {
				return false, nil
			}

			return err == nil, err
		},
	}, raceRule{name: CodeSpendRaceName, noun: "spend", racers: ProviderRaceRacers})
}

// RunAssertionRecordRace holds an assertion-identifier store to deciding by the write:
// ProviderRaceRacers callers record each identifier at once, and exactly one of each must
// be told it is new. Its inputs are checked as RunConsumeRace checks them.
func RunAssertionRecordRace(t *testing.T, harness DurableHarness[oidcprovider.AssertionIDStore]) {
	t.Helper()

	runRace(t, harness, Race[oidcprovider.AssertionIDStore]{
		Seed: func(_ context.Context, _ *testing.T, _ oidcprovider.AssertionIDStore, i int) string {
			return "jti-" + strconv.Itoa(i)
		},
		Attempt: func(ctx context.Context, s oidcprovider.AssertionIDStore, key string, _ int) (bool, error) {
			return s.Record(ctx, opClient, key, assertionUntil)
		},
	}, raceRule{name: AssertionRecordRaceName, noun: "record", racers: ProviderRaceRacers})
}

// RunTouchRace holds a browser-session store to deciding a touch by its one conditional
// write: two touches of each session at once, one moving the idle deadline further than
// the other, and the further one must be what the session holds, as a slower request
// cannot undo a later one. A store that reads the deadline and writes separately, as a
// SELECT followed by an UPDATE with no condition would, shortens it when the nearer touch
// writes last. Its inputs are checked as RunConsumeRace checks them.
//
// BrowserSessionSuite runs this race on the one store its factory returns. A harness run
// here splits the racers between two instances, and so also catches a store serialising
// under a lock of one instance.
func RunTouchRace(t *testing.T, harness DurableHarness[oidcprovider.BrowserSessionStore]) {
	t.Helper()

	nearer, further := browserIdle.Add(time.Minute), browserIdle.Add(2*time.Minute)

	runRace(t, harness, Race[oidcprovider.BrowserSessionStore]{
		Records: meetingRaceRecords,
		Seed: func(ctx context.Context, t *testing.T, s oidcprovider.BrowserSessionStore, i int) string {
			t.Helper()
			key := "browser-" + strconv.Itoa(i)
			r := browserRecord(1, opSignIn("u-1", 1))
			r.Digest = raceDigest(key)
			require.NoError(t, s.Put(ctx, r))

			return key
		},
		// The further touch is the one the engine counts as the win: both always succeed.
		Attempt: func(ctx context.Context, s oidcprovider.BrowserSessionStore, key string, racer int) (bool, error) {
			if racer == 0 {
				return true, s.Touch(ctx, raceDigest(key), further)
			}

			return false, s.Touch(ctx, raceDigest(key), nearer)
		},
		Check: func(ctx context.Context, t *testing.T, s oidcprovider.BrowserSessionStore, key string) {
			t.Helper()
			got, err := s.Load(ctx, raceDigest(key), suiteStart)
			require.NoError(t, err)
			if !further.Equal(got.IdleExpiresAt) {
				t.Errorf("session %s: a touch shortened the idle deadline to %v, and %v was written", key, got.IdleExpiresAt, further)
			}
		},
	}, raceRule{name: TouchRaceName, noun: "touch", racers: 2})
}

// RunGrantRaces holds a grant store to its promises under concurrency, against one code
// store it joins to through UseCodes, in four races:
//
//   - a revocation racing the create of the same grant, one of each for each record, as
//     a code's replay meets the exchange that stores its grant. Whichever goes first the
//     grant must end revoked, with the first revocation's cause and every field the
//     create gave. A store that reads for a revocation and writes separately, as a SELECT
//     followed by an INSERT would, loses it;
//   - ProviderRaceRacers callers ending one sign-in at once. Exactly one must be told of
//     its grant, as a client is notified at most once, and a later report returns nothing;
//   - one family revoked from many callers, a stored grant's and one with no row yet, of whom
//     exactly one is told it is the one that revoked it, as the provider reports only that one;
//   - a sign-in's end racing the exchange of its outstanding code, one of each for each
//     record, some of them codes with offline_access of a client tied to its sign-in.
//     Whichever goes first the grant must end revoked and marked, and a later report of
//     that end returns nothing.
//
// Its inputs are checked as RunConsumeRace checks them, so harness.PoolSize must be at least
// ProviderRaceRacers. It uses the in-memory code store whatever the grant store is, as
// the two meet only through the port.
func RunGrantRaces(t *testing.T, harness DurableHarness[oidcprovider.GrantStore]) {
	t.Helper()

	harness.Require(t)

	harness, codes := joinedGrantHarness(t, harness)

	runRace(t, harness, revocationCreateRace(), raceRule{name: RevocationCreateRaceName, noun: "create", racers: 2})
	runRace(t, harness, revokedOnceRace(), raceRule{name: RevokedOnceRaceName, noun: "first revocation", racers: ProviderRaceRacers})
	runRace(t, harness, endReportedOnceRace(), raceRule{name: EndReportedOnceRaceName, noun: "report", racers: ProviderRaceRacers})
	runRace(t, harness, endCreateRace(codes), raceRule{name: EndCreateRaceName, noun: "create", racers: 2})
}

// joinedGrantHarness is h with every store it builds joined to one in-memory code store,
// which it returns too.
func joinedGrantHarness(
	t *testing.T, h DurableHarness[oidcprovider.GrantStore],
) (DurableHarness[oidcprovider.GrantStore], *oidcprovider.MemoryCodeStore) {
	t.Helper()

	codes, err := oidcprovider.NewMemoryCodeStore()
	require.NoError(t, err)

	joined := func(build func(t *testing.T) oidcprovider.GrantStore) func(t *testing.T) oidcprovider.GrantStore {
		return func(t *testing.T) oidcprovider.GrantStore {
			t.Helper()
			s := build(t)
			require.NoError(t, s.UseCodes(codes))

			return s
		}
	}
	h.New, h.NewReplica = joined(h.New), joined(h.NewReplica)

	return h, codes
}

// RunGrantOrderRaces holds a grant store's operations writing many grants to one lock
// order: for each pair of EndSignIns, RevokeByUser and RevokeByUserAndClient that can
// meet, one of each per record, over stored grants and outstanding codes whose families
// interleave. A durable store whose operations take those rows in different orders
// deadlocks, the database ends one of the two with an error, and its write is lost, which
// the race reports as an unexpected error, and as a family left live. It says nothing
// about how a store avoids that, so it holds any store, and asks no SQL of it.
//
// The sweep is left out: it is store-wide, so it would take the other records' rows, and
// an adapter's own test meets it. Its inputs are checked as RunConsumeRace checks them.
// It uses the in-memory code store whatever the grant store is.
func RunGrantOrderRaces(t *testing.T, harness DurableHarness[oidcprovider.GrantStore]) {
	t.Helper()

	harness.Require(t)

	harness, codes := joinedGrantHarness(t, harness)

	type call = func(ctx context.Context, s oidcprovider.GrantStore, n int) error

	end := func(ctx context.Context, s oidcprovider.GrantStore, n int) error {
		_, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: orderRaceUser(n)}, suiteStart)
		return err
	}
	revokeUser := func(ctx context.Context, s oidcprovider.GrantStore, n int) error {
		_, err := s.RevokeByUser(ctx, orderRaceUser(n), oidcprovider.CauseRecovery, suiteStart)
		return err
	}
	revokeClient := func(ctx context.Context, s oidcprovider.GrantStore, n int) error {
		_, err := s.RevokeByUserAndClient(ctx, orderRaceUser(n), opClient, oidcprovider.CauseRecovery, suiteStart)
		return err
	}

	for i, pair := range []struct {
		name          string
		first, second call
	}{
		{GrantOrderEndRevokeUserRaceName, end, revokeUser},
		{GrantOrderEndRevokeClientRaceName, end, revokeClient},
		{GrantOrderEndsRaceName, end, end},
		{GrantOrderRevokeUsersRaceName, revokeUser, revokeUser},
		{GrantOrderRevokeClientsRaceName, revokeClient, revokeClient},
	} {
		firstFamily := 200000 + i*50000
		runRace(t, harness, grantOrderRace(codes, firstFamily, pair.first, pair.second),
			raceRule{name: pair.name, noun: "call", racers: 2})
	}

	// The pairs above hold identical sets, which a store taking its rows in the order it
	// meets them can still match by luck. These hold a user's grants against one client's,
	// each set large enough to be met in an order of its own.
	for i, pair := range []struct {
		name          string
		first, second call
	}{
		{GrantOrderEndSetsRaceName, end, revokeClient},
		{GrantOrderRevokeUserSetsRaceName, revokeUser, revokeClient},
	} {
		firstFamily := 450000 + i*50000
		runRace(t, harness, grantOrderSetsRace(firstFamily, pair.first, pair.second),
			raceRule{name: pair.name, noun: "call", racers: 2})
	}
}

const (
	// orderRaceTimeout bounds the racing of each pair of RunGrantOrderRaces, in place of
	// the default a race of a few rows is held to. Each call writes many rows and queues
	// behind the other, and a starved database server takes more than the default over
	// it. On PostgreSQL a lock cycle does not wait for this bound, because the server ends
	// it with 40P01 within deadlock_timeout. A call that stays slower than this still fails.
	orderRaceTimeout = 2 * time.Minute

	// orderRaceRecords is how many meetings a pair of RunGrantOrderRaces runs.
	orderRaceRecords = 32

	// orderRaceFamilies is how many families a record spans, half of them stored grants
	// and half named only by an outstanding code.
	orderRaceFamilies = 16
)

const (
	// orderSetsRaceRecords is how many meetings a pair over different sets runs.
	orderSetsRaceRecords = 8

	// orderSetsRaceFamilies is how many grants a record of such a pair spans, alternating
	// between two clients, so one client's are half of the user's.
	orderSetsRaceFamilies = 1200
)

// orderRaceUser is the user of the record whose families start at n.
func orderRaceUser(n int) identity.UserID { return identity.UserID("order-race-u-" + strconv.Itoa(n)) }

// grantOrderRace is first as racer 0 against second as racer 1. Both must succeed, so the
// engine counts racer 0 as the one win, and any error fails the record.
func grantOrderRace(
	codes *oidcprovider.MemoryCodeStore, firstFamily int, first, second func(ctx context.Context, s oidcprovider.GrantStore, n int) error,
) Race[oidcprovider.GrantStore] {
	return Race[oidcprovider.GrantStore]{
		Records: orderRaceRecords,
		Timeout: orderRaceTimeout,
		Seed: func(ctx context.Context, t *testing.T, s oidcprovider.GrantStore, i int) string {
			t.Helper()
			n := firstFamily + i*orderRaceFamilies
			signIn := opSignIn(string(orderRaceUser(n)), n)
			for family := n; family < n+orderRaceFamilies; family += 2 {
				require.NoError(t, s.Create(ctx, grantRecord(family+1, signIn)))

				code := codeRecord(family, signIn)
				code.GrantFamily = suiteID(family)
				require.NoError(t, codes.Create(ctx, code))
			}

			return strconv.Itoa(n)
		},
		Attempt: func(ctx context.Context, s oidcprovider.GrantStore, key string, racer int) (bool, error) {
			if racer == 0 {
				return true, first(ctx, s, raceN(key))
			}

			return false, second(ctx, s, raceN(key))
		},
		Check: func(ctx context.Context, t *testing.T, s oidcprovider.GrantStore, key string) {
			t.Helper()
			n := raceN(key)
			for family := n; family < n+orderRaceFamilies; family++ {
				if got := loadGrant(ctx, t, s, family); !got.Revoked {
					t.Errorf("record %s: family %d was left live", key, family)
				}
			}
		},
	}
}

// grantOrderSetsRace is first as racer 0 against second as racer 1, over one user's
// stored grants of two clients, where one call holds all of them and the other those of
// one client. Both must succeed, and every grant must end revoked. The grants are stored
// in a scrambled order, so no order of the store's own is the family order.
func grantOrderSetsRace(firstFamily int, first, second func(ctx context.Context, s oidcprovider.GrantStore, n int) error) Race[oidcprovider.GrantStore] {
	// stride is coprime to the grants of a record, so the stored order is a permutation.
	const stride = 7

	return Race[oidcprovider.GrantStore]{
		Records: orderSetsRaceRecords,
		Timeout: orderRaceTimeout,
		Seed: func(ctx context.Context, t *testing.T, s oidcprovider.GrantStore, i int) string {
			t.Helper()
			n := firstFamily + i*orderSetsRaceFamilies
			signIn := opSignIn(string(orderRaceUser(n)), n)
			for k := range orderSetsRaceFamilies {
				offset := k * stride % orderSetsRaceFamilies
				grant := grantRecord(n+offset, signIn)
				if offset%2 == 1 {
					grant.ClientID = opOtherClient
				}
				require.NoError(t, s.Create(ctx, grant))
			}

			return strconv.Itoa(n)
		},
		Attempt: func(ctx context.Context, s oidcprovider.GrantStore, key string, racer int) (bool, error) {
			if racer == 0 {
				return true, first(ctx, s, raceN(key))
			}

			return false, second(ctx, s, raceN(key))
		},
		Check: func(ctx context.Context, t *testing.T, s oidcprovider.GrantStore, key string) {
			t.Helper()
			n := raceN(key)
			for family := n; family < n+orderSetsRaceFamilies; family++ {
				if got := loadGrant(ctx, t, s, family); !got.Revoked {
					t.Errorf("record %s: family %d was left live", key, family)
				}
			}
		},
	}
}

// raceGrant is the grant of family n, from a sign-in of a user of its own.
func raceGrant(n int) *oidcprovider.Grant {
	return grantRecord(n, raceSignIn(n))
}

// raceSignIn is the sign-in of the grant of family n.
func raceSignIn(n int) oidcprovider.SignIn {
	return opSignIn("race-u-"+strconv.Itoa(n), n+100000)
}

// endOf selects the sign-in of the grant of family n.
func endOf(n int) oidcprovider.SignInSelector {
	return oidcprovider.SignInSelector{Family: raceSignIn(n).Family}
}

// revocationCreateRace is a create as racer 0 against a revocation as racer 1. The
// create is the one that wins, so the engine counts it, and any error fails the record.
func revocationCreateRace() Race[oidcprovider.GrantStore] {
	const firstFamily = 10000

	return Race[oidcprovider.GrantStore]{
		Records: meetingRaceRecords,
		Seed: func(_ context.Context, _ *testing.T, _ oidcprovider.GrantStore, i int) string {
			return strconv.Itoa(firstFamily + i)
		},
		Attempt: func(ctx context.Context, s oidcprovider.GrantStore, key string, racer int) (bool, error) {
			n := raceN(key)
			if racer == 0 {
				return true, s.Create(ctx, raceGrant(n))
			}

			return false, revokeErr(s.Revoke(ctx, suiteID(n), oidcprovider.CauseCodeReplay, suiteStart))
		},
		Check: func(ctx context.Context, t *testing.T, s oidcprovider.GrantStore, key string) {
			t.Helper()
			got := loadGrant(ctx, t, s, raceN(key))
			if !got.Revoked {
				t.Errorf("grant %s: a revocation raced its create and was lost", key)
			}
			assert.Equal(t, oidcprovider.CauseCodeReplay, got.RevokeCause)
			if got.User != raceSignIn(raceN(key)).User {
				t.Errorf("grant %s: the grant's own fields were lost, its user is %q", key, got.User)
			}
		},
	}
}

// revokedOnceRace revokes one family from every racer, a stored grant's on even records and a
// family with no row on odd ones. Each racer is told whether it is the one that revoked it, which
// is the one win the engine counts.
func revokedOnceRace() Race[oidcprovider.GrantStore] {
	const firstFamily = 90000

	return Race[oidcprovider.GrantStore]{
		Seed: func(ctx context.Context, t *testing.T, s oidcprovider.GrantStore, i int) string {
			t.Helper()
			n := firstFamily + i
			if i%2 == 0 {
				require.NoError(t, s.Create(ctx, raceGrant(n)))
			}

			return strconv.Itoa(n)
		},
		Attempt: func(ctx context.Context, s oidcprovider.GrantStore, key string, _ int) (bool, error) {
			return s.Revoke(ctx, suiteID(raceN(key)), oidcprovider.CauseCodeReplay, suiteStart)
		},
		Check: func(ctx context.Context, t *testing.T, s oidcprovider.GrantStore, key string) {
			t.Helper()
			got := loadGrant(ctx, t, s, raceN(key))
			assert.True(t, got.Revoked, "grant %s", key)
			assert.Equal(t, oidcprovider.CauseCodeReplay, got.RevokeCause, "grant %s", key)
		},
	}
}

// reportOf is what one end returned of the grant of family n: whether it reported it,
// and an error for anything but that grant, or for that grant twice.
func reportOf(got []oidcprovider.Grant, n int) (bool, error) {
	switch {
	case len(got) == 0:
		return false, nil
	case len(got) > 1:
		return true, fmt.Errorf("one end reported %d grants, and one was selected", len(got))
	case got[0].Family != suiteID(n):
		return true, errors.New("an end reported a grant it did not select")
	default:
		return true, nil
	}
}

// assertEndedOnce requires the grant of family n to be revoked and marked by an end, and
// a later report of that end to return nothing.
func assertEndedOnce(ctx context.Context, t *testing.T, s oidcprovider.GrantStore, n int) {
	t.Helper()

	got := loadGrant(ctx, t, s, n)
	if !got.Revoked {
		t.Errorf("grant %d: the sign-in ended, and the grant was left live", n)
	}
	if got.SignInEndedAt.IsZero() {
		t.Errorf("grant %d: the sign-in ended, and the grant was left unmarked", n)
	}
	assert.Equal(t, oidcprovider.CauseSignInEnded, got.RevokeCause)
	if got.User != raceSignIn(n).User {
		t.Errorf("grant %d: the grant's own fields were lost, its user is %q", n, got.User)
	}

	again, err := s.EndSignIns(ctx, endOf(n), suiteStart.Add(time.Minute))
	require.NoError(t, err)
	if len(again) != 0 {
		t.Errorf("grant %d: a second report of the end returned %d grants", n, len(again))
	}
}

// endReportedOnceRace ends one sign-in from every racer. A selected grant is reported by
// one racer alone, which is the one win the engine counts.
func endReportedOnceRace() Race[oidcprovider.GrantStore] {
	const firstFamily = 20000

	return Race[oidcprovider.GrantStore]{
		Seed: func(ctx context.Context, t *testing.T, s oidcprovider.GrantStore, i int) string {
			t.Helper()
			n := firstFamily + i
			require.NoError(t, s.Create(ctx, raceGrant(n)))

			return strconv.Itoa(n)
		},
		Attempt: func(ctx context.Context, s oidcprovider.GrantStore, key string, _ int) (bool, error) {
			n := raceN(key)
			got, err := s.EndSignIns(ctx, endOf(n), suiteStart)
			if err != nil {
				return false, err
			}

			return reportOf(got, n)
		},
		Check: func(ctx context.Context, t *testing.T, s oidcprovider.GrantStore, key string) {
			t.Helper()
			assertEndedOnce(ctx, t, s, raceN(key))
		},
	}
}

// endCreateRace is an exchange's create as racer 0 against an end of the sign-in as
// racer 1, over an outstanding code. The create always succeeds, so the engine counts it.
func endCreateRace(codes *oidcprovider.MemoryCodeStore) Race[oidcprovider.GrantStore] {
	const firstFamily = 30000

	// tied is every third record: a code with offline_access of a client tied to its
	// sign-in, which ends with it as any other.
	tied := func(n int) bool { return n%3 == 0 }

	return Race[oidcprovider.GrantStore]{
		Records: meetingRaceRecords,
		Seed: func(ctx context.Context, t *testing.T, _ oidcprovider.GrantStore, i int) string {
			t.Helper()
			n := firstFamily + i
			r := codeRecord(n, raceSignIn(n))
			r.GrantFamily = suiteID(n)
			r.Offline, r.EndsWithSignIn = tied(n), tied(n)
			require.NoError(t, codes.Create(ctx, r))

			return strconv.Itoa(n)
		},
		Attempt: func(ctx context.Context, s oidcprovider.GrantStore, key string, racer int) (bool, error) {
			n := raceN(key)
			if racer == 0 {
				g := raceGrant(n)
				g.Offline, g.EndsWithSignIn = tied(n), tied(n)

				return true, s.Create(ctx, g)
			}
			got, err := s.EndSignIns(ctx, endOf(n), suiteStart)
			if err != nil {
				return false, err
			}
			if _, err := reportOf(got, n); err != nil {
				return false, err
			}

			return false, nil
		},
		Check: func(ctx context.Context, t *testing.T, s oidcprovider.GrantStore, key string) {
			t.Helper()
			assertEndedOnce(ctx, t, s, raceN(key))
		},
	}
}

// DeviceRaceRacers is how many callers each race of RunDeviceAuthorizationRaces releases
// together per record, and so the least DurableHarness.PoolSize it accepts.
const DeviceRaceRacers = 16

// The names RunDeviceAuthorizationRaces reports its races under.
const (
	DeviceClaimRaceName             = "exactly one claim wins per device authorization"
	DeviceDecideRaceName            = "exactly one approval or denial wins per device authorization"
	DevicePollRaceName              = "exactly one poll is recorded per count seen"
	DeviceSpendRaceName             = "exactly one spend wins per device authorization"
	DeviceCreateRaceName            = "exactly one create wins per user code"
	DeviceCreateOverExpiredRaceName = "exactly one create wins a user code whose holder expired"
)

// RunDeviceAuthorizationRaces holds a device authorization store to deciding each of its
// writes by the write, in six races of DeviceRaceRacers callers per record released
// together, every one of which must leave exactly one winner and the rest refused:
//
//   - claims of one issued record, each from a browser of its own. The winner's flow digest
//     is the one stored;
//   - approvals racing denials of one claimed record. The stored state and approval are
//     the winner's;
//   - polls of one record that all saw the same count. One is recorded, with its time;
//   - spends of one approved record;
//   - creates of records with device codes of their own over one user code no record
//     holds, the losers answered oidcprovider.ErrUserCodeTaken and nothing of theirs stored;
//   - the same over a user code whose holder expired at the time given, a spent holder on
//     even records and an issued one on odd ones, as two issuers drawing one code release
//     it at once. A store releasing the holder and inserting in two steps lets both in.
//
// Every other refusal is oidcprovider.ErrNotFound, and any other error fails the record.
// Racers alternate between harness.New's store and harness.NewReplica's, so a store
// serialising under a lock of one instance is caught. Its inputs are checked as
// RunConsumeRace checks them, so harness.PoolSize must be at least DeviceRaceRacers.
//
// DeviceAuthorizationSuite runs these races on the one store its factory returns.
func RunDeviceAuthorizationRaces(t *testing.T, harness DurableHarness[oidcprovider.DeviceAuthorizationStore]) {
	t.Helper()

	harness.Require(t)

	for _, race := range []struct {
		race Race[oidcprovider.DeviceAuthorizationStore]
		rule raceRule
	}{
		{deviceClaimRace(), raceRule{name: DeviceClaimRaceName, noun: "claim"}},
		{deviceDecideRace(), raceRule{name: DeviceDecideRaceName, noun: "approval or denial"}},
		{devicePollRace(), raceRule{name: DevicePollRaceName, noun: "poll"}},
		{deviceSpendRace(), raceRule{name: DeviceSpendRaceName, noun: "spend"}},
		{deviceCreateRace(false), raceRule{name: DeviceCreateRaceName, noun: "create"}},
		{deviceCreateRace(true), raceRule{name: DeviceCreateOverExpiredRaceName, noun: "create"}},
	} {
		race.rule.racers = DeviceRaceRacers
		runRace(t, harness, race.race, race.rule)
	}
}

// deviceRaceRecord is record n of a race: an issued record of opClient, its device and user
// codes digests of its key, issued at suiteStart and expiring at deviceExpires.
func deviceRaceRecord(n int) *oidcprovider.DeviceAuthorization {
	r := deviceRecord(1)
	key := strconv.Itoa(n)
	r.ID, r.DeviceCodeDigest, r.UserCodeDigest = suiteID(n), raceDigest("device-"+key), raceDigest("user-"+key)

	return r
}

// deviceRaceWinners remembers which racer won each record of a race, for its Check.
type deviceRaceWinners struct{ racers sync.Map } // key -> racer

// won records racer as key's winner when err is nil, and answers what a race's Attempt
// does: a win, a loss when err is refused, or err.
func (w *deviceRaceWinners) won(key string, racer int, err, refused error) (bool, error) {
	switch {
	case err == nil:
		w.racers.Store(key, racer)
		return true, nil
	case errors.Is(err, refused):
		return false, nil
	default:
		return false, err
	}
}

// winner is the racer that won key.
func (w *deviceRaceWinners) winner(t *testing.T, key string) int {
	t.Helper()

	racer, ok := w.racers.Load(key)
	require.True(t, ok, "record %s has no winner", key)

	return racer.(int) //nolint:forcetypeassert // only won stores, and only ints
}

// The identifiers each device race numbers its records from, apart so that the races can
// share one store.
const (
	deviceClaimRaceFirst   = 110000
	deviceDecideRaceFirst  = 120000
	devicePollRaceFirst    = 130000
	deviceSpendRaceFirst   = 140000
	deviceCreateRaceFirst  = 150000
	deviceExpiredRaceFirst = 170000
)

// deviceSeed returns a Seed creating record first+i in state, at deviceLive.
func deviceSeed(first int, state oidcprovider.DeviceState) func(ctx context.Context, t *testing.T, s oidcprovider.DeviceAuthorizationStore, i int) string {
	return func(ctx context.Context, t *testing.T, s oidcprovider.DeviceAuthorizationStore, i int) string {
		t.Helper()
		n := first + i
		r := deviceRaceRecord(n)
		r.State = state
		if state != oidcprovider.DeviceIssued {
			r.ClaimFlowDigest = raceDigest("flow-" + strconv.Itoa(n))
		}
		if state == oidcprovider.DeviceApproved {
			r.Approval = deviceApproval("u-1", 1)
		}
		require.NoError(t, s.Create(ctx, r, deviceLive))

		return strconv.Itoa(n)
	}
}

// loadRaceDevice loads the record of a race's key, which must exist.
func loadRaceDevice(ctx context.Context, t *testing.T, s oidcprovider.DeviceAuthorizationStore, key string) *oidcprovider.DeviceAuthorization {
	t.Helper()

	got, err := s.LoadByDeviceCode(ctx, raceDigest("device-"+key))
	require.NoError(t, err, "record %s", key)

	return got
}

// raceFlow is the flow digest racer claims record key with.
func raceFlow(key string, racer int) []byte {
	return raceDigest("claim-" + key + "-" + strconv.Itoa(racer))
}

func deviceClaimRace() Race[oidcprovider.DeviceAuthorizationStore] {
	var w deviceRaceWinners

	return Race[oidcprovider.DeviceAuthorizationStore]{
		Seed: deviceSeed(deviceClaimRaceFirst, oidcprovider.DeviceIssued),
		Attempt: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore, key string, racer int) (bool, error) {
			return w.won(key, racer, s.Claim(ctx, suiteID(raceN(key)), raceFlow(key, racer), deviceLive), oidcprovider.ErrNotFound)
		},
		Check: func(ctx context.Context, t *testing.T, s oidcprovider.DeviceAuthorizationStore, key string) {
			t.Helper()
			got := loadRaceDevice(ctx, t, s, key)
			assert.Equal(t, oidcprovider.DeviceClaimed, got.State, "record %s", key)
			assert.Equal(t, raceFlow(key, w.winner(t, key)), got.ClaimFlowDigest, "record %s: the winner's browser holds the claim", key)
		},
	}
}

// deviceDecideRace has even racers approve and odd ones deny.
func deviceDecideRace() Race[oidcprovider.DeviceAuthorizationStore] {
	var w deviceRaceWinners

	return Race[oidcprovider.DeviceAuthorizationStore]{
		Seed: deviceSeed(deviceDecideRaceFirst, oidcprovider.DeviceClaimed),
		Attempt: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore, key string, racer int) (bool, error) {
			var approval *oidcprovider.DeviceApproval
			if racer%2 == 0 {
				approval = deviceApproval("u-1", racer)
			}

			return w.won(key, racer, s.Decide(ctx, suiteID(raceN(key)), approval, deviceLive), oidcprovider.ErrNotFound)
		},
		Check: func(ctx context.Context, t *testing.T, s oidcprovider.DeviceAuthorizationStore, key string) {
			t.Helper()
			got, winner := loadRaceDevice(ctx, t, s, key), w.winner(t, key)
			if winner%2 == 1 {
				assert.Equal(t, oidcprovider.DeviceDenied, got.State, "record %s: a denial won", key)
				assert.Nil(t, got.Approval, "record %s: a denied record holds no approval", key)

				return
			}
			assert.Equal(t, oidcprovider.DeviceApproved, got.State, "record %s: an approval won", key)
			require.NotNil(t, got.Approval, "record %s", key)
			assert.Equal(t, suiteID(200+winner), got.Approval.GrantFamily, "record %s holds the winner's approval", key)
		},
	}
}

// devicePollRace has every racer poll having seen no poll, each at a time of its own.
func devicePollRace() Race[oidcprovider.DeviceAuthorizationStore] {
	var w deviceRaceWinners
	at := func(racer int) time.Time { return deviceLive.Add(time.Duration(racer) * time.Second) }

	return Race[oidcprovider.DeviceAuthorizationStore]{
		Seed: deviceSeed(devicePollRaceFirst, oidcprovider.DeviceIssued),
		Attempt: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore, key string, racer int) (bool, error) {
			err := s.RecordPoll(ctx, suiteID(raceN(key)), 0, at(racer), 10*time.Second)

			return w.won(key, racer, err, oidcprovider.ErrNotFound)
		},
		Check: func(ctx context.Context, t *testing.T, s oidcprovider.DeviceAuthorizationStore, key string) {
			t.Helper()
			got := loadRaceDevice(ctx, t, s, key)
			assert.Equal(t, 1, got.PollCount, "record %s", key)
			assertTimeMicro(t, at(w.winner(t, key)), got.LastPolledAt, "record "+key+": LastPolledAt")
		},
	}
}

func deviceSpendRace() Race[oidcprovider.DeviceAuthorizationStore] {
	var w deviceRaceWinners

	return Race[oidcprovider.DeviceAuthorizationStore]{
		Seed: deviceSeed(deviceSpendRaceFirst, oidcprovider.DeviceApproved),
		Attempt: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore, key string, racer int) (bool, error) {
			return w.won(key, racer, s.Spend(ctx, suiteID(raceN(key)), deviceLive), oidcprovider.ErrNotFound)
		},
		Check: func(ctx context.Context, t *testing.T, s oidcprovider.DeviceAuthorizationStore, key string) {
			t.Helper()
			assert.Equal(t, oidcprovider.DeviceSpent, loadRaceDevice(ctx, t, s, key).State, "record %s", key)
		},
	}
}

// deviceCreateRace has every racer create a record of its own over one user code. Over an
// expired holder, the holder expires at the time the racers create at, a spent one on even
// records and an issued one on odd ones.
func deviceCreateRace(overExpired bool) Race[oidcprovider.DeviceAuthorizationStore] {
	var w deviceRaceWinners
	first, at := deviceCreateRaceFirst, deviceLive
	if overExpired {
		first, at = deviceExpiredRaceFirst, deviceExpires
	}
	// record is racer's record for key; racers number theirs past the key's own.
	record := func(key string, racer int) *oidcprovider.DeviceAuthorization {
		r := deviceRaceRecord(raceN(key))
		r.ID = suiteID(raceN(key) + 1 + racer)
		r.DeviceCodeDigest = raceDigest("device-" + key + "-" + strconv.Itoa(racer))
		r.IssuedAt, r.ExpiresAt = at, at.Add(10*time.Minute)

		return r
	}

	return Race[oidcprovider.DeviceAuthorizationStore]{
		Seed: func(ctx context.Context, t *testing.T, s oidcprovider.DeviceAuthorizationStore, i int) string {
			t.Helper()
			n := first + i*(DeviceRaceRacers+1)
			if overExpired {
				holder := deviceRaceRecord(n)
				if i%2 == 0 {
					holder.State, holder.ClaimFlowDigest = oidcprovider.DeviceSpent, raceDigest("flow-"+strconv.Itoa(n))
					holder.Approval = deviceApproval("u-1", 1)
				}
				require.NoError(t, s.Create(ctx, holder, deviceLive))
			}

			return strconv.Itoa(n)
		},
		Attempt: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore, key string, racer int) (bool, error) {
			return w.won(key, racer, s.Create(ctx, record(key, racer), at), oidcprovider.ErrUserCodeTaken)
		},
		Check: func(ctx context.Context, t *testing.T, s oidcprovider.DeviceAuthorizationStore, key string) {
			t.Helper()
			winner := w.winner(t, key)
			got, err := s.LoadByUserCode(ctx, raceDigest("user-"+key), at)
			require.NoError(t, err, "record %s", key)
			assert.Equal(t, suiteID(raceN(key)+1+winner), got.ID, "record %s: the user code finds the winner", key)
			for racer := range DeviceRaceRacers {
				if racer == winner {
					continue
				}
				_, err := s.LoadByDeviceCode(ctx, record(key, racer).DeviceCodeDigest)
				assert.ErrorIs(t, err, oidcprovider.ErrNotFound, "record %s: racer %d lost, so nothing of its record is stored", key, racer)
			}
		},
	}
}
