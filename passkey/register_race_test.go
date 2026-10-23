package passkey_test

// The two tests here race a registration step against its own per-user limit.
// They share no setup beyond the fixture: one holds the passkey count, the
// other the challenge count, at the moment every racer has read it.

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// barrier releases its callers once racers of them have arrived, or after a
// few seconds. Until it is armed, it lets every caller through.
type barrier struct {
	racers  int32
	armed   atomic.Bool
	arrived atomic.Int32
	all     chan struct{}
}

func newBarrier(racers int32) *barrier { return &barrier{racers: racers, all: make(chan struct{})} }

// wait holds the caller until every racer has arrived, once the barrier is
// armed.
func (b *barrier) wait(ctx context.Context) {
	if !b.armed.Load() {
		return
	}

	if b.arrived.Add(1) == b.racers {
		close(b.all)
	}

	select {
	case <-b.all:
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}
}

// countBarrierCredentials is a memory credential store whose Count answers
// only once every racing finish has counted, so a finish that counts and then
// inserts lets every racer read the same count before any of them stores.
type countBarrierCredentials struct {
	*passkey.MemoryCredentialStore

	b *barrier
}

func (s *countBarrierCredentials) Count(ctx context.Context, user identity.UserID) (int, error) {
	n, err := s.MemoryCredentialStore.Count(ctx, user)
	s.b.wait(ctx)

	return n, err
}

// countBarrierChallenges is a memory challenge store whose issuance count
// answers only once every racing begin has counted.
type countBarrierChallenges struct {
	*onetime.MemoryStore

	b *barrier
}

func (s *countBarrierChallenges) CountRecentBySubject(
	ctx context.Context, purpose, subject string, since time.Time,
) (int, error) {
	n, err := s.MemoryStore.CountRecentBySubject(ctx, purpose, subject, since)
	s.b.wait(ctx)

	return n, err
}

// race runs n calls of f released together and returns their errors.
func race(n int, f func(i int) error) []error {
	errs := make([]error, n)
	start := make(chan struct{})

	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			errs[i] = f(i)
		})
	}
	close(start)
	wg.Wait()

	return errs
}

// TestFinishRegistration_ConcurrentFinishesStayWithinPasskeyLimit races four
// finishes for u-1, each answering a challenge of its own, against a passkey
// limit of one. The limit is decided by the write, so exactly one stores a
// passkey and the other three are refused with ErrLimitReached.
func TestFinishRegistration_ConcurrentFinishesStayWithinPasskeyLimit(t *testing.T) {
	t.Parallel()

	const racers = 4

	f := newFixture(t)
	creds := &countBarrierCredentials{MemoryCredentialStore: f.creds, b: newBarrier(racers)}
	f.deps.Credentials = creds
	m := f.manager(t, passkey.WithPasskeyLimit(1))
	s := fullSession("sess-a", "u-1")

	challenges := make([]string, racers)
	for i := range challenges {
		challenges[i] = f.begin(t, m, s)
	}

	creds.b.armed.Store(true)

	errs := race(racers, func(i int) error {
		_, err := m.FinishRegistration(t.Context(), s,
			regBody(challenges[i], "cred-"+strconv.Itoa(i), ""), passkey.RegistrationContext{})

		return err
	})

	var stored, refused int
	for _, err := range errs {
		if err == nil {
			stored++

			continue
		}

		require.ErrorIs(t, err, passkey.ErrLimitReached)
		refused++
	}

	assert.Equal(t, 1, stored, "finishes that stored a passkey")
	assert.Equal(t, racers-1, refused, "finishes refused with the passkey-limit refusal")

	n, err := f.creds.Count(t.Context(), "u-1")
	require.NoError(t, err)
	assert.Equal(t, 1, n, "passkeys u-1 holds")
}

// TestBeginRegistration_ConcurrentBeginsStayWithinChallengeLimit races twenty
// begins for u-1 against the default registration-challenge limit of ten. The
// count and the issue are one decision, so exactly ten challenges are issued
// and the other ten begins are refused with ErrRegistrationThrottled.
func TestBeginRegistration_ConcurrentBeginsStayWithinChallengeLimit(t *testing.T) {
	t.Parallel()

	const (
		racers = 20
		limit  = 10 // the default registration-challenge limit
	)

	f := newFixture(t)
	challenges := &countBarrierChallenges{
		MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(f.clock)),
		b:           newBarrier(racers),
	}
	challenges.b.armed.Store(true)
	f.deps.Challenges = challenges
	m := f.manager(t)
	s := fullSession("sess-a", "u-1")

	errs := race(racers, func(int) error {
		_, err := m.BeginRegistration(t.Context(), s, passkey.RegistrationContext{})

		return err
	})

	var issued, throttled int
	for _, err := range errs {
		if err == nil {
			issued++

			continue
		}

		require.ErrorIs(t, err, passkey.ErrRegistrationThrottled)
		throttled++
	}

	assert.Equal(t, limit, issued, "begins issued a challenge")
	assert.Equal(t, racers-limit, throttled, "begins refused as throttled")
	assert.Equal(t, limit, len(f.creations()), "the refused begins render no options")
}

// staggeredCredentials is a memory credential store that stages two racing
// finishes for one user so the one the limit refuses inserts only after the
// one that stores has:
//
//   - Count answers once both have counted, so both pass the early count;
//   - the first to insert waits until the second has reached its insert too,
//     and the second inserts only once the first has.
//
// Every wait gives up after a few seconds, so a finish that never arrives
// fails the test rather than hanging it.
type staggeredCredentials struct {
	*passkey.MemoryCredentialStore

	counted        *barrier
	writes         atomic.Int32
	secondAtInsert chan struct{}
	firstInserted  chan struct{}
}

func newStaggeredCredentials(inner *passkey.MemoryCredentialStore) *staggeredCredentials {
	return &staggeredCredentials{
		MemoryCredentialStore: inner,
		counted:               newBarrier(2),
		secondAtInsert:        make(chan struct{}),
		firstInserted:         make(chan struct{}),
	}
}

// await waits for ch, the caller's context, or a few seconds.
func await(ctx context.Context, ch <-chan struct{}) {
	select {
	case <-ch:
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}
}

func (s *staggeredCredentials) Count(ctx context.Context, user identity.UserID) (int, error) {
	n, err := s.MemoryCredentialStore.Count(ctx, user)
	s.counted.wait(ctx)

	return n, err
}

func (s *staggeredCredentials) InsertWithin(ctx context.Context, c *passkey.Credential, limit int) (bool, error) {
	if s.writes.Add(1) == 1 {
		await(ctx, s.secondAtInsert)

		defer close(s.firstInserted)

		return s.MemoryCredentialStore.InsertWithin(ctx, c, limit)
	}

	close(s.secondAtInsert)
	await(ctx, s.firstInserted)

	return s.MemoryCredentialStore.InsertWithin(ctx, c, limit)
}

// TestFinishRegistration_RefusedFinishLeavesStoredFinishsCodesWorking races
// two finishes for u-1, who has no way back in, against a passkey limit of
// one. The finish the limit refuses reaches its insert only after the other
// has reached its own. A refused finish stores nothing, so the saved codes the
// stored finish returned are the ones that confirm its passkey.
func TestFinishRegistration_RefusedFinishLeavesStoredFinishsCodesWorking(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.deps.Recovery = recoveryDeps(t, f, recovery.WayBackDeps{})
	creds := newStaggeredCredentials(f.creds)
	f.deps.Credentials = creds
	m := f.manager(t, passkey.WithPasskeyLimit(1))
	s := fullSession("sess-a", "u-1")

	challenges := []string{f.begin(t, m, s), f.begin(t, m, s)}
	f.clock.Advance(time.Minute)
	creds.counted.armed.Store(true)

	results := make([]*passkey.RegistrationResult, len(challenges))
	errs := race(len(challenges), func(i int) error {
		var err error
		results[i], err = m.FinishRegistration(t.Context(), s,
			regBody(challenges[i], "cred-"+strconv.Itoa(i), ""), passkey.RegistrationContext{})

		return err
	})

	var stored *passkey.RegistrationResult
	for i, err := range errs {
		if err != nil {
			require.ErrorIs(t, err, passkey.ErrLimitReached)

			continue
		}

		require.Nil(t, stored, "a second finish stored a passkey")
		stored = results[i]
	}

	require.NotNil(t, stored, "no finish stored a passkey")
	require.Len(t, stored.RecoveryCodes, 10)

	c, err := m.ConfirmSavedCode(t.Context(), s, stored.RecoveryCodes[0], passkey.RegistrationContext{})
	require.NoError(t, err, "the stored finish's own saved codes do not confirm its passkey")
	require.NotNil(t, c)
	assert.Equal(t, stored.Credential.ID, c.ID)
	assert.Equal(t, passkey.StateActive, c.State)
}

// racerKey keys the index of a racing finish in its context.
type racerKey struct{}

// racer returns the index of the racing finish ctx belongs to, or -1.
func racer(ctx context.Context) int {
	if i, ok := ctx.Value(racerKey{}).(int); ok {
		return i
	}

	return -1
}

// lateListCredentials is a memory credential store that stages two racing
// finishes for one user so the second reads the user's passkeys only once the
// first has stored its own:
//
//   - Count answers once both have counted, so both pass the early count;
//   - every List of the second finish waits until the first has inserted.
//
// The second finish therefore decides what its registration replaces while
// the first finish's passkey is already stored. Every wait gives up after a
// few seconds.
type lateListCredentials struct {
	*passkey.MemoryCredentialStore

	counted       *barrier
	firstInserted chan struct{}
}

func (s *lateListCredentials) Count(ctx context.Context, user identity.UserID) (int, error) {
	n, err := s.MemoryCredentialStore.Count(ctx, user)
	s.counted.wait(ctx)

	return n, err
}

func (s *lateListCredentials) List(ctx context.Context, user identity.UserID) ([]*passkey.Credential, error) {
	if racer(ctx) == 1 {
		await(ctx, s.firstInserted)
	}

	return s.MemoryCredentialStore.List(ctx, user)
}

func (s *lateListCredentials) InsertWithin(ctx context.Context, c *passkey.Credential, limit int) (bool, error) {
	ok, err := s.MemoryCredentialStore.InsertWithin(ctx, c, limit)
	if racer(ctx) == 0 {
		close(s.firstInserted)
	}

	return ok, err
}

// TestFinishRegistration_ConcurrentFinishKeepsStoredFinishsPasskey races two
// finishes for u-1 against a passkey limit of one, the second deciding what
// its registration replaces only once the first has stored its pending
// passkey. That passkey was created after the second finish's challenge was
// issued, so it belongs to a concurrent ceremony, not an abandoned one, and is
// kept: the first finish stores, the second is refused with ErrLimitReached,
// and the codes the first returned or sent confirm its own passkey.
func TestFinishRegistration_ConcurrentFinishKeepsStoredFinishsPasskey(t *testing.T) {
	t.Parallel()

	type env struct {
		f *fixture
		m *passkey.Manager
		s *session.Session
	}

	type testCase struct {
		name    string
		session *session.Session
		rc      passkey.RegistrationContext
		codes   bool          // wire saved codes for a user with no way back
		advance time.Duration // between the begins and the finishes
		confirm func(t *testing.T, e *env, res *passkey.RegistrationResult) (*passkey.Credential, error)
	}

	cases := []testCase{
		{
			name:    "a passkey awaiting saved codes",
			session: fullSession("sess-a", "u-1"),
			codes:   true,
			advance: time.Minute,
			confirm: func(t *testing.T, e *env, res *passkey.RegistrationResult) (*passkey.Credential, error) {
				require.Len(t, res.RecoveryCodes, 10)

				return e.m.ConfirmSavedCode(t.Context(), e.s, res.RecoveryCodes[0], passkey.RegistrationContext{})
			},
		},
		{
			name:    "a passkey awaiting an emailed code, created at the instant the challenge was issued",
			session: enrolmentSession("sess-a", "u-1"),
			rc:      passkey.RegistrationContext{EmailConfirmation: true},
			confirm: func(t *testing.T, e *env, _ *passkey.RegistrationResult) (*passkey.Credential, error) {
				return e.m.ConfirmEmailCode(t.Context(), e.s, emailedCode(t, e.f),
					passkey.RegistrationContext{EmailConfirmation: true})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			if tc.codes {
				f.deps.Recovery = recoveryDeps(t, f, recovery.WayBackDeps{})
			}

			creds := &lateListCredentials{
				MemoryCredentialStore: f.creds, counted: newBarrier(2), firstInserted: make(chan struct{}),
			}
			f.deps.Credentials = creds
			e := &env{f: f, m: f.manager(t, passkey.WithPasskeyLimit(1)), s: tc.session}

			challenges := []string{f.begin(t, e.m, e.s), f.begin(t, e.m, e.s)}
			f.clock.Advance(tc.advance)
			creds.counted.armed.Store(true)

			results := make([]*passkey.RegistrationResult, len(challenges))
			errs := race(len(challenges), func(i int) error {
				ctx := context.WithValue(t.Context(), racerKey{}, i)

				var err error
				results[i], err = e.m.FinishRegistration(ctx, e.s,
					regBody(challenges[i], "cred-"+strconv.Itoa(i), ""), tc.rc)

				return err
			})

			require.NoError(t, errs[0], "the first finish")
			require.ErrorIs(t, errs[1], passkey.ErrLimitReached, "the second finish")

			stored := results[0]
			require.NotNil(t, stored)

			held, err := f.creds.List(t.Context(), "u-1")
			require.NoError(t, err)
			require.Len(t, held, 1, "passkeys u-1 holds")
			assert.Equal(t, stored.Credential.ID, held[0].ID, "the passkey u-1 holds")

			c, err := tc.confirm(t, e, stored)
			require.NoError(t, err, "the stored finish's own codes do not confirm its passkey")
			require.NotNil(t, c)
			assert.Equal(t, stored.Credential.ID, c.ID)
			assert.Equal(t, passkey.StateActive, c.State)
		})
	}
}
