package storetest

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
)

// passkeyCredential returns the credential suite's n-th credential: active,
// of user, with WebAuthn credential ID credID, every attribute set, created
// n minutes after suiteStart.
func passkeyCredential(n int, user identity.UserID, credID string) *passkey.Credential {
	return &passkey.Credential{
		ID:                   suiteID(n),
		User:                 user,
		CredentialID:         []byte(credID),
		PublicKey:            []byte("cose-key-" + credID),
		SignCount:            42,
		BackupEligible:       true,
		Transports:           []string{"internal", "hybrid"},
		AAGUID:               bytes.Repeat([]byte{byte(n)}, 16), //nolint:gosec // G115: a small test index
		AttestationFormat:    "packed",
		AttestationStatement: []byte("statement-" + credID),
		Name:                 "Laptop",
		CreatedAt:            suiteStart.Add(time.Duration(n) * time.Minute),
		State:                passkey.StateActive,
	}
}

// passkeyCodeExpiry is when the suite's emailed codes expire.
var passkeyCodeExpiry = suiteStart.Add(time.Hour)

// passkeyPending returns c pending on reasons, with an emailed code when
// AwaitingEmailCode is among them.
func passkeyPending(c *passkey.Credential, reasons passkey.PendingReason) *passkey.Credential {
	c.State = passkey.StatePending
	c.Pending = reasons
	if reasons&passkey.AwaitingEmailCode != 0 {
		c.EmailCode = &passkey.EmailCode{Code: "123456", ExpiresAt: passkeyCodeExpiry}
	}

	return c
}

// passkeySuspended returns c suspended.
func passkeySuspended(c *passkey.Credential) *passkey.Credential {
	c.State = passkey.StateSuspended

	return c
}

// passkeyBoth is both pending reasons.
const passkeyBoth = passkey.AwaitingSavedCodes | passkey.AwaitingEmailCode

// insertCredentials stores every credential, failing the case at the first
// error.
func insertCredentials(ctx context.Context, t *testing.T, s passkey.CredentialStore, cs ...*passkey.Credential) {
	t.Helper()

	for _, c := range cs {
		require.NoError(t, s.Insert(ctx, c), "insert %s", c.ID)
	}
}

// storedCredential is the stored credential with credential ID credID, which
// must exist.
func storedCredential(ctx context.Context, t *testing.T, s passkey.CredentialStore, credID string) *passkey.Credential {
	t.Helper()

	c, err := s.FindByCredentialID(ctx, []byte(credID))
	require.NoError(t, err, "credential %q must be found", credID)
	require.NotNil(t, c, "a found credential must not be nil")

	return c
}

// assertCredential requires got to be want: every attribute equal, and the
// times the same instants, in whatever location the store returns them.
func assertCredential(t *testing.T, want, got *passkey.Credential) {
	t.Helper()

	if want == nil || got == nil {
		assert.Equal(t, want, got)
		return
	}

	w, g := *want, *got
	assertTimeEqual(t, w.CreatedAt, g.CreatedAt, "CreatedAt")
	assertTimeEqual(t, w.LastUsedAt, g.LastUsedAt, "LastUsedAt")
	w.CreatedAt, g.CreatedAt, w.LastUsedAt, g.LastUsedAt = time.Time{}, time.Time{}, time.Time{}, time.Time{}

	if w.EmailCode != nil && g.EmailCode != nil {
		wc, gc := *w.EmailCode, *g.EmailCode
		assertTimeEqual(t, wc.ExpiresAt, gc.ExpiresAt, "EmailCode.ExpiresAt")
		wc.ExpiresAt, gc.ExpiresAt = time.Time{}, time.Time{}
		w.EmailCode, g.EmailCode = &wc, &gc
	}

	assert.Equal(t, w, g)
}

// assertCredentials requires got to be want, in order.
func assertCredentials(t *testing.T, want, got []*passkey.Credential) {
	t.Helper()

	if !assert.Len(t, got, len(want)) {
		return
	}
	for i := range want {
		assertCredential(t, want[i], got[i])
	}
}

// credentialIDs is user's listed credentials' WebAuthn IDs, in list order.
func credentialIDs(ctx context.Context, t *testing.T, s passkey.CredentialStore, user identity.UserID) []string {
	t.Helper()

	list, err := s.List(ctx, user)
	require.NoError(t, err)

	out := make([]string, 0, len(list))
	for _, c := range list {
		out = append(out, string(c.CredentialID))
	}

	return out
}

// requireCount requires user to hold exactly want credentials.
func requireCount(ctx context.Context, t *testing.T, s passkey.CredentialStore, user identity.UserID, want int) {
	t.Helper()

	n, err := s.Count(ctx, user)
	require.NoError(t, err)
	assert.Equal(t, want, n, "credentials of %q", user)
}

// concurrently runs f from n goroutines released together, and counts the
// calls that report true. A call that fails is reported, never counted.
func concurrently(t *testing.T, n int, f func() (bool, error)) int {
	t.Helper()

	var (
		start = make(chan struct{})
		wg    sync.WaitGroup
		mu    sync.Mutex
		wins  int
		errs  []error
	)
	for range n {
		wg.Go(func() {
			<-start
			ok, err := f()

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
			if ok {
				wins++
			}
		})
	}
	close(start)
	wg.Wait()

	assert.Empty(t, errs, "a refused write is false with no error")

	return wins
}

// RunPasskeyCredentialStoreSuite checks a passkey.CredentialStore against the
// contract the passkey manager relies on:
//   - an inserted credential is found with every attribute, by its credential
//     ID and by its library ID within its user, and listed and counted in
//     every state, oldest first, ties in library ID order;
//   - a credential ID or library ID already stored is refused with
//     passkey.ErrDuplicateCredential, whatever its user, and the stored
//     credential is unchanged;
//   - every state change is decided by the write: of 8 concurrent recordings
//     of one counter exactly one wins, and of 20 concurrent charges against
//     one emailed code exactly passkey.MaxEmailCodeAttempts do;
//   - a recording is refused for a credential that is not active, or whose
//     stored counter is not lower, unless both are zero;
//   - RecordUse records the backup state and last use of an active
//     credential only, leaving its counter;
//   - ClearReason clears exactly one known reason, activating the credential
//     with the last one and dropping the emailed code with its own;
//   - a refused write changes nothing and reports false with no error, and a
//     write to another user's credential is refused the same way;
//   - the store keeps its own copies of what it is given and returns.
//
// newStore is called once per case and must return an empty store.
func RunPasskeyCredentialStoreSuite(t *testing.T, newStore func(t *testing.T) passkey.CredentialStore) {
	t.Helper()

	type credCase = suiteCase[passkey.CredentialStore]

	at := suiteStart.Add(30 * time.Minute)
	before := passkeyCodeExpiry.Add(-time.Minute)

	cases := []credCase{
		{
			name: "an inserted credential is found with every attribute",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				want := passkeyPending(passkeyCredential(1, "Alice@Example.COM ", "C"), passkeyBoth)
				want.LastUsedAt = suiteStart.Add(time.Second)
				want.EmailCode.Attempts = 2
				want.SignCount = 1<<32 - 1
				insertCredentials(ctx, t, s, want)

				assertCredential(t, want, storedCredential(ctx, t, s, "C"))
				got, err := s.Find(ctx, want.User, want.ID)
				require.NoError(t, err)
				assertCredential(t, want, got)
			},
		},
		{
			name: "a credential without its optional attributes is found without them",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				want := passkeyCredential(1, "u-1", "C")
				want.Transports, want.AAGUID = nil, nil
				want.AttestationFormat, want.AttestationStatement = "", nil
				want.SignCount = 0
				insertCredentials(ctx, t, s, want)

				assertCredential(t, want, storedCredential(ctx, t, s, "C"))
			},
		},
		{
			name: "a duplicate credential ID is refused whatever its user, and the stored one is unchanged",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyCredential(1, "u-1", "C"))

				dup := passkeyCredential(2, "u-2", "C")
				dup.Name = "Phone"
				require.ErrorIs(t, s.Insert(ctx, dup), passkey.ErrDuplicateCredential)
				require.ErrorIs(t, s.Insert(ctx, passkeyCredential(3, "u-1", "C")), passkey.ErrDuplicateCredential)

				assertCredential(t, passkeyCredential(1, "u-1", "C"), storedCredential(ctx, t, s, "C"))
				requireCount(ctx, t, s, "u-1", 1)
				requireCount(ctx, t, s, "u-2", 0)
			},
		},
		{
			name: "a duplicate library ID is refused",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyCredential(1, "u-1", "C"))

				require.ErrorIs(t, s.Insert(ctx, passkeyCredential(1, "u-2", "D")), passkey.ErrDuplicateCredential)

				_, err := s.FindByCredentialID(ctx, []byte("D"))
				require.ErrorIs(t, err, passkey.ErrNotFound)
				assertCredential(t, passkeyCredential(1, "u-1", "C"), storedCredential(ctx, t, s, "C"))
			},
		},
		{
			name: "the store keeps its own copy of what was inserted",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				c := passkeyPending(passkeyCredential(1, "u-1", "C"), passkey.AwaitingEmailCode)
				insertCredentials(ctx, t, s, c)

				c.CredentialID[0] = 'X'
				c.PublicKey[0] = 'X'
				c.Transports[0] = "usb"
				c.AAGUID[0] = 9
				c.AttestationStatement[0] = 'X'
				c.EmailCode.Code = "000000"

				assertCredential(t, passkeyPending(passkeyCredential(1, "u-1", "C"), passkey.AwaitingEmailCode),
					storedCredential(ctx, t, s, "C"))
			},
		},
		{
			name: "an unknown credential ID is not found",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyCredential(1, "u-1", "C"))

				c, err := s.FindByCredentialID(ctx, []byte("nope"))
				require.ErrorIs(t, err, passkey.ErrNotFound)
				assert.Nil(t, c)
				c, err = s.Find(ctx, "u-1", suiteID(9))
				require.ErrorIs(t, err, passkey.ErrNotFound)
				assert.Nil(t, c)
			},
		},
		{
			name: "find is within the user: another user's credential is not found",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyCredential(1, "u-1", "C1"), passkeyCredential(2, "u-2", "C2"))

				c, err := s.Find(ctx, "u-1", suiteID(2))
				require.ErrorIs(t, err, passkey.ErrNotFound)
				assert.Nil(t, c)

				got, err := s.Find(ctx, "u-2", suiteID(2))
				require.NoError(t, err)
				assertCredential(t, passkeyCredential(2, "u-2", "C2"), got)
			},
		},
		{
			name: "list is every state of the user, oldest first, ties by library ID",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				tied := passkeyCredential(4, "u-1", "C4")
				tied.CreatedAt = passkeyCredential(2, "u-1", "").CreatedAt
				insertCredentials(ctx, t, s,
					passkeyCredential(5, "u-1", "C5"),
					tied,
					passkeySuspended(passkeyCredential(2, "u-1", "C2")),
					passkeyPending(passkeyCredential(1, "u-1", "C1"), passkeyBoth),
					passkeyCredential(3, "u-2", "C3"),
				)

				list, err := s.List(ctx, "u-1")
				require.NoError(t, err)
				want := passkeyCredential(4, "u-1", "C4")
				want.CreatedAt = tied.CreatedAt
				assertCredentials(t, []*passkey.Credential{
					passkeyPending(passkeyCredential(1, "u-1", "C1"), passkeyBoth),
					passkeySuspended(passkeyCredential(2, "u-1", "C2")),
					want,
					passkeyCredential(5, "u-1", "C5"),
				}, list)
			},
		},
		{
			name: "list and count of a user with none are empty and zero",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyCredential(1, "u-1", "C"))

				list, err := s.List(ctx, "u-9")
				require.NoError(t, err)
				assert.Empty(t, list)
				requireCount(ctx, t, s, "u-9", 0)
			},
		},
		{
			name: "count is every state of the user",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s,
					passkeyCredential(1, "u-1", "C1"),
					passkeyPending(passkeyCredential(2, "u-1", "C2"), passkey.AwaitingSavedCodes),
					passkeySuspended(passkeyCredential(3, "u-1", "C3")),
					passkeyCredential(4, "u-2", "C4"),
				)

				requireCount(ctx, t, s, "u-1", 3)
				requireCount(ctx, t, s, "u-2", 1)
			},
		},
		{
			name: "a returned credential is the caller's own copy",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyPending(passkeyCredential(1, "u-1", "C"), passkey.AwaitingEmailCode))

				c := storedCredential(ctx, t, s, "C")
				c.CredentialID[0] = 'X'
				c.PublicKey[0] = 'X'
				c.Transports[0] = "usb"
				c.EmailCode.Code = "000000"
				c.Name = "changed"

				found, err := s.Find(ctx, "u-1", suiteID(1))
				require.NoError(t, err)
				found.AAGUID[0] = 0xFF
				found.State = passkey.StateSuspended

				list, err := s.List(ctx, "u-1")
				require.NoError(t, err)
				list[0].AttestationStatement[0] = 'X'
				list[0].EmailCode.Attempts = 4

				assertCredential(t, passkeyPending(passkeyCredential(1, "u-1", "C"), passkey.AwaitingEmailCode),
					storedCredential(ctx, t, s, "C"))
			},
		},
		{
			name: "a higher counter is recorded with the backup state and last use",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyCredential(1, "u-1", "C"))

				ok, err := s.RecordAssertion(ctx, suiteID(1), 1<<32-1, true, at)
				require.NoError(t, err)
				assert.True(t, ok)

				want := passkeyCredential(1, "u-1", "C")
				want.SignCount, want.BackupState, want.LastUsedAt = 1<<32-1, true, at
				assertCredential(t, want, storedCredential(ctx, t, s, "C"))
			},
		},
		{
			// Two tabs answered by one authenticator present the same next
			// counter. The write decides: one is recorded, the other is the
			// clone signal. This is the contract's choice, not a defect.
			name: "8 concurrent recordings of one counter: exactly one wins",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyCredential(1, "u-1", "C"))

				wins := concurrently(t, 8, func() (bool, error) {
					return s.RecordAssertion(ctx, suiteID(1), 43, true, at)
				})

				assert.Equal(t, 1, wins, "successful recordings of one counter")
				assert.Equal(t, uint32(43), storedCredential(ctx, t, s, "C").SignCount)
			},
		},
		{
			name: "a counter going backwards, or equal and not zero, is refused and changes nothing",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyCredential(1, "u-1", "C"))

				for _, n := range []uint32{41, 42, 0} {
					ok, err := s.RecordAssertion(ctx, suiteID(1), n, true, at)
					require.NoError(t, err)
					assert.False(t, ok, "counter %d over 42 must be refused", n)
				}

				assertCredential(t, passkeyCredential(1, "u-1", "C"), storedCredential(ctx, t, s, "C"))
			},
		},
		{
			name: "zero over zero is recorded and moves the last use",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				c := passkeyCredential(1, "u-1", "C")
				c.SignCount = 0
				insertCredentials(ctx, t, s, c)

				wins := concurrently(t, 8, func() (bool, error) {
					return s.RecordAssertion(ctx, suiteID(1), 0, true, at)
				})
				assert.Equal(t, 8, wins, "every zero recording over zero succeeds")

				got := storedCredential(ctx, t, s, "C")
				assert.Zero(t, got.SignCount)
				assertTimeEqual(t, at, got.LastUsedAt, "LastUsedAt")
			},
		},
		{
			name: "a pending or suspended credential is not recorded",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s,
					passkeyPending(passkeyCredential(1, "u-1", "C1"), passkey.AwaitingSavedCodes),
					passkeySuspended(passkeyCredential(2, "u-1", "C2")),
				)

				for _, n := range []int{1, 2} {
					ok, err := s.RecordAssertion(ctx, suiteID(n), 43, true, at)
					require.NoError(t, err)
					assert.False(t, ok, "credential %d must not be recorded", n)
				}

				assertCredential(t, passkeyPending(passkeyCredential(1, "u-1", "C1"), passkey.AwaitingSavedCodes),
					storedCredential(ctx, t, s, "C1"))
				assertCredential(t, passkeySuspended(passkeyCredential(2, "u-1", "C2")), storedCredential(ctx, t, s, "C2"))
			},
		},
		{
			name: "an unknown credential is not recorded or suspended",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				ok, err := s.RecordAssertion(ctx, suiteID(1), 1, false, at)
				require.NoError(t, err)
				assert.False(t, ok)
				ok, err = s.Suspend(ctx, suiteID(1))
				require.NoError(t, err)
				assert.False(t, ok)
			},
		},
		{
			name: "use is recorded for an active credential only, leaving the counter",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s,
					passkeyCredential(1, "u-1", "C1"),
					passkeyPending(passkeyCredential(2, "u-1", "C2"), passkey.AwaitingSavedCodes),
					passkeySuspended(passkeyCredential(3, "u-1", "C3")),
				)

				ok, err := s.RecordUse(ctx, suiteID(1), true, at)
				require.NoError(t, err)
				assert.True(t, ok, "an active credential records its use")
				want := passkeyCredential(1, "u-1", "C1")
				want.BackupState, want.LastUsedAt = true, at
				assertCredential(t, want, storedCredential(ctx, t, s, "C1"))

				for _, n := range []int{2, 3, 9} {
					ok, err := s.RecordUse(ctx, suiteID(n), true, at)
					require.NoError(t, err)
					assert.False(t, ok, "credential %d must not record its use", n)
				}
				assertCredential(t, passkeyPending(passkeyCredential(2, "u-1", "C2"), passkey.AwaitingSavedCodes),
					storedCredential(ctx, t, s, "C2"))
				assertCredential(t, passkeySuspended(passkeyCredential(3, "u-1", "C3")), storedCredential(ctx, t, s, "C3"))
			},
		},
		{
			name: "an active credential is suspended once: of 8 concurrent suspensions exactly one reports it",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyCredential(1, "u-1", "C"))

				wins := concurrently(t, 8, func() (bool, error) { return s.Suspend(ctx, suiteID(1)) })

				assert.Equal(t, 1, wins, "suspensions reported")
				assertCredential(t, passkeySuspended(passkeyCredential(1, "u-1", "C")), storedCredential(ctx, t, s, "C"))
				ok, err := s.RecordAssertion(ctx, suiteID(1), 43, true, at)
				require.NoError(t, err)
				assert.False(t, ok, "a suspended credential is not recorded")
			},
		},
		{
			name: "a pending or suspended credential is not suspended",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s,
					passkeyPending(passkeyCredential(1, "u-1", "C1"), passkey.AwaitingSavedCodes),
					passkeySuspended(passkeyCredential(2, "u-1", "C2")),
				)

				for _, n := range []int{1, 2} {
					ok, err := s.Suspend(ctx, suiteID(n))
					require.NoError(t, err)
					assert.False(t, ok, "credential %d must not be suspended", n)
				}

				assertCredential(t, passkeyPending(passkeyCredential(1, "u-1", "C1"), passkey.AwaitingSavedCodes),
					storedCredential(ctx, t, s, "C1"))
			},
		},
		{
			name: "two reasons cleared one by one: pending, then active, the emailed code dropped",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyPending(passkeyCredential(1, "u-1", "C"), passkeyBoth))

				state, ok, err := s.ClearReason(ctx, "u-1", suiteID(1), passkey.AwaitingEmailCode)
				require.NoError(t, err)
				assert.True(t, ok)
				assert.Equal(t, passkey.StatePending, state)

				mid := storedCredential(ctx, t, s, "C")
				assert.Equal(t, passkey.StatePending, mid.State)
				assert.Equal(t, passkey.AwaitingSavedCodes, mid.Pending)
				assert.Nil(t, mid.EmailCode, "clearing the emailed-code reason drops the code")

				state, ok, err = s.ClearReason(ctx, "u-1", suiteID(1), passkey.AwaitingSavedCodes)
				require.NoError(t, err)
				assert.True(t, ok)
				assert.Equal(t, passkey.StateActive, state)

				assertCredential(t, passkeyCredential(1, "u-1", "C"), storedCredential(ctx, t, s, "C"))
			},
		},
		{
			name: "a reason cleared twice, or not set, is refused",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s,
					passkeyPending(passkeyCredential(1, "u-1", "C1"), passkeyBoth),
					passkeyPending(passkeyCredential(2, "u-1", "C2"), passkey.AwaitingSavedCodes),
				)

				_, ok, err := s.ClearReason(ctx, "u-1", suiteID(1), passkey.AwaitingSavedCodes)
				require.NoError(t, err)
				require.True(t, ok)
				state, ok, err := s.ClearReason(ctx, "u-1", suiteID(1), passkey.AwaitingSavedCodes)
				require.NoError(t, err)
				assert.False(t, ok, "a reason cleared twice")
				assert.Zero(t, state)

				state, ok, err = s.ClearReason(ctx, "u-1", suiteID(2), passkey.AwaitingEmailCode)
				require.NoError(t, err)
				assert.False(t, ok, "a reason not set")
				assert.Zero(t, state)

				assertCredential(t, passkeyPending(passkeyCredential(1, "u-1", "C1"), passkey.AwaitingEmailCode),
					storedCredential(ctx, t, s, "C1"))
				assertCredential(t, passkeyPending(passkeyCredential(2, "u-1", "C2"), passkey.AwaitingSavedCodes),
					storedCredential(ctx, t, s, "C2"))
			},
		},
		{
			name: "a reason that is not exactly one known reason is refused and changes nothing",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyPending(passkeyCredential(1, "u-1", "C"), passkeyBoth))

				for _, r := range []passkey.PendingReason{passkeyBoth, 0, 4, passkey.AwaitingSavedCodes | 4, 0x80} {
					state, ok, err := s.ClearReason(ctx, "u-1", suiteID(1), r)
					require.NoError(t, err)
					assert.False(t, ok, "reason %#x must be refused", uint8(r))
					assert.Zero(t, state)
				}

				assertCredential(t, passkeyPending(passkeyCredential(1, "u-1", "C"), passkeyBoth),
					storedCredential(ctx, t, s, "C"))
			},
		},
		{
			name: "another user's or a suspended credential's reason is refused",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				gone := passkeyPending(passkeyCredential(2, "u-1", "C2"), passkey.AwaitingSavedCodes)
				gone.State = passkey.StateSuspended
				insertCredentials(ctx, t, s, passkeyPending(passkeyCredential(1, "u-1", "C1"), passkey.AwaitingSavedCodes), gone)

				_, ok, err := s.ClearReason(ctx, "u-2", suiteID(1), passkey.AwaitingSavedCodes)
				require.NoError(t, err)
				assert.False(t, ok, "another user's credential")
				_, ok, err = s.ClearReason(ctx, "u-1", suiteID(2), passkey.AwaitingSavedCodes)
				require.NoError(t, err)
				assert.False(t, ok, "a suspended credential")
				_, ok, err = s.ClearReason(ctx, "u-1", suiteID(9), passkey.AwaitingSavedCodes)
				require.NoError(t, err)
				assert.False(t, ok, "an unknown credential")

				assertCredential(t, passkeyPending(passkeyCredential(1, "u-1", "C1"), passkey.AwaitingSavedCodes),
					storedCredential(ctx, t, s, "C1"))
				assertCredential(t, gone, storedCredential(ctx, t, s, "C2"))
			},
		},
		{
			name: "a charge counts one attempt and returns the code",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyPending(passkeyCredential(1, "u-1", "C"), passkey.AwaitingEmailCode))

				code, ok, err := s.ChargeEmailAttempt(ctx, "u-1", suiteID(1), before)
				require.NoError(t, err)
				require.True(t, ok)
				require.NotNil(t, code)
				assert.Equal(t, "123456", code.Code)
				assert.Equal(t, 1, code.Attempts)
				assertTimeEqual(t, passkeyCodeExpiry, code.ExpiresAt, "ExpiresAt")

				want := passkeyPending(passkeyCredential(1, "u-1", "C"), passkey.AwaitingEmailCode)
				want.EmailCode.Attempts = 1
				assertCredential(t, want, storedCredential(ctx, t, s, "C"))

				code.Code, code.Attempts = "000000", 0
				assertCredential(t, want, storedCredential(ctx, t, s, "C"))
			},
		},
		{
			name: "20 concurrent charges: exactly five succeed",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyPending(passkeyCredential(1, "u-1", "C"), passkey.AwaitingEmailCode))

				wins := concurrently(t, 20, func() (bool, error) {
					code, ok, err := s.ChargeEmailAttempt(ctx, "u-1", suiteID(1), before)
					if ok != (code != nil) {
						return false, assert.AnError
					}
					return ok, err
				})

				assert.Equal(t, passkey.MaxEmailCodeAttempts, wins, "successful charges")
				assert.Equal(t, passkey.MaxEmailCodeAttempts, storedCredential(ctx, t, s, "C").EmailCode.Attempts)
			},
		},
		{
			name: "the fifth attempt is the last, and a sixth is refused",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				c := passkeyPending(passkeyCredential(1, "u-1", "C"), passkey.AwaitingEmailCode)
				c.EmailCode.Attempts = passkey.MaxEmailCodeAttempts - 1
				insertCredentials(ctx, t, s, c)

				code, ok, err := s.ChargeEmailAttempt(ctx, "u-1", suiteID(1), before)
				require.NoError(t, err)
				require.True(t, ok, "the fifth attempt")
				assert.Equal(t, passkey.MaxEmailCodeAttempts, code.Attempts)

				code, ok, err = s.ChargeEmailAttempt(ctx, "u-1", suiteID(1), before)
				require.NoError(t, err)
				assert.False(t, ok, "a sixth attempt")
				assert.Nil(t, code)
				assert.Equal(t, passkey.MaxEmailCodeAttempts, storedCredential(ctx, t, s, "C").EmailCode.Attempts)
			},
		},
		{
			name: "a charge at the expiry is refused",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyPending(passkeyCredential(1, "u-1", "C"), passkey.AwaitingEmailCode))

				for _, when := range []time.Time{passkeyCodeExpiry, passkeyCodeExpiry.Add(time.Second)} {
					code, ok, err := s.ChargeEmailAttempt(ctx, "u-1", suiteID(1), when)
					require.NoError(t, err)
					assert.False(t, ok, "a charge at %v", when)
					assert.Nil(t, code)
				}

				assertCredential(t, passkeyPending(passkeyCredential(1, "u-1", "C"), passkey.AwaitingEmailCode),
					storedCredential(ctx, t, s, "C"))
			},
		},
		{
			name: "a charge is refused for another user, without an outstanding code, or not pending on it",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				noCode := passkeyPending(passkeyCredential(2, "u-1", "C2"), passkey.AwaitingEmailCode)
				noCode.EmailCode = nil
				suspended := passkeyPending(passkeyCredential(4, "u-1", "C4"), passkey.AwaitingEmailCode)
				suspended.State = passkey.StateSuspended
				insertCredentials(ctx, t, s,
					passkeyPending(passkeyCredential(1, "u-1", "C1"), passkey.AwaitingEmailCode),
					noCode,
					passkeyPending(passkeyCredential(3, "u-1", "C3"), passkey.AwaitingSavedCodes),
					suspended,
				)

				for _, tc := range []struct {
					user identity.UserID
					cid  id.ID
				}{{"u-2", suiteID(1)}, {"u-1", suiteID(2)}, {"u-1", suiteID(3)}, {"u-1", suiteID(4)}, {"u-1", suiteID(9)}} {
					code, ok, err := s.ChargeEmailAttempt(ctx, tc.user, tc.cid, before)
					require.NoError(t, err)
					assert.False(t, ok, "a charge by %q on %s", tc.user, tc.cid)
					assert.Nil(t, code)
				}

				assertCredential(t, passkeyPending(passkeyCredential(1, "u-1", "C1"), passkey.AwaitingEmailCode),
					storedCredential(ctx, t, s, "C1"))
				assertCredential(t, suspended, storedCredential(ctx, t, s, "C4"))
			},
		},
		{
			name: "rename is within the user",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyCredential(1, "u-1", "C1"), passkeyCredential(2, "u-2", "C2"))

				ok, err := s.Rename(ctx, "u-1", suiteID(1), "Phone")
				require.NoError(t, err)
				assert.True(t, ok)
				ok, err = s.Rename(ctx, "u-1", suiteID(2), "Stolen")
				require.NoError(t, err)
				assert.False(t, ok, "another user's credential")
				ok, err = s.Rename(ctx, "u-1", suiteID(9), "Ghost")
				require.NoError(t, err)
				assert.False(t, ok, "an unknown credential")

				assert.Equal(t, "Phone", storedCredential(ctx, t, s, "C1").Name)
				assert.Equal(t, "Laptop", storedCredential(ctx, t, s, "C2").Name)
			},
		},
		{
			name: "delete is within the user, and a deleted credential ID may be inserted again",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s, passkeyCredential(1, "u-1", "C1"), passkeyCredential(2, "u-2", "C2"))

				ok, err := s.Delete(ctx, "u-1", suiteID(2))
				require.NoError(t, err)
				assert.False(t, ok, "another user's credential")
				ok, err = s.Delete(ctx, "u-1", suiteID(1))
				require.NoError(t, err)
				assert.True(t, ok)
				ok, err = s.Delete(ctx, "u-1", suiteID(1))
				require.NoError(t, err)
				assert.False(t, ok, "a credential deleted twice")

				_, err = s.FindByCredentialID(ctx, []byte("C1"))
				require.ErrorIs(t, err, passkey.ErrNotFound)
				assert.Equal(t, []string{"C2"}, credentialIDs(ctx, t, s, "u-2"))

				insertCredentials(ctx, t, s, passkeyCredential(3, "u-2", "C1"))
				assert.Equal(t, identity.UserID("u-2"), storedCredential(ctx, t, s, "C1").User)
			},
		},
		{
			name: "delete awaiting saved codes removes only the user's credentials with the reason, and counts them",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s,
					passkeyCredential(1, "u-1", "C1"),
					passkeyPending(passkeyCredential(2, "u-1", "C2"), passkey.AwaitingSavedCodes),
					passkeyPending(passkeyCredential(3, "u-1", "C3"), passkeyBoth),
					passkeyPending(passkeyCredential(4, "u-1", "C4"), passkey.AwaitingEmailCode),
					passkeyCredential(5, "u-2", "C5"),
					passkeyPending(passkeyCredential(6, "u-2", "C6"), passkey.AwaitingSavedCodes),
				)

				n, err := s.DeleteAwaitingSavedCodes(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 2, n)
				assert.Equal(t, []string{"C1", "C4"}, credentialIDs(ctx, t, s, "u-1"))
				assert.Equal(t, []string{"C5", "C6"}, credentialIDs(ctx, t, s, "u-2"))

				n, err = s.DeleteAwaitingSavedCodes(ctx, "u-1")
				require.NoError(t, err)
				assert.Zero(t, n)
			},
		},
		{
			name: "delete user removes every credential of the user, and counts them",
			assert: func(t *testing.T, ctx context.Context, s passkey.CredentialStore, _ *clockwork.FakeClock) {
				insertCredentials(ctx, t, s,
					passkeyCredential(1, "u-1", "C1"),
					passkeyPending(passkeyCredential(2, "u-1", "C2"), passkeyBoth),
					passkeySuspended(passkeyCredential(3, "u-1", "C3")),
					passkeyCredential(4, "u-2", "C4"),
				)

				n, err := s.DeleteUser(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 3, n)
				requireCount(ctx, t, s, "u-1", 0)
				assert.Equal(t, []string{"C4"}, credentialIDs(ctx, t, s, "u-2"))
				_, err = s.FindByCredentialID(ctx, []byte("C2"))
				require.ErrorIs(t, err, passkey.ErrNotFound)

				n, err = s.DeleteUser(ctx, "u-9")
				require.NoError(t, err)
				assert.Zero(t, n)
			},
		},
	}

	runSuite(t, cases, withoutClock(newStore))
}
