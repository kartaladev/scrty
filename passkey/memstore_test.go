package passkey_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
)

// storeTime is the instant credentials are created at; later writes use
// storeTime plus an offset.
var storeTime = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

// credential returns an active credential of user with library ID n and
// WebAuthn credential ID credID, with every attribute set.
func credential(user identity.UserID, n byte, credID string) *passkey.Credential {
	return &passkey.Credential{
		ID:                   id.ID{15: n},
		User:                 user,
		CredentialID:         []byte(credID),
		PublicKey:            []byte("cose-key-" + credID),
		SignCount:            42,
		BackupEligible:       true,
		BackupState:          false,
		Transports:           []string{"internal", "hybrid"},
		AAGUID:               make([]byte, 16),
		AttestationFormat:    "packed",
		AttestationStatement: []byte("statement"),
		Name:                 "Laptop",
		CreatedAt:            storeTime.Add(time.Duration(n) * time.Minute),
		State:                passkey.StateActive,
	}
}

// pending returns c pending on reasons, with an emailed code when
// AwaitingEmailCode is among them.
func pending(c *passkey.Credential, reasons passkey.PendingReason) *passkey.Credential {
	c.State = passkey.StatePending
	c.Pending = reasons

	if reasons&passkey.AwaitingEmailCode != 0 {
		c.EmailCode = &passkey.EmailCode{Code: "123456", ExpiresAt: storeTime.Add(10 * time.Minute)}
	}

	return c
}

func suspended(c *passkey.Credential) *passkey.Credential {
	c.State = passkey.StateSuspended

	return c
}

// seededStore returns a memory store holding seed.
func seededStore(t *testing.T, seed ...*passkey.Credential) *passkey.MemoryCredentialStore {
	t.Helper()

	s := passkey.NewMemoryCredentialStore()
	for _, c := range seed {
		require.NoError(t, s.Insert(t.Context(), c))
	}

	return s
}

// concurrently runs f from n goroutines released together, and counts the
// calls that report true. Every call must succeed without error.
func concurrently(t *testing.T, n int, f func() (bool, error)) int {
	t.Helper()

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		wins  int
		errs  []error
		start = make(chan struct{})
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
	require.Empty(t, errs)

	return wins
}

// stored returns the stored copy of the credential with credential ID credID.
func stored(t *testing.T, s passkey.CredentialStore, credID string) *passkey.Credential {
	t.Helper()

	c, err := s.FindByCredentialID(t.Context(), []byte(credID))
	require.NoError(t, err)
	require.NotNil(t, c)

	return c
}

func TestMemoryCredentialStore_Insert(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		seed   []*passkey.Credential
		insert func() *passkey.Credential
		// after runs once Insert has returned, with the value inserted.
		after  func(c *passkey.Credential)
		assert func(t *testing.T, s passkey.CredentialStore, err error)
	}

	cases := []testCase{
		{
			name:   "stores every attribute",
			insert: func() *passkey.Credential { return pending(credential("u-1", 1, "C"), passkey.AwaitingEmailCode) },
			assert: func(t *testing.T, s passkey.CredentialStore, err error) {
				require.NoError(t, err)
				assert.Equal(t, pending(credential("u-1", 1, "C"), passkey.AwaitingEmailCode), stored(t, s, "C"))
			},
		},
		{
			name:   "duplicate credential ID across users is refused",
			seed:   []*passkey.Credential{credential("u-1", 1, "C")},
			insert: func() *passkey.Credential { return credential("u-2", 2, "C") },
			assert: func(t *testing.T, s passkey.CredentialStore, err error) {
				require.ErrorIs(t, err, passkey.ErrDuplicateCredential)
				assert.Equal(t, credential("u-1", 1, "C"), stored(t, s, "C"))

				n, err := s.Count(t.Context(), "u-2")
				require.NoError(t, err)
				assert.Zero(t, n)
			},
		},
		{
			name:   "duplicate library ID is refused",
			seed:   []*passkey.Credential{credential("u-1", 1, "C")},
			insert: func() *passkey.Credential { return credential("u-1", 1, "D") },
			assert: func(t *testing.T, s passkey.CredentialStore, err error) {
				require.ErrorIs(t, err, passkey.ErrDuplicateCredential)

				_, err = s.FindByCredentialID(t.Context(), []byte("D"))
				require.ErrorIs(t, err, passkey.ErrNotFound)
			},
		},
		{
			name:   "mutating the inserted value changes nothing stored",
			insert: func() *passkey.Credential { return pending(credential("u-1", 1, "C"), passkey.AwaitingEmailCode) },
			after: func(c *passkey.Credential) {
				c.CredentialID[0] = 'X'
				c.PublicKey[0] = 'X'
				c.Transports[0] = "usb"
				c.AAGUID[0] = 9
				c.AttestationStatement[0] = 'X'
				c.EmailCode.Code = "000000"
				c.SignCount = 1
			},
			assert: func(t *testing.T, s passkey.CredentialStore, err error) {
				require.NoError(t, err)
				assert.Equal(t, pending(credential("u-1", 1, "C"), passkey.AwaitingEmailCode), stored(t, s, "C"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := seededStore(t, tc.seed...)
			c := tc.insert()
			err := s.Insert(t.Context(), c)

			if tc.after != nil {
				tc.after(c)
			}

			tc.assert(t, s, err)
		})
	}
}

func TestMemoryCredentialStore_Reads(t *testing.T) {
	t.Parallel()

	seed := func() []*passkey.Credential {
		return []*passkey.Credential{
			credential("u-1", 3, "C3"),
			pending(credential("u-1", 1, "C1"), passkey.AwaitingSavedCodes),
			suspended(credential("u-1", 2, "C2")),
			credential("u-2", 4, "C4"),
		}
	}

	type testCase struct {
		name   string
		assert func(t *testing.T, s passkey.CredentialStore)
	}

	cases := []testCase{
		{
			name: "find by credential ID",
			assert: func(t *testing.T, s passkey.CredentialStore) {
				assert.Equal(t, credential("u-2", 4, "C4"), stored(t, s, "C4"))
			},
		},
		{
			name: "unknown credential ID is not found",
			assert: func(t *testing.T, s passkey.CredentialStore) {
				c, err := s.FindByCredentialID(t.Context(), []byte("nope"))
				require.ErrorIs(t, err, passkey.ErrNotFound)
				assert.Nil(t, c)
			},
		},
		{
			name: "find within the user",
			assert: func(t *testing.T, s passkey.CredentialStore) {
				c, err := s.Find(t.Context(), "u-1", id.ID{15: 2})
				require.NoError(t, err)
				assert.Equal(t, suspended(credential("u-1", 2, "C2")), c)
			},
		},
		{
			name: "another user's credential is not found",
			assert: func(t *testing.T, s passkey.CredentialStore) {
				c, err := s.Find(t.Context(), "u-1", id.ID{15: 4})
				require.ErrorIs(t, err, passkey.ErrNotFound)
				assert.Nil(t, c)
			},
		},
		{
			name: "list is every state, oldest first",
			assert: func(t *testing.T, s passkey.CredentialStore) {
				list, err := s.List(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, []*passkey.Credential{
					pending(credential("u-1", 1, "C1"), passkey.AwaitingSavedCodes),
					suspended(credential("u-1", 2, "C2")),
					credential("u-1", 3, "C3"),
				}, list)
			},
		},
		{
			name: "list of a user with none is empty",
			assert: func(t *testing.T, s passkey.CredentialStore) {
				list, err := s.List(t.Context(), "u-9")
				require.NoError(t, err)
				assert.Empty(t, list)
			},
		},
		{
			name: "count is every state",
			assert: func(t *testing.T, s passkey.CredentialStore) {
				n, err := s.Count(t.Context(), "u-1")
				require.NoError(t, err)
				assert.Equal(t, 3, n)
			},
		},
		{
			name: "mutating a returned value changes nothing stored",
			assert: func(t *testing.T, s passkey.CredentialStore) {
				c := stored(t, s, "C3")
				c.CredentialID[0] = 'X'
				c.PublicKey[0] = 'X'
				c.Transports[0] = "usb"
				c.Name = "changed"

				list, err := s.List(t.Context(), "u-2")
				require.NoError(t, err)
				list[0].AAGUID[0] = 9

				assert.Equal(t, credential("u-1", 3, "C3"), stored(t, s, "C3"))
				assert.Equal(t, credential("u-2", 4, "C4"), stored(t, s, "C4"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, seededStore(t, seed()...))
		})
	}
}

func TestMemoryCredentialStore_RecordAssertion(t *testing.T) {
	t.Parallel()

	at := storeTime.Add(time.Hour)

	type testCase struct {
		name      string
		seed      *passkey.Credential
		callers   int
		signCount uint32
		assert    func(t *testing.T, wins int, after *passkey.Credential)
	}

	unchanged := func(t *testing.T, wins int, after *passkey.Credential, want *passkey.Credential) {
		t.Helper()
		assert.Zero(t, wins)
		assert.Equal(t, want, after)
	}

	zeroCounter := func() *passkey.Credential {
		c := credential("u-1", 1, "C")
		c.SignCount = 0

		return c
	}

	cases := []testCase{
		{
			name:      "higher counter is recorded with backup state and last use",
			seed:      credential("u-1", 1, "C"),
			callers:   1,
			signCount: 43,
			assert: func(t *testing.T, wins int, after *passkey.Credential) {
				assert.Equal(t, 1, wins)
				assert.Equal(t, uint32(43), after.SignCount)
				assert.True(t, after.BackupState)
				assert.Equal(t, at, after.LastUsedAt)
			},
		},
		{
			name:      "8 concurrent recordings of one counter: exactly one wins",
			seed:      credential("u-1", 1, "C"),
			callers:   8,
			signCount: 43,
			assert: func(t *testing.T, wins int, after *passkey.Credential) {
				assert.Equal(t, 1, wins)
				assert.Equal(t, uint32(43), after.SignCount)
			},
		},
		{
			// Two tabs answered by one authenticator present the same next
			// counter. The write decides: one is recorded, the other is the
			// clone signal. This is the contract's choice, not a defect.
			name:      "two recordings with the same next counter: exactly one succeeds",
			seed:      credential("u-1", 1, "C"),
			callers:   2,
			signCount: 43,
			assert: func(t *testing.T, wins int, after *passkey.Credential) {
				assert.Equal(t, 1, wins)
				assert.Equal(t, uint32(43), after.SignCount)
			},
		},
		{
			name:      "counter going backwards is refused",
			seed:      credential("u-1", 1, "C"),
			callers:   1,
			signCount: 41,
			assert: func(t *testing.T, wins int, after *passkey.Credential) {
				unchanged(t, wins, after, credential("u-1", 1, "C"))
			},
		},
		{
			name:      "equal non-zero counter is refused",
			seed:      credential("u-1", 1, "C"),
			callers:   1,
			signCount: 42,
			assert: func(t *testing.T, wins int, after *passkey.Credential) {
				unchanged(t, wins, after, credential("u-1", 1, "C"))
			},
		},
		{
			name:      "zero over zero is recorded and moves last use",
			seed:      zeroCounter(),
			callers:   1,
			signCount: 0,
			assert: func(t *testing.T, wins int, after *passkey.Credential) {
				assert.Equal(t, 1, wins)
				assert.Zero(t, after.SignCount)
				assert.Equal(t, at, after.LastUsedAt)
			},
		},
		{
			name:      "8 concurrent zero recordings all succeed",
			seed:      zeroCounter(),
			callers:   8,
			signCount: 0,
			assert: func(t *testing.T, wins int, after *passkey.Credential) {
				assert.Equal(t, 8, wins)
			},
		},
		{
			name:      "suspended credential is not recorded",
			seed:      suspended(credential("u-1", 1, "C")),
			callers:   1,
			signCount: 43,
			assert: func(t *testing.T, wins int, after *passkey.Credential) {
				unchanged(t, wins, after, suspended(credential("u-1", 1, "C")))
			},
		},
		{
			name:      "pending credential is not recorded",
			seed:      pending(credential("u-1", 1, "C"), passkey.AwaitingSavedCodes),
			callers:   1,
			signCount: 43,
			assert: func(t *testing.T, wins int, after *passkey.Credential) {
				unchanged(t, wins, after, pending(credential("u-1", 1, "C"), passkey.AwaitingSavedCodes))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := seededStore(t, tc.seed)
			wins := concurrently(t, tc.callers, func() (bool, error) {
				return s.RecordAssertion(t.Context(), tc.seed.ID, tc.signCount, true, at)
			})

			tc.assert(t, wins, stored(t, s, "C"))
		})
	}

	t.Run("unknown credential is not recorded", func(t *testing.T) {
		t.Parallel()

		ok, err := passkey.NewMemoryCredentialStore().RecordAssertion(t.Context(), id.ID{1}, 1, false, at)
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

func TestMemoryCredentialStore_Suspend(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		seed    *passkey.Credential
		callers int
		assert  func(t *testing.T, wins int, after *passkey.Credential)
	}

	cases := []testCase{
		{
			name:    "active becomes suspended",
			seed:    credential("u-1", 1, "C"),
			callers: 1,
			assert: func(t *testing.T, wins int, after *passkey.Credential) {
				assert.Equal(t, 1, wins)
				assert.Equal(t, suspended(credential("u-1", 1, "C")), after)
			},
		},
		{
			name:    "8 concurrent suspensions: exactly one reports it",
			seed:    credential("u-1", 1, "C"),
			callers: 8,
			assert: func(t *testing.T, wins int, after *passkey.Credential) {
				assert.Equal(t, 1, wins)
				assert.Equal(t, passkey.StateSuspended, after.State)
			},
		},
		{
			name:    "pending is not suspended",
			seed:    pending(credential("u-1", 1, "C"), passkey.AwaitingSavedCodes),
			callers: 1,
			assert: func(t *testing.T, wins int, after *passkey.Credential) {
				assert.Zero(t, wins)
				assert.Equal(t, pending(credential("u-1", 1, "C"), passkey.AwaitingSavedCodes), after)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := seededStore(t, tc.seed)
			wins := concurrently(t, tc.callers, func() (bool, error) {
				return s.Suspend(t.Context(), tc.seed.ID)
			})

			tc.assert(t, wins, stored(t, s, "C"))
		})
	}
}

func TestMemoryCredentialStore_ClearReason(t *testing.T) {
	t.Parallel()

	both := passkey.AwaitingSavedCodes | passkey.AwaitingEmailCode

	type step struct {
		user   identity.UserID
		reason passkey.PendingReason
	}

	type result struct {
		state passkey.State
		ok    bool
	}

	type testCase struct {
		name   string
		seed   *passkey.Credential
		steps  []step
		assert func(t *testing.T, results []result, after *passkey.Credential)
	}

	cases := []testCase{
		{
			name: "two reasons cleared one by one: pending, then active",
			seed: pending(credential("u-1", 1, "C"), both),
			steps: []step{
				{user: "u-1", reason: passkey.AwaitingEmailCode},
				{user: "u-1", reason: passkey.AwaitingSavedCodes},
			},
			assert: func(t *testing.T, results []result, after *passkey.Credential) {
				assert.Equal(t, []result{{passkey.StatePending, true}, {passkey.StateActive, true}}, results)
				assert.Equal(t, passkey.StateActive, after.State)
				assert.Zero(t, after.Pending)
				assert.Nil(t, after.EmailCode)
			},
		},
		{
			name:  "clearing the emailed-code reason drops the code",
			seed:  pending(credential("u-1", 1, "C"), both),
			steps: []step{{user: "u-1", reason: passkey.AwaitingEmailCode}},
			assert: func(t *testing.T, results []result, after *passkey.Credential) {
				assert.Equal(t, []result{{passkey.StatePending, true}}, results)
				assert.Equal(t, passkey.AwaitingSavedCodes, after.Pending)
				assert.Nil(t, after.EmailCode)
			},
		},
		{
			name: "a reason cleared twice is refused the second time",
			seed: pending(credential("u-1", 1, "C"), both),
			steps: []step{
				{user: "u-1", reason: passkey.AwaitingSavedCodes},
				{user: "u-1", reason: passkey.AwaitingSavedCodes},
			},
			assert: func(t *testing.T, results []result, after *passkey.Credential) {
				assert.Equal(t, []result{{passkey.StatePending, true}, {0, false}}, results)
				assert.Equal(t, passkey.AwaitingEmailCode, after.Pending)
			},
		},
		{
			name:  "a reason not set is refused",
			seed:  pending(credential("u-1", 1, "C"), passkey.AwaitingSavedCodes),
			steps: []step{{user: "u-1", reason: passkey.AwaitingEmailCode}},
			assert: func(t *testing.T, results []result, after *passkey.Credential) {
				assert.Equal(t, []result{{0, false}}, results)
				assert.Equal(t, pending(credential("u-1", 1, "C"), passkey.AwaitingSavedCodes), after)
			},
		},
		{
			name:  "both reasons at once are refused and change nothing",
			seed:  pending(credential("u-1", 1, "C"), both),
			steps: []step{{user: "u-1", reason: both}},
			assert: func(t *testing.T, results []result, after *passkey.Credential) {
				assert.Equal(t, []result{{0, false}}, results)
				assert.Equal(t, pending(credential("u-1", 1, "C"), both), after)
			},
		},
		{
			name:  "a known reason with an unknown bit is refused and changes nothing",
			seed:  pending(credential("u-1", 1, "C"), both),
			steps: []step{{user: "u-1", reason: passkey.AwaitingSavedCodes | 4}},
			assert: func(t *testing.T, results []result, after *passkey.Credential) {
				assert.Equal(t, []result{{0, false}}, results)
				assert.Equal(t, pending(credential("u-1", 1, "C"), both), after)
			},
		},
		{
			name:  "the zero reason is refused and changes nothing",
			seed:  pending(credential("u-1", 1, "C"), both),
			steps: []step{{user: "u-1", reason: 0}},
			assert: func(t *testing.T, results []result, after *passkey.Credential) {
				assert.Equal(t, []result{{0, false}}, results)
				assert.Equal(t, pending(credential("u-1", 1, "C"), both), after)
			},
		},
		{
			name:  "an unknown reason is refused and changes nothing",
			seed:  pending(credential("u-1", 1, "C"), both),
			steps: []step{{user: "u-1", reason: 4}},
			assert: func(t *testing.T, results []result, after *passkey.Credential) {
				assert.Equal(t, []result{{0, false}}, results)
				assert.Equal(t, pending(credential("u-1", 1, "C"), both), after)
			},
		},
		{
			name:  "another user's credential is refused",
			seed:  pending(credential("u-1", 1, "C"), passkey.AwaitingSavedCodes),
			steps: []step{{user: "u-2", reason: passkey.AwaitingSavedCodes}},
			assert: func(t *testing.T, results []result, after *passkey.Credential) {
				assert.Equal(t, []result{{0, false}}, results)
				assert.Equal(t, passkey.StatePending, after.State)
			},
		},
		{
			name: "a suspended credential is refused",
			seed: func() *passkey.Credential {
				c := pending(credential("u-1", 1, "C"), passkey.AwaitingSavedCodes)
				c.State = passkey.StateSuspended

				return c
			}(),
			steps: []step{{user: "u-1", reason: passkey.AwaitingSavedCodes}},
			assert: func(t *testing.T, results []result, after *passkey.Credential) {
				assert.Equal(t, []result{{0, false}}, results)
				assert.Equal(t, passkey.StateSuspended, after.State)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := seededStore(t, tc.seed)

			var results []result

			for _, st := range tc.steps {
				state, ok, err := s.ClearReason(t.Context(), st.user, tc.seed.ID, st.reason)
				require.NoError(t, err)

				results = append(results, result{state, ok})
			}

			tc.assert(t, results, stored(t, s, "C"))
		})
	}
}

func TestMemoryCredentialStore_ChargeEmailAttempt(t *testing.T) {
	t.Parallel()

	before := storeTime.Add(5 * time.Minute)

	type testCase struct {
		name    string
		seed    *passkey.Credential
		user    identity.UserID
		at      time.Time
		callers int
		assert  func(t *testing.T, wins int, codes []*passkey.EmailCode, after *passkey.Credential)
	}

	withAttempts := func(n int) *passkey.Credential {
		c := pending(credential("u-1", 1, "C"), passkey.AwaitingEmailCode)
		c.EmailCode.Attempts = n

		return c
	}

	refused := func(want *passkey.Credential) func(*testing.T, int, []*passkey.EmailCode, *passkey.Credential) {
		return func(t *testing.T, wins int, codes []*passkey.EmailCode, after *passkey.Credential) {
			t.Helper()
			assert.Zero(t, wins)
			assert.Empty(t, codes)
			assert.Equal(t, want, after)
		}
	}

	cases := []testCase{
		{
			name:    "charges one attempt and returns the code",
			seed:    withAttempts(0),
			user:    "u-1",
			at:      before,
			callers: 1,
			assert: func(t *testing.T, wins int, codes []*passkey.EmailCode, after *passkey.Credential) {
				assert.Equal(t, 1, wins)
				require.Len(t, codes, 1)
				assert.Equal(t, &passkey.EmailCode{
					Code: "123456", ExpiresAt: storeTime.Add(10 * time.Minute), Attempts: 1,
				}, codes[0])
				assert.Equal(t, 1, after.EmailCode.Attempts)
			},
		},
		{
			name:    "20 concurrent charges: exactly five succeed",
			seed:    withAttempts(0),
			user:    "u-1",
			at:      before,
			callers: 20,
			assert: func(t *testing.T, wins int, codes []*passkey.EmailCode, after *passkey.Credential) {
				assert.Equal(t, passkey.MaxEmailCodeAttempts, wins)
				assert.Len(t, codes, passkey.MaxEmailCodeAttempts)
				assert.Equal(t, passkey.MaxEmailCodeAttempts, after.EmailCode.Attempts)
			},
		},
		{
			name: "the fifth attempt is the last", seed: withAttempts(4), user: "u-1", at: before, callers: 1,
			assert: func(t *testing.T, wins int, _ []*passkey.EmailCode, after *passkey.Credential) {
				assert.Equal(t, 1, wins)
				assert.Equal(t, 5, after.EmailCode.Attempts)
			},
		},
		{
			name: "five attempts charged is refused", seed: withAttempts(5), user: "u-1", at: before, callers: 1,
			assert: refused(withAttempts(5)),
		},
		{
			name: "at the expiry is refused", seed: withAttempts(0), user: "u-1",
			at: storeTime.Add(10 * time.Minute), callers: 1,
			assert: refused(withAttempts(0)),
		},
		{
			name: "another user's credential is refused", seed: withAttempts(0), user: "u-2", at: before, callers: 1,
			assert: refused(withAttempts(0)),
		},
		{
			name: "not awaiting an emailed code is refused",
			seed: pending(credential("u-1", 1, "C"), passkey.AwaitingSavedCodes),
			user: "u-1", at: before, callers: 1,
			assert: refused(pending(credential("u-1", 1, "C"), passkey.AwaitingSavedCodes)),
		},
		{
			name: "no code outstanding is refused",
			seed: func() *passkey.Credential {
				c := withAttempts(0)
				c.EmailCode = nil

				return c
			}(),
			user: "u-1", at: before, callers: 1,
			assert: func(t *testing.T, wins int, codes []*passkey.EmailCode, after *passkey.Credential) {
				assert.Zero(t, wins)
				assert.Empty(t, codes)
				assert.Nil(t, after.EmailCode)
			},
		},
		{
			name: "a suspended credential is refused",
			seed: func() *passkey.Credential {
				c := withAttempts(0)
				c.State = passkey.StateSuspended

				return c
			}(),
			user: "u-1", at: before, callers: 1,
			assert: func(t *testing.T, wins int, codes []*passkey.EmailCode, after *passkey.Credential) {
				assert.Zero(t, wins)
				assert.Zero(t, after.EmailCode.Attempts)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := seededStore(t, tc.seed)

			var (
				mu    sync.Mutex
				codes []*passkey.EmailCode
			)

			wins := concurrently(t, tc.callers, func() (bool, error) {
				code, ok, err := s.ChargeEmailAttempt(t.Context(), tc.user, tc.seed.ID, tc.at)
				if code != nil {
					mu.Lock()
					codes = append(codes, code)
					mu.Unlock()
				}

				return ok, err
			})

			tc.assert(t, wins, codes, stored(t, s, "C"))
		})
	}

	t.Run("mutating the returned code changes nothing stored", func(t *testing.T) {
		t.Parallel()

		s := seededStore(t, withAttempts(0))
		code, ok, err := s.ChargeEmailAttempt(t.Context(), "u-1", id.ID{15: 1}, before)
		require.NoError(t, err)
		require.True(t, ok)

		code.Code = "000000"
		code.Attempts = 0

		after := stored(t, s, "C")
		assert.Equal(t, "123456", after.EmailCode.Code)
		assert.Equal(t, 1, after.EmailCode.Attempts)
	})
}

func TestMemoryCredentialStore_Writes(t *testing.T) {
	t.Parallel()

	seed := func() []*passkey.Credential {
		return []*passkey.Credential{
			credential("u-1", 1, "C1"),
			pending(credential("u-1", 2, "C2"), passkey.AwaitingSavedCodes),
			pending(credential("u-1", 3, "C3"), passkey.AwaitingSavedCodes|passkey.AwaitingEmailCode),
			pending(credential("u-1", 4, "C4"), passkey.AwaitingEmailCode),
			credential("u-2", 5, "C5"),
			pending(credential("u-2", 6, "C6"), passkey.AwaitingSavedCodes),
		}
	}

	type testCase struct {
		name   string
		write  func(ctx context.Context, s passkey.CredentialStore) (any, error)
		assert func(t *testing.T, s passkey.CredentialStore, got any, err error)
	}

	credIDs := func(t *testing.T, s passkey.CredentialStore, user identity.UserID) []string {
		t.Helper()

		list, err := s.List(t.Context(), user)
		require.NoError(t, err)

		out := make([]string, 0, len(list))
		for _, c := range list {
			out = append(out, string(c.CredentialID))
		}

		return out
	}

	cases := []testCase{
		{
			name: "rename within the user",
			write: func(ctx context.Context, s passkey.CredentialStore) (any, error) {
				return s.Rename(ctx, "u-1", id.ID{15: 1}, "Phone")
			},
			assert: func(t *testing.T, s passkey.CredentialStore, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, true, got)
				assert.Equal(t, "Phone", stored(t, s, "C1").Name)
			},
		},
		{
			name: "rename of another user's credential is refused",
			write: func(ctx context.Context, s passkey.CredentialStore) (any, error) {
				return s.Rename(ctx, "u-1", id.ID{15: 5}, "Phone")
			},
			assert: func(t *testing.T, s passkey.CredentialStore, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, false, got)
				assert.Equal(t, "Laptop", stored(t, s, "C5").Name)
			},
		},
		{
			name: "delete within the user",
			write: func(ctx context.Context, s passkey.CredentialStore) (any, error) {
				return s.Delete(ctx, "u-1", id.ID{15: 1})
			},
			assert: func(t *testing.T, s passkey.CredentialStore, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, true, got)
				assert.Equal(t, []string{"C2", "C3", "C4"}, credIDs(t, s, "u-1"))

				_, err = s.FindByCredentialID(t.Context(), []byte("C1"))
				require.ErrorIs(t, err, passkey.ErrNotFound)
			},
		},
		{
			name: "delete of another user's credential is refused",
			write: func(ctx context.Context, s passkey.CredentialStore) (any, error) {
				return s.Delete(ctx, "u-1", id.ID{15: 5})
			},
			assert: func(t *testing.T, s passkey.CredentialStore, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, false, got)
				assert.Equal(t, []string{"C5", "C6"}, credIDs(t, s, "u-2"))
			},
		},
		{
			name: "a deleted credential ID may be inserted again",
			write: func(ctx context.Context, s passkey.CredentialStore) (any, error) {
				if _, err := s.Delete(ctx, "u-1", id.ID{15: 1}); err != nil {
					return nil, err
				}

				return nil, s.Insert(ctx, credential("u-2", 7, "C1"))
			},
			assert: func(t *testing.T, s passkey.CredentialStore, _ any, err error) {
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-2"), stored(t, s, "C1").User)
			},
		},
		{
			name: "delete awaiting saved codes removes only the user's credentials with the bit",
			write: func(ctx context.Context, s passkey.CredentialStore) (any, error) {
				return s.DeleteAwaitingSavedCodes(ctx, "u-1")
			},
			assert: func(t *testing.T, s passkey.CredentialStore, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, 2, got)
				assert.Equal(t, []string{"C1", "C4"}, credIDs(t, s, "u-1"))
				assert.Equal(t, []string{"C5", "C6"}, credIDs(t, s, "u-2"))
			},
		},
		{
			name: "delete user removes every credential of the user",
			write: func(ctx context.Context, s passkey.CredentialStore) (any, error) {
				return s.DeleteUser(ctx, "u-1")
			},
			assert: func(t *testing.T, s passkey.CredentialStore, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, 4, got)
				assert.Empty(t, credIDs(t, s, "u-1"))
				assert.Equal(t, []string{"C5", "C6"}, credIDs(t, s, "u-2"))

				_, err = s.FindByCredentialID(t.Context(), []byte("C3"))
				require.ErrorIs(t, err, passkey.ErrNotFound)
			},
		},
		{
			name: "delete user of a user with none removes nothing",
			write: func(ctx context.Context, s passkey.CredentialStore) (any, error) {
				return s.DeleteUser(ctx, "u-9")
			},
			assert: func(t *testing.T, s passkey.CredentialStore, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, 0, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := seededStore(t, seed()...)
			got, err := tc.write(t.Context(), s)
			tc.assert(t, s, got, err)
		})
	}
}
