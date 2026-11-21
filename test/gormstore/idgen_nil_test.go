package gormstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/test/internal/idgenmock"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/store/gormstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// sequenceIDs is a MockGenerator that answers answers in order, then the
// last one for every later call, with a nil error.
func sequenceIDs(t *testing.T, answers ...id.ID) *idgenmock.MockGenerator {
	t.Helper()

	g := idgenmock.NewMockGenerator(gomock.NewController(t))
	calls := 0
	g.EXPECT().NewID().DoAndReturn(func() (id.ID, error) {
		got := answers[min(calls, len(answers)-1)]
		calls++

		return got, nil
	}).AnyTimes()

	return g
}

func rowCount(ctx context.Context, t *testing.T, d database, query string, args ...any) int {
	t.Helper()

	var n int
	require.NoError(t, d.conn.DB.QueryRowContext(ctx, query, args...).Scan(&n))

	return n
}

// TestStores_NilGeneratedID pins that a generator answering the nil
// identifier is a failing dependency at every id site of the attempt,
// password-history and identity stores: the call fails with the generator
// outcome and no row is stored under the nil identifier.
func TestStores_NilGeneratedID(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)
	good := id.MustParse("00000000-0000-4000-8000-0000000000a1")
	good2 := id.MustParse("00000000-0000-4000-8000-0000000000a2")
	good3 := id.MustParse("00000000-0000-4000-8000-0000000000b3")
	good4 := id.MustParse("00000000-0000-4000-8000-0000000000b4")
	good5 := id.MustParse("00000000-0000-4000-8000-0000000000b5")
	good6 := id.MustParse("00000000-0000-4000-8000-0000000000b6")
	good7 := id.MustParse("00000000-0000-4000-8000-0000000000b7")
	good8 := id.MustParse("00000000-0000-4000-8000-0000000000b8")
	good9 := id.MustParse("00000000-0000-4000-8000-0000000000b9")
	good10 := id.MustParse("00000000-0000-4000-8000-0000000000c1")
	good11 := id.MustParse("00000000-0000-4000-8000-0000000000c2")
	good12 := id.MustParse("00000000-0000-4000-8000-0000000000c3")
	cipher := storefix.TestCipher(t)
	at := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, d database)
	}

	// refused asserts err is the generator outcome: it walks to idgen.ErrNil
	// and carries the operation text a plain generator error carries at the
	// site, "gormstore: <op>: ...".
	refusedText := func(t *testing.T, err error, text string) {
		t.Helper()
		require.Error(t, err)
		require.ErrorIs(t, err, idgen.ErrNil)
		assert.Contains(t, err.Error(), text)
	}
	refused := func(t *testing.T, err error, op string) {
		t.Helper()
		refusedText(t, err, "gormstore: "+op+":")
	}

	// nilRows counts the rows of table stored under the nil identifier, and
	// rowsOf those stored under rowID.
	nilRows := func(ctx context.Context, t *testing.T, d database, table string) int {
		t.Helper()

		// table is one of this test's own constants.
		return rowCount(ctx, t, d, "SELECT count(*) FROM "+table+" WHERE id = $1", id.Nil.String())
	}
	rowsOf := func(ctx context.Context, t *testing.T, d database, table string, rowID id.ID) int {
		t.Helper()

		return rowCount(ctx, t, d, "SELECT count(*) FROM "+table+" WHERE id = $1", rowID.String())
	}

	cases := []testCase{
		{
			name: "attempts record nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newAttemptStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				refused(t, s.RecordFailure(ctx, "nil-attempt", at), "record login failure")
				assert.Empty(t, storefix.AttemptIDs(ctx, t, d.conn.DB, "nil-attempt"))
			},
		},
		{
			name: "attempts record good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newAttemptStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, good)))
				require.NoError(t, s.RecordFailure(ctx, "good-attempt", at))
				assert.Equal(t, []string{good.String()}, storefix.AttemptIDs(ctx, t, d.conn.DB, "good-attempt"))
			},
		},
		{
			name: "streak nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newAttemptStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				_, _, err := s.AddStreakFailure(ctx, "nil-streak", at, at.Add(-time.Hour), 5)
				refused(t, err, "add to login failure streak")
				assert.Zero(t, rowCount(ctx, t, d, `SELECT count(*) FROM login_failure_streaks WHERE username = $1`, "nil-streak"))
			},
		},
		{
			name: "streak good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newAttemptStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, good)))
				_, _, err := s.AddStreakFailure(ctx, "good-streak", at, at.Add(-time.Hour), 5)
				require.NoError(t, err)
				assert.Equal(t, 1, rowCount(ctx, t, d, `SELECT count(*) FROM login_failure_streaks WHERE username = $1`, "good-streak"))
			},
		},
		{
			name: "history nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				user := newHistoryUser(t)
				refused(t, s.RetirePassword(ctx, user, []byte("h"), 3), "retire password")
				got, err := s.RecentPasswords(ctx, user, 10)
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
		{
			name: "history good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, good)))
				user := newHistoryUser(t)
				require.NoError(t, s.RetirePassword(ctx, user, []byte("h"), 3))
				got, err := s.RecentPasswords(ctx, user, 10)
				require.NoError(t, err)
				assert.Equal(t, [][]byte{[]byte("h")}, got)
			},
		},
		{
			name: "provision user nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				_, err := s.Provision(ctx, "nil-user", identity.WithUserRoles("admin"))
				refused(t, err, "provision user")
				assert.Zero(t, userRowCount(ctx, t, d.conn.DB, "nil-user"))
			},
		},
		{
			name: "provision grant nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, good, id.Nil)))
				_, err := s.Provision(ctx, "nil-grant", identity.WithUserRoles("admin"))
				refused(t, err, "provision user")
				assert.Zero(t, userRowCount(ctx, t, d.conn.DB, "nil-grant"))
			},
		},
		{
			name: "provision good ids",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newIdentityStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, good, good2)))
				_, err := s.Provision(ctx, "good-user", identity.WithUserRoles("admin"))
				require.NoError(t, err)
				assert.Equal(t, 1, userRowCount(ctx, t, d.conn.DB, "good-user"))
			},
		},
		{
			name: "update grant rebuild nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				plain := newIdentityStore(t, d.db)
				_, err := plain.Provision(ctx, "nil-rebuild", identity.WithUserName("Before"), identity.WithUserRoles("admin"))
				require.NoError(t, err)

				s := newIdentityStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				_, err = s.Update(ctx, "nil-rebuild", identity.WithUserName("After"), identity.WithUserRoles("admin", "viewer"))
				refused(t, err, "update user")

				got, err := plain.LoadByUsername(ctx, "nil-rebuild")
				require.NoError(t, err)
				assert.Equal(t, "Before", got.Name, "the failed update renamed the user")
				require.Len(t, got.Roles, 1)
				assert.Equal(t, "admin", got.Roles[0].Name)
			},
		},
		{
			name: "update grant rebuild good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				plain := newIdentityStore(t, d.db)
				_, err := plain.Provision(ctx, "good-rebuild", identity.WithUserRoles("admin"))
				require.NoError(t, err)

				s := newIdentityStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, good)))
				_, err = s.Update(ctx, "good-rebuild", identity.WithUserRoles("admin", "viewer"))
				require.NoError(t, err)

				got, err := plain.LoadByUsername(ctx, "good-rebuild")
				require.NoError(t, err)
				assert.Len(t, got.Roles, 2)
			},
		},
		{
			name: "consent give nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newConsentStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				refused(t, s.Give(ctx, "u-nil", "c-nil", nil, false, opTime), "give consent")
				assert.Zero(t, nilRows(ctx, t, d, pgschema.ConsentTable))
			},
		},
		{
			name: "consent give good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newConsentStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, good3)))
				require.NoError(t, s.Give(ctx, "u-good", "c-good", nil, false, opTime))
				assert.Equal(t, 1, rowsOf(ctx, t, d, pgschema.ConsentTable, good3))
			},
		},
		{
			name: "assertion record nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newAssertionStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				fresh, err := s.Record(ctx, "c-nil", "jti-nil", opTime)
				refused(t, err, "record assertion identifier")
				assert.False(t, fresh)
				assert.Zero(t, nilRows(ctx, t, d, pgschema.AssertionIDTable))
			},
		},
		{
			name: "assertion record good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newAssertionStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, good4)))
				fresh, err := s.Record(ctx, "c-good", "jti-good", opTime)
				require.NoError(t, err)
				assert.True(t, fresh)
				assert.Equal(t, 1, rowsOf(ctx, t, d, pgschema.AssertionIDTable, good4))
			},
		},
		{
			name: "browser session put nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newBrowserStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				err := s.Put(ctx, &oidcprovider.BrowserSession{Digest: []byte{0xb1}, IdleExpiresAt: opTime, AbsoluteExpiresAt: opTime})
				refused(t, err, "put browser session")
				assert.Zero(t, nilRows(ctx, t, d, pgschema.BrowserSessionTable))
			},
		},
		{
			name: "browser session put good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newBrowserStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, good5)))
				require.NoError(t, s.Put(ctx, &oidcprovider.BrowserSession{Digest: []byte{0xb2}, IdleExpiresAt: opTime, AbsoluteExpiresAt: opTime}))
				assert.Equal(t, 1, rowsOf(ctx, t, d, pgschema.BrowserSessionTable, good5))
			},
		},
		{
			name: "client put nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newClientStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				refused(t, s.Put(ctx, confidentialClient("c-nilgen")), "put client")
				assert.Zero(t, nilRows(ctx, t, d, pgschema.ClientTable))
			},
		},
		{
			name: "client put good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newClientStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, good6)))
				require.NoError(t, s.Put(ctx, confidentialClient("c-goodgen")))
				assert.Equal(t, 1, rowsOf(ctx, t, d, pgschema.ClientTable, good6))
			},
		},
		{
			name: "login flow begin nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newFlowStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				handle, err := s.Begin(ctx, storefix.Flow("p-nil", "s-nil"))
				refused(t, err, "begin login flow")
				assert.Empty(t, handle)
				assert.Zero(t, nilRows(ctx, t, d, "oidc_flows"))
			},
		},
		{
			name: "login flow begin good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newFlowStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, good7)))
				handle, err := s.Begin(ctx, storefix.Flow("p-good", "s-good"))
				require.NoError(t, err)
				assert.NotEmpty(t, handle)
				assert.Equal(t, 1, rowsOf(ctx, t, d, "oidc_flows", good7))
			},
		},
		{
			name: "mfa put pending nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newEnrolmentStore(t, d.db, storefix.TestCipher(t), gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				refusedText(t, s.PutPending(ctx, storefix.Pending("mfa-nil-user", "TOTP-NIL")),
					"seal: the inner store could not store the pending MFA enrolment")
				assert.Zero(t, nilRows(ctx, t, d, "mfa_enrolments"))
			},
		},
		{
			name: "mfa put pending good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newEnrolmentStore(t, d.db, storefix.TestCipher(t), gormstore.WithIDGenerator(sequenceIDs(t, good8)))
				require.NoError(t, s.PutPending(ctx, storefix.Pending("mfa-good-user", "TOTP-GOOD")))
				assert.Equal(t, 1, rowsOf(ctx, t, d, "mfa_enrolments", good8))
			},
		},
		{
			name: "passkey handle assign nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newPasskeyHandleStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				_, err := s.Assign(ctx, "nil-id-user", storefix.PasskeyOffer("nil-id-user", 0))
				refused(t, err, "assign passkey user handle")
				assert.Zero(t, nilRows(ctx, t, d, "passkey_user_handles"))
			},
		},
		{
			name: "passkey handle assign good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newPasskeyHandleStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, good9)))
				_, err := s.Assign(ctx, "good-id-user", storefix.PasskeyOffer("good-id-user", 0))
				require.NoError(t, err)
				assert.Equal(t, 1, rowsOf(ctx, t, d, "passkey_user_handles", good9))
			},
		},
		{
			name: "recovery codes replace nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newRecoveryCodeStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				refused(t, s.ReplaceSet(ctx, "nil-id-user", recoveryHashes("nil-id", 1), recoveryAt), "replace recovery codes")
				assert.Zero(t, nilRows(ctx, t, d, "recovery_codes"))
			},
		},
		{
			name: "recovery codes replace good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newRecoveryCodeStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, good10)))
				require.NoError(t, s.ReplaceSet(ctx, "good-id-user", recoveryHashes("good-id", 1), recoveryAt))
				assert.Equal(t, 1, rowsOf(ctx, t, d, "recovery_codes", good10))
			},
		},
		{
			name: "recovery codes replace nil id keeps the old set",
			assert: func(t *testing.T, ctx context.Context, d database) {
				const user = "nil-id-replace"
				require.NoError(t, newRecoveryCodeStore(t, d.db).ReplaceSet(ctx, user, recoveryHashes("old", 2), recoveryAt))

				s := newRecoveryCodeStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				refused(t, s.ReplaceSet(ctx, user, recoveryHashes("new", 3), recoveryAt), "replace recovery codes")

				left, err := newRecoveryCodeStore(t, d.db).Remaining(ctx, user)
				require.NoError(t, err)
				assert.Equal(t, 2, left, "the old set must survive the rolled-back replace")
			},
		},
		{
			name: "session create nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newSessionStore(t, d.db, cipher, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				refusedText(t, s.Create(ctx, storefix.DurableSession("nil-id", opTime)),
					"session: the inner store could not create the session")
				assert.Zero(t, nilRows(ctx, t, d, "sessions"))
			},
		},
		{
			name: "session create good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newSessionStore(t, d.db, cipher, gormstore.WithIDGenerator(sequenceIDs(t, good11)))
				require.NoError(t, s.Create(ctx, storefix.DurableSession("good-id", opTime)))
				assert.Equal(t, 1, rowsOf(ctx, t, d, "sessions", good11))
			},
		},
		{
			name: "signing key store nil id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newSigningKeyStore(t, d.db, cipher, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				refusedText(t, s.Store(ctx, storefix.SigningKey("nil-id-kid", []byte("private"))),
					"seal: the inner store could not store the signing key")
				assert.Zero(t, nilRows(ctx, t, d, "signing_keys"))
			},
		},
		{
			name: "signing key store good id",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newSigningKeyStore(t, d.db, cipher, gormstore.WithIDGenerator(sequenceIDs(t, good12)))
				require.NoError(t, s.Store(ctx, storefix.SigningKey("good-id-kid", []byte("private"))))
				assert.Equal(t, 1, rowsOf(ctx, t, d, "signing_keys", good12))
			},
		},
		{
			name: "signing key store nil id keeps the old key",
			assert: func(t *testing.T, ctx context.Context, d database) {
				require.NoError(t, newSigningKeyStore(t, d.db, cipher).Store(ctx, storefix.SigningKey("kid-keep", []byte("old"))))

				s := newSigningKeyStore(t, d.db, cipher, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil)))
				refusedText(t, s.Store(ctx, storefix.SigningKey("kid-keep", []byte("new"))),
					"seal: the inner store could not store the signing key")

				all, err := newSigningKeyStore(t, d.db, cipher).LoadAll(ctx)
				require.NoError(t, err)
				var found bool
				for _, r := range all {
					if r.Kid == "kid-keep" {
						found = true
						assert.Equal(t, []byte("old"), r.Private)
					}
				}
				assert.True(t, found, "the old key must still be stored")
			},
		},
		{
			name: "client put nil id keeps the old client",
			assert: func(t *testing.T, ctx context.Context, d database) {
				old := confidentialClient("c-keep")
				require.NoError(t, newClientStore(t, d.db).Put(ctx, old))
				before, err := newClientStore(t, d.db).Client(ctx, "c-keep")
				require.NoError(t, err)

				changed := old
				changed.Name = "Renamed"
				refused(t, newClientStore(t, d.db, gormstore.WithIDGenerator(sequenceIDs(t, id.Nil))).Put(ctx, changed), "put client")

				after, err := newClientStore(t, d.db).Client(ctx, "c-keep")
				require.NoError(t, err)
				assert.Equal(t, before, after)
				assert.Equal(t, old.Name, after.Name)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, t.Context(), d)
		})
	}
}
