package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/store/sqlstore"
	"github.com/kartaladev/scrty/test/internal/idgenmock"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestSQLStore_NilIdentifierFromGenerator pins, against a real database, that a
// store whose generator answers the nil identifier fails like one whose
// generator fails: the same operation text, no row stored.
func TestSQLStore_NilIdentifierFromGenerator(t *testing.T) {
	t.Parallel()

	errGenerator := errors.New("generator exhausted")

	type site struct {
		name  string
		table string
		op    string
		write func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error
	}

	sites := []site{
		{"consents", pgschema.ConsentTable, "give consent",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				return newConsentStore(t, db, sqlstore.WithIDGenerator(g)).Give(ctx, "u-1", "c-1", nil, false, opTime)
			}},
		{"assertion identifiers", pgschema.AssertionIDTable, "record assertion identifier",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				_, err := newAssertionStore(t, db, sqlstore.WithIDGenerator(g)).Record(ctx, "c-1", "jti", opTime)
				return err
			}},
		{"browser sessions", pgschema.BrowserSessionTable, "put browser session",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				return newBrowserStore(t, db, sqlstore.WithIDGenerator(g)).Put(ctx, &oidcprovider.BrowserSession{
					Digest: []byte{1}, IdleExpiresAt: opTime, AbsoluteExpiresAt: opTime,
				})
			}},
		{"clients", pgschema.ClientTable, "put client",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				return newClientStore(t, db, sqlstore.WithIDGenerator(g)).Put(ctx, confidentialClient("c-1"))
			}},
		{"login flows", "oidc_flows", "begin login flow",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				_, err := newFlowStore(t, db, sqlstore.WithIDGenerator(g)).Begin(ctx, oidc.Flow{
					Provider: "p", State: "s", Nonce: "n", Verifier: "v", ExpiresAt: opTime,
				})
				return err
			}},
		{"MFA enrolments", "mfa_enrolments", "seal: the inner store could not store the pending MFA enrolment",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				return newEnrolmentStore(t, db, storefix.TestCipher(t), sqlstore.WithIDGenerator(g)).
					PutPending(ctx, storefix.Pending("nil-id-user", "TOTP"))
			}},
		{"passkey user handles", "passkey_user_handles", "assign passkey user handle",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				_, err := newPasskeyHandleStore(t, db, sqlstore.WithIDGenerator(g)).
					Assign(ctx, "nil-id-user", storefix.PasskeyOffer("nil-id-user", 0))
				return err
			}},
		{"recovery codes", "recovery_codes", "replace recovery codes",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				return newRecoveryCodeStore(t, db, sqlstore.WithIDGenerator(g)).
					ReplaceSet(ctx, "nil-id-user", recoveryHashes("nil-id", 1), recoveryAt)
			}},
		{"sessions", "sessions", "session: the inner store could not create the session",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				return newSessionStore(t, db, storefix.TestCipher(t), sqlstore.WithIDGenerator(g)).
					Create(ctx, storefix.DurableSession("nil-id", opTime))
			}},
		{"signing keys", "signing_keys", "seal: the inner store could not store the signing key",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				return newSigningKeyStore(t, db, storefix.TestCipher(t), sqlstore.WithIDGenerator(g)).
					Store(ctx, storefix.SigningKey("nil-id-kid", []byte("private")))
			}},
	}

	type testCase struct {
		name   string
		got    id.ID
		genErr error
		assert func(t *testing.T, s site, err error, rows int)
	}

	cases := []testCase{
		{
			name: "a good id stores the row",
			got:  storefix.NewID(t),
			assert: func(t *testing.T, _ site, err error, rows int) {
				require.NoError(t, err)
				assert.Equal(t, 1, rows)
			},
		},
		{
			name:   "a generator failure fails the write and stores nothing",
			genErr: errGenerator,
			assert: func(t *testing.T, s site, err error, rows int) {
				require.ErrorIs(t, err, errGenerator)
				assert.Contains(t, err.Error(), s.op)
				assert.Zero(t, rows)
			},
		},
		{
			name: "a generator answering the nil id fails like a generator failure and stores nothing",
			got:  id.Nil,
			assert: func(t *testing.T, s site, err error, rows int) {
				require.ErrorIs(t, err, idgen.ErrNil)
				assert.Contains(t, err.Error(), s.op)
				assert.Zero(t, rows)
			},
		},
	}

	for _, s := range sites {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()

					ctx := t.Context()
					db := migratedDB(t).DB
					g := idgenmock.NewMockGenerator(gomock.NewController(t))
					g.EXPECT().NewID().Return(tc.got, tc.genErr).AnyTimes()

					err := s.write(t, ctx, db, g)

					var rows int
					// table is one of this test's own constants.
					require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM "+s.table).Scan(&rows))
					tc.assert(t, s, err, rows)
				})
			}
		})
	}
}

// TestSQLStore_NilIdentifierLeavesStoredRecordUnchanged pins, against a real
// database, that a write which would replace an existing record keeps that
// record when the generator answers the nil identifier.
func TestSQLStore_NilIdentifierLeavesStoredRecordUnchanged(t *testing.T) {
	t.Parallel()

	nilGen := func(t *testing.T) id.Generator {
		g := idgenmock.NewMockGenerator(gomock.NewController(t))
		g.EXPECT().NewID().Return(id.Nil, nil).AnyTimes()

		return g
	}

	t.Run("recovery codes keep the old set", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		db := migratedDB(t).DB
		const user = "nil-id-replace"
		require.NoError(t, newRecoveryCodeStore(t, db).ReplaceSet(ctx, user, recoveryHashes("old", 2), recoveryAt))

		err := newRecoveryCodeStore(t, db, sqlstore.WithIDGenerator(nilGen(t))).
			ReplaceSet(ctx, user, recoveryHashes("new", 3), recoveryAt)
		require.ErrorIs(t, err, idgen.ErrNil)

		left, err := newRecoveryCodeStore(t, db).Remaining(ctx, user)
		require.NoError(t, err)
		assert.Equal(t, 2, left)
	})

	t.Run("clients keep the old client", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		db := migratedDB(t).DB
		old := confidentialClient("c-keep")
		require.NoError(t, newClientStore(t, db).Put(ctx, old))
		before, err := newClientStore(t, db).Client(ctx, "c-keep")
		require.NoError(t, err)

		changed := old
		changed.Name = "Renamed"
		err = newClientStore(t, db, sqlstore.WithIDGenerator(nilGen(t))).Put(ctx, changed)
		require.ErrorIs(t, err, idgen.ErrNil)

		after, err := newClientStore(t, db).Client(ctx, "c-keep")
		require.NoError(t, err)
		assert.Equal(t, before, after)
		assert.Equal(t, old.Name, after.Name)
	})

	t.Run("signing keys keep the old key", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		db := migratedDB(t).DB
		c := storefix.TestCipher(t)
		require.NoError(t, newSigningKeyStore(t, db, c).Store(ctx, storefix.SigningKey("kid-1", []byte("old"))))

		err := newSigningKeyStore(t, db, c, sqlstore.WithIDGenerator(nilGen(t))).
			Store(ctx, storefix.SigningKey("kid-1", []byte("new")))
		require.ErrorIs(t, err, idgen.ErrNil)

		got, err := newSigningKeyStore(t, db, c).LoadAll(ctx)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []byte("old"), got[0].Private)
	})
}
