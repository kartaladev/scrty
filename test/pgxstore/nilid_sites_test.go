package pgxstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/internal/idgen/idgentest"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestStores_GeneratorAnswers pins, per store that mints a row identifier, that
// a generator answering the nil identifier is refused like a failing one (same
// operation text), stores nothing under the nil id, and that a good identifier
// still stores the row.
func TestStores_GeneratorAnswers(t *testing.T) {
	t.Parallel()

	conn := migrated(t)
	cipher := storefix.TestCipher(t)
	errOutage := errors.New("generator outage")

	type testCase struct {
		name  string
		op    string
		table string
		write func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error
	}

	cases := []testCase{
		{"consent give", "pgxstore: give consent:", pgschema.ConsentTable,
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				return newConsentStore(t, pool, opt).Give(ctx, "u-1", "c-1", nil, false, opTime)
			}},
		{"assertion identifier record", "pgxstore: record assertion identifier:", pgschema.AssertionIDTable,
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				_, err := newAssertionStore(t, pool, opt).Record(ctx, "c-1", "jti", opTime)
				return err
			}},
		{"browser session put", "pgxstore: put browser session:", pgschema.BrowserSessionTable,
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				return newBrowserStore(t, pool, opt).Put(ctx, &oidcprovider.BrowserSession{
					Digest: []byte{1}, IdleExpiresAt: opTime, AbsoluteExpiresAt: opTime})
			}},
		{"client put", "pgxstore: put client:", pgschema.ClientTable,
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				return newClientStore(t, pool, opt).Put(ctx, confidentialClient("c-1"))
			}},
		{"login flow begin", "pgxstore: begin login flow:", "oidc_flows",
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				_, err := newFlowStore(t, pool, opt).Begin(ctx, oidc.Flow{
					Provider: "p", State: "s", Nonce: "n", Verifier: "v", Next: "/", ExpiresAt: time.Now().Add(time.Hour)})
				return err
			}},
		{"enrolment put pending", "seal: the inner store could not store the pending MFA enrolment", "mfa_enrolments",
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				return newEnrolmentStore(t, pool, cipher, opt).PutPending(ctx, mfa.Enrolment{
					User: "u-1", Secret: []byte("secret"), CreatedAt: opTime})
			}},
		{"passkey user handle assign", "pgxstore: assign passkey user handle:", "passkey_user_handles",
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				_, err := newPasskeyHandleStore(t, pool, opt).Assign(ctx, "nil-id-user", storefix.PasskeyOffer("nil-id-user", 0))
				return err
			}},
		{"recovery codes replace", "pgxstore: replace recovery codes:", "recovery_codes",
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				return newRecoveryCodeStore(t, pool, opt).ReplaceSet(ctx, "nil-id-user", recoveryHashes("nil-id", 1), recoveryAt)
			}},
		{"session create", "session: the inner store could not create the session", "sessions",
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				return newSessionStore(t, pool, cipher, opt).Create(ctx, storefix.DurableSession("nil-id", opTime))
			}},
		{"signing key store", "seal: the inner store could not store the signing key", "signing_keys",
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				return newSigningKeyStore(t, pool, cipher, opt).Store(ctx, storefix.SigningKey("nil-id-kid", []byte("private")))
			}},
	}

	nilGen := func(t *testing.T) pgxstore.Option {
		g := idgentest.NewMockGenerator(gomock.NewController(t))
		g.EXPECT().NewID().Return(id.Nil, nil).AnyTimes()

		return pgxstore.WithIDGenerator(g)
	}
	failGen := func(t *testing.T) pgxstore.Option {
		g := idgentest.NewMockGenerator(gomock.NewController(t))
		g.EXPECT().NewID().Return(id.Nil, errOutage).AnyTimes()

		return pgxstore.WithIDGenerator(g)
	}

	nilRows := func(ctx context.Context, t *testing.T, table string) int {
		t.Helper()

		var n int
		// table is one of this test's own constants.
		require.NoError(t, conn.Pool.QueryRow(ctx,
			"SELECT count(*) FROM "+table+" WHERE id = $1", id.Nil.String()).Scan(&n))

		return n
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			t.Run("good id stores the row", func(t *testing.T) {
				require.NoError(t, tc.write(t, ctx, conn.Pool, pgxstore.WithIDGenerator(id.NewV7Generator())))
			})
			t.Run("failing generator is refused", func(t *testing.T) {
				err := tc.write(t, ctx, conn.Pool, failGen(t))
				require.ErrorIs(t, err, errOutage)
				assert.Contains(t, err.Error(), tc.op)
			})
			t.Run("nil id is refused like a failing generator, nothing stored", func(t *testing.T) {
				err := tc.write(t, ctx, conn.Pool, nilGen(t))
				require.ErrorIs(t, err, idgen.ErrNil)
				assert.Contains(t, err.Error(), tc.op)
				assert.Zero(t, nilRows(ctx, t, tc.table), "a row was stored under the nil id")
			})
		})
	}
}

// TestStores_NilIdentifierLeavesStoredRecordUnchanged pins, against a real
// database, that a write which would replace an existing record keeps that
// record when the generator answers the nil identifier.
func TestStores_NilIdentifierLeavesStoredRecordUnchanged(t *testing.T) {
	t.Parallel()

	conn := migrated(t)
	cipher := storefix.TestCipher(t)

	nilGen := func(t *testing.T) pgxstore.Option {
		g := idgentest.NewMockGenerator(gomock.NewController(t))
		g.EXPECT().NewID().Return(id.Nil, nil).AnyTimes()

		return pgxstore.WithIDGenerator(g)
	}

	t.Run("client put keeps the old client", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		old := confidentialClient("c-keep")
		require.NoError(t, newClientStore(t, conn.Pool).Put(ctx, old))
		before, err := newClientStore(t, conn.Pool).Client(ctx, "c-keep")
		require.NoError(t, err)

		changed := old
		changed.Name = "Renamed"
		err = newClientStore(t, conn.Pool, nilGen(t)).Put(ctx, changed)
		require.ErrorIs(t, err, idgen.ErrNil)

		after, err := newClientStore(t, conn.Pool).Client(ctx, "c-keep")
		require.NoError(t, err)
		assert.Equal(t, before, after)
		assert.Equal(t, old.Name, after.Name)
	})

	t.Run("recovery codes replace keeps the old set", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		const user = "nil-id-replace"
		require.NoError(t, newRecoveryCodeStore(t, conn.Pool).ReplaceSet(ctx, user, recoveryHashes("old", 2), recoveryAt))

		err := newRecoveryCodeStore(t, conn.Pool, nilGen(t)).ReplaceSet(ctx, user, recoveryHashes("new", 3), recoveryAt)
		require.ErrorIs(t, err, idgen.ErrNil)

		left, err := newRecoveryCodeStore(t, conn.Pool).Remaining(ctx, user)
		require.NoError(t, err)
		assert.Equal(t, 2, left, "the old set must survive the rolled-back replace")
	})

	t.Run("signing key store keeps the old key", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		require.NoError(t, newSigningKeyStore(t, conn.Pool, cipher).Store(ctx, storefix.SigningKey("kid-keep", []byte("old"))))

		err := newSigningKeyStore(t, conn.Pool, cipher, nilGen(t)).Store(ctx, storefix.SigningKey("kid-keep", []byte("new")))
		require.ErrorIs(t, err, idgen.ErrNil)

		all, err := newSigningKeyStore(t, conn.Pool, cipher).LoadAll(ctx)
		require.NoError(t, err)
		var found bool
		for _, r := range all {
			if r.Kid == "kid-keep" {
				found = true
				assert.Equal(t, []byte("old"), r.Private)
			}
		}
		assert.True(t, found, "the old key must still be stored")
	})
}
