package crossbackend_test

import (
	"bytes"
	"crypto/sha512"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/sqlstore"
)

// passkeyCredentialStore builds the passkey credential store of the named
// backend.
func (b backends) passkeyCredentialStore(t *testing.T, name string) passkey.CredentialStore {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewPasskeyCredentialStore(b.conn.DB, b.cipher)
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewPasskeyCredentialStore(b.pool, b.cipher)
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewPasskeyCredentialStore(b.gdb, b.cipher)
		require.NoError(t, err)
		return s
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// passkeyHandleStore builds the passkey user-handle store of the named
// backend.
func (b backends) passkeyHandleStore(t *testing.T, name string) passkey.HandleStore {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewPasskeyHandleStore(b.conn.DB)
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewPasskeyHandleStore(b.pool)
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewPasskeyHandleStore(b.gdb)
		require.NoError(t, err)
		return s
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// crossBackendPasskey is a credential of seed's own with every attribute set,
// pending on both reasons, with an emailed code part way through its
// attempts, so every column carries a value.
func crossBackendPasskey(seed string) *passkey.Credential {
	created := time.Date(2030, 1, 1, 10, 0, 0, 123000, time.UTC)

	return &passkey.Credential{
		ID:                   crossBackendID(seed),
		User:                 identity.UserID("u-" + seed),
		CredentialID:         []byte("cred-" + seed),
		PublicKey:            []byte("cose-" + seed),
		SignCount:            1<<32 - 2,
		BackupEligible:       true,
		BackupState:          true,
		Transports:           []string{"usb", "nfc", "hybrid"},
		AAGUID:               bytes.Repeat([]byte{0x5A}, 16),
		AttestationFormat:    "packed",
		AttestationStatement: []byte("statement-" + seed),
		Name:                 "Laptop " + seed,
		CreatedAt:            created,
		LastUsedAt:           created.Add(time.Hour),
		State:                passkey.StatePending,
		Pending:              passkey.AwaitingSavedCodes | passkey.AwaitingEmailCode,
		EmailCode:            &passkey.EmailCode{Code: "314159", ExpiresAt: created.Add(10 * time.Minute), Attempts: 2},
	}
}

// TestCrossBackendPasskey proves every ordered pair of backends agrees on the
// passkey tables: a credential inserted through the writer is found by its
// credential ID through the reader with every attribute equal, its emailed
// code opening there; a counter the writer records is refused again by the
// reader; and a handle the writer assigns is the one the reader returns and
// maps back.
func TestCrossBackendPasskey(t *testing.T) {
	t.Parallel()

	conn := migratedConn(t)
	b := backends{conn: conn, pool: openPgxPool(t, conn.DSN), gdb: openGormDB(t, conn.DSN), cipher: testCipher(t)}

	for _, writer := range backendNames {
		for _, reader := range backendNames {
			if writer == reader {
				continue
			}

			t.Run(writer+"_writes_"+reader+"_reads", func(t *testing.T) {
				t.Parallel()

				ctx := t.Context()
				seed := "passkey-" + writer + "-" + reader
				want := crossBackendPasskey(seed)
				w, rd := b.passkeyCredentialStore(t, writer), b.passkeyCredentialStore(t, reader)
				require.NoError(t, w.Insert(ctx, want))

				got, err := rd.FindByCredentialID(ctx, want.CredentialID)
				require.NoError(t, err)
				assert.Equal(t, want, got)

				active := crossBackendPasskey(seed + "-active")
				active.State, active.Pending, active.EmailCode = passkey.StateActive, 0, nil
				require.NoError(t, w.Insert(ctx, active))
				ok, err := w.RecordAssertion(ctx, active.ID, 1<<32-1, false, active.LastUsedAt.Add(time.Hour))
				require.NoError(t, err)
				require.True(t, ok)
				ok, err = rd.RecordAssertion(ctx, active.ID, 1<<32-1, false, active.LastUsedAt.Add(2*time.Hour))
				require.NoError(t, err)
				assert.False(t, ok, "a counter recorded through %s must be refused through %s", writer, reader)

				user := identity.UserID("u-" + seed)
				first, second := sha512.Sum512([]byte(seed+"-first")), sha512.Sum512([]byte(seed+"-second"))
				held, err := b.passkeyHandleStore(t, writer).Assign(ctx, user, first[:])
				require.NoError(t, err)
				require.Equal(t, first[:], held)
				again, err := b.passkeyHandleStore(t, reader).Assign(ctx, user, second[:])
				require.NoError(t, err)
				assert.Equal(t, held, again, "the handle assigned through %s is the one %s returns", writer, reader)
				owner, found, err := b.passkeyHandleStore(t, reader).UserFor(ctx, held)
				require.NoError(t, err)
				assert.True(t, found)
				assert.Equal(t, user, owner)
			})
		}
	}
}
