package pgx

import (
	"context"
	"errors"
	"time"

	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
)

// PasskeyCredentialStore keeps passkey credentials in the passkey_credentials
// table the migrate package creates. It implements passkey.CredentialStore,
// and is safe for concurrent use.
//
// Every state change is one conditional statement with every condition in its
// WHERE clause, so it is decided by the write, on this process or on another
// replica: of concurrent recordings of one counter exactly one succeeds, and
// of concurrent charges against one emailed code no more than
// passkey.MaxEmailCodeAttempts do. A refused write changes nothing and
// reports false with a nil error. Insert refuses a credential ID or library
// identifier already stored with passkey.ErrDuplicateCredential, decided by
// the table's unique indexes without failing a statement, so the refusal
// never aborts a caller's transaction. A database failure is returned wrapped
// with the operation's name, never as a refusal or as absence.
//
// Limit, stated: the refusal never aborting a caller's transaction holds under
// READ COMMITTED, the PostgreSQL default. Under a caller-owned REPEATABLE READ
// or SERIALIZABLE transaction, a conflicting row committed after the caller's
// snapshot surfaces as a serialization failure (SQLSTATE 40001) that aborts
// the caller's transaction, and the caller retries it.
//
// The emailed code is sealed with the store's cipher before it is written,
// bound to the credential's library identifier and user reference
// (seal.PasskeyEmailCodeAAD), and stored base64url-encoded; it is opened when
// read and never re-sealed on read. A code that will not open is an error,
// never a missing code.
//
// The transports column holds the transports one per line.
type PasskeyCredentialStore struct {
	c      *config
	cipher seal.Cipher
}

// NewPasskeyCredentialStore returns a durable passkey credential store on
// pool, sealing emailed codes with c. There is no unsealed variant, and a nil
// c, typed nil included, is a configuration error.
//
// It honours WithTxResolver and refuses any other option: a credential
// carries its own library identifier, so WithIDGenerator does not apply, and
// every time comes from the caller, so WithClock does not either.
//
// Limits, stated:
//   - PostgreSQL text cannot hold a NUL byte or invalid UTF-8. An insert whose
//     user reference, name, attestation format or a transport holds either is
//     refused with an error that names the field, never the value, and
//     nothing is written; any other operation for such a user reference
//     matches nothing.
//   - A transport that is empty or holds a line break is refused the same
//     way, since the column holds one transport per line.
//   - Stored times are UTC, truncated to the microsecond.
func NewPasskeyCredentialStore(pool *pgxpool.Pool, c seal.Cipher, opts ...Option) (*PasskeyCredentialStore, error) {
	cfg, err := newConfig(pool, opts)
	if err != nil {
		return nil, err
	}
	if err := storekit.RequireCipher(c, ErrConfig); err != nil {
		return nil, err
	}

	return &PasskeyCredentialStore{c: cfg, cipher: c}, nil
}

// Insert stores c, refusing a credential ID or library identifier already
// stored with passkey.ErrDuplicateCredential. Under READ COMMITTED the refusal
// never aborts a caller's transaction; under a caller-owned REPEATABLE READ or
// SERIALIZABLE one, a conflicting row committed after the caller's snapshot is
// a serialization failure (SQLSTATE 40001) that aborts it, and the caller
// retries. That failure is returned as a database failure, not as a refusal.
func (s *PasskeyCredentialStore) Insert(ctx context.Context, c *passkey.Credential) error {
	const op = "insert passkey credential"

	if err := storekit.CheckID(c.ID, "passkey credential"); err != nil {
		return failed(op, err)
	}
	transports, err := pgschema.PasskeyTransportsText(c.Transports)
	if err == nil {
		err = storekit.CheckStorable(
			storekit.Text("user", string(c.User)),
			storekit.Text("name", c.Name),
			storekit.Text("attestation format", c.AttestationFormat),
			storekit.Text("transports", transports),
		)
	}
	if err != nil {
		return failed(op, err)
	}

	var (
		code      pgtype.Text
		codeUntil pgtype.Timestamptz
		attempts  int16
	)
	if c.EmailCode != nil {
		sealed, err := s.cipher.Seal([]byte(c.EmailCode.Code), seal.PasskeyEmailCodeAAD(c.ID, c.User))
		if err != nil {
			return failed(op, err)
		}
		code = pgtype.Text{String: storekit.SecretText(sealed), Valid: true}
		codeUntil, attempts = nullTs(c.EmailCode.ExpiresAt), int16(c.EmailCode.Attempts) //nolint:gosec // G115: at most a few
	}

	return s.c.execOrRefuse(ctx, op, passkey.ErrDuplicateCredential, pgschema.PasskeyCredentialInsert,
		uuidArg(c.ID), string(c.User), storekit.OrEmpty(c.CredentialID), storekit.OrEmpty(c.PublicKey),
		int64(c.SignCount), c.BackupEligible, c.BackupState, transports, c.AAGUID, nullText(c.AttestationFormat),
		c.AttestationStatement, c.Name, storekit.Time(c.CreatedAt), nullTs(c.LastUsedAt),
		int16(c.State), int16(c.Pending), code, codeUntil, attempts)
}

// FindByCredentialID returns the credential with credential ID credID, or
// passkey.ErrNotFound.
func (s *PasskeyCredentialStore) FindByCredentialID(ctx context.Context, credID []byte) (*passkey.Credential, error) {
	return s.one(ctx, "find passkey credential", pgschema.PasskeyCredentialByCredentialID, storekit.OrEmpty(credID))
}

// Find returns user's credential cid, or passkey.ErrNotFound.
func (s *PasskeyCredentialStore) Find(ctx context.Context, user identity.UserID, cid id.ID) (*passkey.Credential, error) {
	if !storekit.Storable(string(user)) {
		return nil, passkey.ErrNotFound
	}

	return s.one(ctx, "find passkey credential", pgschema.PasskeyCredentialFind, uuidArg(cid), string(user))
}

// one reads the single credential query selects, or passkey.ErrNotFound.
func (s *PasskeyCredentialStore) one(ctx context.Context, op, query string, args ...any) (*passkey.Credential, error) {
	list, err := s.list(ctx, op, query, args...)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, passkey.ErrNotFound
	}

	return list[0], nil
}

// List returns user's credentials in every state, oldest first, ties in
// library identifier order.
func (s *PasskeyCredentialStore) List(ctx context.Context, user identity.UserID) ([]*passkey.Credential, error) {
	if !storekit.Storable(string(user)) {
		return nil, nil
	}

	return s.list(ctx, "list passkey credentials", pgschema.PasskeyCredentialList, string(user))
}

// list runs query and scans every credential it selects, opening each
// emailed code.
func (s *PasskeyCredentialStore) list(ctx context.Context, op, query string, args ...any) ([]*passkey.Credential, error) {
	var out []*passkey.Credential
	err := s.c.query(ctx, op, query, args, func(rows pgxv5.Rows) error {
		c, err := s.scan(rows)
		if err != nil {
			return err
		}
		out = append(out, c)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// scan reads one credential row, in the column order of the selects.
func (s *PasskeyCredentialStore) scan(rows pgxv5.Rows) (*passkey.Credential, error) {
	var (
		c                   passkey.Credential
		rowID               pgtype.UUID
		user, transports    string
		signCount           int64
		format, code        pgtype.Text
		created             pgtype.Timestamptz
		lastUsed, codeUntil pgtype.Timestamptz
		state, pending      int16
		attempts            int16
	)
	if err := rows.Scan(&rowID, &user, &c.CredentialID, &c.PublicKey, &signCount, &c.BackupEligible,
		&c.BackupState, &transports, &c.AAGUID, &format, &c.AttestationStatement, &c.Name, &created, &lastUsed,
		&state, &pending, &code, &codeUntil, &attempts); err != nil {
		return nil, err
	}

	var err error
	if c.ID, err = scanID(rowID); err != nil {
		return nil, err
	}
	if c.CreatedAt, err = fromNull(created); err != nil {
		return nil, err
	}
	if c.LastUsedAt, err = fromNull(lastUsed); err != nil {
		return nil, err
	}
	c.User = identity.UserID(user)
	c.SignCount = uint32(signCount) //nolint:gosec // G115: the column only ever holds a uint32
	c.Transports = pgschema.ParsePasskeyTransports(transports)
	c.AttestationFormat = format.String
	c.State, c.Pending = passkey.State(state), passkey.PendingReason(pending) //nolint:gosec // G115: small enums

	if code.Valid {
		until, err := fromNull(codeUntil)
		if err != nil {
			return nil, err
		}
		opened, err := s.open(code.String, c.ID, c.User)
		if err != nil {
			return nil, err
		}
		c.EmailCode = &passkey.EmailCode{Code: opened, ExpiresAt: until, Attempts: int(attempts)}
	}

	return &c, nil
}

// open opens the emailed code of user's credential cid, stored as text.
func (s *PasskeyCredentialStore) open(text string, cid id.ID, user identity.UserID) (string, error) {
	sealed, err := storekit.SecretFromText(text)
	if err != nil {
		return "", err
	}
	plain, _, err := s.cipher.Open(sealed, seal.PasskeyEmailCodeAAD(cid, user))
	if err != nil {
		return "", err
	}

	return string(plain), nil
}

// Count counts user's credentials in every state.
func (s *PasskeyCredentialStore) Count(ctx context.Context, user identity.UserID) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	return s.c.count(ctx, "count passkey credentials", pgschema.PasskeyCredentialCount, string(user))
}

// RecordAssertion records the counter, backup state and last use of active
// credential cid whose stored counter is lower than signCount, or where both
// are zero, in one conditional update.
func (s *PasskeyCredentialStore) RecordAssertion(
	ctx context.Context, cid id.ID, signCount uint32, backupState bool, at time.Time,
) (bool, error) {
	n, err := s.c.exec(ctx, "record passkey assertion", pgschema.PasskeyRecordAssertion,
		uuidArg(cid), int64(signCount), backupState, storekit.Time(at))

	return n > 0, err
}

// RecordUse records the backup state and last use of active credential cid,
// leaving its counter, in one conditional update.
func (s *PasskeyCredentialStore) RecordUse(ctx context.Context, cid id.ID, backupState bool, at time.Time) (bool, error) {
	n, err := s.c.exec(ctx, "record passkey use", pgschema.PasskeyRecordUse,
		uuidArg(cid), backupState, storekit.Time(at))

	return n > 0, err
}

// Suspend moves active credential cid to suspended, in one conditional
// update.
func (s *PasskeyCredentialStore) Suspend(ctx context.Context, cid id.ID) (bool, error) {
	n, err := s.c.exec(ctx, "suspend passkey credential", pgschema.PasskeySuspend, uuidArg(cid))

	return n > 0, err
}

// ClearReason clears the single reason r of user's pending credential cid, in
// one conditional update. Any r that is not exactly one known reason is
// refused before a statement runs.
func (s *PasskeyCredentialStore) ClearReason(
	ctx context.Context, user identity.UserID, cid id.ID, r passkey.PendingReason,
) (passkey.State, bool, error) {
	if (r != passkey.AwaitingSavedCodes && r != passkey.AwaitingEmailCode) || !storekit.Storable(string(user)) {
		return 0, false, nil
	}

	var state int16
	err := s.c.queryRow(ctx, "clear passkey pending reason", pgschema.PasskeyClearReason,
		[]any{uuidArg(cid), string(user), int16(r)}, &state)
	if errors.Is(err, pgxv5.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}

	return passkey.State(state), true, nil //nolint:gosec // G115: a small enum
}

// ChargeEmailAttempt charges one attempt against the outstanding, unexpired
// emailed code of user's pending credential cid, in one conditional update
// that returns the sealed code, which is then opened. When the stored code
// cannot be opened, the attempt has already been charged and committed, and an
// error is returned: it fails closed, and the attempt is not refunded.
func (s *PasskeyCredentialStore) ChargeEmailAttempt(
	ctx context.Context, user identity.UserID, cid id.ID, at time.Time,
) (*passkey.EmailCode, bool, error) {
	const op = "charge passkey emailed code"

	if !storekit.Storable(string(user)) {
		return nil, false, nil
	}

	var (
		text     string
		until    pgtype.Timestamptz
		attempts int16
	)
	err := s.c.queryRow(ctx, op, pgschema.PasskeyChargeEmailAttempt,
		[]any{uuidArg(cid), string(user), storekit.Time(at), int16(passkey.MaxEmailCodeAttempts)},
		&text, &until, &attempts)
	if errors.Is(err, pgxv5.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	expires, err := fromNull(until)
	if err != nil {
		return nil, false, failed(op, err)
	}
	code, err := s.open(text, cid, user)
	if err != nil {
		return nil, false, failed(op, err)
	}

	return &passkey.EmailCode{Code: code, ExpiresAt: expires, Attempts: int(attempts)}, true, nil
}

// Rename sets the name of user's credential cid.
func (s *PasskeyCredentialStore) Rename(ctx context.Context, user identity.UserID, cid id.ID, name string) (bool, error) {
	const op = "rename passkey credential"

	if !storekit.Storable(string(user)) {
		return false, nil
	}
	if err := storekit.CheckStorable(storekit.Text("name", name)); err != nil {
		return false, failed(op, err)
	}

	n, err := s.c.exec(ctx, op, pgschema.PasskeyRename, uuidArg(cid), string(user), name)

	return n > 0, err
}

// Delete removes user's credential cid.
func (s *PasskeyCredentialStore) Delete(ctx context.Context, user identity.UserID, cid id.ID) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	n, err := s.c.exec(ctx, "delete passkey credential", pgschema.PasskeyDelete, uuidArg(cid), string(user))

	return n > 0, err
}

// DeleteAwaitingSavedCodes removes user's credentials awaiting saved codes,
// and reports how many.
func (s *PasskeyCredentialStore) DeleteAwaitingSavedCodes(ctx context.Context, user identity.UserID) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	n, err := s.c.exec(ctx, "delete passkey credentials awaiting saved codes",
		pgschema.PasskeyDeleteAwaitingSavedCodes, string(user))

	return int(n), err
}

// DeleteUser removes every credential of user, and reports how many.
func (s *PasskeyCredentialStore) DeleteUser(ctx context.Context, user identity.UserID) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	n, err := s.c.exec(ctx, "delete passkey credentials", pgschema.PasskeyDeleteUser, string(user))

	return int(n), err
}

// nullText is v as stored in a nullable text column: NULL for the empty text.
func nullText(v string) pgtype.Text {
	return pgtype.Text{String: v, Valid: v != ""}
}

var _ passkey.CredentialStore = (*PasskeyCredentialStore)(nil)
