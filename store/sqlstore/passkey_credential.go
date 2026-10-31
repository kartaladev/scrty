package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/store/seal"
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

// NewPasskeyCredentialStore returns a durable passkey credential store on db,
// sealing emailed codes with c. There is no unsealed variant, and a nil c,
// typed nil included, is a configuration error.
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
func NewPasskeyCredentialStore(db *sql.DB, c seal.Cipher, opts ...Option) (*PasskeyCredentialStore, error) {
	cfg, err := newConfig(db, opts)
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

	args, err := s.insertArgs(c)
	if err != nil {
		return failed(op, err)
	}

	return s.c.execOrRefuse(ctx, op, passkey.ErrDuplicateCredential, pgschema.PasskeyCredentialInsert, args...)
}

// insertArgs checks c is storable and returns PasskeyCredentialInsert's
// arguments for it, its emailed code sealed.
func (s *PasskeyCredentialStore) insertArgs(c *passkey.Credential) ([]any, error) {
	if err := storekit.CheckID(c.ID, "passkey credential"); err != nil {
		return nil, err
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
		return nil, err
	}

	var (
		code      any
		codeUntil any
		attempts  int
	)
	if c.EmailCode != nil {
		sealed, err := s.cipher.Seal([]byte(c.EmailCode.Code), seal.PasskeyEmailCodeAAD(c.ID, c.User))
		if err != nil {
			return nil, err
		}
		code, codeUntil, attempts = storekit.SecretText(sealed), nullTs(c.EmailCode.ExpiresAt), c.EmailCode.Attempts
	}

	return []any{
		c.ID, string(c.User), storekit.OrEmpty(c.CredentialID), storekit.OrEmpty(c.PublicKey), int64(c.SignCount),
		c.BackupEligible, c.BackupState, transports, nullBytes(c.AAGUID), nullText(c.AttestationFormat),
		nullBytes(c.AttestationStatement), c.Name, storekit.Time(c.CreatedAt), nullTs(c.LastUsedAt),
		int16(c.State), int16(c.Pending), code, codeUntil, attempts,
	}, nil
}

// InsertWithin stores c only while its user holds fewer than limit
// credentials, in every state, and reports whether it did. A refused insert
// writes nothing. Under the limit, a credential ID or library identifier
// already stored is refused with passkey.ErrDuplicateCredential, as Insert
// refuses it.
//
// The decision is taken under the transaction-scoped advisory lock of c's
// user: the lock, then the count, then the insert, in a READ COMMITTED
// transaction of the store's own, so a racer for the same user, on this
// process or on another replica, counts only after this one's credential is
// committed. Racers for different users do not wait for one another.
//
// Inside a caller's transaction the three statements join it, and the lock
// is held until the caller commits or rolls back. A caller's transaction
// stronger than READ COMMITTED is refused with ErrIsolationTooStrong and
// nothing is written: its snapshot would predate the lock, so the count could
// miss a racer's committed credential.
func (s *PasskeyCredentialStore) InsertWithin(ctx context.Context, c *passkey.Credential, limit int) (bool, error) {
	const op = "insert passkey credential within a limit"

	args, err := s.insertArgs(c)
	if err != nil {
		return false, failed(op, err)
	}
	if limit < 1 {
		return false, nil
	}

	var stored bool
	decide := func(q DBTX) error {
		if _, err := q.ExecContext(ctx, pgschema.PasskeyCredentialLockUser, string(c.User)); err != nil {
			return err
		}
		var n int
		if err := q.QueryRowContext(ctx, pgschema.PasskeyCredentialCount, string(c.User)).Scan(&n); err != nil {
			return err
		}
		if n >= limit {
			return nil
		}
		res, err := q.ExecContext(ctx, pgschema.PasskeyCredentialInsert, args...)
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return passkey.ErrDuplicateCredential
		}
		stored = true

		return nil
	}

	q, _, ambient, err := s.c.conn(ctx)
	if err != nil {
		return false, failed(op, err)
	}
	if ambient {
		if err = s.c.requireReadCommitted(ctx, q); err == nil {
			err = decide(q)
		}
	} else {
		err = s.c.readCommitted(ctx, func(tx *sql.Tx) error { return decide(tx) })
	}

	switch {
	case errors.Is(err, passkey.ErrDuplicateCredential):
		return false, passkey.ErrDuplicateCredential
	case err != nil:
		return false, failed(op, err)
	}

	return stored, nil
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

	return s.one(ctx, "find passkey credential", pgschema.PasskeyCredentialFind, cid, string(user))
}

// one reads the single credential query selects, or passkey.ErrNotFound.
func (s *PasskeyCredentialStore) one(ctx context.Context, op, query string, args ...any) (*passkey.Credential, error) {
	list, err := s.query(ctx, op, query, args...)
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

	return s.query(ctx, "list passkey credentials", pgschema.PasskeyCredentialList, string(user))
}

// query runs query and scans every credential it selects, opening each
// emailed code.
func (s *PasskeyCredentialStore) query(ctx context.Context, op, query string, args ...any) ([]*passkey.Credential, error) {
	q, _, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, failed(op, err)
	}
	defer func() { _ = rows.Close() }()

	var out []*passkey.Credential
	for rows.Next() {
		c, err := s.scan(rows)
		if err != nil {
			return nil, failed(op, err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, failed(op, err)
	}

	return out, nil
}

// scan reads one credential row, in the column order of the selects.
func (s *PasskeyCredentialStore) scan(rows *sql.Rows) (*passkey.Credential, error) {
	var (
		c          passkey.Credential
		user       string
		signCount  int64
		transports string
		format     sql.NullString
		created    time.Time
		lastUsed   sql.NullTime
		state      int16
		pending    int16
		code       sql.NullString
		codeUntil  sql.NullTime
		attempts   int16
	)
	if err := rows.Scan(&c.ID, &user, &c.CredentialID, &c.PublicKey, &signCount, &c.BackupEligible,
		&c.BackupState, &transports, &c.AAGUID, &format, &c.AttestationStatement, &c.Name, &created, &lastUsed,
		&state, &pending, &code, &codeUntil, &attempts); err != nil {
		return nil, err
	}

	c.User = identity.UserID(user)
	c.SignCount = uint32(signCount) //nolint:gosec // G115: the column only ever holds a uint32
	c.Transports = pgschema.ParsePasskeyTransports(transports)
	c.AttestationFormat = format.String
	c.CreatedAt, c.LastUsedAt = created.UTC(), fromNull(lastUsed)
	c.State, c.Pending = passkey.State(state), passkey.PendingReason(pending) //nolint:gosec // G115: small enums

	if code.Valid {
		opened, err := s.open(code.String, c.ID, c.User)
		if err != nil {
			return nil, err
		}
		c.EmailCode = &passkey.EmailCode{Code: opened, ExpiresAt: fromNull(codeUntil), Attempts: int(attempts)}
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
		cid, int64(signCount), backupState, storekit.Time(at))

	return n > 0, err
}

// RecordUse records the backup state and last use of active credential cid,
// leaving its counter, in one conditional update.
func (s *PasskeyCredentialStore) RecordUse(ctx context.Context, cid id.ID, backupState bool, at time.Time) (bool, error) {
	n, err := s.c.exec(ctx, "record passkey use", pgschema.PasskeyRecordUse, cid, backupState, storekit.Time(at))

	return n > 0, err
}

// Suspend moves active credential cid to suspended, in one conditional
// update.
func (s *PasskeyCredentialStore) Suspend(ctx context.Context, cid id.ID) (bool, error) {
	n, err := s.c.exec(ctx, "suspend passkey credential", pgschema.PasskeySuspend, cid)

	return n > 0, err
}

// ClearReason clears the single reason r of user's pending credential cid, in
// one conditional update. Any r that is not exactly one known reason is
// refused before a statement runs.
func (s *PasskeyCredentialStore) ClearReason(
	ctx context.Context, user identity.UserID, cid id.ID, r passkey.PendingReason,
) (passkey.State, bool, error) {
	if (r != passkey.PendingSavedCodes && r != passkey.PendingEmailCode) || !storekit.Storable(string(user)) {
		return 0, false, nil
	}

	var state int16
	err := s.c.queryRow(ctx, "clear passkey pending reason", pgschema.PasskeyClearReason,
		[]any{cid, string(user), int16(r)}, &state)
	if errors.Is(err, sql.ErrNoRows) {
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
		until    time.Time
		attempts int16
	)
	err := s.c.queryRow(ctx, op, pgschema.PasskeyChargeEmailAttempt,
		[]any{cid, string(user), storekit.Time(at), passkey.MaxEmailCodeAttempts}, &text, &until, &attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	code, err := s.open(text, cid, user)
	if err != nil {
		return nil, false, failed(op, err)
	}

	return &passkey.EmailCode{Code: code, ExpiresAt: until.UTC(), Attempts: int(attempts)}, true, nil
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

	n, err := s.c.exec(ctx, op, pgschema.PasskeyRename, cid, string(user), name)

	return n > 0, err
}

// Delete removes user's credential cid.
func (s *PasskeyCredentialStore) Delete(ctx context.Context, user identity.UserID, cid id.ID) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	n, err := s.c.exec(ctx, "delete passkey credential", pgschema.PasskeyDelete, cid, string(user))

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

// nullBytes is b as stored in a nullable byte column: NULL for nil.
func nullBytes(b []byte) any {
	if b == nil {
		return nil
	}

	return b
}

// nullText is v as stored in a nullable text column: NULL for the empty text.
func nullText(v string) any {
	if v == "" {
		return nil
	}

	return v
}

var _ passkey.CredentialStore = (*PasskeyCredentialStore)(nil)
