package gorm

import (
	"context"
	"database/sql"
	"errors"
	"time"

	gormdb "gorm.io/gorm"
	"gorm.io/gorm/clause"

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
// identifier already stored with passkey.ErrDuplicateCredential: one INSERT …
// ON CONFLICT DO NOTHING, decided by the table's unique indexes without
// failing a statement, so the refusal never aborts a caller's transaction. A
// database failure is returned wrapped with the operation's name, never as a
// refusal or as absence.
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
func NewPasskeyCredentialStore(db *gormdb.DB, c seal.Cipher, opts ...Option) (*PasskeyCredentialStore, error) {
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

	row := passkeyCredentialRow{
		ID:                   c.ID,
		UserID:               string(c.User),
		CredentialID:         storekit.OrEmpty(c.CredentialID),
		PublicKey:            storekit.OrEmpty(c.PublicKey),
		SignCount:            int64(c.SignCount),
		BackupEligible:       c.BackupEligible,
		BackupState:          c.BackupState,
		Transports:           transports,
		AAGUID:               c.AAGUID,
		AttestationFormat:    nullText(c.AttestationFormat),
		AttestationStatement: c.AttestationStatement,
		Name:                 c.Name,
		CreatedAt:            storekit.Time(c.CreatedAt),
		LastUsedAt:           nullTs(c.LastUsedAt),
		State:                int64(c.State),
		Pending:              int64(c.Pending),
	}
	if c.EmailCode != nil {
		sealed, err := s.cipher.Seal([]byte(c.EmailCode.Code), seal.PasskeyEmailCodeAAD(c.ID, c.User))
		if err != nil {
			return failed(op, err)
		}
		text := storekit.SecretText(sealed)
		row.EmailCode, row.EmailCodeExpiresAt = &text, nullTs(c.EmailCode.ExpiresAt)
		row.EmailCodeAttempts = int64(c.EmailCode.Attempts)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	res := q.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if res.Error != nil {
		return failed(op, res.Error)
	}
	if res.RowsAffected == 0 {
		return passkey.ErrDuplicateCredential
	}

	return nil
}

// FindByCredentialID returns the credential with credential ID credID, or
// passkey.ErrNotFound.
func (s *PasskeyCredentialStore) FindByCredentialID(ctx context.Context, credID []byte) (*passkey.Credential, error) {
	return s.one(ctx, "credential_id = ?", storekit.OrEmpty(credID))
}

// Find returns user's credential cid, or passkey.ErrNotFound.
func (s *PasskeyCredentialStore) Find(ctx context.Context, user identity.UserID, cid id.ID) (*passkey.Credential, error) {
	if !storekit.Storable(string(user)) {
		return nil, passkey.ErrNotFound
	}

	return s.one(ctx, "id = ? AND user_id = ?", cid, string(user))
}

// one reads the single credential matching query, or passkey.ErrNotFound.
func (s *PasskeyCredentialStore) one(ctx context.Context, query string, args ...any) (*passkey.Credential, error) {
	const op = "find passkey credential"

	row, found, err := takeWhere[passkeyCredentialRow](ctx, s.c, op, query, args...)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, passkey.ErrNotFound
	}
	c, err := s.fromRow(row)
	if err != nil {
		return nil, failed(op, err)
	}

	return c, nil
}

// List returns user's credentials in every state, oldest first, ties in
// library identifier order.
func (s *PasskeyCredentialStore) List(ctx context.Context, user identity.UserID) ([]*passkey.Credential, error) {
	const op = "list passkey credentials"

	if !storekit.Storable(string(user)) {
		return nil, nil
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}
	var rows []passkeyCredentialRow
	if err := q.Where("user_id = ?", string(user)).Order("created_at, id").Find(&rows).Error; err != nil {
		return nil, failed(op, err)
	}

	var out []*passkey.Credential
	for _, row := range rows {
		c, err := s.fromRow(row)
		if err != nil {
			return nil, failed(op, err)
		}
		out = append(out, c)
	}

	return out, nil
}

// fromRow is the credential row holds, its emailed code opened.
func (s *PasskeyCredentialStore) fromRow(row passkeyCredentialRow) (*passkey.Credential, error) {
	c := &passkey.Credential{
		ID:                   row.ID,
		User:                 identity.UserID(row.UserID),
		CredentialID:         row.CredentialID,
		PublicKey:            row.PublicKey,
		SignCount:            uint32(row.SignCount), //nolint:gosec // G115: the column only ever holds a uint32
		BackupEligible:       row.BackupEligible,
		BackupState:          row.BackupState,
		Transports:           pgschema.ParsePasskeyTransports(row.Transports),
		AAGUID:               row.AAGUID,
		AttestationStatement: row.AttestationStatement,
		Name:                 row.Name,
		CreatedAt:            row.CreatedAt.UTC(),
		LastUsedAt:           fromNull(row.LastUsedAt),
		State:                passkey.State(row.State),           //nolint:gosec // G115: a small enum
		Pending:              passkey.PendingReason(row.Pending), //nolint:gosec // G115: a small enum
	}
	if row.AttestationFormat != nil {
		c.AttestationFormat = *row.AttestationFormat
	}
	if row.EmailCode != nil {
		code, err := s.open(*row.EmailCode, c.ID, c.User)
		if err != nil {
			return nil, err
		}
		c.EmailCode = &passkey.EmailCode{
			Code: code, ExpiresAt: fromNull(row.EmailCodeExpiresAt), Attempts: int(row.EmailCodeAttempts),
		}
	}

	return c, nil
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
	const op = "count passkey credentials"

	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}
	var n int64
	if err := q.Model(&passkeyCredentialRow{}).Where("user_id = ?", string(user)).Count(&n).Error; err != nil {
		return 0, failed(op, err)
	}

	return int(n), nil
}

// exec runs one conditional statement on the handle ctx resolves to, and
// reports how many rows it affected.
func (s *PasskeyCredentialStore) exec(ctx context.Context, op, query string, args ...any) (int64, error) {
	q, _, err := s.c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}
	res := q.Exec(query, args...)
	if res.Error != nil {
		return 0, failed(op, res.Error)
	}

	return res.RowsAffected, nil
}

// returning runs one conditional statement whose RETURNING row scans into
// dest. It reports false, with no error, when the statement returned no row.
func (s *PasskeyCredentialStore) returning(ctx context.Context, op, query string, args []any, dest ...any) (bool, error) {
	q, _, err := s.c.conn(ctx)
	if err != nil {
		return false, failed(op, err)
	}
	err = q.Raw(query, args...).Row().Scan(dest...)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, failed(op, err)
	}

	return true, nil
}

// RecordAssertion records the counter, backup state and last use of active
// credential cid whose stored counter is lower than signCount, or where both
// are zero, in one conditional update.
func (s *PasskeyCredentialStore) RecordAssertion(
	ctx context.Context, cid id.ID, signCount uint32, backupState bool, at time.Time,
) (bool, error) {
	n, err := s.exec(ctx, "record passkey assertion", pgschema.PasskeyRecordAssertion,
		cid, int64(signCount), backupState, storekit.Time(at))

	return n > 0, err
}

// RecordUse records the backup state and last use of active credential cid,
// leaving its counter, in one conditional update.
func (s *PasskeyCredentialStore) RecordUse(ctx context.Context, cid id.ID, backupState bool, at time.Time) (bool, error) {
	n, err := s.exec(ctx, "record passkey use", pgschema.PasskeyRecordUse, cid, backupState, storekit.Time(at))

	return n > 0, err
}

// Suspend moves active credential cid to suspended, in one conditional
// update.
func (s *PasskeyCredentialStore) Suspend(ctx context.Context, cid id.ID) (bool, error) {
	n, err := s.exec(ctx, "suspend passkey credential", pgschema.PasskeySuspend, cid)

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

	var state int64
	ok, err := s.returning(ctx, "clear passkey pending reason", pgschema.PasskeyClearReason,
		[]any{cid, string(user), int64(r)}, &state)
	if !ok || err != nil {
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
		attempts int64
	)
	ok, err := s.returning(ctx, op, pgschema.PasskeyChargeEmailAttempt,
		[]any{cid, string(user), storekit.Time(at), passkey.MaxEmailCodeAttempts}, &text, &until, &attempts)
	if !ok || err != nil {
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

	n, err := s.exec(ctx, op, pgschema.PasskeyRename, cid, string(user), name)

	return n > 0, err
}

// Delete removes user's credential cid.
func (s *PasskeyCredentialStore) Delete(ctx context.Context, user identity.UserID, cid id.ID) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	n, err := deleteWhere[passkeyCredentialRow](ctx, s.c, "delete passkey credential",
		"id = ? AND user_id = ?", cid, string(user))

	return n > 0, err
}

// DeleteAwaitingSavedCodes removes user's credentials awaiting saved codes,
// and reports how many.
func (s *PasskeyCredentialStore) DeleteAwaitingSavedCodes(ctx context.Context, user identity.UserID) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	n, err := s.exec(ctx, "delete passkey credentials awaiting saved codes",
		pgschema.PasskeyDeleteAwaitingSavedCodes, string(user))

	return int(n), err
}

// DeleteUser removes every credential of user, and reports how many.
func (s *PasskeyCredentialStore) DeleteUser(ctx context.Context, user identity.UserID) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	return deleteWhere[passkeyCredentialRow](ctx, s.c, "delete passkey credentials", "user_id = ?", string(user))
}

// nullText is v as stored in a nullable text column: nil, NULL, for the empty
// text.
func nullText(v string) *string {
	if v == "" {
		return nil
	}

	return &v
}

var _ passkey.CredentialStore = (*PasskeyCredentialStore)(nil)
