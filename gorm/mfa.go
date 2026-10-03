package gorm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	gormdb "gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
)

// NewEnrolmentStore returns a durable MFA enrolment store on db, keeping
// enrolments in the mfa_enrolments table the migrate package creates.
//
// Each secret is sealed with c before it is written and opened when it is
// read, through seal.NewEnrolmentStore, bound to the user reference; the
// column holds the sealed value base64url-encoded. There is no unsealed
// variant, and a nil c, typed nil included, is a configuration error. A
// secret that will not open, a stored value that is not base64url, and a
// database failure are each an error with the found flag false, never an
// absent enrolment, which a caller would read as "no second factor".
//
// PutPending, Confirm and AcceptStep are each one conditional statement: a
// begin over a confirmed enrolment is refused with mfa.ErrAlreadyEnrolled, a
// second confirmation reports false, and a step at or below the recorded one
// reports false, each without writing, so of concurrent verifications of one
// step exactly one succeeds, on this process or on another replica.
//
// The returned store implements mfa.DeviceProofStore, so the enrolment path
// runs over it. PutPending starts the enrolment's generation, clearing any
// device proof, emailed code and TOTP verification attempts; ProveDevice,
// Complete, ChargeEmailCode, ChargeVerifyAttempt and RefundVerifyAttempt are
// each one conditional statement with every condition in its WHERE clause, so
// of concurrent completions of one generation exactly one succeeds, and of
// concurrent charges against one code no more than mfa.MaxEmailCodeFailures
// do. Every write that clears a column names it in a map or an explicit
// assignment, never a struct, whose zero fields gorm would leave out. The nil
// generation is stored and compared as NULL, so it matches no enrolment, not
// even one stored without a generation. The emailed code is sealed with c
// too, bound to the user reference and the generation, in its own base64url
// column; it is never re-sealed on read.
//
// By default a read re-seals, under c's active key, a secret that opened under
// a retired one, with one conditional update that replaces the stored value
// only while it still holds the value that was read, so a new pending
// enrolment written in between keeps its new secret. A read inside a caller's
// transaction re-seals nothing, since a failed write there would abort the
// caller's transaction. WithResealOnRead(false) turns re-sealing off.
//
// A read judges an emailed code's expiry with the store's clock: a code whose
// EmailCodeUntil has passed is not opened, and is returned as no code, with
// EmailCodeUntil kept. The default is clock.System(); WithClock replaces it.
//
// It honours WithTxResolver, WithIDGenerator (default id.NewV7Generator, for
// the rows' primary keys), WithClock (default clock.System()) and
// WithResealOnRead (default on), and refuses any other option.
//
// Limits, stated:
//   - PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A begin for a
//     user reference holding either is refused with an error that names the
//     field, never the value, and nothing is written; a read, confirmation,
//     step, device proof, completion, charge or deletion for such a
//     reference matches nothing.
//   - Stored times are UTC, truncated to the microsecond.
func NewEnrolmentStore(db *gormdb.DB, c seal.Cipher, opts ...Option) (mfa.EnrolmentStore, error) {
	cfg, err := newConfig(db, opts, optIDGenerator, optClock, optResealOnRead)
	if err != nil {
		return nil, err
	}
	if err := storekit.RequireCipher(c, ErrConfig); err != nil {
		return nil, err
	}

	inner := &enrolmentStore{c: cfg}
	s, err := seal.NewEnrolmentStore(inner, inner, c, seal.WithClock(cfg.clock), seal.WithResealOnRead(cfg.resealOnRead))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	return s, nil
}

// enrolmentStore is the unsealed store NewEnrolmentStore wraps, and the
// re-seal port the wrapper writes through. It stores Secret as given, which
// is why it is not exported.
type enrolmentStore struct{ c *config }

// Get returns the user's enrolment, its secret and emailed code still sealed:
// one SELECT.
func (s *enrolmentStore) Get(ctx context.Context, user identity.UserID) (mfa.Enrolment, bool, error) {
	const op = "get MFA enrolment"

	if !storekit.Storable(string(user)) {
		return mfa.Enrolment{}, false, nil
	}

	row, found, err := takeWhere[enrolmentRow](ctx, s.c, op, "user_id = ?", string(user))
	if err != nil || !found {
		return mfa.Enrolment{}, false, err
	}

	sealed, err := storekit.SecretFromText(row.Secret)
	if err != nil {
		return mfa.Enrolment{}, false, failed(op, err)
	}
	var code []byte
	if row.EmailCode != nil {
		if code, err = storekit.SecretFromText(*row.EmailCode); err != nil {
			return mfa.Enrolment{}, false, failed(op, err)
		}
	}
	var gen id.ID
	if row.Generation != nil {
		gen = *row.Generation
	}

	return mfa.Enrolment{
		User:              user,
		Secret:            sealed,
		ConfirmedAt:       fromNull(row.ConfirmedAt),
		LastStep:          row.LastStep,
		CreatedAt:         row.CreatedAt.UTC(),
		Generation:        gen,
		DeviceProvenAt:    fromNull(row.DeviceProvenAt),
		EmailCode:         code,
		EmailCodeUntil:    fromNull(row.EmailCodeUntil),
		EmailCodeAttempts: int(row.EmailCodeAttempts),
		VerifyAttempts:    int(row.VerifyAttempts),
		VerifyWindowUntil: fromNull(row.VerifyWindowUntil),
	}, true, nil
}

// PutPending stores e as the user's pending enrolment on e's generation,
// refusing with mfa.ErrAlreadyEnrolled when a confirmed one exists: one
// INSERT … ON CONFLICT (user_id) DO UPDATE … WHERE
// mfa_enrolments.confirmed_at IS NULL, which keeps the row's id, clears its
// accepted step, device proof and emailed code with its expiry and attempts,
// and whose zero rows affected is the refusal. Every cleared column is an
// explicit assignment, so no zero value is left out of the write.
func (s *enrolmentStore) PutPending(ctx context.Context, e mfa.Enrolment) error {
	const op = "store pending MFA enrolment"

	if err := storekit.CheckStorable(storekit.Text("user reference", string(e.User))); err != nil {
		return failed(op, err)
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return failed(op, err)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	row := enrolmentRow{
		ID:         rowID,
		UserID:     string(e.User),
		Secret:     storekit.SecretText(e.Secret),
		CreatedAt:  storekit.Time(e.CreatedAt),
		Generation: nullID(e.Generation),
	}
	res := q.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id"}},
		DoUpdates: append(clause.AssignmentColumns([]string{"secret", "created_at", "generation"}),
			clause.Assignment{Column: clause.Column{Name: "last_step"}, Value: 0},
			clause.Assignment{Column: clause.Column{Name: "device_proven_at"}, Value: nil},
			clause.Assignment{Column: clause.Column{Name: "email_code"}, Value: nil},
			clause.Assignment{Column: clause.Column{Name: "email_code_until"}, Value: nil},
			clause.Assignment{Column: clause.Column{Name: "email_code_attempts"}, Value: 0},
			clause.Assignment{Column: clause.Column{Name: "verify_attempts"}, Value: 0},
			clause.Assignment{Column: clause.Column{Name: "verify_window_until"}, Value: nil}),
		Where: clause.Where{Exprs: []clause.Expression{clause.Expr{SQL: "mfa_enrolments.confirmed_at IS NULL"}}},
	}).Create(&row)
	if res.Error != nil {
		return failed(op, res.Error)
	}
	if res.RowsAffected == 0 {
		return mfa.ErrAlreadyEnrolled
	}

	return nil
}

// Confirm confirms the user's pending enrolment at at, recording step and
// never moving the recorded step backwards, and clears its emailed code,
// keeping the code's expiry: one conditional UPDATE, whose zero rows affected
// reports false.
func (s *enrolmentStore) Confirm(ctx context.Context, user identity.UserID, step int64, at time.Time) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	n, err := updateWhere[enrolmentRow](ctx, s.c, "confirm MFA enrolment",
		map[string]any{
			"confirmed_at": storekit.Time(at),
			"last_step":    gormdb.Expr("GREATEST(last_step, ?)", step),
			"email_code":   nil,
		},
		"user_id = ? AND confirmed_at IS NULL", string(user))

	return n > 0, err
}

// AcceptStep records step for user where the enrolment is confirmed and its
// recorded step is strictly lower: one conditional UPDATE, whose zero rows
// affected reports false.
func (s *enrolmentStore) AcceptStep(ctx context.Context, user identity.UserID, step int64) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	n, err := updateWhere[enrolmentRow](ctx, s.c, "accept MFA time step",
		map[string]any{"last_step": step},
		"user_id = ? AND confirmed_at IS NOT NULL AND last_step < ?", string(user), step)

	return n > 0, err
}

// Delete removes the user's enrolment; an absent one is not an error.
func (s *enrolmentStore) Delete(ctx context.Context, user identity.UserID) error {
	if !storekit.Storable(string(user)) {
		return nil
	}

	_, err := deleteWhere[enrolmentRow](ctx, s.c, "delete MFA enrolment", "user_id = ?", string(user))

	return err
}

// ProveDevice records the device proof of the user's enrolment on gen, with
// its emailed code as it is given (sealed by the wrapper): one conditional
// UPDATE, written from a map so that the cleared attempt count and a nil code
// are written rather than skipped as zero values. Its zero rows affected
// reports false: gen is not the pending enrolment's generation, the device is
// already proven, or step is not later than the recorded one.
func (s *enrolmentStore) ProveDevice(
	ctx context.Context, user identity.UserID, gen id.ID,
	step int64, code []byte, codeUntil, at time.Time,
) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	var stored any
	if code != nil {
		stored = storekit.SecretText(code)
	}
	n, err := updateWhere[enrolmentRow](ctx, s.c, "prove MFA device",
		map[string]any{
			"last_step":           step,
			"device_proven_at":    storekit.Time(at),
			"email_code":          stored,
			"email_code_until":    nullTs(codeUntil),
			"email_code_attempts": 0,
		},
		"user_id = ? AND generation = ? AND confirmed_at IS NULL AND device_proven_at IS NULL AND last_step < ?",
		string(user), genArg(gen), step)

	return n > 0, err
}

// Complete confirms the user's proven enrolment on gen at at and clears its
// emailed code, keeping the code's expiry: one conditional UPDATE, whose zero
// rows affected reports false.
func (s *enrolmentStore) Complete(ctx context.Context, user identity.UserID, gen id.ID, at time.Time) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	n, err := updateWhere[enrolmentRow](ctx, s.c, "complete MFA enrolment",
		map[string]any{"confirmed_at": storekit.Time(at), "email_code": nil},
		"user_id = ? AND generation = ? AND device_proven_at IS NOT NULL AND confirmed_at IS NULL",
		string(user), genArg(gen))

	return n > 0, err
}

// ChargeEmailCode charges one attempt against the emailed code of the user's
// enrolment on gen at at: one conditional UPDATE … RETURNING the count after
// the write. It charges only where the enrolment is pending on gen, proven,
// holds a code not expired at at, and has fewer than
// mfa.MaxEmailCodeFailures attempts charged; otherwise it reports false.
func (s *enrolmentStore) ChargeEmailCode(
	ctx context.Context, user identity.UserID, gen id.ID, at time.Time,
) (int, bool, error) {
	const op = "charge emailed MFA code"

	if !storekit.Storable(string(user)) {
		return 0, false, nil
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return 0, false, failed(op, err)
	}
	var row enrolmentRow
	res := q.Model(&row).
		Clauses(clause.Returning{Columns: []clause.Column{{Name: "email_code_attempts"}}}).
		Where("user_id = ? AND generation = ? AND confirmed_at IS NULL"+
			" AND device_proven_at IS NOT NULL AND email_code IS NOT NULL"+
			" AND email_code_until > ? AND email_code_attempts < ?",
			string(user), genArg(gen), storekit.Time(at), mfa.MaxEmailCodeFailures).
		Updates(map[string]any{"email_code_attempts": gormdb.Expr("email_code_attempts + 1")})
	if res.Error != nil {
		return 0, false, failed(op, res.Error)
	}
	if res.RowsAffected != 1 {
		return 0, false, nil
	}

	return int(row.EmailCodeAttempts), true, nil
}

// genArg is gen as compared with the generation column: NULL for the nil
// identifier. id.ID's own Value sends the nil identifier as the all-zero
// UUID, which "generation = ?" would match on a row stored without a
// generation; NULL matches nothing.
func genArg(gen id.ID) any {
	if gen.IsZero() {
		return nil
	}

	return gen
}

// nullID is v as stored in a nullable uuid column: nil, NULL, for the nil
// identifier, never the all-zero UUID.
func nullID(v id.ID) *id.ID {
	if v.IsZero() {
		return nil
	}

	return &v
}

// ResealEnrolmentSecret replaces the user's secret with resealed only while
// it still holds old: one conditional UPDATE. Inside a caller's transaction it
// writes nothing.
func (s *enrolmentStore) ResealEnrolmentSecret(ctx context.Context, user identity.UserID, old, resealed []byte) error {
	return resealWhere[enrolmentRow](ctx, s.c, "re-seal MFA secret",
		map[string]any{"secret": storekit.SecretText(resealed)},
		"user_id = ? AND secret = ?", string(user), storekit.SecretText(old))
}

var (
	_ mfa.EnrolmentStore     = (*enrolmentStore)(nil)
	_ mfa.DeviceProofStore   = (*enrolmentStore)(nil)
	_ seal.EnrolmentResealer = (*enrolmentStore)(nil)
)

// ChargeVerifyAttempt charges one TOTP verification attempt against the user's
// confirmed enrolment at at: one conditional UPDATE … RETURNING the window's
// end, run as the shared statement. The end is computed here, truncated to the
// microsecond the column keeps, so the value returned is the value a give-back
// must match.
func (s *enrolmentStore) ChargeVerifyAttempt(
	ctx context.Context, user identity.UserID, at time.Time, limit int, window time.Duration,
) (time.Time, bool, error) {
	const op = "charge TOTP verification attempt"

	if !storekit.Storable(string(user)) {
		return time.Time{}, false, nil
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return time.Time{}, false, failed(op, err)
	}
	if q.Error != nil {
		// A handle that carries an error runs nothing, and Row() would be nil.
		return time.Time{}, false, failed(op, q.Error)
	}
	var until time.Time
	err = q.Raw(pgschema.EnrolmentChargeVerifyAttempt,
		string(user), storekit.Time(at), storekit.Time(at.Add(window).Truncate(time.Microsecond)), limit,
	).Row().Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, failed(op, err)
	}

	return until.UTC(), true, nil
}

// RefundVerifyAttempt gives back one attempt charged in the window ending at
// until: one conditional UPDATE, whose zero rows affected reports false.
func (s *enrolmentStore) RefundVerifyAttempt(ctx context.Context, user identity.UserID, until time.Time) (bool, error) {
	const op = "give back TOTP verification attempt"

	if !storekit.Storable(string(user)) {
		return false, nil
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return false, failed(op, err)
	}
	res := q.Exec(pgschema.EnrolmentRefundVerifyAttempt, string(user), storekit.Time(until))
	if res.Error != nil {
		return false, failed(op, res.Error)
	}

	return res.RowsAffected > 0, nil
}
