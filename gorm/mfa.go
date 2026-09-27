package gorm

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	gormdb "gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
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
// By default a read re-seals, under c's active key, a secret that opened under
// a retired one, with one conditional update that replaces the stored value
// only while it still holds the value that was read, so a new pending
// enrolment written in between keeps its new secret. A read inside a caller's
// transaction re-seals nothing, since a failed write there would abort the
// caller's transaction. WithResealOnRead(false) turns re-sealing off.
//
// It honours WithTxResolver, WithIDGenerator (default id.NewV7Generator, for
// the rows' primary keys) and WithResealOnRead (default on), and refuses any
// other option.
//
// Limits, stated:
//   - The enrolment path's fields (the generation, the device-proof time and
//     the emailed code with its expiry and attempt count) have no columns
//     yet. The store neither stores nor returns them, and does not implement
//     mfa.DeviceProofStore, so the enrolment path is refused at construction
//     over it rather than running without its proofs.
//   - PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A begin for a
//     user reference holding either is refused with an error that names the
//     field, never the value, and nothing is written; a read, confirmation,
//     step or deletion for such a reference matches nothing.
//   - Stored times are UTC, truncated to the microsecond.
func NewEnrolmentStore(db *gormdb.DB, c seal.Cipher, opts ...Option) (mfa.EnrolmentStore, error) {
	cfg, err := newConfig(db, opts, optIDGenerator, optResealOnRead)
	if err != nil {
		return nil, err
	}
	if err := requireCipher(c); err != nil {
		return nil, err
	}

	inner := &enrolmentStore{c: cfg}
	s, err := seal.NewEnrolmentStore(inner, inner, c, seal.WithResealOnRead(cfg.resealOnRead))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	return s, nil
}

// enrolmentStore is the unsealed store NewEnrolmentStore wraps, and the
// re-seal port the wrapper writes through. It stores Secret as given, which
// is why it is not exported.
type enrolmentStore struct{ c *config }

// secretText is how a sealed secret is stored in the text column.
func secretText(sealed []byte) string {
	return base64.RawURLEncoding.EncodeToString(sealed)
}

// Get returns the user's enrolment, its secret still sealed: one SELECT.
func (s *enrolmentStore) Get(ctx context.Context, user identity.UserID) (mfa.Enrolment, bool, error) {
	const op = "get MFA enrolment"

	if !storable(string(user)) {
		return mfa.Enrolment{}, false, nil
	}

	row, found, err := takeWhere[enrolmentRow](ctx, s.c, op, "user_id = ?", string(user))
	if err != nil || !found {
		return mfa.Enrolment{}, false, err
	}

	sealed, err := base64.RawURLEncoding.DecodeString(row.Secret)
	if err != nil {
		return mfa.Enrolment{}, false, failed(op, errors.New("the stored secret is not base64url"))
	}

	return mfa.Enrolment{
		User:        user,
		Secret:      sealed,
		ConfirmedAt: fromNull(row.ConfirmedAt),
		LastStep:    row.LastStep,
		CreatedAt:   row.CreatedAt.UTC(),
	}, true, nil
}

// PutPending stores e as the user's pending enrolment, refusing with
// mfa.ErrAlreadyEnrolled when a confirmed one exists: one INSERT … ON
// CONFLICT (user_id) DO UPDATE … WHERE mfa_enrolments.confirmed_at IS NULL,
// which keeps the row's id and clears its accepted step, and whose zero rows
// affected is the refusal.
func (s *enrolmentStore) PutPending(ctx context.Context, e mfa.Enrolment) error {
	const op = "store pending MFA enrolment"

	if err := checkStorable(op, textField{"user reference", string(e.User)}); err != nil {
		return err
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
		ID:        rowID,
		UserID:    string(e.User),
		Secret:    secretText(e.Secret),
		CreatedAt: ts(e.CreatedAt),
	}
	res := q.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id"}},
		DoUpdates: append(clause.AssignmentColumns([]string{"secret", "created_at"}),
			clause.Assignment{Column: clause.Column{Name: "last_step"}, Value: 0}),
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
// never moving the recorded step backwards: one conditional UPDATE, whose
// zero rows affected reports false.
func (s *enrolmentStore) Confirm(ctx context.Context, user identity.UserID, step int64, at time.Time) (bool, error) {
	if !storable(string(user)) {
		return false, nil
	}

	n, err := updateWhere[enrolmentRow](ctx, s.c, "confirm MFA enrolment",
		map[string]any{"confirmed_at": ts(at), "last_step": gormdb.Expr("GREATEST(last_step, ?)", step)},
		"user_id = ? AND confirmed_at IS NULL", string(user))

	return n > 0, err
}

// AcceptStep records step for user where the enrolment is confirmed and its
// recorded step is strictly lower: one conditional UPDATE, whose zero rows
// affected reports false.
func (s *enrolmentStore) AcceptStep(ctx context.Context, user identity.UserID, step int64) (bool, error) {
	if !storable(string(user)) {
		return false, nil
	}

	n, err := updateWhere[enrolmentRow](ctx, s.c, "accept MFA time step",
		map[string]any{"last_step": step},
		"user_id = ? AND confirmed_at IS NOT NULL AND last_step < ?", string(user), step)

	return n > 0, err
}

// Delete removes the user's enrolment; an absent one is not an error.
func (s *enrolmentStore) Delete(ctx context.Context, user identity.UserID) error {
	if !storable(string(user)) {
		return nil
	}

	_, err := deleteWhere[enrolmentRow](ctx, s.c, "delete MFA enrolment", "user_id = ?", string(user))

	return err
}

// ResealEnrolmentSecret replaces the user's secret with resealed only while
// it still holds old: one conditional UPDATE. Inside a caller's transaction it
// writes nothing.
func (s *enrolmentStore) ResealEnrolmentSecret(ctx context.Context, user identity.UserID, old, resealed []byte) error {
	return resealWhere[enrolmentRow](ctx, s.c, "re-seal MFA secret",
		map[string]any{"secret": secretText(resealed)}, "user_id = ? AND secret = ?", string(user), secretText(old))
}

var (
	_ mfa.EnrolmentStore     = (*enrolmentStore)(nil)
	_ seal.EnrolmentResealer = (*enrolmentStore)(nil)
)
