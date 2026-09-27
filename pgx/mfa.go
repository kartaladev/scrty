package pgx

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/seal"
)

// NewEnrolmentStore returns a durable MFA enrolment store on pool, keeping
// enrolments in the mfa_enrolments table the migrate package creates.
//
// Each secret is sealed with c before it is written and opened when it is
// read, through seal.NewEnrolmentStore, bound to the user reference; the
// column holds the sealed value base64url-encoded. There is no unsealed
// variant, and a nil c, typed nil included, is a configuration error. A
// secret that will not open, a stored value that is not base64url, a stored
// time no enrolment can have, and a database failure are each an error with
// the found flag false, never an absent enrolment, which a caller would read
// as "no second factor".
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
func NewEnrolmentStore(pool *pgxpool.Pool, c seal.Cipher, opts ...Option) (mfa.EnrolmentStore, error) {
	cfg, err := newConfig(pool, opts, optIDGenerator, optResealOnRead)
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

// Get returns the user's enrolment, its secret still sealed.
func (s *enrolmentStore) Get(ctx context.Context, user identity.UserID) (mfa.Enrolment, bool, error) {
	const op = "get MFA enrolment"

	if !storable(string(user)) {
		return mfa.Enrolment{}, false, nil
	}

	var (
		secret    string
		confirmed pgtype.Timestamptz
		created   time.Time
		e         = mfa.Enrolment{User: user}
	)
	err := s.c.queryRow(ctx, op, pgschema.EnrolmentGet, []any{string(user)}, &secret, &confirmed, &e.LastStep, &created)
	if errors.Is(err, pgxv5.ErrNoRows) {
		return mfa.Enrolment{}, false, nil
	}
	if err != nil {
		return mfa.Enrolment{}, false, err
	}

	sealed, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		return mfa.Enrolment{}, false, failed(op, errors.New("the stored secret is not base64url"))
	}
	if e.ConfirmedAt, err = fromNull(confirmed); err != nil {
		return mfa.Enrolment{}, false, failed(op, err)
	}
	e.Secret, e.CreatedAt = sealed, created.UTC()

	return e, true, nil
}

// PutPending stores e as the user's pending enrolment, refusing with
// mfa.ErrAlreadyEnrolled when a confirmed one exists.
func (s *enrolmentStore) PutPending(ctx context.Context, e mfa.Enrolment) error {
	const op = "store pending MFA enrolment"

	if err := checkStorable(op, textField{"user reference", string(e.User)}); err != nil {
		return err
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return failed(op, err)
	}

	return s.c.execOrRefuse(ctx, op, mfa.ErrAlreadyEnrolled, pgschema.EnrolmentPutPending,
		uuidArg(rowID), string(e.User), secretText(e.Secret), ts(e.CreatedAt))
}

// Confirm confirms the user's pending enrolment at at, recording step.
func (s *enrolmentStore) Confirm(ctx context.Context, user identity.UserID, step int64, at time.Time) (bool, error) {
	if !storable(string(user)) {
		return false, nil
	}

	n, err := s.c.exec(ctx, "confirm MFA enrolment", pgschema.EnrolmentConfirm, string(user), step, ts(at))

	return n > 0, err
}

// AcceptStep records step for user where the enrolment is confirmed and its
// recorded step is lower.
func (s *enrolmentStore) AcceptStep(ctx context.Context, user identity.UserID, step int64) (bool, error) {
	if !storable(string(user)) {
		return false, nil
	}

	n, err := s.c.exec(ctx, "accept MFA time step", pgschema.EnrolmentAcceptStep, string(user), step)

	return n > 0, err
}

// Delete removes the user's enrolment; an absent one is not an error.
func (s *enrolmentStore) Delete(ctx context.Context, user identity.UserID) error {
	if !storable(string(user)) {
		return nil
	}

	_, err := s.c.exec(ctx, "delete MFA enrolment", pgschema.EnrolmentDelete, string(user))

	return err
}

// ResealEnrolmentSecret replaces the user's secret with resealed only while
// it still holds old. Inside a caller's transaction it writes nothing.
func (s *enrolmentStore) ResealEnrolmentSecret(ctx context.Context, user identity.UserID, old, resealed []byte) error {
	return s.c.execOutsideTx(ctx, "re-seal MFA secret", pgschema.EnrolmentReseal,
		string(user), secretText(old), secretText(resealed))
}

var (
	_ mfa.EnrolmentStore     = (*enrolmentStore)(nil)
	_ seal.EnrolmentResealer = (*enrolmentStore)(nil)
)
