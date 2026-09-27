package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

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
// device proof and emailed code; ProveDevice, Complete and ChargeEmailCode are
// each one conditional statement with every condition in its WHERE clause, so
// of concurrent completions of one generation exactly one succeeds, and of
// concurrent charges against one code no more than mfa.MaxEmailCodeFailures
// do. The nil generation is bound as NULL, stored and compared, so it matches
// no enrolment, not even one stored without a generation. The emailed code is
// sealed with c too, bound to the user reference and the generation, in its
// own base64url column; it is never re-sealed on read.
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
// EmailCodeUntil kept. The default is time.Now; WithClock replaces it.
//
// It honours WithTxResolver, WithIDGenerator (default id.NewV7Generator, for
// the rows' primary keys), WithClock (default time.Now) and WithResealOnRead
// (default on), and refuses any other option.
//
// Limits, stated:
//   - PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A begin for a
//     user reference holding either is refused with an error that names the
//     field, never the value, and nothing is written; a read, confirmation,
//     step, device proof, completion, charge or deletion for such a
//     reference matches nothing.
//   - Stored times are UTC, truncated to the microsecond.
func NewEnrolmentStore(db *sql.DB, c seal.Cipher, opts ...Option) (mfa.EnrolmentStore, error) {
	cfg, err := newConfig(db, opts, optIDGenerator, optClock, optResealOnRead)
	if err != nil {
		return nil, err
	}
	if err := storekit.RequireCipher(c, ErrConfig); err != nil {
		return nil, err
	}

	inner := &enrolmentStore{c: cfg}
	s, err := seal.NewEnrolmentStore(inner, inner, c, seal.WithClock(cfg.now), seal.WithResealOnRead(cfg.resealOnRead))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	return s, nil
}

// enrolmentStore is the unsealed store NewEnrolmentStore wraps, and the
// re-seal port the wrapper writes through. It stores Secret as given, which
// is why it is not exported.
type enrolmentStore struct{ c *config }

// Get returns the user's enrolment, its secret and emailed code still
// sealed.
func (s *enrolmentStore) Get(ctx context.Context, user identity.UserID) (mfa.Enrolment, bool, error) {
	const op = "get MFA enrolment"

	if !storekit.Storable(string(user)) {
		return mfa.Enrolment{}, false, nil
	}

	var (
		secret    string
		confirmed sql.NullTime
		created   time.Time
		gen       sql.Null[id.ID]
		proven    sql.NullTime
		code      sql.NullString
		codeUntil sql.NullTime
		attempts  int64
		e         = mfa.Enrolment{User: user}
	)
	err := s.c.queryRow(ctx, op, pgschema.EnrolmentGet, []any{string(user)},
		&secret, &confirmed, &e.LastStep, &created, &gen, &proven, &code, &codeUntil, &attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return mfa.Enrolment{}, false, nil
	}
	if err != nil {
		return mfa.Enrolment{}, false, err
	}

	sealed, err := storekit.SecretFromText(secret)
	if err != nil {
		return mfa.Enrolment{}, false, failed(op, err)
	}
	if code.Valid {
		if e.EmailCode, err = storekit.SecretFromText(code.String); err != nil {
			return mfa.Enrolment{}, false, failed(op, err)
		}
	}
	e.Secret, e.ConfirmedAt, e.CreatedAt = sealed, fromNull(confirmed), created.UTC()
	e.Generation, e.DeviceProvenAt = gen.V, fromNull(proven)
	e.EmailCodeUntil, e.EmailCodeAttempts = fromNull(codeUntil), int(attempts)

	return e, true, nil
}

// PutPending stores e as the user's pending enrolment on e's generation,
// clearing any device proof and emailed code, refusing with
// mfa.ErrAlreadyEnrolled when a confirmed one exists.
func (s *enrolmentStore) PutPending(ctx context.Context, e mfa.Enrolment) error {
	const op = "store pending MFA enrolment"

	if err := storekit.CheckStorable(storekit.Text("user reference", string(e.User))); err != nil {
		return failed(op, err)
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return failed(op, err)
	}

	return s.c.execOrRefuse(ctx, op, mfa.ErrAlreadyEnrolled, pgschema.EnrolmentPutPending,
		rowID, string(e.User), storekit.SecretText(e.Secret), storekit.Time(e.CreatedAt), nullID(e.Generation))
}

// Confirm confirms the user's pending enrolment at at, recording step.
func (s *enrolmentStore) Confirm(ctx context.Context, user identity.UserID, step int64, at time.Time) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	n, err := s.c.exec(ctx, "confirm MFA enrolment", pgschema.EnrolmentConfirm, string(user), step, storekit.Time(at))

	return n > 0, err
}

// AcceptStep records step for user where the enrolment is confirmed and its
// recorded step is lower.
func (s *enrolmentStore) AcceptStep(ctx context.Context, user identity.UserID, step int64) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	n, err := s.c.exec(ctx, "accept MFA time step", pgschema.EnrolmentAcceptStep, string(user), step)

	return n > 0, err
}

// Delete removes the user's enrolment; an absent one is not an error.
func (s *enrolmentStore) Delete(ctx context.Context, user identity.UserID) error {
	if !storekit.Storable(string(user)) {
		return nil
	}

	_, err := s.c.exec(ctx, "delete MFA enrolment", pgschema.EnrolmentDelete, string(user))

	return err
}

// ProveDevice records the device proof of the user's enrolment on gen, with
// its emailed code, as it is given (sealed by the wrapper), in one
// conditional update.
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
	n, err := s.c.exec(ctx, "prove MFA device", pgschema.EnrolmentProveDevice,
		string(user), nullID(gen), step, stored, nullTs(codeUntil), storekit.Time(at))

	return n > 0, err
}

// Complete confirms the user's proven enrolment on gen at at, in one
// conditional update.
func (s *enrolmentStore) Complete(ctx context.Context, user identity.UserID, gen id.ID, at time.Time) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	n, err := s.c.exec(ctx, "complete MFA enrolment", pgschema.EnrolmentComplete,
		string(user), nullID(gen), storekit.Time(at))

	return n > 0, err
}

// ChargeEmailCode charges one attempt against the emailed code of the user's
// enrolment on gen at at, in one conditional update that returns the count.
func (s *enrolmentStore) ChargeEmailCode(
	ctx context.Context, user identity.UserID, gen id.ID, at time.Time,
) (int, bool, error) {
	if !storekit.Storable(string(user)) {
		return 0, false, nil
	}

	var attempts int64
	err := s.c.queryRow(ctx, "charge emailed MFA code", pgschema.EnrolmentChargeEmailCode,
		[]any{string(user), nullID(gen), storekit.Time(at), mfa.MaxEmailCodeFailures}, &attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}

	return int(attempts), true, nil
}

// ResealEnrolmentSecret replaces the user's secret with resealed only while
// it still holds old. Inside a caller's transaction it writes nothing.
func (s *enrolmentStore) ResealEnrolmentSecret(ctx context.Context, user identity.UserID, old, resealed []byte) error {
	return s.c.execOutsideTx(ctx, "re-seal MFA secret", pgschema.EnrolmentReseal,
		string(user), storekit.SecretText(old), storekit.SecretText(resealed))
}

// nullID is v as bound to a nullable uuid column or compared with one: NULL
// for the nil identifier. id.ID's own Value sends the nil identifier as the
// all-zero UUID, which "generation = $n" would match on a row stored without
// a generation; NULL matches nothing.
func nullID(v id.ID) any {
	if v.IsZero() {
		return nil
	}

	return v
}

var (
	_ mfa.EnrolmentStore     = (*enrolmentStore)(nil)
	_ mfa.DeviceProofStore   = (*enrolmentStore)(nil)
	_ seal.EnrolmentResealer = (*enrolmentStore)(nil)
)
