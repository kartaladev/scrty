package gorm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	gormdb "gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
)

// NewSessionStore returns a durable session store on db, keeping sessions in
// the sessions table the migrate package creates.
//
// The provider ID token a federated session carries is sealed with c before
// it is written and opened when it is read, through session.NewEncryptedStore
// and seal.SessionCipher; there is no unsealed variant, and a nil c, typed
// nil included, is a configuration error. A token that will not open makes
// the load fail with session.ErrSessionUnreadable, never
// session.ErrSessionNotFound. A load never rewrites the record, so a token
// sealed under a retired key is re-sealed only by the session's next save.
//
// The session identifier, a bearer credential, is never stored: a session is
// kept and found under the SHA-256 digest of its identifier, behind a
// primary key minted from the store's id generator. Create is an insert that
// refuses an identifier already stored, and Save an update that reports
// session.ErrSessionNotFound when the session is gone, so a save racing a
// logout never brings the session back.
//
// The enrolment path's session state is stored and returned whole: the
// enrolment-origin marker, NULL when the session is not marked, and the
// enrolment generation, NULL when the session has begun no enrolment. Neither
// is a secret, and neither is sealed. RecoveredAt, the time an account
// recovery produced the session, is kept the same way: NULL when the session
// was never recovered.
//
// The federated assurance a login asserted, the amr values in the order given
// and the acr, is kept in columns of its own, unsealed: none is stored as an
// empty list and the empty string, and reads back as a nil list and "".
//
// Expiry is judged with the store's clock, on Load, on CountActiveByUser and
// on DeleteExpired. Stored times are UTC, truncated to the microsecond.
//
// It honours WithTxResolver, WithClock (default clock.System()) and
// WithIDGenerator (default id.NewV7Generator), and refuses any other option.
//
// Limits, stated:
//   - PostgreSQL text and jsonb cannot hold a NUL byte or invalid UTF-8. A
//     session whose user reference, first factor, provider fields, data, amr
//     values or acr hold either is refused with an error that names the
//     field, never the value, and nothing is written; the value is never
//     altered.
func NewSessionStore(db *gormdb.DB, c seal.Cipher, opts ...Option) (session.Store, error) {
	cfg, err := newConfig(db, opts, optIDGenerator, optClock)
	if err != nil {
		return nil, err
	}
	if err := storekit.RequireCipher(c, ErrConfig); err != nil {
		return nil, err
	}

	s, err := session.NewEncryptedStore(&sessionStore{c: cfg}, seal.SessionCipher(c))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	return s, nil
}

// sessionStore is the unsealed store NewSessionStore wraps. It stores
// ExternalIDToken as given, which is why it is not exported.
type sessionStore struct {
	c *config

	// savepoints numbers the savepoints this store opens inside a caller's
	// transaction, so each is named apart from any other open on it.
	savepoints atomic.Uint64
}

// sessionRecord returns sess as a row, without its primary key, or the
// refusal of a session this store cannot hold without altering it.
func sessionRecord(op string, sess *session.Session) (sessionRow, error) {
	if err := storekit.CheckSession(sess); err != nil {
		return sessionRow{}, failed(op, err)
	}

	encoded, err := storekit.EncodeSessionData(sess.Data)
	if err != nil {
		return sessionRow{}, failed(op, err)
	}
	amr, err := storekit.EncodeAMR(sess.FederatedAMR)
	if err != nil {
		return sessionRow{}, failed(op, err)
	}

	return sessionRow{
		IDDigest:              storekit.SessionDigest(sess.ID),
		UserID:                string(sess.UserID),
		CreatedAt:             storekit.Time(sess.CreatedAt),
		LastAccessedAt:        storekit.Time(sess.LastAccessedAt),
		IdleExpiresAt:         storekit.Time(sess.IdleExpiresAt),
		AbsoluteExpiresAt:     storekit.Time(sess.AbsoluteExpiresAt),
		FirstFactor:           string(sess.FirstFactor),
		MFAState:              int64(sess.MFA),
		MFASatisfiedAt:        nullTs(sess.MFASatisfiedAt),
		PasswordChangePending: sess.PasswordChangePending,
		ExternalProvider:      sess.ExternalProvider,
		ExternalIssuer:        sess.ExternalIssuer,
		ExternalSessionID:     sess.ExternalSessionID,
		ExternalIDToken:       sess.ExternalIDToken,
		Data:                  encoded,
		// NULL when the session is not marked, or has begun no enrolment.
		EnrolmentOriginDeadline: nullTs(sess.EnrolmentOriginDeadline),
		EnrolmentGeneration:     nullID(sess.EnrolmentGeneration),
		// NULL when the session was never recovered.
		RecoveredAt:  nullTs(sess.RecoveredAt),
		FederatedAMR: amr,
		FederatedACR: sess.FederatedACR,
		// Written on Create only: Save omits the column.
		MFAAtFirstFactor: sess.MFAAtFirstFactor,
		// Written on Create, Supersede and MarkPresented only: Save omits
		// the columns.
		FamilyID:         sess.FamilyID,
		FamilyCreatedAt:  storekit.Time(sess.FamilyCreatedAt),
		SupersededAt:     nullTs(sess.SupersededAt),
		AcceptUntil:      nullTs(sess.AcceptUntil),
		SuccessorDigest:  storekit.OptionalDigest(sess.SuccessorDigest),
		FirstPresentedAt: nullTs(sess.FirstPresentedAt),
		// As given, NULL when zero; Save omits the column.
		RetainUntil: nullTs(sess.RetainUntil),
		// Written on Create only: Save omits the column.
		AuthenticatedAt: storekit.Time(sess.AuthenticatedAt),
	}, nil
}

// Create inserts sess, refusing an identifier already stored: one INSERT …
// ON CONFLICT (id_digest) DO NOTHING, whose zero rows affected is the refusal.
// A session with no family, the nil family, is refused with an error before
// any statement runs: every stored session belongs to a family.
func (s *sessionStore) Create(ctx context.Context, sess *session.Session) error {
	const op = "create session"

	if sess.FamilyID.IsZero() {
		return errors.New("gorm: create session: a session with no family cannot be stored")
	}
	if sess.FamilyCreatedAt.IsZero() {
		return errors.New("gorm: create session: a session with no family start time cannot be stored")
	}

	row, err := s.newRow(op, sess)
	if err != nil {
		return err
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	inserted, err := insertSession(q, op, &row)
	if err != nil {
		return err
	}
	if !inserted {
		return errors.New("gorm: create session: the identifier is already in use")
	}

	return nil
}

// newRow returns sess as a row under a primary key minted from the store's id
// generator, or the refusal of a session this store cannot hold without
// altering it.
func (s *sessionStore) newRow(op string, sess *session.Session) (sessionRow, error) {
	row, err := sessionRecord(op, sess)
	if err != nil {
		return sessionRow{}, err
	}
	if row.ID, err = s.c.ids.NewID(); err != nil {
		return sessionRow{}, failed(op, err)
	}

	return row, nil
}

// insertSession runs the insert of row on q, and reports false when its
// digest is already stored.
func insertSession(q *gormdb.DB, op string, row *sessionRow) (bool, error) {
	res := q.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "id_digest"}}, DoNothing: true}).Create(row)
	if res.Error != nil {
		return false, failed(op, res.Error)
	}

	return res.RowsAffected > 0, nil
}

// savedColumnsOmitted are the columns a save never writes: the keys, the marker
// (MFAAtFirstFactor, written on Create only), and the family, supersession
// and presentation columns (written on Create, Supersede and MarkPresented
// only).
var savedColumnsOmitted = []string{
	"id", "id_digest", "mfa_at_first_factor",
	"family_id", "family_created_at", "superseded_at", "accept_until", "successor_digest", "first_presented_at",
	"retain_until", "authenticated_at",
}

// Save replaces the stored session whole, and never inserts: one UPDATE of
// every column but the keys, the marker (MFAAtFirstFactor, written on Create
// only) and the family, supersession (retain_until included) and
// presentation columns, whose zero rows affected is
// session.ErrSessionNotFound. A superseded session keeps both of its own
// deadlines: the UPDATE writes each only while superseded_at is NULL.
func (s *sessionStore) Save(ctx context.Context, sess *session.Session) error {
	const op = "save session"

	row, err := sessionRecord(op, sess)
	if err != nil {
		return err
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	// Every column is named, zero values included: a struct update would skip
	// false, 0, "" and nil, so a save clearing a field would silently keep
	// the stored value. The deadlines are expressions, which a struct update
	// cannot carry.
	values := map[string]any{
		"user_id":          row.UserID,
		"created_at":       row.CreatedAt,
		"last_accessed_at": row.LastAccessedAt,
		"idle_expires_at": gormdb.Expr(
			"CASE WHEN superseded_at IS NULL THEN ? ELSE idle_expires_at END", row.IdleExpiresAt),
		"absolute_expires_at": gormdb.Expr(
			"CASE WHEN superseded_at IS NULL THEN ? ELSE absolute_expires_at END", row.AbsoluteExpiresAt),
		"first_factor":              row.FirstFactor,
		"mfa_state":                 row.MFAState,
		"mfa_satisfied_at":          row.MFASatisfiedAt,
		"password_change_pending":   row.PasswordChangePending,
		"external_provider":         row.ExternalProvider,
		"external_issuer":           row.ExternalIssuer,
		"external_session_id":       row.ExternalSessionID,
		"external_id_token":         row.ExternalIDToken,
		"data":                      row.Data,
		"enrolment_origin_deadline": row.EnrolmentOriginDeadline,
		"enrolment_generation":      row.EnrolmentGeneration,
		"recovered_at":              row.RecoveredAt,
		"federated_amr":             row.FederatedAMR,
		"federated_acr":             row.FederatedACR,
	}
	res := q.Model(&sessionRow{}).Where("id_digest = ?", row.IDDigest).
		Omit(savedColumnsOmitted...).Updates(values)
	if res.Error != nil {
		return failed(op, res.Error)
	}
	if res.RowsAffected == 0 {
		return session.ErrSessionNotFound
	}

	return nil
}

// Load returns the session with this identifier, judging its expiry with the
// store's clock: a superseded session with a retention deadline is returned
// until that deadline, whatever its own deadlines say and with them intact,
// and any other session until either of its own deadlines. A stored session
// past them is session.ErrSessionExpired.
func (s *sessionStore) Load(ctx context.Context, sessionID string) (*session.Session, error) {
	const op = "load session"

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}
	var row sessionRow
	err = q.Where("id_digest = ?", storekit.SessionDigest(sessionID)).Take(&row).Error
	if errors.Is(err, gormdb.ErrRecordNotFound) {
		return nil, session.ErrSessionNotFound
	}
	if err != nil {
		return nil, failed(op, err)
	}

	if row.stale(s.c.clock.Now()) {
		return nil, session.ErrSessionExpired
	}

	sess := session.Session{
		ID:                      sessionID,
		UserID:                  identity.UserID(row.UserID),
		CreatedAt:               row.CreatedAt.UTC(),
		LastAccessedAt:          row.LastAccessedAt.UTC(),
		IdleExpiresAt:           row.IdleExpiresAt.UTC(),
		AbsoluteExpiresAt:       row.AbsoluteExpiresAt.UTC(),
		FirstFactor:             factor.Kind(row.FirstFactor),
		MFA:                     session.MFAState(row.MFAState),
		MFASatisfiedAt:          fromNull(row.MFASatisfiedAt),
		PasswordChangePending:   row.PasswordChangePending,
		ExternalProvider:        row.ExternalProvider,
		ExternalIssuer:          row.ExternalIssuer,
		ExternalSessionID:       row.ExternalSessionID,
		ExternalIDToken:         row.ExternalIDToken,
		EnrolmentOriginDeadline: fromNull(row.EnrolmentOriginDeadline),
		RecoveredAt:             fromNull(row.RecoveredAt),
		MFAAtFirstFactor:        row.MFAAtFirstFactor,
		FamilyID:                row.FamilyID,
		FamilyCreatedAt:         row.FamilyCreatedAt.UTC(),
		SupersededAt:            fromNull(row.SupersededAt),
		AcceptUntil:             fromNull(row.AcceptUntil),
		SuccessorDigest:         row.SuccessorDigest,
		FirstPresentedAt:        fromNull(row.FirstPresentedAt),
		RetainUntil:             fromNull(row.RetainUntil),
		AuthenticatedAt:         row.AuthenticatedAt.UTC(),
	}
	if row.EnrolmentGeneration != nil {
		sess.EnrolmentGeneration = *row.EnrolmentGeneration
	}
	if sess.FederatedAMR, err = storekit.DecodeAMR([]byte(row.FederatedAMR)); err != nil {
		return nil, failed(op, err)
	}
	sess.FederatedACR = row.FederatedACR
	if sess.Data, err = storekit.DecodeSessionData([]byte(row.Data)); err != nil {
		return nil, failed(op, err)
	}

	return &sess, nil
}

// Delete removes the session with this identifier; one not there is not an
// error.
func (s *sessionStore) Delete(ctx context.Context, sessionID string) error {
	_, err := deleteWhere[sessionRow](ctx, s.c, "delete session", "id_digest = ?", storekit.SessionDigest(sessionID))
	return err
}

// DeleteByUser removes every session of user, expired ones included. A user
// reference PostgreSQL text cannot hold matches nothing.
//
// The delete is repeated until a pass removes nothing. Under PostgreSQL's
// default READ COMMITTED isolation, a delete that waited on a session an
// in-flight Supersede holds removes that session once the supersession
// commits, but cannot see the successor it inserted; the next pass, on a
// fresh snapshot, does. Inside a caller's transaction at REPEATABLE READ or
// SERIALIZABLE, such a pass fails with the driver's serialization failure
// (SQLSTATE 40001) instead, and the caller retries its transaction.
//
// The passes are bounded at 64: when every one of them removed sessions,
// because sessions it matches are being created as fast as it removes them,
// it stops with an error wrapping ErrDeleteDidNotSettle rather than running
// until ctx ends. What its passes removed stays removed.
func (s *sessionStore) DeleteByUser(ctx context.Context, user identity.UserID) error {
	if !storekit.Storable(string(user)) {
		return nil
	}

	_, err := untilSettled("delete user's sessions", func() (int, error) {
		return deleteWhere[sessionRow](ctx, s.c, "delete user's sessions", "user_id = ?", string(user))
	})

	return err
}

// DeleteByUserExcept removes every session of user except the one named by
// keep and, when user holds keep, its family's current session, expired ones
// included, and reports how many it removed. Every other member of keep's
// family goes, superseded ones included. Each pass is one statement, so the
// family kept is read on the snapshot the pass deletes on. keep is compared
// by its digest, as Delete's identifier is, so one no store could hold names
// no session and every session of the user goes. A user reference PostgreSQL
// text cannot hold matches nothing. It runs SessionDeleteByUserExcept, the
// statement the other drivers run.
//
// The delete is repeated until a pass removes nothing, summing what each pass removed. Under PostgreSQL's
// default READ COMMITTED isolation, a delete that waited on a session an
// in-flight Supersede holds removes that session once the supersession
// commits, but cannot see the successor it inserted; the next pass, on a
// fresh snapshot, does. Inside a caller's transaction at REPEATABLE READ or
// SERIALIZABLE, such a pass fails with the driver's serialization failure
// (SQLSTATE 40001) instead, and the caller retries its transaction. On an
// error, the number of rows the earlier passes removed is returned with it.
//
// The passes are bounded at 64: when every one of them removed sessions,
// because sessions it matches are being created as fast as it removes them,
// it stops with an error wrapping ErrDeleteDidNotSettle rather than running
// until ctx ends. What its passes removed stays removed.
func (s *sessionStore) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	const op = "delete user's other sessions"

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}
	digest := storekit.SessionDigest(keep)

	return untilSettled(op, func() (int, error) {
		res := q.Exec(pgschema.SessionDeleteByUserExcept, string(user), digest)
		if res.Error != nil {
			return 0, failed(op, res.Error)
		}
		return int(res.RowsAffected), nil
	})
}

// CountActiveByUser counts user's sessions unexpired by the store's clock and
// not superseded.
func (s *sessionStore) CountActiveByUser(ctx context.Context, user identity.UserID) (int, error) {
	const op = "count user's active sessions"

	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}
	now := storekit.Time(s.c.clock.Now())
	var n int64
	err = q.Model(&sessionRow{}).
		Where("user_id = ? AND idle_expires_at > ? AND absolute_expires_at > ? AND superseded_at IS NULL", string(user), now, now).
		Count(&n).Error
	if err != nil {
		return 0, failed(op, err)
	}

	return int(n), nil
}

// stale reports whether row is past what Load returns at now: a superseded
// row with a retention deadline once that deadline is not after now, any
// other once either of its own deadlines is not. It is the condition
// SessionDeleteExpired deletes by, judged in Go.
func (row *sessionRow) stale(now time.Time) bool {
	if row.SupersededAt != nil && row.RetainUntil != nil {
		return !now.Before(*row.RetainUntil)
	}

	return !now.Before(row.IdleExpiresAt) || !now.Before(row.AbsoluteExpiresAt)
}

// DeleteExpired removes every session Load would no longer return by the
// store's clock: a superseded session once its retention deadline passes, or
// its own deadlines when it has none, and any other once either of its own
// deadlines passes. It runs SessionDeleteExpired, the statement the other
// drivers run.
func (s *sessionStore) DeleteExpired(ctx context.Context) (int, error) {
	const op = "delete expired sessions"

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}
	res := q.Exec(pgschema.SessionDeleteExpired, storekit.Time(s.c.clock.Now()))
	if res.Error != nil {
		return 0, failed(op, res.Error)
	}

	return int(res.RowsAffected), nil
}

// DeleteByExternalSession removes the sessions of issuer and provider session
// sessionID. An empty argument matches nothing: the absent federation values
// are stored as empty text, and the statement's own condition excludes them.
//
// The delete is repeated until a pass removes nothing, summing what each pass removed. Under PostgreSQL's
// default READ COMMITTED isolation, a delete that waited on a session an
// in-flight Supersede holds removes that session once the supersession
// commits, but cannot see the successor it inserted; the next pass, on a
// fresh snapshot, does. Inside a caller's transaction at REPEATABLE READ or
// SERIALIZABLE, such a pass fails with the driver's serialization failure
// (SQLSTATE 40001) instead, and the caller retries its transaction. On an
// error, the number of rows the earlier passes removed is returned with it.
//
// The passes are bounded at 64: when every one of them removed sessions,
// because sessions it matches are being created as fast as it removes them,
// it stops with an error wrapping ErrDeleteDidNotSettle rather than running
// until ctx ends. What its passes removed stays removed.
func (s *sessionStore) DeleteByExternalSession(ctx context.Context, issuer, sessionID string) (int, error) {
	if !storekit.Storable(issuer, sessionID) {
		return 0, nil
	}

	return untilSettled("delete provider session's sessions", func() (int, error) {
		return deleteWhere[sessionRow](ctx, s.c, "delete provider session's sessions",
			"external_issuer = ? AND external_session_id = ? AND external_issuer <> '' AND external_session_id <> ''",
			issuer, sessionID)
	})
}

// DeleteByUserAndExternalIssuer removes user's sessions from issuer. An empty
// issuer matches nothing.
//
// The delete is repeated until a pass removes nothing, summing what each pass removed. Under PostgreSQL's
// default READ COMMITTED isolation, a delete that waited on a session an
// in-flight Supersede holds removes that session once the supersession
// commits, but cannot see the successor it inserted; the next pass, on a
// fresh snapshot, does. Inside a caller's transaction at REPEATABLE READ or
// SERIALIZABLE, such a pass fails with the driver's serialization failure
// (SQLSTATE 40001) instead, and the caller retries its transaction. On an
// error, the number of rows the earlier passes removed is returned with it.
//
// The passes are bounded at 64: when every one of them removed sessions,
// because sessions it matches are being created as fast as it removes them,
// it stops with an error wrapping ErrDeleteDidNotSettle rather than running
// until ctx ends. What its passes removed stays removed.
func (s *sessionStore) DeleteByUserAndExternalIssuer(
	ctx context.Context, user identity.UserID, issuer string,
) (int, error) {
	if !storekit.Storable(string(user), issuer) {
		return 0, nil
	}

	return untilSettled("delete user's sessions from issuer", func() (int, error) {
		return deleteWhere[sessionRow](ctx, s.c, "delete user's sessions from issuer",
			"user_id = ? AND external_issuer = ? AND external_issuer <> ''", string(user), issuer)
	})
}

// untilNone runs pass, a delete of sessions, until it removes nothing, and
// returns what every pass removed, those before an error included. A pass
// that waited on a session an in-flight supersession holds cannot see the
// successor that supersession inserted; the pass after it can.
func untilNone(pass func() (int, error)) (int, error) {
	total := 0
	for {
		n, err := pass()
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
		total += n
	}
}

// RecordActivity writes lastAccessed and idleExpires, the latter capped at the
// stored absolute deadline, and nothing else, to a session last accessed
// not later than olderThan and not superseded: one conditional UPDATE of those two
// columns. A session that is fresher or superseded is left unchanged and is
// not an error; one that is not stored is session.ErrSessionNotFound.
func (s *sessionStore) RecordActivity(
	ctx context.Context, sessionID string, lastAccessed, idleExpires, olderThan time.Time,
) error {
	const op = "record session activity"

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	digest := storekit.SessionDigest(sessionID)
	res := q.Exec(pgschema.SessionRecordActivity, digest,
		storekit.Time(lastAccessed), storekit.Time(idleExpires), storekit.Time(olderThan))
	if res.Error != nil {
		return failed(op, res.Error)
	}
	if res.RowsAffected == 0 {
		return storekit.NotFoundUnless(stored(q, op, digest))
	}

	return nil
}

// stored reports whether a session with digest is stored, expired or not,
// reading through q: what a conditional write that changed no row runs to
// tell a missing session from one whose condition did not hold.
func stored(q *gormdb.DB, op string, digest []byte) (bool, error) {
	var exists bool
	if err := q.Raw(pgschema.SessionExists, digest).Scan(&exists).Error; err != nil {
		return false, failed(op, err)
	}

	return exists, nil
}

// Supersede marks op.Old superseded by op.Successor, supersedes Old's previous
// successor, and inserts op.Successor, in one transaction: the caller's when
// one is attached, under a savepoint of its own, otherwise one it begins and
// commits. The conditional UPDATE of Old decides the outcome: when it changes
// no row, nothing is written, and the store reports
// session.ErrSessionRenewalConflict when Old is stored and
// session.ErrSessionNotFound when it is not. A successor whose identifier is
// already stored is an error, and nothing is written. A nil Successor, a
// Successor with no family (the nil family), and an op.RetainUntil before
// op.AcceptUntil are errors too, refused before any statement runs.
//
// When Old is updated, its observed previous successor, if any, is updated
// next under the same transaction, conditional on it not being superseded
// and, with op.RequireUnpresentedSuccessor, never presented. When that update
// changes no row, the successor has moved on or is no longer stored: nothing
// is written and the store reports session.ErrSuccessorAdvanced. Old and its
// previous successor are kept for reuse detection until the later of their
// stored retention deadline and op.RetainUntil, never lowered, so the sweep
// removes them only once their family could no longer be live; neither has
// its own deadlines changed. A zero op.RetainUntil is refused with the other
// invalid supersessions, before any statement, whenever op.AcceptUntil is set.
// A stored record with no retention deadline, one written before the column
// existed, is judged by its own deadlines. No other
// session of the family is read or written, however many renewals came
// before.
//
// Two rules refuse a supersession whatever it observed. A session in no
// family, the nil family, is refused with an error, since every family-less
// session carries it; the family read in the conditional update decides it,
// so nothing is written. A session superseded already is superseded again
// only through its observed successor: with none observed it is
// session.ErrSessionRenewalConflict, as it was knocked out of its chain and
// renewing it would give the family a second live head.
//
// Locking: the transaction first locks the rows it updates, Old and the
// observed previous successor (Old alone on a first rotation), in row id
// order, and only then updates either, so it takes them in the order
// DeleteFamily takes the whole family in. Two supersessions of one family, or
// a supersession and a family revocation, therefore wait for each other
// instead of deadlocking, whichever of the two rows sorts first.
// A presentation, rotation or removal of the observed successor either
// commits first and refuses the supersession, or waits for it.
//
// Isolation: at the default READ COMMITTED, a supersession that loses a race
// to another one is session.ErrSessionRenewalConflict, and one whose
// successor moved on while it waited is session.ErrSuccessorAdvanced. Inside
// a caller's transaction at REPEATABLE READ or SERIALIZABLE, a lost race may
// instead surface as the driver's serialization failure (SQLSTATE 40001),
// when PostgreSQL refuses a conditional UPDATE of a row changed since the
// transaction's snapshot; it is still one of the sentinels when the
// competitor committed before that snapshot was taken, and under
// SERIALIZABLE the failure can also arrive at commit. The caller handles it
// as it handles any other serialization failure, by retrying its
// transaction.
func (s *sessionStore) Supersede(ctx context.Context, op session.Supersession) error {
	const name = "supersede session"

	if err := storekit.CheckSupersession(op); err != nil {
		return failed(name, err)
	}
	row, err := s.newRow(name, op.Successor)
	if err != nil {
		return err
	}
	q, ambient, err := s.c.conn(ctx)
	if err != nil {
		return failed(name, err)
	}

	return storekit.Supersede(ctx, &supersession{s: s, op: name, row: row}, q, ambient, op)
}

// supersession is this store's side of storekit.Supersede, for one call to
// op: gorm's transaction, savepoint and statement calls, each failure wrapped
// with the adapter prefix and op. The statements run on q, which carries the
// call's context.
type supersession struct {
	s  *sessionStore
	op string
	// row is the successor's row.
	row sessionRow
	// tx is the transaction Begin began, when the store owns the unit.
	tx *gormdb.DB
}

// Begin begins a transaction of the store's own on q, the handle the call
// resolved to on the store's *gorm.DB.
func (u *supersession) Begin(ctx context.Context, q *gormdb.DB) (*gormdb.DB, error) {
	tx, err := beginReadCommitted(ctx, q)
	if err != nil {
		return nil, failed(u.op, err)
	}
	u.tx = tx

	return tx, nil
}

func (u *supersession) Commit(context.Context) error {
	if err := u.tx.Commit().Error; err != nil {
		return failed(u.op, err)
	}

	return nil
}

// Rollback takes no context: the transaction carries the one it was begun
// under.
func (u *supersession) Rollback(context.Context) { u.tx.Rollback() }

func (u *supersession) SavepointName() string {
	return "scrty_sessions_" + strconv.FormatUint(u.s.savepoints.Add(1), 10)
}

// ExecSavepoint runs stmt through Exec, as the identity store's savepoints
// do, so its error is seen, and bypasses a prepared-statement connection. The
// name comes from the store's own counter, never from input.
func (u *supersession) ExecSavepoint(ctx context.Context, q *gormdb.DB, stmt string) error {
	if err := savepointSession(ctx, q).Exec(stmt).Error; err != nil {
		return failed(u.op, err)
	}

	return nil
}

func (u *supersession) Exec(_ context.Context, q *gormdb.DB, stmt string, args ...any) (int64, error) {
	res := q.Exec(stmt, args...)
	if res.Error != nil {
		return 0, failed(u.op, res.Error)
	}

	return res.RowsAffected, nil
}

func (u *supersession) QueryInt(_ context.Context, q *gormdb.DB, stmt string, args ...any) (int, error) {
	var n int
	if err := q.Raw(stmt, args...).Scan(&n).Error; err != nil {
		return 0, failed(u.op, err)
	}

	return n, nil
}

func (u *supersession) InsertSuccessor(_ context.Context, q *gormdb.DB) (bool, error) {
	return insertSession(q, u.op, &u.row)
}

func (u *supersession) NullTime(t time.Time) any { return nullTs(t) }

func (u *supersession) Failed(err error) error { return failed(u.op, err) }

// DeleteFamily removes every session of family, superseded or not and expired
// or not, and reports how many went. The nil family is refused before any
// statement runs: sessions written with no family all carry it.
//
// The delete is repeated until it removes nothing, summing what each pass
// removed, in the caller's transaction when one is attached. Under PostgreSQL's
// default READ COMMITTED isolation, a delete that waited on a member an
// in-flight Supersede holds removes that member once the supersession
// commits, but cannot see the successor it inserted; the next pass, on a
// fresh snapshot, does. Each pass that removes something removes members of
// a family that only a supersession of a remaining member grows, so the
// passes end once no supersession is in flight; a Create that keeps adding
// members to the family as fast as they go would keep it running. Both of
// the library's callers, the revocation of a reused session's family and
// logout, pass a context detached from cancellation, so nothing but the
// store bounds the passes.
//
// Each pass locks the family's sessions in row id order before deleting
// them, the order Supersede locks them in, so a revocation and a supersession
// of the same family wait for each other instead of deadlocking.
//
// Inside a caller's transaction at REPEATABLE READ or SERIALIZABLE, a pass
// that waited on an in-flight supersession fails with the driver's
// serialization failure (SQLSTATE 40001) instead of looping, and the caller
// retries its transaction. On any error, the number of rows the earlier
// passes removed is returned with it.
//
// Inside a caller's transaction the passes run directly in it, with no
// savepoint of the store's own: the count returned is of deletes not yet
// committed, which the caller's commit makes final and its rollback undoes.
// After an error the caller must roll its transaction back: a failed
// statement leaves it aborted, with no savepoint to return to.
func (s *sessionStore) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	if family.IsZero() {
		return 0, errors.New("gorm: delete session family: the nil family names no family")
	}

	const op = "delete session family"

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}
	return untilNone(func() (int, error) {
		res := q.Exec(pgschema.SessionDeleteFamily, family)
		if res.Error != nil {
			return 0, failed(op, res.Error)
		}
		return int(res.RowsAffected), nil
	})
}

// MarkPresented records at as the session's first presentation, only when
// none is recorded and the session is not superseded: one conditional UPDATE
// of that column, so a supersession racing it either commits first and
// refuses it, or waits on the row and sees it. Only when it changes no row
// does one read tell why: a session that is not stored is
// session.ErrSessionNotFound, a superseded one is
// session.ErrSessionSuperseded, with nothing written, and one already
// presented is not an error.
func (s *sessionStore) MarkPresented(ctx context.Context, sessionID string, at time.Time) error {
	const op = "mark session presented"

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	digest := storekit.SessionDigest(sessionID)
	res := q.Exec(pgschema.SessionMarkPresented, digest, storekit.Time(at))
	if res.Error != nil {
		return failed(op, res.Error)
	}
	if res.RowsAffected == 0 {
		var exists, superseded bool
		if err := q.Raw(pgschema.SessionPresentationRefusal, digest).Row().Scan(&exists, &superseded); err != nil {
			return failed(op, err)
		}

		return storekit.PresentationRefusal(exists, superseded, nil)
	}

	return nil
}

var _ session.Store = (*sessionStore)(nil)

// SuccessorPresented reports whether the current successor of the session
// with this identifier was used, in one read that writes nothing: true when
// that successor is stored and was presented or has been superseded, false
// when it is stored unused, is no longer stored, or the session has none. A
// session that is not stored is session.ErrSessionNotFound. "Stored" is
// judged as Load judges it, with the store's clock, for the session and its
// successor alike, so a row past its deadlines that the sweep has not yet
// removed is not stored. It reads through the caller's transaction when one
// is attached.
func (s *sessionStore) SuccessorPresented(ctx context.Context, sessionID string) (bool, error) {
	const op = "read whether session successor was used"

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return false, failed(op, err)
	}
	var used bool
	err = q.Raw(pgschema.SessionSuccessorPresented,
		storekit.SessionDigest(sessionID), storekit.Time(s.c.clock.Now())).Row().Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		return false, session.ErrSessionNotFound
	}
	if err != nil {
		return false, failed(op, err)
	}

	return used, nil
}
