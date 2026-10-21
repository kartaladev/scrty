package gorm

import (
	"context"
	"encoding/json"
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

	data := sess.Data
	if data == nil {
		data = map[string]string{}
	}
	encoded, err := json.Marshal(data)
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
		Data:                  string(encoded),
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
		SuccessorDigest:  digestArg(sess.SuccessorDigest),
		FirstPresentedAt: nullTs(sess.FirstPresentedAt),
		// Written on Create only: Save omits the column.
		AuthenticatedAt: storekit.Time(sess.AuthenticatedAt),
	}, nil
}

// digestArg is a successor digest as stored in its nullable column, or
// compared with it: nil, NULL, for none, an empty one included, since the
// contract reads an empty digest as none.
func digestArg(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}

	return b
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
	"authenticated_at",
}

// Save replaces the stored session whole, and never inserts: one UPDATE of
// every column but the keys, the marker (MFAAtFirstFactor, written on Create
// only) and the family, supersession and presentation columns, whose zero
// rows affected is session.ErrSessionNotFound. A superseded session keeps both
// of its deadlines: the UPDATE writes each only while superseded_at is NULL.
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
// store's clock.
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

	now := s.c.clock.Now()
	if !now.Before(row.IdleExpiresAt) || !now.Before(row.AbsoluteExpiresAt) {
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
		AuthenticatedAt:         row.AuthenticatedAt.UTC(),
	}
	if row.EnrolmentGeneration != nil {
		sess.EnrolmentGeneration = *row.EnrolmentGeneration
	}
	if sess.FederatedAMR, err = storekit.DecodeAMR([]byte(row.FederatedAMR)); err != nil {
		return nil, failed(op, err)
	}
	sess.FederatedACR = row.FederatedACR
	if err := json.Unmarshal([]byte(row.Data), &sess.Data); err != nil {
		return nil, failed(op, err)
	}
	if sess.Data == nil {
		sess.Data = map[string]string{}
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
func (s *sessionStore) DeleteByUser(ctx context.Context, user identity.UserID) error {
	if !storekit.Storable(string(user)) {
		return nil
	}

	_, err := deleteWhere[sessionRow](ctx, s.c, "delete user's sessions", "user_id = ?", string(user))

	return err
}

// DeleteByUserExcept removes every session of user except the one named by
// keep, expired ones included, and reports how many it removed. keep is
// compared by its digest, as Delete's identifier is, so one no store could
// hold names no session and every session of the user goes. A user reference
// PostgreSQL text cannot hold matches nothing.
func (s *sessionStore) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	return deleteWhere[sessionRow](ctx, s.c, "delete user's other sessions",
		"user_id = ? AND id_digest <> ?", string(user), storekit.SessionDigest(keep))
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

// DeleteExpired removes every session expired by the store's clock.
func (s *sessionStore) DeleteExpired(ctx context.Context) (int, error) {
	now := storekit.Time(s.c.clock.Now())
	return deleteWhere[sessionRow](ctx, s.c, "delete expired sessions", "idle_expires_at <= ? OR absolute_expires_at <= ?", now, now)
}

// DeleteByExternalSession removes the sessions of issuer and provider session
// sessionID. An empty argument matches nothing: the absent federation values
// are stored as empty text, and the statement's own condition excludes them.
func (s *sessionStore) DeleteByExternalSession(ctx context.Context, issuer, sessionID string) (int, error) {
	if !storekit.Storable(issuer, sessionID) {
		return 0, nil
	}

	return deleteWhere[sessionRow](ctx, s.c, "delete provider session's sessions",
		"external_issuer = ? AND external_session_id = ? AND external_issuer <> '' AND external_session_id <> ''",
		issuer, sessionID)
}

// DeleteByUserAndExternalIssuer removes user's sessions from issuer. An empty
// issuer matches nothing.
func (s *sessionStore) DeleteByUserAndExternalIssuer(
	ctx context.Context, user identity.UserID, issuer string,
) (int, error) {
	if !storekit.Storable(string(user), issuer) {
		return 0, nil
	}

	return deleteWhere[sessionRow](ctx, s.c, "delete user's sessions from issuer",
		"user_id = ? AND external_issuer = ? AND external_issuer <> ''", string(user), issuer)
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
		return notFoundUnless(stored(q, op, digest))
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

// notFoundUnless is nil when exists, and session.ErrSessionNotFound when not.
func notFoundUnless(exists bool, err error) error {
	if err != nil {
		return err
	}
	if !exists {
		return session.ErrSessionNotFound
	}

	return nil
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
// previous successor have each deadline raised to op.RetainUntil when it is
// earlier, and never lowered, so the sweep removes them only once their
// family could no longer be live. No other session of the family is read or
// written, however many renewals came before.
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

	if op.Successor == nil {
		return errors.New("gorm: supersede session: a supersession needs a successor")
	}
	if op.Successor.FamilyID.IsZero() {
		return errors.New("gorm: supersede session: a successor with no family cannot be stored")
	}
	if op.RetainUntil.Before(op.AcceptUntil) {
		return errors.New("gorm: supersede session: the retention deadline is before the end of the window")
	}
	row, err := s.newRow(name, op.Successor)
	if err != nil {
		return err
	}
	oldDigest := storekit.SessionDigest(op.Old)

	return s.atomically(ctx, name, func(q *gormdb.DB) error {
		if res := q.Exec(pgschema.SessionLockSupersession, oldDigest,
			digestArg(op.ObservedSuccessor)); res.Error != nil {
			return failed(name, res.Error)
		}

		res := q.Exec(pgschema.SessionSupersedeOld, oldDigest, digestArg(op.ObservedSuccessor),
			storekit.Time(op.Now), storekit.Time(op.AcceptUntil), storekit.SessionDigest(op.Successor.ID),
			storekit.Time(op.RetainUntil))
		if res.Error != nil {
			return failed(name, res.Error)
		}
		if res.RowsAffected == 0 {
			var cause int
			if err := q.Raw(pgschema.SessionSupersedeRefusal, oldDigest).Scan(&cause).Error; err != nil {
				return failed(name, err)
			}
			switch cause {
			case pgschema.SupersedeRefusalMissing:
				return session.ErrSessionNotFound
			case pgschema.SupersedeRefusalNoFamily:
				return errors.New("gorm: supersede session: a session with no family cannot be superseded")
			}
			return session.ErrSessionRenewalConflict
		}

		if len(op.ObservedSuccessor) > 0 {
			res := q.Exec(pgschema.SessionSupersedePrevious, op.ObservedSuccessor,
				storekit.Time(op.Now), op.RequireUnpresentedSuccessor, storekit.Time(op.RetainUntil))
			if res.Error != nil {
				return failed(name, res.Error)
			}
			if res.RowsAffected == 0 {
				return session.ErrSuccessorAdvanced
			}
		}

		inserted, err := insertSession(q, name, &row)
		if err != nil {
			return err
		}
		if !inserted {
			return errors.New("gorm: supersede session: the successor's identifier is already in use")
		}

		return nil
	})
}

// atomically runs fn as one unit on the handle ctx resolves to: under a
// savepoint inside a caller's transaction, otherwise in a transaction of the
// store's own begun on its *gorm.DB. A refusal fn returns is returned as it
// is, so a sentinel stays bare.
func (s *sessionStore) atomically(ctx context.Context, op string, fn func(q *gormdb.DB) error) error {
	q, ambient, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}

	if ambient {
		return s.underSavepoint(ctx, q, op, fn)
	}

	tx := q.Begin()
	if tx.Error != nil {
		return failed(op, tx.Error)
	}
	// Rolled back on every way out but a commit, a panic in fn included, so
	// the transaction and the row lock it holds never outlive the call. After
	// a commit the rollback does nothing.
	defer func() { tx.Rollback() }()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit().Error; err != nil {
		return failed(op, err)
	}

	return nil
}

// underSavepoint runs fn on q, a caller's transaction, under a savepoint of
// its own. When fn fails, the savepoint is rolled back, which undoes fn's
// writes and clears the aborted state a failed statement leaves, so the
// caller's transaction stays usable with its earlier writes intact; the
// savepoint is then released either way. When fn panics, or a panic
// interrupts a statement that closes the savepoint, the savepoint is rolled
// back and released before the panic goes on.
//
// The savepoint statements run through Exec, as the identity store's do, so
// their errors are seen, and bypass a prepared-statement connection. The name
// comes from the store's own counter, never from input. The statements that
// close the savepoint run even when ctx is done.
func (s *sessionStore) underSavepoint(ctx context.Context, q *gormdb.DB, op string, fn func(q *gormdb.DB) error) error {
	name := "scrty_sessions_" + strconv.FormatUint(s.savepoints.Add(1), 10)

	if err := savepointSession(ctx, q).Exec("SAVEPOINT " + name).Error; err != nil {
		return failed(op, err)
	}

	closing := savepointSession(context.WithoutCancel(ctx), q)
	exec := func(stmt string) error {
		if err := closing.Exec(stmt + name).Error; err != nil {
			return failed(op, err)
		}
		return nil
	}

	// open tracks whether the savepoint is still open; every normal return
	// clears it, having closed the savepoint or tried to.
	open := true
	defer func() {
		if open {
			bestEffort(func() { _ = exec("ROLLBACK TO SAVEPOINT ") })
			bestEffort(func() { _ = exec("RELEASE SAVEPOINT ") })
		}
	}()

	err := fn(q)

	if err != nil {
		rbErr := exec("ROLLBACK TO SAVEPOINT ")
		if rbErr == nil {
			rbErr = exec("RELEASE SAVEPOINT ")
		}
		open = false
		if rbErr != nil {
			return errors.Join(err, rbErr)
		}

		return err
	}

	relErr := exec("RELEASE SAVEPOINT ")
	open = false

	return relErr
}

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
// members to the family as fast as they go would keep it running, and ctx
// bounds it.
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
	total := 0
	for {
		res := q.Exec(pgschema.SessionDeleteFamily, family)
		if res.Error != nil {
			return total, failed(op, res.Error)
		}
		if res.RowsAffected == 0 {
			return total, nil
		}
		total += int(res.RowsAffected)
	}
}

// MarkPresented records at as the session's first presentation, only when
// none is recorded: one conditional UPDATE of that column. A session that is
// not stored is session.ErrSessionNotFound.
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
		return notFoundUnless(stored(q, op, digest))
	}

	return nil
}

var _ session.Store = (*sessionStore)(nil)
