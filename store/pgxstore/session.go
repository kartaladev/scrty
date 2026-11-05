package pgxstore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/seal"
)

// NewSessionStore returns a durable session store on pool, keeping sessions in
// the sessions table the migrate package creates.
//
// The provider ID token a federated session carries is sealed with c before
// it is written and opened when it is read, through session.NewEncryptedStore
// and seal.SessionCipher; there is no unsealed variant, and a nil c, typed
// nil included, is a configuration error. Every seal and open runs under the
// context of the save or load it serves. A token that will not open makes the
// load fail with session.ErrUnreadable, never session.ErrNotFound. An open
// that is an outage is not that: one abandoned by the context's cancellation
// or deadline, or one c marks by wrapping its error with seal.ErrUnavailable
// (for example errors.Join(seal.ErrUnavailable, err)), fails the load with a
// store failure that matches the cause, and session.ErrCipherUnavailable for
// a marked one, never session.ErrUnreadable. A load never rewrites the
// record, so a token sealed under a retired key is re-sealed only by the
// session's next save.
//
// The session identifier, a bearer credential, is never stored: a session is
// kept and found under the SHA-256 digest of its identifier, behind a
// primary key minted from the store's id generator. Create is an insert that
// refuses an identifier already stored, and Save an update that reports
// session.ErrNotFound when the session is gone, so a save racing a
// logout never brings the session back.
//
// The enrolment-origin marker and the enrolment generation are kept in
// columns of their own, NULL when the session carries neither, so a session
// confined to MFA enrolment stays confined when it is loaded again.
// RecoveredAt, the time an account recovery produced the session, is kept the
// same way: NULL when the session was never recovered, and read back as the
// zero time.
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
func NewSessionStore(pool *pgxpool.Pool, c seal.Cipher, opts ...Option) (session.Store, error) {
	cfg, err := newConfig(pool, opts, optIDGenerator, optClock)
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

// sessionColumns returns the values of sess's columns from user_id to
// federated_acr, in the order SessionUpdate takes them, or the refusal
// of a session this store cannot hold without altering it.
func sessionColumns(op string, sess *session.Session) ([]any, error) {
	if err := storekit.CheckSession(sess); err != nil {
		return nil, failed(op, err)
	}

	// The marshalled text is sent as a string, which pgx passes to jsonb as is
	// rather than marshalling it again.
	encoded, err := storekit.EncodeSessionData(sess.Data)
	if err != nil {
		return nil, failed(op, err)
	}

	amr, err := storekit.EncodeAMR(sess.FederatedAMR)
	if err != nil {
		return nil, failed(op, err)
	}

	return []any{
		string(sess.UserID), storekit.Time(sess.CreatedAt), storekit.Time(sess.LastAccessedAt),
		storekit.Time(sess.IdleExpiresAt), storekit.Time(sess.AbsoluteExpiresAt), string(sess.FirstFactor),
		int64(sess.MFA), nullTs(sess.MFASatisfiedAt),
		sess.PasswordChangePending, sess.ExternalProvider, sess.ExternalIssuer, sess.ExternalSessionID,
		sess.ExternalIDToken, encoded,
		nullTs(sess.EnrolmentOriginDeadline), nullID(sess.EnrolmentGeneration),
		nullTs(sess.RecoveredAt), amr, sess.FederatedACR,
	}, nil
}

// Create inserts sess, refusing an identifier already stored. A session with
// no family, the nil family, is refused with an error before any statement
// runs: every stored session belongs to a family.
func (s *sessionStore) Create(ctx context.Context, sess *session.Session) error {
	const op = "create session"

	if sess.FamilyID.IsZero() {
		return errors.New("pgxstore: create session: a session with no family cannot be stored")
	}
	if sess.FamilyCreatedAt.IsZero() {
		return errors.New("pgxstore: create session: a session with no family start time cannot be stored")
	}

	args, err := s.insertArgs(op, sess)
	if err != nil {
		return err
	}
	n, err := s.c.exec(ctx, op, pgschema.SessionInsert, args...)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("pgxstore: create session: the identifier is already in use")
	}

	return nil
}

// insertArgs returns SessionInsert's arguments for sess, under a primary key
// minted from the store's id generator, or the refusal of a session this
// store cannot hold without altering it. Only the insert writes the marker,
// the sign-in state (metadata, key binding and CSRF token) and the family,
// supersession and presentation columns: SessionUpdate has no column for
// them. A session is inserted with its RetainUntil as given,
// NULL when it is zero.
func (s *sessionStore) insertArgs(op string, sess *session.Session) ([]any, error) {
	cols, err := sessionColumns(op, sess)
	if err != nil {
		return nil, err
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return nil, failed(op, err)
	}

	signIn, err := pgschema.SessionSignInArgs(sess)
	if err != nil {
		return nil, failed(op, err)
	}

	args := append([]any{uuidArg(rowID), storekit.SessionDigest(sess.ID)}, cols...)
	args = append(args, sess.MFAAtFirstFactor, uuidArg(sess.FamilyID), storekit.Time(sess.FamilyCreatedAt),
		nullTs(sess.SupersededAt), nullTs(sess.AcceptUntil), storekit.OptionalDigestArg(sess.SuccessorDigest),
		nullTs(sess.FirstPresentedAt), storekit.Time(sess.AuthenticatedAt), nullTs(sess.RetainUntil))

	return append(args, signIn...), nil
}

// Save replaces the stored session whole, except for MFAAtFirstFactor, the
// sign-in state (ClientIP, UserAgent, KeyBinding and CSRFToken) and the
// family, supersession (RetainUntil included) and presentation fields, and
// never inserts. A superseded session also keeps both of its own deadlines.
func (s *sessionStore) Save(ctx context.Context, sess *session.Session) error {
	const op = "save session"

	cols, err := sessionColumns(op, sess)
	if err != nil {
		return err
	}
	n, err := s.c.exec(ctx, op, pgschema.SessionUpdate, append([]any{storekit.SessionDigest(sess.ID)}, cols...)...)
	if err != nil {
		return err
	}
	if n == 0 {
		return session.ErrNotFound
	}

	return nil
}

// Load returns the session with this identifier, judging its expiry with the
// store's clock: a superseded session with a retention deadline is returned
// until that deadline, whatever its own deadlines say and with them intact,
// and any other session until either of its own deadlines. A stored session
// past them is session.ErrExpired.
func (s *sessionStore) Load(ctx context.Context, sessionID string) (*session.Session, error) {
	const op = "load session"

	var row sessionRow
	err := s.c.queryRow(ctx, op, pgschema.SessionSelect, []any{storekit.SessionDigest(sessionID)}, row.dest()...)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, session.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	retainUntil, err := fromNull(row.retain)
	if err != nil {
		return nil, failed(op, err)
	}
	if stale(s.c.clock.Now(), row.superseded.Valid, row.retain.Valid, retainUntil, row.idle, row.abs) {
		return nil, session.ErrExpired
	}

	sess, err := row.session()
	if err != nil {
		return nil, failed(op, err)
	}
	sess.ID = sessionID

	return sess, nil
}

// sessionRow is a sessions row as SessionSelect and SessionListByUser read
// it.
type sessionRow struct {
	sess          session.Session
	user          string
	firstFactor   string
	mfaState      int64
	mfaSatisfied  pgtype.Timestamptz
	encoded, amr  []byte
	origin        pgtype.Timestamptz
	generation    pgtype.UUID
	recovered     pgtype.Timestamptz
	created, last time.Time
	idle, abs     time.Time
	family        pgtype.UUID
	familyCreated time.Time
	authenticated time.Time
	superseded    pgtype.Timestamptz
	acceptUntil   pgtype.Timestamptz
	presented     pgtype.Timestamptz
	retain        pgtype.Timestamptz
	bindingKind   string
	thumbprint    string
}

// dest is the scan destinations of SessionSelect's columns, in its order.
func (r *sessionRow) dest() []any {
	return []any{
		&r.user, &r.created, &r.last, &r.idle, &r.abs, &r.firstFactor, &r.mfaState, &r.mfaSatisfied,
		&r.sess.PasswordChangePending, &r.sess.ExternalProvider, &r.sess.ExternalIssuer, &r.sess.ExternalSessionID,
		&r.sess.ExternalIDToken, &r.encoded, &r.origin, &r.generation, &r.recovered, &r.sess.MFAAtFirstFactor,
		&r.amr, &r.sess.FederatedACR, &r.family, &r.familyCreated, &r.superseded, &r.acceptUntil,
		&r.sess.SuccessorDigest, &r.presented, &r.authenticated, &r.retain, &r.sess.RotatedStrictly,
		&r.sess.ClientIP, &r.sess.UserAgent, &r.bindingKind, &r.thumbprint, &r.sess.CSRFToken,
	}
}

// session is the row as a session, with no identifier: the row does not
// hold one. A column that will not decode is an error naming no stored value.
func (r *sessionRow) session() (*session.Session, error) {
	sess := r.sess

	var err error
	if sess.Data, err = storekit.DecodeSessionData(r.encoded); err != nil {
		return nil, err
	}
	if sess.FederatedAMR, err = storekit.DecodeAMR(r.amr); err != nil {
		return nil, err
	}
	if sess.KeyBinding, err = pgschema.ParseSessionBinding(r.bindingKind, r.thumbprint); err != nil {
		return nil, err
	}
	sess.UserID = identity.UserID(r.user)
	sess.FirstFactor = factor.Kind(r.firstFactor)
	sess.MFA = session.MFAState(r.mfaState)
	sess.EnrolmentGeneration = nullableID(r.generation)
	if sess.FamilyID, err = scanID(r.family); err != nil {
		return nil, err
	}
	for _, t := range []struct {
		dst *time.Time
		src pgtype.Timestamptz
	}{
		{&sess.MFASatisfiedAt, r.mfaSatisfied},
		{&sess.EnrolmentOriginDeadline, r.origin},
		{&sess.RecoveredAt, r.recovered},
		{&sess.SupersededAt, r.superseded},
		{&sess.AcceptUntil, r.acceptUntil},
		{&sess.FirstPresentedAt, r.presented},
		{&sess.RetainUntil, r.retain},
	} {
		if *t.dst, err = fromNull(t.src); err != nil {
			return nil, err
		}
	}
	sess.FamilyCreatedAt = r.familyCreated.UTC()
	sess.AuthenticatedAt = r.authenticated.UTC()
	sess.CreatedAt, sess.LastAccessedAt = r.created.UTC(), r.last.UTC()
	sess.IdleExpiresAt, sess.AbsoluteExpiresAt = r.idle.UTC(), r.abs.UTC()

	return &sess, nil
}

// Delete removes the session with this identifier; one not there is not an
// error.
func (s *sessionStore) Delete(ctx context.Context, sessionID string) error {
	_, err := s.c.exec(ctx, "delete session", pgschema.SessionDelete, storekit.SessionDigest(sessionID))
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

	_, err := s.deleteUntilSettled(ctx, "delete user's sessions", pgschema.SessionDeleteByUser, string(user))

	return err
}

// DeleteByUserExcept removes every session of user except the one named by
// keep and, when user holds keep, its family's current session, expired ones
// included, and reports how many it removed. Every other member of keep's
// family goes, superseded ones included. Each pass is one statement, so the
// family kept is read on the snapshot the pass deletes on. keep is compared
// by its digest, as Delete's identifier is, so one no store could hold names
// no session and every session of the user goes. A user reference PostgreSQL
// text cannot hold matches nothing.
//
// The delete is repeated until a pass removes nothing, summing what each pass
// removed. Under PostgreSQL's default READ COMMITTED isolation, a delete that
// waited on a session an in-flight Supersede holds removes that session once
// the supersession commits, but cannot see the successor it inserted; the next
// pass, on a fresh snapshot, does. Inside a caller's transaction at REPEATABLE
// READ or SERIALIZABLE, such a pass fails with the driver's serialization
// failure (SQLSTATE 40001) instead, and the caller retries its transaction. On
// an error, the number of rows the earlier passes removed is returned with it.
//
// The passes are bounded at 64: when every one of them removed sessions,
// because sessions it matches are being created as fast as it removes them,
// it stops with an error wrapping ErrDeleteDidNotSettle rather than running
// until ctx ends. What its passes removed stays removed.
func (s *sessionStore) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	return s.deleteUntilSettled(ctx, "delete user's other sessions", pgschema.SessionDeleteByUserExcept,
		string(user), storekit.SessionDigest(keep))
}

// CountActiveByUser counts user's sessions unexpired by the store's clock and
// not superseded.
func (s *sessionStore) CountActiveByUser(ctx context.Context, user identity.UserID) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	return s.c.count(ctx, "count user's active sessions", pgschema.SessionCountActive,
		string(user), storekit.Time(s.c.clock.Now()))
}

// ListByUser returns user's sessions that are not superseded and are before
// both of their own deadlines at now, the caller's time, in one query over
// the sessions_user index. The reference is matched exactly; one PostgreSQL
// text cannot hold matches nothing. A listed session carries no identifier,
// which is never stored, and neither sealed token: the listing reads neither
// column. A row that will not decode fails the whole call.
func (s *sessionStore) ListByUser(ctx context.Context, user identity.UserID, now time.Time) ([]*session.Session, error) {
	return s.list(ctx, "list user's sessions", pgschema.SessionListByUser, user, now)
}

// ListByFamily is ListByUser narrowed to family, as session.FamilyReader states
// it, in one query. A row of the family that will not decode fails the call,
// and a row of another family is never read. The sealing store NewSessionStore
// wraps this one in answers the nil family before asking here.
func (s *sessionStore) ListByFamily(ctx context.Context, user identity.UserID, family id.ID, now time.Time) ([]*session.Session, error) {
	return s.list(ctx, "list sign-in's sessions", pgschema.SessionListByFamily, user, now, uuidArg(family))
}

// list runs a listing statement, whose $1 is user and $2 now, and whose further
// parameters are args. A reference one PostgreSQL text cannot hold matches
// nothing.
func (s *sessionStore) list(ctx context.Context, op, statement string, user identity.UserID, now time.Time, args ...any) ([]*session.Session, error) {
	if !storekit.Storable(string(user)) {
		return []*session.Session{}, nil
	}
	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}
	rows, err := q.Query(ctx, statement, append([]any{string(user), storekit.Time(now)}, args...)...)
	if err != nil {
		return nil, failed(op, err)
	}
	defer rows.Close()

	listed := []*session.Session{}
	for rows.Next() {
		var row sessionRow
		if err := rows.Scan(row.dest()...); err != nil {
			return nil, failed(op, err)
		}
		sess, err := row.session()
		if err != nil {
			return nil, failed(op, err)
		}
		listed = append(listed, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, failed(op, err)
	}

	return listed, nil
}

// stale reports whether a stored session is past what Load returns at now: a
// superseded one with a retention deadline (hasRetain) once retain is not
// after now, any other once either of its own deadlines is not. It is the
// condition SessionDeleteExpired deletes by, judged in Go.
func stale(now time.Time, superseded, hasRetain bool, retain, idle, abs time.Time) bool {
	if superseded && hasRetain {
		return !now.Before(retain)
	}

	return !now.Before(idle) || !now.Before(abs)
}

// DeleteExpired removes every session Load would no longer return by the
// store's clock: a superseded session once its retention deadline passes, or
// its own deadlines when it has none, and any other once either of its own
// deadlines passes.
func (s *sessionStore) DeleteExpired(ctx context.Context) (int, error) {
	n, err := s.c.exec(ctx, "delete expired sessions", pgschema.SessionDeleteExpired, storekit.Time(s.c.clock.Now()))
	return int(n), err
}

// DeleteByExternalSession removes the sessions of issuer and provider session
// sessionID. An empty argument matches nothing.
//
// The delete is repeated until a pass removes nothing, summing what each pass
// removed. Under PostgreSQL's default READ COMMITTED isolation, a delete that
// waited on a session an in-flight Supersede holds removes that session once
// the supersession commits, but cannot see the successor it inserted; the next
// pass, on a fresh snapshot, does. Inside a caller's transaction at REPEATABLE
// READ or SERIALIZABLE, such a pass fails with the driver's serialization
// failure (SQLSTATE 40001) instead, and the caller retries its transaction. On
// an error, the number of rows the earlier passes removed is returned with it.
//
// The passes are bounded at 64: when every one of them removed sessions,
// because sessions it matches are being created as fast as it removes them,
// it stops with an error wrapping ErrDeleteDidNotSettle rather than running
// until ctx ends. What its passes removed stays removed.
func (s *sessionStore) DeleteByExternalSession(ctx context.Context, issuer, sessionID string) (int, error) {
	if !storekit.Storable(issuer, sessionID) {
		return 0, nil
	}

	return s.deleteUntilSettled(ctx, "delete provider session's sessions", pgschema.SessionDeleteByExternal,
		issuer, sessionID)
}

// DeleteByUserAndExternalIssuer removes user's sessions from issuer. An empty
// issuer matches nothing.
//
// The delete is repeated until a pass removes nothing, summing what each pass
// removed. Under PostgreSQL's default READ COMMITTED isolation, a delete that
// waited on a session an in-flight Supersede holds removes that session once
// the supersession commits, but cannot see the successor it inserted; the next
// pass, on a fresh snapshot, does. Inside a caller's transaction at REPEATABLE
// READ or SERIALIZABLE, such a pass fails with the driver's serialization
// failure (SQLSTATE 40001) instead, and the caller retries its transaction. On
// an error, the number of rows the earlier passes removed is returned with it.
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

	return s.deleteUntilSettled(ctx, "delete user's sessions from issuer", pgschema.SessionDeleteByUserIssuer,
		string(user), issuer)
}

// deleteUntilNone runs statement, a delete of sessions, until a pass removes
// nothing, and returns what every pass removed, those before an error
// included. A pass that waited on a session an in-flight supersession holds
// cannot see the successor that supersession inserted; the pass after it
// can.
func (s *sessionStore) deleteUntilNone(ctx context.Context, op, statement string, args ...any) (int, error) {
	total := 0
	for {
		n, err := s.c.exec(ctx, op, statement, args...)
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
		total += int(n)
	}
}

// RecordActivity writes lastAccessed and idleExpires, and nothing else, to a
// session last accessed not later than olderThan and not superseded: one conditional
// UPDATE of those two columns. A session that is fresher or superseded is left
// unchanged and is not an error; one that is not stored is
// session.ErrNotFound.
func (s *sessionStore) RecordActivity(
	ctx context.Context, sessionID string, lastAccessed, idleExpires, olderThan time.Time,
) error {
	const op = "record session activity"

	digest := storekit.SessionDigest(sessionID)
	n, err := s.c.exec(ctx, op, pgschema.SessionRecordActivity, digest,
		storekit.Time(lastAccessed), storekit.Time(idleExpires), storekit.Time(olderThan))
	if err != nil {
		return err
	}
	if n == 0 {
		return storekit.NotFoundUnless(s.stored(ctx, op, digest))
	}

	return nil
}

// stored reports whether a session with digest is stored, expired or not,
// reading through the handle ctx resolves to: what a conditional write that
// changed no row runs to tell a missing session from one whose condition did
// not hold.
func (s *sessionStore) stored(ctx context.Context, op string, digest []byte) (bool, error) {
	var exists bool
	err := s.c.queryRow(ctx, op, pgschema.SessionExists, []any{digest}, &exists)

	return exists, err
}

// Supersede marks op.Old superseded by op.Successor, supersedes Old's previous
// successor, and inserts op.Successor, in one transaction: the caller's when
// one is attached, under a savepoint of its own, otherwise one it begins and
// commits. The conditional UPDATE of Old decides the outcome: when it changes
// no row, nothing is written, and the store reports
// session.ErrRenewalConflict when Old is stored and
// session.ErrNotFound when it is not. A successor whose identifier is
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
// session.ErrRenewalConflict, as it was knocked out of its chain and
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
// to another one is session.ErrRenewalConflict, and one whose
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
	args, err := s.insertArgs(name, op.Successor)
	if err != nil {
		return err
	}
	q, ambient, err := s.c.conn(ctx)
	if err != nil {
		return failed(name, err)
	}

	return storekit.Supersede(ctx, &supersession{s: s, op: name, insert: args}, q, ambient, op)
}

// supersession is this store's side of storekit.Supersede, for one call to
// op: pgx's transaction, savepoint and statement calls, each failure wrapped
// with the adapter prefix and op.
//
// Inside a caller's transaction the savepoint statements are issued through
// q's Exec, so a consumer's transaction wrapper sees them. pgx's own nesting
// (Tx.Begin) is not used: its Rollback does not release the savepoint.
type supersession struct {
	s  *sessionStore
	op string
	// insert is the successor's SessionInsert arguments.
	insert []any
	// tx is the transaction Begin began, when the store owns the unit.
	tx pgx.Tx
}

// Begin begins a transaction of the store's own on its pool.
func (u *supersession) Begin(ctx context.Context, _ DBTX) (DBTX, error) {
	tx, err := u.s.c.beginReadCommitted(ctx)
	if err != nil {
		return nil, failed(u.op, err)
	}
	u.tx = tx

	return u.s.c.boundTo(tx), nil
}

func (u *supersession) Commit(ctx context.Context) error {
	if err := u.tx.Commit(ctx); err != nil {
		return failed(u.op, err)
	}

	return nil
}

// Rollback detaches from ctx, so the transaction and the row locks it holds
// never outlive the call even when ctx is done.
func (u *supersession) Rollback(ctx context.Context) { _ = u.tx.Rollback(context.WithoutCancel(ctx)) }

func (u *supersession) SavepointName() string {
	return "scrty_sessions_" + strconv.FormatUint(u.s.savepoints.Add(1), 10)
}

func (u *supersession) ExecSavepoint(ctx context.Context, q DBTX, stmt string) error {
	if _, err := q.Exec(ctx, stmt); err != nil {
		return failed(u.op, err)
	}

	return nil
}

func (u *supersession) Exec(ctx context.Context, q DBTX, stmt string, args ...any) (int64, error) {
	tag, err := q.Exec(ctx, stmt, args...)
	if err != nil {
		return 0, failed(u.op, err)
	}

	return tag.RowsAffected(), nil
}

func (u *supersession) QueryInt(ctx context.Context, q DBTX, stmt string, args ...any) (int, error) {
	var n int
	if err := q.QueryRow(ctx, stmt, args...).Scan(&n); err != nil {
		return 0, failed(u.op, err)
	}

	return n, nil
}

func (u *supersession) InsertSuccessor(ctx context.Context, q DBTX) (bool, error) {
	n, err := u.Exec(ctx, q, pgschema.SessionInsert, u.insert...)
	if err != nil {
		return false, err
	}

	return n > 0, nil
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
		return 0, errors.New("pgxstore: delete session family: the nil family names no family")
	}

	return s.deleteUntilNone(ctx, "delete session family", pgschema.SessionDeleteFamily, uuidArg(family))
}

// MarkPresented records at as the session's first presentation, only when
// none is recorded and the session is not superseded: one conditional UPDATE
// of that column, so a supersession racing it either commits first and
// refuses it, or waits on the row and sees it. Only when it changes no row
// does one read tell why: a session that is not stored is
// session.ErrNotFound, a superseded one is
// session.ErrSuperseded, with nothing written, and one already
// presented is not an error.
func (s *sessionStore) MarkPresented(ctx context.Context, sessionID string, at time.Time) error {
	const op = "mark session presented"

	digest := storekit.SessionDigest(sessionID)
	n, err := s.c.exec(ctx, op, pgschema.SessionMarkPresented, digest, storekit.Time(at))
	if err != nil {
		return err
	}
	if n == 0 {
		var exists, superseded bool
		err := s.c.queryRow(ctx, op, pgschema.SessionPresentationRefusal, []any{digest}, &exists, &superseded)

		return storekit.PresentationRefusal(exists, superseded, err)
	}

	return nil
}

var (
	_ session.Store        = (*sessionStore)(nil)
	_ session.FamilyReader = (*sessionStore)(nil)
)

// SuccessorPresented reports whether the current successor of the session
// with this identifier was used, in one read that writes nothing: true when
// that successor is stored and was presented or has been superseded, false
// when it is stored unused, is no longer stored, or the session has none. A
// session that is not stored is session.ErrNotFound. "Stored" is
// judged as Load judges it, with the store's clock, for the session and its
// successor alike, so a row past its deadlines that the sweep has not yet
// removed is not stored. It reads through the caller's transaction when one
// is attached.
func (s *sessionStore) SuccessorPresented(ctx context.Context, sessionID string) (bool, error) {
	var used bool
	err := s.c.queryRow(ctx, "read whether session successor was used", pgschema.SessionSuccessorPresented,
		[]any{storekit.SessionDigest(sessionID), storekit.Time(s.c.clock.Now())}, &used)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, session.ErrNotFound
	}

	return used, err
}

// ErrDeleteDidNotSettle is wrapped by the error a user-wide session delete
// (DeleteByUser, DeleteByUserExcept, DeleteByExternalSession and
// DeleteByUserAndExternalIssuer) returns when each of its 64 bounded passes
// removed sessions. It is session.ErrDeleteDidNotSettle under this package's
// name, so errors.Is matches either.
var ErrDeleteDidNotSettle = session.ErrDeleteDidNotSettle

// deleteUntilSettled runs statement, a user-wide delete of sessions, through
// storekit.UntilSettled.
func (s *sessionStore) deleteUntilSettled(ctx context.Context, op, statement string, args ...any) (int, error) {
	return storekit.UntilSettled(op, func() (int, error) {
		n, err := s.c.exec(ctx, op, statement, args...)
		return int(n), err
	}, failed)
}
