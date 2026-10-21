package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

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
// The enrolment-origin marker and the enrolment generation of a session
// confined to MFA enrolment are kept in columns of their own, NULL when the
// session is not marked or has begun no enrolment, and read back as the zero
// time and id.Nil. They are not secrets and are not sealed. RecoveredAt, the
// time an account recovery produced the session, is kept the same way: NULL
// when the session was never recovered, and read back as the zero time.
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
func NewSessionStore(db *sql.DB, c seal.Cipher, opts ...Option) (session.Store, error) {
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

// sessionColumns returns the values of sess's columns from user_id to
// federated_acr, in the order SessionUpdate takes them, or the
// refusal of a session this store cannot hold without altering it.
func sessionColumns(op string, sess *session.Session) ([]any, error) {
	if err := storekit.CheckSession(sess); err != nil {
		return nil, failed(op, err)
	}

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
		return errors.New("sqlstore: create session: a session with no family cannot be stored")
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
		return errors.New("sqlstore: create session: the identifier is already in use")
	}

	return nil
}

// insertArgs returns SessionInsert's arguments for sess, under a primary key
// minted from the store's id generator, or the refusal of a session this
// store cannot hold without altering it. Only the insert writes the marker
// and the family, supersession and presentation columns: SessionUpdate has
// no column for them.
func (s *sessionStore) insertArgs(op string, sess *session.Session) ([]any, error) {
	cols, err := sessionColumns(op, sess)
	if err != nil {
		return nil, err
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return nil, failed(op, err)
	}

	args := append([]any{rowID, storekit.SessionDigest(sess.ID)}, cols...)

	return append(args, sess.MFAAtFirstFactor, sess.FamilyID, storekit.Time(sess.FamilyCreatedAt),
		nullTs(sess.SupersededAt), nullTs(sess.AcceptUntil), storekit.OptionalDigestArg(sess.SuccessorDigest),
		nullTs(sess.FirstPresentedAt), storekit.Time(sess.AuthenticatedAt)), nil
}

// Save replaces the stored session whole, except for MFAAtFirstFactor and the
// family, supersession and presentation fields, and never inserts. A
// superseded session also keeps both of its deadlines.
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
		return session.ErrSessionNotFound
	}

	return nil
}

// Load returns the session with this identifier, judging its expiry with the
// store's clock.
func (s *sessionStore) Load(ctx context.Context, sessionID string) (*session.Session, error) {
	const op = "load session"

	var (
		sess          = session.Session{ID: sessionID}
		user          string
		firstFactor   string
		mfaState      int64
		mfaSatisfied  sql.NullTime
		encoded, amr  []byte
		created, last time.Time
		idle, abs     time.Time
		origin        sql.NullTime
		generation    sql.Null[id.ID]
		recovered     sql.NullTime
		familyCreated time.Time
		authenticated time.Time
		superseded    sql.NullTime
		acceptUntil   sql.NullTime
		presented     sql.NullTime
	)
	err := s.c.queryRow(ctx, op, pgschema.SessionSelect, []any{storekit.SessionDigest(sessionID)},
		&user, &created, &last, &idle, &abs, &firstFactor, &mfaState, &mfaSatisfied,
		&sess.PasswordChangePending, &sess.ExternalProvider, &sess.ExternalIssuer, &sess.ExternalSessionID,
		&sess.ExternalIDToken, &encoded, &origin, &generation, &recovered, &sess.MFAAtFirstFactor,
		&amr, &sess.FederatedACR, &sess.FamilyID, &familyCreated, &superseded, &acceptUntil,
		&sess.SuccessorDigest, &presented, &authenticated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, session.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	now := s.c.clock.Now()
	if !now.Before(idle) || !now.Before(abs) {
		return nil, session.ErrSessionExpired
	}

	if sess.Data, err = storekit.DecodeSessionData(encoded); err != nil {
		return nil, failed(op, err)
	}
	if sess.FederatedAMR, err = storekit.DecodeAMR(amr); err != nil {
		return nil, failed(op, err)
	}
	sess.UserID = identity.UserID(user)
	sess.FirstFactor = factor.Kind(firstFactor)
	sess.MFA = session.MFAState(mfaState)
	sess.MFASatisfiedAt = fromNull(mfaSatisfied)
	sess.EnrolmentOriginDeadline, sess.EnrolmentGeneration = fromNull(origin), generation.V
	sess.RecoveredAt = fromNull(recovered)
	sess.FamilyCreatedAt = familyCreated.UTC()
	sess.AuthenticatedAt = authenticated.UTC()
	sess.SupersededAt, sess.AcceptUntil = fromNull(superseded), fromNull(acceptUntil)
	sess.FirstPresentedAt = fromNull(presented)
	sess.CreatedAt, sess.LastAccessedAt = created.UTC(), last.UTC()
	sess.IdleExpiresAt, sess.AbsoluteExpiresAt = idle.UTC(), abs.UTC()

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
func (s *sessionStore) DeleteByUser(ctx context.Context, user identity.UserID) error {
	if !storekit.Storable(string(user)) {
		return nil
	}

	_, err := s.c.exec(ctx, "delete user's sessions", pgschema.SessionDeleteByUser, string(user))

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

	n, err := s.c.exec(ctx, "delete user's other sessions", pgschema.SessionDeleteByUserExcept,
		string(user), storekit.SessionDigest(keep))

	return int(n), err
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

// DeleteExpired removes every session expired by the store's clock.
func (s *sessionStore) DeleteExpired(ctx context.Context) (int, error) {
	n, err := s.c.exec(ctx, "delete expired sessions", pgschema.SessionDeleteExpired, storekit.Time(s.c.clock.Now()))
	return int(n), err
}

// DeleteByExternalSession removes the sessions of issuer and provider session
// sessionID. An empty argument matches nothing.
func (s *sessionStore) DeleteByExternalSession(ctx context.Context, issuer, sessionID string) (int, error) {
	if !storekit.Storable(issuer, sessionID) {
		return 0, nil
	}

	n, err := s.c.exec(ctx, "delete provider session's sessions", pgschema.SessionDeleteByExternal,
		issuer, sessionID)

	return int(n), err
}

// DeleteByUserAndExternalIssuer removes user's sessions from issuer. An empty
// issuer matches nothing.
func (s *sessionStore) DeleteByUserAndExternalIssuer(
	ctx context.Context, user identity.UserID, issuer string,
) (int, error) {
	if !storekit.Storable(string(user), issuer) {
		return 0, nil
	}

	n, err := s.c.exec(ctx, "delete user's sessions from issuer", pgschema.SessionDeleteByUserIssuer,
		string(user), issuer)

	return int(n), err
}

// RecordActivity writes lastAccessed and idleExpires, and nothing else, to a
// session last accessed not later than olderThan and not superseded: one conditional
// UPDATE of those two columns. A session that is fresher or superseded is left
// unchanged and is not an error; one that is not stored is
// session.ErrSessionNotFound.
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
		return errors.New("sqlstore: supersede session: a supersession needs a successor")
	}
	if op.Successor.FamilyID.IsZero() {
		return errors.New("sqlstore: supersede session: a successor with no family cannot be stored")
	}
	if op.RetainUntil.Before(op.AcceptUntil) {
		return errors.New("sqlstore: supersede session: the retention deadline is before the end of the window")
	}
	args, err := s.insertArgs(name, op.Successor)
	if err != nil {
		return err
	}
	oldDigest := storekit.SessionDigest(op.Old)

	return s.atomically(ctx, name, func(q DBTX) error {
		if _, err := q.ExecContext(ctx, pgschema.SessionLockSupersession, oldDigest,
			storekit.OptionalDigestArg(op.ObservedSuccessor)); err != nil {
			return failed(name, err)
		}

		res, err := q.ExecContext(ctx, pgschema.SessionSupersedeOld, oldDigest,
			storekit.OptionalDigestArg(op.ObservedSuccessor), storekit.Time(op.Now), storekit.Time(op.AcceptUntil),
			storekit.SessionDigest(op.Successor.ID), storekit.Time(op.RetainUntil))
		if err != nil {
			return failed(name, err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return failed(name, err)
		} else if n == 0 {
			var cause int
			if err := q.QueryRowContext(ctx, pgschema.SessionSupersedeRefusal, oldDigest).Scan(&cause); err != nil {
				return failed(name, err)
			}
			return storekit.SupersedeRefusal(cause,
				errors.New("sqlstore: supersede session: a session with no family cannot be superseded"))
		}

		if len(op.ObservedSuccessor) > 0 {
			res, err := q.ExecContext(ctx, pgschema.SessionSupersedePrevious, op.ObservedSuccessor,
				storekit.Time(op.Now), op.RequireUnpresentedSuccessor, storekit.Time(op.RetainUntil))
			if err != nil {
				return failed(name, err)
			}
			if n, err := res.RowsAffected(); err != nil {
				return failed(name, err)
			} else if n == 0 {
				return session.ErrSuccessorAdvanced
			}
		}

		res, err = q.ExecContext(ctx, pgschema.SessionInsert, args...)
		if err != nil {
			return failed(name, err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return failed(name, err)
		} else if n == 0 {
			return errors.New("sqlstore: supersede session: the successor's identifier is already in use")
		}

		return nil
	})
}

// atomically runs fn as one unit on the handle ctx resolves to: under a
// savepoint inside a caller's transaction, otherwise in a transaction of the
// store's own on its *sql.DB. A refusal fn returns is returned as it is, so a
// sentinel stays bare.
func (s *sessionStore) atomically(ctx context.Context, op string, fn func(q DBTX) error) error {
	q, _, ambient, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}

	if ambient {
		return s.underSavepoint(ctx, q, op, fn)
	}

	tx, err := s.c.base.BeginTx(ctx, nil)
	if err != nil {
		return failed(op, err)
	}
	// Rolled back on every way out but a commit, a panic in fn included, so
	// the transaction and the row lock it holds never outlive the call. After
	// a commit the rollback does nothing.
	defer func() { _ = tx.Rollback() }()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return failed(op, err)
	}

	return nil
}

// underSavepoint runs fn on q, a caller's transaction, under a savepoint of
// its own. When fn fails, the savepoint is rolled back, which undoes fn's
// writes and clears the aborted state a failed statement leaves, so the
// caller's transaction stays usable with its earlier writes intact; the
// savepoint is released either way. When fn panics, the savepoint is rolled
// back and released before the panic goes on.
//
// The statements that close the savepoint run even when ctx is done, since
// leaving it open would leave the caller's transaction aborted, or commit
// fn's writes with the caller's.
func (s *sessionStore) underSavepoint(ctx context.Context, q DBTX, op string, fn func(q DBTX) error) error {
	name := "scrty_sessions_" + strconv.FormatUint(s.savepoints.Add(1), 10)

	if _, err := q.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
		return failed(op, err)
	}

	closeCtx := context.WithoutCancel(ctx)
	exec := func(stmt string) error {
		if _, err := q.ExecContext(closeCtx, stmt+name); err != nil {
			return failed(op, err)
		}
		return nil
	}

	// open is cleared by every normal return, which has already closed the
	// savepoint or tried to; only a panic leaves it set.
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
		return 0, errors.New("sqlstore: delete session family: the nil family names no family")
	}

	total := 0
	for {
		n, err := s.c.exec(ctx, "delete session family", pgschema.SessionDeleteFamily, family)
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
		total += int(n)
	}
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

var _ session.Store = (*sessionStore)(nil)
