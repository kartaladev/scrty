package pgx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
)

// NewSessionStore returns a durable session store on pool, keeping sessions in
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
// The enrolment-origin marker and the enrolment generation are kept in
// columns of their own, NULL when the session carries neither, so a session
// confined to MFA enrolment stays confined when it is loaded again.
// RecoveredAt, the time an account recovery produced the session, is kept the
// same way: NULL when the session was never recovered, and read back as the
// zero time.
//
// Expiry is judged with the store's clock, on Load, on CountActiveByUser and
// on DeleteExpired. Stored times are UTC, truncated to the microsecond.
//
// It honours WithTxResolver, WithClock (default clock.System()) and
// WithIDGenerator (default id.NewV7Generator), and refuses any other option.
//
// Limits, stated:
//   - PostgreSQL text and jsonb cannot hold a NUL byte or invalid UTF-8. A
//     session whose user reference, first factor, provider fields or data
//     hold either is refused with an error that names the field, never the
//     value, and nothing is written; the value is never altered.
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
type sessionStore struct{ c *config }

// sessionColumns returns the values of sess's columns from user_id to
// recovered_at, in the order SessionUpdate takes them, or the refusal
// of a session this store cannot hold without altering it.
func sessionColumns(op string, sess *session.Session) ([]any, error) {
	if err := storekit.CheckSession(sess); err != nil {
		return nil, failed(op, err)
	}

	// The marshalled text is sent as a string, which pgx passes to jsonb as is
	// rather than marshalling it again.
	data := sess.Data
	if data == nil {
		data = map[string]string{}
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, failed(op, err)
	}

	return []any{
		string(sess.UserID), storekit.Time(sess.CreatedAt), storekit.Time(sess.LastAccessedAt),
		storekit.Time(sess.IdleExpiresAt), storekit.Time(sess.AbsoluteExpiresAt), string(sess.FirstFactor),
		int64(sess.MFA), nullTs(sess.MFASatisfiedAt),
		sess.PasswordChangePending, sess.ExternalProvider, sess.ExternalIssuer, sess.ExternalSessionID,
		sess.ExternalIDToken, string(encoded),
		nullTs(sess.EnrolmentOriginDeadline), nullID(sess.EnrolmentGeneration),
		nullTs(sess.RecoveredAt),
	}, nil
}

// Create inserts sess, refusing an identifier already stored.
func (s *sessionStore) Create(ctx context.Context, sess *session.Session) error {
	const op = "create session"

	cols, err := sessionColumns(op, sess)
	if err != nil {
		return err
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return failed(op, err)
	}

	// Only the insert writes the marker: SessionUpdate has no column for it.
	args := append([]any{uuidArg(rowID), storekit.SessionDigest(sess.ID)}, cols...)
	n, err := s.c.exec(ctx, op, pgschema.SessionInsert, append(args, sess.MFAAtFirstFactor)...)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("pgx: create session: the identifier is already in use")
	}

	return nil
}

// Save replaces the stored session whole, except for MFAAtFirstFactor, and
// never inserts.
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
		mfaSatisfied  pgtype.Timestamptz
		encoded       []byte
		origin        pgtype.Timestamptz
		generation    pgtype.UUID
		recovered     pgtype.Timestamptz
		created, last time.Time
		idle, abs     time.Time
	)
	err := s.c.queryRow(ctx, op, pgschema.SessionSelect, []any{storekit.SessionDigest(sessionID)},
		&user, &created, &last, &idle, &abs, &firstFactor, &mfaState, &mfaSatisfied,
		&sess.PasswordChangePending, &sess.ExternalProvider, &sess.ExternalIssuer, &sess.ExternalSessionID,
		&sess.ExternalIDToken, &encoded, &origin, &generation, &recovered, &sess.MFAAtFirstFactor)
	if errors.Is(err, pgxv5.ErrNoRows) {
		return nil, session.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	now := s.c.clock.Now()
	if !now.Before(idle) || !now.Before(abs) {
		return nil, session.ErrSessionExpired
	}

	if err := json.Unmarshal(encoded, &sess.Data); err != nil {
		return nil, failed(op, err)
	}
	if sess.Data == nil {
		sess.Data = map[string]string{}
	}
	sess.UserID = identity.UserID(user)
	sess.FirstFactor = factor.Kind(firstFactor)
	sess.MFA = session.MFAState(mfaState)
	if sess.MFASatisfiedAt, err = fromNull(mfaSatisfied); err != nil {
		return nil, failed(op, err)
	}
	if sess.EnrolmentOriginDeadline, err = fromNull(origin); err != nil {
		return nil, failed(op, err)
	}
	sess.EnrolmentGeneration = nullableID(generation)
	if sess.RecoveredAt, err = fromNull(recovered); err != nil {
		return nil, failed(op, err)
	}
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

// CountActiveByUser counts user's sessions unexpired by the store's clock.
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

var _ session.Store = (*sessionStore)(nil)
