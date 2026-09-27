package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
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
// Expiry is judged with the store's clock, on Load, on CountActiveByUser and
// on DeleteExpired. Stored times are UTC, truncated to the microsecond.
//
// It honours WithTxResolver, WithClock (default time.Now) and WithIDGenerator
// (default id.NewV7Generator), and refuses any other option.
//
// Limits, stated:
//   - PostgreSQL text and jsonb cannot hold a NUL byte or invalid UTF-8. A
//     session whose user reference, first factor, provider fields or data
//     hold either is refused with an error that names the field, never the
//     value, and nothing is written; the value is never altered.
//   - The enrolment-origin marker and the enrolment generation have no
//     columns yet. A Create or Save of a session carrying either is refused
//     with an error naming the field, and nothing is written, rather than
//     dropping the marker, which would release a session confined to MFA
//     enrolment.
func NewSessionStore(db *sql.DB, c seal.Cipher, opts ...Option) (session.Store, error) {
	cfg, err := newConfig(db, opts, optIDGenerator, optClock)
	if err != nil {
		return nil, err
	}
	if err := requireCipher(c); err != nil {
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

// sessionDigest is the key a session is stored and found under.
func sessionDigest(sessionID string) []byte {
	sum := sha256.Sum256([]byte(sessionID))
	return sum[:]
}

// sessionColumns returns the values of sess's columns from user_id to data,
// in the order SessionUpdate takes them, or the refusal of a session this
// store cannot hold without altering it.
func sessionColumns(op string, sess *session.Session) ([]any, error) {
	if !sess.EnrolmentOriginDeadline.IsZero() {
		return nil, fmt.Errorf("sqlstore: %s: the enrolment-origin marker is not supported by this store", op)
	}
	if !sess.EnrolmentGeneration.IsZero() {
		return nil, fmt.Errorf("sqlstore: %s: the enrolment generation is not supported by this store", op)
	}

	if err := checkStorable(op,
		textField{"user reference", string(sess.UserID)},
		textField{"first factor", string(sess.FirstFactor)},
		textField{"external provider", sess.ExternalProvider},
		textField{"external issuer", sess.ExternalIssuer},
		textField{"external session identifier", sess.ExternalSessionID},
		textField{"external ID token", sess.ExternalIDToken},
	); err != nil {
		return nil, err
	}
	// json.Marshal would replace invalid UTF-8 with U+FFFD, and jsonb refuses
	// an escaped NUL, so the data is judged before it is marshalled.
	for k, v := range sess.Data {
		if !storable(k, v) {
			return nil, errUnstorable(op, "session data")
		}
	}

	data := sess.Data
	if data == nil {
		data = map[string]string{}
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, failed(op, err)
	}

	return []any{
		string(sess.UserID), ts(sess.CreatedAt), ts(sess.LastAccessedAt), ts(sess.IdleExpiresAt),
		ts(sess.AbsoluteExpiresAt), string(sess.FirstFactor), int64(sess.MFA), nullTs(sess.MFASatisfiedAt),
		sess.PasswordChangePending, sess.ExternalProvider, sess.ExternalIssuer, sess.ExternalSessionID,
		sess.ExternalIDToken, string(encoded),
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

	n, err := s.c.exec(ctx, op, pgschema.SessionInsert, append([]any{rowID, sessionDigest(sess.ID)}, cols...)...)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("sqlstore: create session: the identifier is already in use")
	}

	return nil
}

// Save replaces the stored session whole, and never inserts.
func (s *sessionStore) Save(ctx context.Context, sess *session.Session) error {
	const op = "save session"

	cols, err := sessionColumns(op, sess)
	if err != nil {
		return err
	}
	n, err := s.c.exec(ctx, op, pgschema.SessionUpdate, append([]any{sessionDigest(sess.ID)}, cols...)...)
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
		encoded       []byte
		created, last time.Time
		idle, abs     time.Time
	)
	err := s.c.queryRow(ctx, op, pgschema.SessionSelect, []any{sessionDigest(sessionID)},
		&user, &created, &last, &idle, &abs, &firstFactor, &mfaState, &mfaSatisfied,
		&sess.PasswordChangePending, &sess.ExternalProvider, &sess.ExternalIssuer, &sess.ExternalSessionID,
		&sess.ExternalIDToken, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, session.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	now := s.c.now()
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
	sess.MFASatisfiedAt = fromNull(mfaSatisfied)
	sess.CreatedAt, sess.LastAccessedAt = created.UTC(), last.UTC()
	sess.IdleExpiresAt, sess.AbsoluteExpiresAt = idle.UTC(), abs.UTC()

	return &sess, nil
}

// Delete removes the session with this identifier; one not there is not an
// error.
func (s *sessionStore) Delete(ctx context.Context, sessionID string) error {
	_, err := s.c.exec(ctx, "delete session", pgschema.SessionDelete, sessionDigest(sessionID))
	return err
}

// DeleteByUser removes every session of user, expired ones included. A user
// reference PostgreSQL text cannot hold matches nothing.
func (s *sessionStore) DeleteByUser(ctx context.Context, user identity.UserID) error {
	if !storable(string(user)) {
		return nil
	}

	_, err := s.c.exec(ctx, "delete user's sessions", pgschema.SessionDeleteByUser, string(user))

	return err
}

// CountActiveByUser counts user's sessions unexpired by the store's clock.
func (s *sessionStore) CountActiveByUser(ctx context.Context, user identity.UserID) (int, error) {
	if !storable(string(user)) {
		return 0, nil
	}

	return s.c.count(ctx, "count user's active sessions", pgschema.SessionCountActive,
		string(user), ts(s.c.now()))
}

// DeleteExpired removes every session expired by the store's clock.
func (s *sessionStore) DeleteExpired(ctx context.Context) (int, error) {
	n, err := s.c.exec(ctx, "delete expired sessions", pgschema.SessionDeleteExpired, ts(s.c.now()))
	return int(n), err
}

// DeleteByExternalSession removes the sessions of issuer and provider session
// sessionID. An empty argument matches nothing.
func (s *sessionStore) DeleteByExternalSession(ctx context.Context, issuer, sessionID string) (int, error) {
	if !storable(issuer, sessionID) {
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
	if !storable(string(user), issuer) {
		return 0, nil
	}

	n, err := s.c.exec(ctx, "delete user's sessions from issuer", pgschema.SessionDeleteByUserIssuer,
		string(user), issuer)

	return int(n), err
}

var _ session.Store = (*sessionStore)(nil)
