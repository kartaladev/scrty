package gorm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	gormdb "gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/storekit"
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
type sessionStore struct{ c *config }

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
		RecoveredAt: nullTs(sess.RecoveredAt),
		// Written on Create only: Save omits the column.
		MFAAtFirstFactor: sess.MFAAtFirstFactor,
	}, nil
}

// Create inserts sess, refusing an identifier already stored: one INSERT …
// ON CONFLICT (id_digest) DO NOTHING, whose zero rows affected is the refusal.
func (s *sessionStore) Create(ctx context.Context, sess *session.Session) error {
	const op = "create session"

	row, err := sessionRecord(op, sess)
	if err != nil {
		return err
	}
	if row.ID, err = s.c.ids.NewID(); err != nil {
		return failed(op, err)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	res := q.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "id_digest"}}, DoNothing: true}).Create(&row)
	if res.Error != nil {
		return failed(op, res.Error)
	}
	if res.RowsAffected == 0 {
		return errors.New("gorm: create session: the identifier is already in use")
	}

	return nil
}

// Save replaces the stored session whole, and never inserts: one UPDATE of
// every column but the keys and the marker (MFAAtFirstFactor, written on
// Create only), whose zero rows affected is
// session.ErrSessionNotFound.
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
	// Select("*") makes gorm write every column, zero values included:
	// without it Updates skips false, 0, "" and nil, so a save clearing a
	// field would silently keep the stored value. The keys are left out: id
	// is minted once on Create, and id_digest is what the row is found by.
	res := q.Model(&sessionRow{}).Where("id_digest = ?", row.IDDigest).
		Select("*").Omit("id", "id_digest", "mfa_at_first_factor").Updates(&row)
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
	}
	if row.EnrolmentGeneration != nil {
		sess.EnrolmentGeneration = *row.EnrolmentGeneration
	}
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

// CountActiveByUser counts user's sessions unexpired by the store's clock.
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
		Where("user_id = ? AND idle_expires_at > ? AND absolute_expires_at > ?", string(user), now, now).
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

var _ session.Store = (*sessionStore)(nil)
