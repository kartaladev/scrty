package pgxstore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// The stores of an OpenID Provider, each implementing the port package oidcprovider
// defines and behaving as its in-memory default does. Together with NewGrantStore,
// NewClientStore and NewRefreshTokenStore they run against the tables the security-state
// migration set creates, and hand a provider what its With*Store options take.
//
// Limits, stated for all of them: PostgreSQL text and jsonb cannot hold a NUL byte or
// invalid UTF-8. The provider refuses such text first. A store handed one anyway
// refuses a write with an error naming the field and never the value, and writes
// nothing; a load by one is the port's not-found. Stored times are UTC, truncated to the
// microsecond. No error's text carries a digest, a secret or a credential.

// wroteOrHeld is the refusal of a record already held, when a conditional insert wrote
// no row. The refusal is fixed text, so it can carry no digest.
func wroteOrHeld(op string, n int64) error {
	if n == 0 {
		return failed(op, storekit.ErrIdentifierInUse)
	}

	return nil
}

// insertRecord runs an insert whose conflict is the refusal of a record already held.
func (c *config) insertRecord(ctx context.Context, op, statement string, args []any, argsErr error) error {
	if argsErr != nil {
		return failed(op, argsErr)
	}
	n, err := c.exec(ctx, op, statement, args...)
	if err != nil {
		return err
	}

	return wroteOrHeld(op, n)
}

// deleteBefore runs a delete judged by before alone.
func (c *config) deleteBefore(ctx context.Context, op, statement string, before time.Time) (int, error) {
	n, err := c.exec(ctx, op, statement, storekit.Time(before))

	return int(n), err
}

// scannable is a row type of package pgschema: what a row scans into, and the record it
// reads back as.
type scannable[R any] interface {
	Dest() []any
	Record() (*R, error)
}

// loadRecord reads one record, returning absent when there is no row.
func loadRecord[R any, S scannable[R]](
	ctx context.Context, c *config, op string, absent error, row S, query string, args ...any,
) (*R, error) {
	err := c.queryRow(ctx, op, query, args, row.Dest()...)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, absent
	}
	if err != nil {
		return nil, err
	}
	rec, err := row.Record()
	if err != nil {
		return nil, failed(op, err)
	}

	return rec, nil
}

// queryIDs reads a statement's one uuid column.
func (c *config) queryIDs(ctx context.Context, op, query string, args ...any) ([]id.ID, error) {
	var out []id.ID
	err := c.query(ctx, op, query, args, func(rows pgx.Rows) error {
		var u pgtype.UUID
		if err := rows.Scan(&u); err != nil {
			return err
		}
		v, err := scanID(u)
		if err != nil {
			return err
		}
		out = append(out, v)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// PendingRequestStore keeps parked requests in the op_pending_requests table. It
// implements oidcprovider.PendingRequestStore, and is safe for concurrent use. A stage
// is spent by one conditional update, so of callers racing on a record, on this process
// or on another replica, exactly one moves it.
type PendingRequestStore struct{ c *config }

// NewPendingRequestStore returns a durable store on pool. It honours WithTxResolver and
// refuses any other option: a record arrives with its own identifier, and expiry is
// judged by the time a caller gives.
func NewPendingRequestStore(pool *pgxpool.Pool, opts ...Option) (*PendingRequestStore, error) {
	c, err := newConfig(pool, opts)
	if err != nil {
		return nil, err
	}

	return &PendingRequestStore{c: c}, nil
}

// Create implements oidcprovider.PendingRequestStore.
func (s *PendingRequestStore) Create(ctx context.Context, request *oidcprovider.PendingRequest) error {
	const op = "create pending request"

	if err := storekit.CheckID(request.ID, "pending request"); err != nil {
		return failed(op, err)
	}
	args, err := pgschema.PendingRequestArgs(request)

	return s.c.insertRecord(ctx, op, pgschema.PendingRequestInsert, args, err)
}

// Load implements oidcprovider.PendingRequestStore.
func (s *PendingRequestStore) Load(ctx context.Context, handleDigest []byte) (*oidcprovider.PendingRequest, error) {
	return loadRecord[oidcprovider.PendingRequest](ctx, s.c, "load pending request", oidcprovider.ErrNotFound,
		&pgschema.PendingRequestRow{}, pgschema.PendingRequestSelect, storekit.OrEmpty(handleDigest))
}

// Advance implements oidcprovider.PendingRequestStore. It judges the move here, and
// decides the stage with one UPDATE conditional on it.
func (s *PendingRequestStore) Advance(
	ctx context.Context, handleDigest []byte, from, to oidcprovider.Stage, signIn *oidcprovider.SignIn,
) error {
	const op = "advance pending request"

	encoded, err := pgschema.EncodeSignIn(signIn)
	if err != nil {
		return failed(op, err)
	}
	if !pgschema.StageMoveAllowed(from, to) {
		return oidcprovider.ErrNotFound
	}

	return s.c.execOrRefuse(ctx, op, oidcprovider.ErrNotFound, pgschema.PendingRequestAdvance,
		storekit.OrEmpty(handleDigest), int16(from), int16(to), encoded)
}

// DeleteExpired implements oidcprovider.PendingRequestStore.
func (s *PendingRequestStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	return s.c.deleteBefore(ctx, "delete expired pending requests", pgschema.PendingRequestDeleteExpired, before)
}

// CodeStore keeps the request data of authorization codes in the
// op_authorization_codes table. It implements oidcprovider.CodeStore, and is safe for
// concurrent use. A code's secret and single spend live in the one-time token store, so
// this table holds no credential, and every row is a held code.
type CodeStore struct{ c *config }

// NewCodeStore returns a durable store on pool. It honours WithTxResolver and refuses any
// other option: a record arrives with its own identifier, and expiry is judged by the
// time a caller gives.
func NewCodeStore(pool *pgxpool.Pool, opts ...Option) (*CodeStore, error) {
	c, err := newConfig(pool, opts)
	if err != nil {
		return nil, err
	}

	return &CodeStore{c: c}, nil
}

// Create implements oidcprovider.CodeStore.
func (s *CodeStore) Create(ctx context.Context, record *oidcprovider.CodeRecord) error {
	const op = "create code record"

	if err := storekit.CheckID(record.TokenID, "code record"); err != nil {
		return failed(op, err)
	}
	args, err := pgschema.CodeArgs(record)

	return s.c.insertRecord(ctx, op, pgschema.CodeInsert, args, err)
}

// Load implements oidcprovider.CodeStore.
func (s *CodeStore) Load(ctx context.Context, tokenID id.ID) (*oidcprovider.CodeRecord, error) {
	return loadRecord[oidcprovider.CodeRecord](ctx, s.c, "load code record", oidcprovider.ErrNotFound,
		&pgschema.CodeRow{}, pgschema.CodeSelect, tokenID.String())
}

// DeleteExpired implements oidcprovider.CodeStore.
func (s *CodeStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	return s.c.deleteBefore(ctx, "delete expired code records", pgschema.CodeDeleteExpired, before)
}

// UnspentBySignIn implements oidcprovider.UnspentCodes.
func (s *CodeStore) UnspentBySignIn(ctx context.Context, sel oidcprovider.SignInSelector, includeOffline bool) ([]id.ID, error) {
	const op = "list a sign-in's outstanding codes"

	if err := pgschema.CheckSelector(sel); err != nil {
		return nil, failed(op, err)
	}
	statement, args := pgschema.CodeUnspentBySignIn(sel, includeOffline)

	return s.c.queryIDs(ctx, op, statement, args...)
}

// UnspentByClient implements oidcprovider.UnspentCodes.
func (s *CodeStore) UnspentByClient(ctx context.Context, user identity.UserID, clientID string) ([]id.ID, error) {
	const op = "list a client's outstanding codes"

	if err := pgschema.CheckConsentKey(user, clientID); err != nil {
		return nil, failed(op, err)
	}

	return s.c.queryIDs(ctx, op, pgschema.CodeUnspentByClient, string(user), clientID)
}

// ConsentStore keeps consents in the op_consents table, one per user and client. It
// implements oidcprovider.ConsentStore, and is safe for concurrent use. Give is one
// statement, so scopes given at once all accumulate.
type ConsentStore struct{ c *config }

// NewConsentStore returns a durable store on pool. It honours WithTxResolver and
// WithIDGenerator (default id.NewV7Generator, for the rows' primary keys), and refuses
// any other option.
func NewConsentStore(pool *pgxpool.Pool, opts ...Option) (*ConsentStore, error) {
	c, err := newConfig(pool, opts, optIDGenerator)
	if err != nil {
		return nil, err
	}

	return &ConsentStore{c: c}, nil
}

// Give implements oidcprovider.ConsentStore.
func (s *ConsentStore) Give(
	ctx context.Context, user identity.UserID, clientID string, scopes []string, offline bool, at time.Time,
) error {
	const op = "give consent"

	rowID, err := s.c.ids.NewID()
	if err != nil {
		return failed(op, err)
	}
	args, err := pgschema.ConsentGiveArgs(rowID, user, clientID, scopes, offline, at)
	if err != nil {
		return failed(op, err)
	}
	_, err = s.c.exec(ctx, op, pgschema.ConsentGive, args...)

	return err
}

// Load implements oidcprovider.ConsentStore.
func (s *ConsentStore) Load(ctx context.Context, user identity.UserID, clientID string) (*oidcprovider.Consent, error) {
	if !pgschema.Storable(string(user), clientID) {
		return nil, oidcprovider.ErrNotFound
	}

	return loadRecord[oidcprovider.Consent](ctx, s.c, "load consent", oidcprovider.ErrNotFound,
		&pgschema.ConsentRow{}, pgschema.ConsentSelect, string(user), clientID)
}

// Revoke implements oidcprovider.ConsentStore.
func (s *ConsentStore) Revoke(ctx context.Context, user identity.UserID, clientID string) (bool, error) {
	const op = "revoke consent"

	if err := pgschema.CheckConsentKey(user, clientID); err != nil {
		return false, failed(op, err)
	}
	n, err := s.c.exec(ctx, op, pgschema.ConsentDelete, string(user), clientID)

	return n > 0, err
}

// ListByUser implements oidcprovider.ConsentStore.
func (s *ConsentStore) ListByUser(ctx context.Context, user identity.UserID) ([]oidcprovider.Consent, error) {
	const op = "list user's consents"

	if err := pgschema.CheckText("user reference", string(user)); err != nil {
		return nil, failed(op, err)
	}
	var out []oidcprovider.Consent
	err := s.c.query(ctx, op, pgschema.ConsentListByUser, []any{string(user)}, func(rows pgx.Rows) error {
		var row pgschema.ConsentRow
		if err := rows.Scan(row.Dest()...); err != nil {
			return err
		}
		rec, err := row.Record()
		if err != nil {
			return err
		}
		out = append(out, *rec)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// AccessTokenStore keeps opaque access tokens in the op_access_tokens table, each
// secret only as its digest. It implements oidcprovider.AccessTokenStore, and is safe
// for concurrent use.
type AccessTokenStore struct{ c *config }

// NewAccessTokenStore returns a durable store on pool. It honours WithTxResolver and
// refuses any other option: a record arrives with its own identifier, and expiry is
// judged by the time a caller gives.
func NewAccessTokenStore(pool *pgxpool.Pool, opts ...Option) (*AccessTokenStore, error) {
	c, err := newConfig(pool, opts)
	if err != nil {
		return nil, err
	}

	return &AccessTokenStore{c: c}, nil
}

// Create implements oidcprovider.AccessTokenStore.
func (s *AccessTokenStore) Create(ctx context.Context, record *oidcprovider.AccessTokenRecord) error {
	const op = "create access token"

	if err := storekit.CheckID(record.ID, "access token"); err != nil {
		return failed(op, err)
	}
	args, err := pgschema.AccessTokenArgs(record)

	return s.c.insertRecord(ctx, op, pgschema.AccessTokenInsert, args, err)
}

// Load implements oidcprovider.AccessTokenStore.
func (s *AccessTokenStore) Load(ctx context.Context, tokenID id.ID) (*oidcprovider.AccessTokenRecord, error) {
	return loadRecord[oidcprovider.AccessTokenRecord](ctx, s.c, "load access token", oidcprovider.ErrNotFound,
		&pgschema.AccessTokenRow{}, pgschema.AccessTokenSelect, tokenID.String())
}

// Revoke implements oidcprovider.AccessTokenStore.
func (s *AccessTokenStore) Revoke(ctx context.Context, tokenID id.ID) error {
	return s.c.execOrRefuse(ctx, "revoke access token", oidcprovider.ErrNotFound, pgschema.AccessTokenRevoke, tokenID.String())
}

// DeleteExpired implements oidcprovider.AccessTokenStore.
func (s *AccessTokenStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	return s.c.deleteBefore(ctx, "delete expired access tokens", pgschema.AccessTokenDeleteExpired, before)
}

// AssertionIDStore keeps the client-assertion identifiers already accepted, in the
// op_client_assertions table. It implements oidcprovider.AssertionIDStore, and is safe
// for concurrent use. Record is one insert the pair's uniqueness decides, so of callers
// racing, on this process or on another replica, exactly one is told the pair is new.
type AssertionIDStore struct{ c *config }

// NewAssertionIDStore returns a durable store on pool. It honours WithTxResolver and
// WithIDGenerator (default id.NewV7Generator, for the rows' primary keys), and refuses
// any other option.
func NewAssertionIDStore(pool *pgxpool.Pool, opts ...Option) (*AssertionIDStore, error) {
	c, err := newConfig(pool, opts, optIDGenerator)
	if err != nil {
		return nil, err
	}

	return &AssertionIDStore{c: c}, nil
}

// Record implements oidcprovider.AssertionIDStore.
func (s *AssertionIDStore) Record(ctx context.Context, clientID, jti string, until time.Time) (bool, error) {
	const op = "record assertion identifier"

	rowID, err := s.c.ids.NewID()
	if err != nil {
		return false, failed(op, err)
	}
	args, err := pgschema.AssertionIDArgs(rowID, clientID, jti, until)
	if err != nil {
		return false, failed(op, err)
	}
	n, err := s.c.exec(ctx, op, pgschema.AssertionIDRecord, args...)

	return n == 1, err
}

// DeleteExpired implements oidcprovider.AssertionIDStore.
func (s *AssertionIDStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	return s.c.deleteBefore(ctx, "delete expired assertion identifiers", pgschema.AssertionIDDeleteExpired, before)
}

// BrowserSessionStore keeps browser sessions in the op_browser_sessions table, each
// cookie's secret only as its digest. It implements oidcprovider.BrowserSessionStore,
// and is safe for concurrent use. Touch is one conditional update that only extends, so
// a slower request cannot undo a later one.
type BrowserSessionStore struct{ c *config }

// NewBrowserSessionStore returns a durable store on pool. It honours WithTxResolver and
// WithIDGenerator (default id.NewV7Generator, for the rows' primary keys), and refuses
// any other option: a load is judged by the time its caller gives.
func NewBrowserSessionStore(pool *pgxpool.Pool, opts ...Option) (*BrowserSessionStore, error) {
	c, err := newConfig(pool, opts, optIDGenerator)
	if err != nil {
		return nil, err
	}

	return &BrowserSessionStore{c: c}, nil
}

// Put implements oidcprovider.BrowserSessionStore.
func (s *BrowserSessionStore) Put(ctx context.Context, rec *oidcprovider.BrowserSession) error {
	const op = "put browser session"

	if err := pgschema.CheckBrowserSession(rec); err != nil {
		return failed(op, err)
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return failed(op, err)
	}
	args, err := pgschema.BrowserSessionArgs(rowID, rec)

	return s.c.insertRecord(ctx, op, pgschema.BrowserSessionInsert, args, err)
}

// Load implements oidcprovider.BrowserSessionStore.
func (s *BrowserSessionStore) Load(ctx context.Context, digest []byte, now time.Time) (*oidcprovider.BrowserSession, error) {
	const op = "load browser session"

	if err := pgschema.RequireTime("BrowserSessionStore.Load", now); err != nil {
		return nil, failed(op, err)
	}

	return loadRecord[oidcprovider.BrowserSession](ctx, s.c, op, oidcprovider.ErrNotFound,
		&pgschema.BrowserSessionRow{}, pgschema.BrowserSessionSelect, storekit.OrEmpty(digest), storekit.Time(now))
}

// Touch implements oidcprovider.BrowserSessionStore.
func (s *BrowserSessionStore) Touch(ctx context.Context, digest []byte, idleUntil time.Time) error {
	const op = "touch browser session"

	if err := pgschema.RequireTime("BrowserSessionStore.Touch", idleUntil); err != nil {
		return failed(op, err)
	}

	return s.c.execOrRefuse(ctx, op, oidcprovider.ErrNotFound, pgschema.BrowserSessionTouch,
		storekit.OrEmpty(digest), storekit.Time(idleUntil))
}

// Delete implements oidcprovider.BrowserSessionStore.
func (s *BrowserSessionStore) Delete(ctx context.Context, digest []byte) error {
	_, err := s.c.exec(ctx, "delete browser session", pgschema.BrowserSessionDelete, storekit.OrEmpty(digest))

	return err
}

// DeleteBySignIn implements oidcprovider.BrowserSessionStore.
func (s *BrowserSessionStore) DeleteBySignIn(ctx context.Context, sel oidcprovider.SignInSelector) (int, error) {
	const op = "delete a sign-in's browser sessions"

	if err := pgschema.CheckSelector(sel); err != nil {
		return 0, failed(op, err)
	}
	statement, args := pgschema.BrowserSessionDeleteBySignIn(sel)
	n, err := s.c.exec(ctx, op, statement, args...)

	return int(n), err
}

// DeleteExpired implements oidcprovider.BrowserSessionStore.
func (s *BrowserSessionStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	return s.c.deleteBefore(ctx, "delete expired browser sessions", pgschema.BrowserSessionDeleteExpired, before)
}

// ClientStore keeps registered clients in the op_clients table, each secret only as
// its digest. It implements oidcprovider.ClientStore, and behaves as MemoryRegistry
// does: every write is validated as that registry validates it, through the registry
// itself, so the two cannot disagree. It is safe for concurrent use.
type ClientStore struct{ c *config }

// NewClientStore returns a durable store on pool. It honours WithTxResolver and
// WithIDGenerator (default id.NewV7Generator, for the rows' primary keys), and refuses
// any other option. An algorithm the provider's keys cannot produce is reported when
// the client is next read, as an unknown client, as with MemoryRegistry.
func NewClientStore(pool *pgxpool.Pool, opts ...Option) (*ClientStore, error) {
	c, err := newConfig(pool, opts, optIDGenerator)
	if err != nil {
		return nil, err
	}

	return &ClientStore{c: c}, nil
}

// Client implements oidcprovider.ClientRegistry. An identifier no client could hold is
// oidcprovider.ErrClientNotFound.
func (s *ClientStore) Client(ctx context.Context, clientID string) (*oidcprovider.RegisteredClient, error) {
	if !pgschema.Storable(clientID) {
		return nil, oidcprovider.ErrClientNotFound
	}

	return loadRecord[oidcprovider.RegisteredClient](ctx, s.c, "load client", oidcprovider.ErrClientNotFound,
		&pgschema.ClientRow{}, pgschema.ClientSelect, clientID)
}

// Put implements oidcprovider.ClientStore. A supplied Secret replaces the digests held,
// and no Secret keeps them, so changing a setting does not sign the client out.
func (s *ClientStore) Put(ctx context.Context, client oidcprovider.Client) error {
	const op = "put client"

	validated, err := oidcprovider.NewMemoryRegistry([]oidcprovider.Client{client})
	if err != nil {
		return failed(op, err)
	}
	rc, err := validated.Client(ctx, client.ID)
	if err != nil {
		return failed(op, err)
	}

	return s.upsert(ctx, op, rc, len(rc.Secrets) == 0 && pgschema.ClientUsesSecret(rc.AuthMethod))
}

// PutRegistered adds or replaces a client with exactly the secrets given, at most two,
// which is how a rotation is expressed: read the client, give the old secret an expiry,
// add the new one built by oidcprovider.NewClientSecret. A failure leaves what was held
// unchanged.
func (s *ClientStore) PutRegistered(ctx context.Context, client oidcprovider.RegisteredClient) error {
	const op = "put registered client"

	validated, err := oidcprovider.NewMemoryRegistry(nil)
	if err != nil {
		return failed(op, err)
	}
	if err := validated.PutRegistered(ctx, client); err != nil {
		return failed(op, err)
	}
	rc, err := validated.Client(ctx, client.ID)
	if err != nil {
		return failed(op, err)
	}

	return s.upsert(ctx, op, rc, false)
}

func (s *ClientStore) upsert(ctx context.Context, op string, rc *oidcprovider.RegisteredClient, keepHeld bool) error {
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return failed(op, err)
	}
	args, err := pgschema.ClientArgs(rowID, rc, keepHeld)
	if err != nil {
		return failed(op, err)
	}
	_, err = s.c.exec(ctx, op, pgschema.ClientUpsert, args...)

	return err
}

// Delete implements oidcprovider.ClientStore.
func (s *ClientStore) Delete(ctx context.Context, clientID string) error {
	if !pgschema.Storable(clientID) {
		return oidcprovider.ErrClientNotFound
	}

	return s.c.execOrRefuse(ctx, "delete client", oidcprovider.ErrClientNotFound, pgschema.ClientDelete, clientID)
}

// GenerateSecret implements oidcprovider.ClientStore: a new secret of 256 bits, from
// MemoryRegistry's own generator, replacing every secret held. The secret is returned
// this once, and only its digest is written. A client that uses no secret fails with
// oidcprovider.ErrConfig, and an unknown one with oidcprovider.ErrClientNotFound.
func (s *ClientStore) GenerateSecret(ctx context.Context, clientID string) (string, error) {
	const op = "generate client secret"

	rc, err := s.Client(ctx, clientID)
	if err != nil {
		return "", err
	}
	generator, err := oidcprovider.NewMemoryRegistry(nil)
	if err != nil {
		return "", failed(op, err)
	}
	if err := generator.PutRegistered(ctx, *rc); err != nil {
		return "", failed(op, err)
	}
	secret, err := generator.GenerateSecret(ctx, clientID)
	if err != nil {
		return "", failed(op, err)
	}
	generated, err := generator.Client(ctx, clientID)
	if err != nil {
		return "", failed(op, err)
	}
	encoded, err := pgschema.EncodeClientSecrets(generated.Secrets)
	if err != nil {
		return "", failed(op, err)
	}
	if err := s.c.execOrRefuse(ctx, op, oidcprovider.ErrClientNotFound, pgschema.ClientSetSecrets,
		clientID, string(rc.AuthMethod), encoded); err != nil {
		return "", err
	}

	return secret, nil
}

var (
	_ oidcprovider.PendingRequestStore = (*PendingRequestStore)(nil)
	_ oidcprovider.CodeStore           = (*CodeStore)(nil)
	_ oidcprovider.ConsentStore        = (*ConsentStore)(nil)
	_ oidcprovider.AccessTokenStore    = (*AccessTokenStore)(nil)
	_ oidcprovider.AssertionIDStore    = (*AssertionIDStore)(nil)
	_ oidcprovider.BrowserSessionStore = (*BrowserSessionStore)(nil)
	_ oidcprovider.ClientStore         = (*ClientStore)(nil)
)
