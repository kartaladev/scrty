package pgxstore

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// GrantStore keeps grants, and the revocations recorded before their grant was stored,
// in the op_grants table. It implements oidcprovider.GrantStore, and is safe for
// concurrent use.
//
// Create and Revoke are one statement each, so a revocation racing the create of its
// grant is kept whichever goes first. EndSignIns, RevokeByUser and RevokeByUserAndClient
// read the outstanding codes first, holding nothing, then run the two steps of a
// pgschema.GrantBulkWrite as one unit: a transaction of the store's own at READ COMMITTED,
// or a savepoint inside a caller's transaction, so a failure there leaves that transaction
// usable with its earlier work. Those steps and DeleteExpired take their rows in one order,
// so they wait for each other instead of deadlocking.
//
// Limits inside a caller's transaction: at a stronger isolation, a lost race surfaces as
// the driver's serialization failure, which the caller retries. The order holds within one
// call, so a transaction that has already written a grant of a later family holds it out of
// order, and can deadlock with another call; that surfaces as the driver's deadlock error,
// and the caller retries that too.
type GrantStore struct {
	c     *config
	codes pgschema.CodeSource

	// savepoints numbers the savepoints this store opens inside a caller's
	// transaction, so each is named apart from any other open on it.
	savepoints atomic.Uint64
}

// NewGrantStore returns a durable store on pool. It honours WithTxResolver and refuses any
// other option: a grant's family is its key, and every time it judges by is a caller's.
//
// The store must be joined to the provider's code store through UseCodes, which
// oidcprovider.New does; until then it refuses every operation that could miss a code.
func NewGrantStore(pool *pgxpool.Pool, opts ...Option) (*GrantStore, error) {
	c, err := newConfig(pool, opts)
	if err != nil {
		return nil, err
	}

	return &GrantStore{c: c}, nil
}

// UseCodes implements oidcprovider.GrantStore.
func (s *GrantStore) UseCodes(codes oidcprovider.UnspentCodes) error { return s.codes.Join(codes) }

// Create implements oidcprovider.GrantStore. A grant already stored is refused, and
// only a revocation recorded first can be filled in, keeping the revocation and any
// sign-in-ended mark. A grant's zero family is refused, as the record no revocation or
// token could name.
func (s *GrantStore) Create(ctx context.Context, g *oidcprovider.Grant) error {
	const op = "create grant"

	if err := storekit.CheckID(g.Family, "grant"); err != nil {
		return failed(op, err)
	}
	args, err := pgschema.GrantArgs(g)

	return s.c.insertRecord(ctx, op, pgschema.GrantInsert, args, err)
}

// Load implements oidcprovider.GrantStore.
func (s *GrantStore) Load(ctx context.Context, family id.ID) (*oidcprovider.Grant, error) {
	return loadRecord[oidcprovider.Grant](ctx, s.c, "load grant", oidcprovider.ErrNotFound,
		&pgschema.GrantRow{}, pgschema.GrantSelect, family.String())
}

// Revoke implements oidcprovider.GrantStore.
func (s *GrantStore) Revoke(ctx context.Context, family id.ID, cause oidcprovider.RevocationCause, at time.Time) (bool, error) {
	const op = "revoke grant"

	if err := pgschema.RequireTime("GrantStore.Revoke", at); err != nil {
		return false, failed(op, err)
	}
	if err := pgschema.CheckText("revocation cause", string(cause)); err != nil {
		return false, failed(op, err)
	}
	n, err := s.c.exec(ctx, op, pgschema.GrantRevoke, family.String(), storekit.Time(at), string(cause))

	return n > 0, err
}

// RevokeByUser implements oidcprovider.GrantStore.
func (s *GrantStore) RevokeByUser(
	ctx context.Context, user identity.UserID, cause oidcprovider.RevocationCause, at time.Time,
) ([]oidcprovider.Grant, error) {
	const op = "revoke user's grants"

	if user == "" {
		return nil, failed(op, fmt.Errorf("%w: GrantStore.RevokeByUser: the user must not be empty", oidcprovider.ErrConfig))
	}
	if err := checkRevocation("GrantStore.RevokeByUser", user, "", cause, at); err != nil {
		return nil, failed(op, err)
	}
	codes, err := s.codes.Read()
	if err != nil {
		return nil, failed(op, err)
	}
	families, err := codes.UnspentBySignIn(ctx, oidcprovider.SignInSelector{User: user}, true)
	if err != nil {
		return nil, failed(op, fmt.Errorf("reading a user's outstanding codes: %w", err))
	}

	return s.writeBulk(ctx, op, pgschema.GrantRevokeByUser(user, families, cause, at))
}

// RevokeByUserAndClient implements oidcprovider.GrantStore.
func (s *GrantStore) RevokeByUserAndClient(
	ctx context.Context, user identity.UserID, clientID string, cause oidcprovider.RevocationCause, at time.Time,
) ([]oidcprovider.Grant, error) {
	const op = "revoke user's grants of a client"

	if user == "" || clientID == "" {
		return nil, failed(op, fmt.Errorf("%w: GrantStore.RevokeByUserAndClient: the user and the client must not be empty",
			oidcprovider.ErrConfig))
	}
	if err := checkRevocation("GrantStore.RevokeByUserAndClient", user, clientID, cause, at); err != nil {
		return nil, failed(op, err)
	}
	codes, err := s.codes.Read()
	if err != nil {
		return nil, failed(op, err)
	}
	families, err := codes.UnspentByClient(ctx, user, clientID)
	if err != nil {
		return nil, failed(op, fmt.Errorf("reading a client's outstanding codes: %w", err))
	}

	return s.writeBulk(ctx, op, pgschema.GrantRevokeByUserAndClient(user, clientID, families, cause, at))
}

// checkRevocation refuses what a user-wide revocation cannot record.
func checkRevocation(operation string, user identity.UserID, clientID string, cause oidcprovider.RevocationCause, at time.Time) error {
	if err := pgschema.RequireTime(operation, at); err != nil {
		return err
	}
	if err := pgschema.CheckConsentKey(user, clientID); err != nil {
		return err
	}

	return pgschema.CheckText("revocation cause", string(cause))
}

// writeBulk runs the two steps of w as one unit, and returns the grants it reports.
func (s *GrantStore) writeBulk(ctx context.Context, op string, w pgschema.GrantBulkWrite) ([]oidcprovider.Grant, error) {
	var reported []oidcprovider.Grant
	err := s.atomically(ctx, op, func(q DBTX) error {
		var held string
		if err := q.QueryRow(ctx, w.Hold, w.HoldArgs...).Scan(&held); err != nil {
			return failed(op, err)
		}
		var err error
		reported, err = returnedGrants(ctx, q, op, w.Write, w.WriteArgs(held)...)

		return err
	})
	if err != nil {
		return nil, err
	}

	return reported, nil
}

// EndSignIns implements oidcprovider.GrantStore. A family's revocation and a grant's mark
// are decided together, so a family's grant, if stored, is still counted as newly marked.
func (s *GrantStore) EndSignIns(ctx context.Context, sel oidcprovider.SignInSelector, at time.Time) ([]oidcprovider.Grant, error) {
	const op = "end sign-ins"

	if err := pgschema.CheckSelector(sel); err != nil {
		return nil, failed(op, err)
	}
	if err := pgschema.RequireTime("GrantStore.EndSignIns", at); err != nil {
		return nil, failed(op, err)
	}
	codes, err := s.codes.Read()
	if err != nil {
		return nil, failed(op, err)
	}
	families, err := codes.UnspentBySignIn(ctx, sel, false)
	if err != nil {
		return nil, failed(op, fmt.Errorf("reading a sign-in's outstanding codes: %w", err))
	}

	return s.writeBulk(ctx, op, pgschema.GrantEndSignIns(sel, families, at))
}

// returnedGrants runs a statement returning grants, and closes its rows before returning.
func returnedGrants(ctx context.Context, q DBTX, op, statement string, args ...any) ([]oidcprovider.Grant, error) {
	rows, err := q.Query(ctx, statement, args...)
	if err != nil {
		return nil, failed(op, err)
	}
	defer rows.Close()

	var out []oidcprovider.Grant
	for rows.Next() {
		var row pgschema.GrantRow
		if err := rows.Scan(row.Dest()...); err != nil {
			return nil, failed(op, err)
		}
		g, err := row.Record()
		if err != nil {
			return nil, failed(op, err)
		}
		out = append(out, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, failed(op, err)
	}

	return out, nil
}

// DeleteExpired implements oidcprovider.GrantStore.
func (s *GrantStore) DeleteExpired(ctx context.Context, now time.Time, keepRevoked time.Duration) (int, error) {
	const op = "delete expired grants"

	if keepRevoked <= 0 {
		return 0, failed(op, fmt.Errorf("%w: GrantStore.DeleteExpired: keepRevoked must be positive, got %s",
			oidcprovider.ErrConfig, keepRevoked))
	}
	n, err := s.c.exec(ctx, op, pgschema.GrantDeleteExpired, storekit.Time(now), storekit.Time(now.Add(-keepRevoked)))

	return int(n), err
}

// atomically runs fn as one unit: under a savepoint inside a caller's transaction, and
// otherwise in a READ COMMITTED transaction of the store's own.
func (s *GrantStore) atomically(ctx context.Context, op string, fn func(q DBTX) error) error {
	q, ambient, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}

	return storekit.Atomically(ctx, &grantUnit{s: s, op: op}, q, ambient, fn)
}

// grantUnit is this store's side of storekit.Atomically, for one call to op.
type grantUnit struct {
	s  *GrantStore
	op string
	tx pgx.Tx
}

// Begin begins a transaction of the store's own on its pool.
func (u *grantUnit) Begin(ctx context.Context, _ DBTX) (DBTX, error) {
	tx, err := u.s.c.beginReadCommitted(ctx)
	if err != nil {
		return nil, failed(u.op, err)
	}
	u.tx = tx

	return tx, nil
}

func (u *grantUnit) Commit(ctx context.Context) error {
	if err := u.tx.Commit(ctx); err != nil {
		return failed(u.op, err)
	}

	return nil
}

// Rollback detaches from ctx, so the transaction and the row locks it holds never
// outlive the call even when ctx is done.
func (u *grantUnit) Rollback(ctx context.Context) { _ = u.tx.Rollback(context.WithoutCancel(ctx)) }

func (u *grantUnit) SavepointName() string {
	return "scrty_op_grants_" + strconv.FormatUint(u.s.savepoints.Add(1), 10)
}

func (u *grantUnit) ExecSavepoint(ctx context.Context, q DBTX, stmt string) error {
	if _, err := q.Exec(ctx, stmt); err != nil {
		return failed(u.op, err)
	}

	return nil
}

var _ oidcprovider.GrantStore = (*GrantStore)(nil)
