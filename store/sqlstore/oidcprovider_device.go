package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// errDeviceNoFlow refuses a claim with no flow digest. Its text is fixed.
var errDeviceNoFlow = errors.New("a claim needs the flow digest of the claiming browser")

// deviceConflict is the answer to an insert that wrote no row, given whether DeviceHeld
// found its identifier or device-code digest held. Otherwise the user code was held, or
// the row that conflicted was swept in between: nothing was stored either way, so the
// answer is a taken user code, which the provider retries with a fresh code.
func deviceConflict(op string, keyHeld bool) error {
	if keyHeld {
		return failed(op, storekit.ErrIdentifierInUse)
	}

	return oidcprovider.ErrUserCodeTaken
}

// DeviceAuthorizationStore keeps device authorizations (RFC 8628) in the
// scrty_op_device_authorizations table. It implements oidcprovider.DeviceAuthorizationStore, and
// is safe for concurrent use, across replicas too: every transition is one conditional
// UPDATE, so of callers racing on a record exactly one moves it, and the others answer
// oidcprovider.ErrNotFound.
//
// It reads no clock: every expiry is judged by the time the provider passes. A poll's
// compare-and-set reads the poll count, never a time, as a time read back here has lost
// its nanoseconds. A spent record is kept until a minute past its expiry, the window in
// which a replay of its device code is detected.
//
// Create releases an expired holder's user code and inserts in one unit: a READ COMMITTED
// transaction of the store's own, or a savepoint inside a caller's transaction, so a
// refusal undoes the release and leaves that transaction usable. The unique index on the
// user-code digest decides two creates of one code, the loser answering
// oidcprovider.ErrUserCodeTaken. Inside a caller's transaction at a stronger isolation, a
// lost race surfaces as the driver's serialization failure instead, which the caller
// retries.
//
// Its refusals carry no digest. Stored times are UTC, truncated to the microsecond.
type DeviceAuthorizationStore struct {
	c *config

	// savepoints numbers the savepoints this store opens inside a caller's transaction.
	savepoints atomic.Uint64
}

// NewDeviceAuthorizationStore returns a durable store on db. It honours WithTxResolver and
// refuses any other option: a record arrives with its own identifier, and every time it
// judges by is a caller's. Without WithTxResolver it uses the transaction attached to the
// operation's context with WithTx, and db otherwise.
//
// The provider's default is an in-memory store (oidcprovider.MemoryDeviceAuthorizationStore),
// lost with the process; pass this one to oidcprovider.WithDeviceAuthorizationStore to replace
// it. The provider then also needs oidcprovider.WithUserCodeKey, the same on every replica,
// or New fails. The table comes from the security-state baseline,
// 20261126000000_security_state.
func NewDeviceAuthorizationStore(db *sql.DB, opts ...Option) (*DeviceAuthorizationStore, error) {
	c, err := newConfig(db, opts)
	if err != nil {
		return nil, err
	}

	return &DeviceAuthorizationStore{c: c}, nil
}

// Create implements oidcprovider.DeviceAuthorizationStore.
func (s *DeviceAuthorizationStore) Create(ctx context.Context, record *oidcprovider.DeviceAuthorization, now time.Time) error {
	const op = "create device authorization"

	if err := pgschema.CheckDevice(record); err != nil {
		return failed(op, err)
	}
	args, err := pgschema.DeviceArgs(record)
	if err != nil {
		return failed(op, err)
	}

	q, _, ambient, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}

	return storekit.Atomically(ctx, &deviceUnit{s: s, op: op}, q, ambient, func(q DBTX) error {
		if _, err := q.ExecContext(ctx, pgschema.DeviceRelease, record.UserCodeDigest, storekit.Time(now)); err != nil {
			return failed(op, err)
		}
		res, err := q.ExecContext(ctx, pgschema.DeviceInsert, args...)
		if err != nil {
			return failed(op, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return failed(op, err)
		}
		if n > 0 {
			return nil
		}

		// The insert wrote nothing, so a unique key is held. A later snapshot sees which.
		var keyHeld, userCodeHeld bool
		if err := q.QueryRowContext(ctx, pgschema.DeviceHeld,
			record.ID.String(), record.DeviceCodeDigest, record.UserCodeDigest).Scan(&keyHeld, &userCodeHeld); err != nil {
			return failed(op, err)
		}

		return deviceConflict(op, keyHeld)
	})
}

// LoadByDeviceCode implements oidcprovider.DeviceAuthorizationStore.
func (s *DeviceAuthorizationStore) LoadByDeviceCode(ctx context.Context, digest []byte) (*oidcprovider.DeviceAuthorization, error) {
	if len(digest) == 0 {
		return nil, oidcprovider.ErrNotFound
	}

	return loadRecord[oidcprovider.DeviceAuthorization](ctx, s.c, "load device authorization", oidcprovider.ErrNotFound,
		&pgschema.DeviceRow{}, pgschema.DeviceSelectByDeviceCode, digest)
}

// LoadByUserCode implements oidcprovider.DeviceAuthorizationStore.
func (s *DeviceAuthorizationStore) LoadByUserCode(
	ctx context.Context, digest []byte, now time.Time,
) (*oidcprovider.DeviceAuthorization, error) {
	if len(digest) == 0 {
		return nil, oidcprovider.ErrNotFound
	}

	return loadRecord[oidcprovider.DeviceAuthorization](ctx, s.c, "load device authorization by user code",
		oidcprovider.ErrNotFound, &pgschema.DeviceRow{}, pgschema.DeviceSelectByUserCode, digest, storekit.Time(now))
}

// Claim implements oidcprovider.DeviceAuthorizationStore.
func (s *DeviceAuthorizationStore) Claim(ctx context.Context, deviceID id.ID, flowDigest []byte, now time.Time) error {
	const op = "claim device authorization"

	if len(flowDigest) == 0 {
		return failed(op, errDeviceNoFlow)
	}

	return s.c.execOrRefuse(ctx, op, oidcprovider.ErrNotFound, pgschema.DeviceClaim,
		deviceID.String(), flowDigest, storekit.Time(now))
}

// Decide implements oidcprovider.DeviceAuthorizationStore. An approval naming no grant
// family is refused, as no revocation could reach the grant it would create.
func (s *DeviceAuthorizationStore) Decide(
	ctx context.Context, deviceID id.ID, approval *oidcprovider.DeviceApproval, now time.Time,
) error {
	const op = "decide device authorization"

	args, err := pgschema.DeviceDecideArgs(deviceID, approval, now)
	if err != nil {
		return failed(op, err)
	}

	return s.c.execOrRefuse(ctx, op, oidcprovider.ErrNotFound, pgschema.DeviceDecide, args...)
}

// RecordPoll implements oidcprovider.DeviceAuthorizationStore.
func (s *DeviceAuthorizationStore) RecordPoll(
	ctx context.Context, deviceID id.ID, seenPolls int, at time.Time, interval time.Duration,
) error {
	const op = "record device poll"

	args, ok, err := pgschema.DeviceRecordPollArgs(deviceID, seenPolls, at, interval)
	if err != nil {
		return failed(op, err)
	}
	if !ok {
		return oidcprovider.ErrNotFound
	}

	return s.c.execOrRefuse(ctx, op, oidcprovider.ErrNotFound, pgschema.DeviceRecordPoll, args...)
}

// Spend implements oidcprovider.DeviceAuthorizationStore.
func (s *DeviceAuthorizationStore) Spend(ctx context.Context, deviceID id.ID, now time.Time) error {
	return s.c.execOrRefuse(ctx, "spend device authorization", oidcprovider.ErrNotFound, pgschema.DeviceSpend,
		deviceID.String(), storekit.Time(now))
}

// DeleteExpired implements oidcprovider.DeviceAuthorizationStore.
func (s *DeviceAuthorizationStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	n, err := s.c.exec(ctx, "delete expired device authorizations", pgschema.DeviceDeleteExpired,
		pgschema.DeviceDeleteExpiredArgs(now)...)

	return int(n), err
}

// UnspentBySignIn implements oidcprovider.UnspentCodes.
func (s *DeviceAuthorizationStore) UnspentBySignIn(
	ctx context.Context, sel oidcprovider.SignInSelector, includeOffline bool,
) ([]id.ID, error) {
	const op = "list a sign-in's approved device authorizations"

	if err := pgschema.CheckSelector(sel); err != nil {
		return nil, failed(op, err)
	}
	statement, args := pgschema.DeviceUnspentBySignIn(sel, includeOffline)

	return s.c.queryIDs(ctx, op, statement, args...)
}

// UnspentByClient implements oidcprovider.UnspentCodes.
func (s *DeviceAuthorizationStore) UnspentByClient(ctx context.Context, user identity.UserID, clientID string) ([]id.ID, error) {
	const op = "list a client's approved device authorizations"

	if err := pgschema.CheckConsentKey(user, clientID); err != nil {
		return nil, failed(op, err)
	}

	return s.c.queryIDs(ctx, op, pgschema.DeviceUnspentByClient, pgschema.DeviceUnspentByClientArgs(user, clientID)...)
}

// deviceUnit is this store's side of storekit.Atomically, for one call to op.
type deviceUnit struct {
	s  *DeviceAuthorizationStore
	op string
	tx *sql.Tx
}

// Begin begins a transaction of the store's own on its *sql.DB.
func (u *deviceUnit) Begin(ctx context.Context, _ DBTX) (DBTX, error) {
	tx, err := u.s.c.beginReadCommitted(ctx)
	if err != nil {
		return nil, failed(u.op, err)
	}
	u.tx = tx

	return tx, nil
}

func (u *deviceUnit) Commit(context.Context) error {
	if err := u.tx.Commit(); err != nil {
		return failed(u.op, err)
	}

	return nil
}

// Rollback takes no context: database/sql binds the transaction to the one BeginTx was
// given, and rolls it back itself when that one is done.
func (u *deviceUnit) Rollback(context.Context) { _ = u.tx.Rollback() }

func (u *deviceUnit) SavepointName() string {
	return "scrty_op_device_" + strconv.FormatUint(u.s.savepoints.Add(1), 10)
}

func (u *deviceUnit) ExecSavepoint(ctx context.Context, q DBTX, stmt string) error {
	if _, err := q.ExecContext(ctx, stmt); err != nil {
		return failed(u.op, err)
	}

	return nil
}

var _ oidcprovider.DeviceAuthorizationStore = (*DeviceAuthorizationStore)(nil)
