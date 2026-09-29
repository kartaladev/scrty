package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/oidc"
)

// FlowStore keeps OIDC login flows, between Authorize and Callback, in the
// oidc_flows table the migrate package creates. It implements oidc.FlowStore,
// and is safe for concurrent use.
//
// Begin mints the flow's handle from crypto/rand: 32 bytes, base64url
// without padding. Complete is one statement that completes the flow only
// where its handle, provider and non-empty state all match, it is not yet
// completed and it has not expired by the store's clock, so of concurrent
// completions exactly one succeeds, and every refusal is oidc.ErrInvalidState
// and leaves the flow completable as it was.
type FlowStore struct{ c *config }

// NewFlowStore returns a durable flow store on db.
//
// Complete judges expiry with the store's clock: a flow is expired from its
// ExpiresAt instant on. It honours WithTxResolver, WithClock (default
// time.Now) and WithIDGenerator (default id.NewV7Generator, for the rows'
// primary keys), and refuses any other option.
//
// Limits, stated: PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A
// flow whose provider, state, nonce, verifier or next location holds either
// is refused with an error that names the field, never the value, and
// nothing is written; a completion with such a value is refused as
// oidc.ErrInvalidState. The flow's values are stored as given: they are
// single-use and short-lived, and are not sealed. Stored times are UTC,
// truncated to the microsecond.
func NewFlowStore(db *sql.DB, opts ...Option) (*FlowStore, error) {
	c, err := newConfig(db, opts, optIDGenerator, optClock)
	if err != nil {
		return nil, err
	}

	return &FlowStore{c: c}, nil
}

// Begin stores f and returns the handle the store minted for it.
func (s *FlowStore) Begin(ctx context.Context, f oidc.Flow) (string, error) {
	const op = "begin login flow"

	if err := storekit.CheckStorable(
		storekit.Text("provider", f.Provider), storekit.Text("state", f.State), storekit.Text("nonce", f.Nonce),
		storekit.Text("verifier", f.Verifier), storekit.Text("next location", f.Next),
	); err != nil {
		return "", failed(op, err)
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return "", failed(op, err)
	}
	handle, err := storekit.NewFlowHandle()
	if err != nil {
		return "", failed(op, err)
	}

	if _, err := s.c.exec(ctx, op, pgschema.FlowInsert, rowID, handle, f.Provider, f.State, f.Nonce, f.Verifier,
		f.Next, storekit.Time(f.ExpiresAt)); err != nil {
		return "", err
	}

	return handle, nil
}

// Complete completes the flow named by handle and returns it, or refuses
// with oidc.ErrInvalidState.
func (s *FlowStore) Complete(ctx context.Context, handle, provider, state string) (oidc.Flow, error) {
	if !storekit.Storable(handle, provider, state) {
		return oidc.Flow{}, oidc.ErrInvalidState
	}

	var f oidc.Flow
	var expires time.Time
	err := s.c.queryRow(ctx, "complete login flow", pgschema.FlowComplete,
		[]any{handle, provider, state, storekit.Time(s.c.clock.Now())},
		&f.Provider, &f.State, &f.Nonce, &f.Verifier, &f.Next, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.Flow{}, oidc.ErrInvalidState
	}
	if err != nil {
		return oidc.Flow{}, err
	}
	f.ExpiresAt = expires.UTC()

	return f, nil
}

// DeleteExpired removes flows that expired strictly before before and
// reports how many it removed. A zero cutoff is refused with
// oidc.ErrRetainSinceRequired, and nothing is deleted.
func (s *FlowStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	if before.IsZero() {
		return 0, oidc.ErrRetainSinceRequired
	}

	n, err := s.c.exec(ctx, "purge expired login flows", pgschema.FlowDeleteExpired, storekit.Time(before))

	return int(n), err
}

var _ oidc.FlowStore = (*FlowStore)(nil)
