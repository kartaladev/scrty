package apikey

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// Store persists issued key records.
//
// With no store configured a Manager uses NewMemoryStore, which does not
// survive a restart: every key issued by the previous process stops working. A
// consumer replaces it with any implementation through WithStore, typically one
// backed by a table, and nothing else about the manager changes.
//
// The records this contract carries hold no secrets. A key's secret exists only
// in the string Issue returned; what is stored is a digest of it, so these
// records may be kept wherever a digest of a secret may go. Principal, Name and
// Scopes are the consumer's own values, stored and returned unchanged.
//
// An implementation must be safe for concurrent use, and must copy the byte and
// slice fields it keeps or returns: a caller that writes to what it read must
// not be able to change what is stored.
//
//go:generate mockgen -source=store.go -package=apikey_test -destination=mocks_test.go -typed
type Store interface {
	// Put stores rec. The record's identifier is freshly minted by the
	// manager, so an implementation may insert without checking for one
	// already present.
	Put(ctx context.Context, rec Key) error

	// Get returns the record with this identifier, revoked and expired ones
	// included, and ErrKeyNotFound when there is none. Expiry and revocation
	// are the manager's to judge, not the store's.
	Get(ctx context.Context, keyID id.ID) (Key, error)

	// Revoke marks the record revoked at, and reports ErrKeyNotFound when
	// there is no such record.
	//
	// A record already revoked keeps the time first recorded. The first
	// revocation is the one that happened, and a later call must not be able
	// to rewrite when the key stopped being accepted.
	Revoke(ctx context.Context, keyID id.ID, at time.Time) error

	// TouchLastUsed records that a verification of this key succeeded at, and
	// reports ErrKeyNotFound when there is no such record.
	//
	// The manager calls this best effort and never fails a verification on its
	// error, so an implementation may make it the cheapest write it has.
	TouchLastUsed(ctx context.Context, keyID id.ID, at time.Time) error

	// List returns every record belonging to principal, revoked and expired
	// ones included, so whoever manages a principal's keys sees all of them.
	// A principal with no keys is an empty result, not an error.
	List(ctx context.Context, principal identity.UserID) ([]Key, error)
}
