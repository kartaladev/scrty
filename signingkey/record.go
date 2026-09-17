package signingkey

import (
	"context"
	"slices"
	"sync"
	"time"
)

// Record is one stored signing key.
//
// Private holds the private key as PKCS #8 DER, or whatever a decorating store
// turned that into. A store persists it exactly as given and never interprets
// it.
type Record struct {
	// Kid is the key identifier: the base64url-encoded RFC 7638 SHA-256
	// thumbprint of the public key.
	Kid string

	// Alg is the signature algorithm the key signs with.
	Alg Alg

	// Private is opaque to the store: PKCS #8 DER as the key manager writes
	// it, or a sealed envelope a decorating store produced from it.
	Private []byte

	// PublicJWK is the public key as a JSON JWK, carrying Kid, Alg and use
	// "sig". The key manager does not need it to reload a key; it is there so
	// a store can publish the set without decoding private material.
	PublicJWK []byte

	// CreatedAt is when the key was generated, read from the key manager's
	// clock.
	CreatedAt time.Time
}

// KeyStore persists signing keys.
//
// With no store configured the key manager uses NewInMemoryKeyStore, which does
// not survive a restart. A consumer replaces it with any implementation through
// WithKeyStore, such as a durable one, or one that seals Record.Private.
//
//go:generate mockgen -source=record.go -package=signingkey_test -destination=keystore_mock_test.go -typed
type KeyStore interface {
	// Store inserts rec, replacing any record with the same Kid.
	Store(ctx context.Context, rec Record) error

	// LoadAll returns every stored record, oldest first by CreatedAt.
	LoadAll(ctx context.Context) ([]Record, error)
}

type inMemoryKeyStore struct {
	mu      sync.RWMutex
	records map[string]Record
}

// NewInMemoryKeyStore returns a KeyStore that keeps records in process memory.
// It is the default, and it is not durable: a new process starts with no keys,
// so every token signed by the previous process stops verifying. Supply a
// durable store through WithKeyStore to keep tokens valid across a restart.
func NewInMemoryKeyStore() KeyStore {
	return &inMemoryKeyStore{records: make(map[string]Record)}
}

// copyRecord returns a record that shares no backing array with rec.
//
// A Record's byte fields are slices, so copying the struct copies only their
// headers. Without this the store is a window onto the caller's buffers: a
// consumer wiping its own PKCS #8 buffer after handing it over — ordinary key
// hygiene — would destroy the stored key, and one reader zeroing or decrypting
// in place would corrupt what the next reader loads.
func copyRecord(rec Record) Record {
	rec.Private = slices.Clone(rec.Private)
	rec.PublicJWK = slices.Clone(rec.PublicJWK)

	return rec
}

func (s *inMemoryKeyStore) Store(_ context.Context, rec Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records[rec.Kid] = copyRecord(rec)

	return nil
}

func (s *inMemoryKeyStore) LoadAll(_ context.Context) ([]Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Record, 0, len(s.records))
	for _, rec := range s.records {
		out = append(out, copyRecord(rec))
	}
	slices.SortStableFunc(out, func(a, b Record) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}
