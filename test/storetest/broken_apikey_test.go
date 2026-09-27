package storetest_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// apiKeyDefect is one deliberate flaw an apiKeyStore can carry.
type apiKeyDefect string

//nolint:gosec // G101: these are defect names, not credentials
const (
	apiKeyConforming apiKeyDefect = "conforming"
	// Put keeps the caller's scopes and digest rather than copies of them.
	apiKeyPutKeepsSlices apiKeyDefect = "put-keeps-caller-slices"
	// Get hands back the stored scopes and digest rather than copies of them.
	apiKeyGetSharesSlices apiKeyDefect = "get-shares-stored-slices"
	// A touch keeps the first use recorded, as a COALESCE would.
	apiKeyTouchKeepsFirst apiKeyDefect = "touch-keeps-first"
	// Get refuses a key expired by the system clock, judging what the
	// contract leaves to the manager.
	apiKeyGetDropsExpired apiKeyDefect = "get-drops-expired"
	// List leaves out keys expired by the system clock.
	apiKeyListDropsExpired apiKeyDefect = "list-drops-expired"
	// Put stores a new key as never revoked and never used, whatever it is
	// given.
	apiKeyPutDropsUse apiKeyDefect = "put-drops-revocation-and-use"
	// List hands back the stored scopes and digest rather than copies of them.
	apiKeyListSharesSlices apiKeyDefect = "list-shares-stored-slices"
	// Get hands back every instant truncated to the millisecond, as a column
	// of millisecond precision would.
	apiKeyGetTruncatesMillis apiKeyDefect = "get-truncates-milliseconds"
	// Put refuses a key with no scopes, reading them as required.
	apiKeyPutRefusesNoScopes apiKeyDefect = "put-refuses-no-scopes"
	// Put replaces invalid UTF-8 in a scope or the name with U+FFFD, and
	// strips NUL bytes from either, as encoding them to JSON and then
	// trimming would.
	apiKeyPutAltersText apiKeyDefect = "put-alters-scopes-and-name"
	// Put refuses a NUL byte or invalid UTF-8 in a scope, the name or the
	// principal, without echoing it. The contract allows it, so this
	// conforms.
	apiKeyPutRefusesText apiKeyDefect = "put-refuses-unstorable-text"
)

// unstorableAPIKeyText reports whether rec holds, in a scope, its name or its
// principal, what a PostgreSQL text column cannot: a NUL byte or invalid
// UTF-8.
func unstorableAPIKeyText(rec apikey.Key) bool {
	values := append([]string{rec.Name, string(rec.Principal)}, rec.Scopes...)
	for _, v := range values {
		if strings.ContainsRune(v, 0) || !utf8.ValidString(v) {
			return true
		}
	}
	return false
}

// alterAPIKeyText rewrites rec's scopes and name the way apiKeyPutAltersText
// does.
func alterAPIKeyText(rec apikey.Key) apikey.Key {
	rec.Name = strings.ReplaceAll(strings.ToValidUTF8(rec.Name, "�"), "\x00", "")
	scopes := make([]string, len(rec.Scopes))
	for i, v := range rec.Scopes {
		scopes[i] = strings.ReplaceAll(strings.ToValidUTF8(v, "�"), "\x00", "")
	}
	rec.Scopes = scopes
	return rec
}

// expiredNow reports whether k is expired by the system clock.
func expiredNow(k apikey.Key) bool {
	return k.ExpiresAt != nil && !time.Now().Before(*k.ExpiresAt)
}

// truncatePtr truncates an optional instant to d.
func truncatePtr(at *time.Time, d time.Duration) *time.Time {
	if at == nil {
		return nil
	}
	out := at.Truncate(d)
	return &out
}

// apiKeyStore is an API key store over process memory, written apart from
// the shipped store so a defect can reach state the shipped store never
// exposes. Without a defect it conforms.
type apiKeyStore struct {
	defect apiKeyDefect

	mu      sync.Mutex
	records map[id.ID]apikey.Key
}

var _ apikey.Store = (*apiKeyStore)(nil)

func newAPIKeyStore(defect apiKeyDefect) *apiKeyStore {
	return &apiKeyStore{defect: defect, records: make(map[id.ID]apikey.Key)}
}

func cloneKey(k apikey.Key) apikey.Key {
	k.Scopes = slices.Clone(k.Scopes)
	k.SecretDigest = bytes.Clone(k.SecretDigest)
	return k
}

func (s *apiKeyStore) Put(_ context.Context, rec apikey.Key) error {
	if s.defect == apiKeyPutRefusesNoScopes && len(rec.Scopes) == 0 {
		return errors.New("a key must carry at least one scope")
	}
	if s.defect == apiKeyPutRefusesText && unstorableAPIKeyText(rec) {
		return errors.New("a key value holds text the store cannot keep")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.defect != apiKeyPutKeepsSlices {
		rec = cloneKey(rec)
	}
	if s.defect == apiKeyPutDropsUse {
		rec.RevokedAt, rec.LastUsedAt = nil, nil
	}
	if s.defect == apiKeyPutAltersText {
		rec = alterAPIKeyText(rec)
	}
	s.records[rec.ID] = rec
	return nil
}

func (s *apiKeyStore) Get(_ context.Context, keyID id.ID) (apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[keyID]
	if !ok || (s.defect == apiKeyGetDropsExpired && expiredNow(rec)) {
		return apikey.Key{}, apikey.ErrKeyNotFound
	}
	switch s.defect {
	case apiKeyGetSharesSlices:
		return rec, nil
	case apiKeyGetTruncatesMillis:
		rec.ExpiresAt = truncatePtr(rec.ExpiresAt, time.Millisecond)
		rec.RevokedAt = truncatePtr(rec.RevokedAt, time.Millisecond)
		rec.LastUsedAt = truncatePtr(rec.LastUsedAt, time.Millisecond)
		rec.CreatedAt = rec.CreatedAt.Truncate(time.Millisecond)
	}
	return cloneKey(rec), nil
}

func (s *apiKeyStore) Revoke(_ context.Context, keyID id.ID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[keyID]
	if !ok {
		return apikey.ErrKeyNotFound
	}
	if rec.RevokedAt == nil {
		rec.RevokedAt = &at
		s.records[keyID] = rec
	}
	return nil
}

func (s *apiKeyStore) TouchLastUsed(_ context.Context, keyID id.ID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[keyID]
	if !ok {
		return apikey.ErrKeyNotFound
	}
	if rec.LastUsedAt == nil || s.defect != apiKeyTouchKeepsFirst {
		rec.LastUsedAt = &at
		s.records[keyID] = rec
	}
	return nil
}

func (s *apiKeyStore) List(_ context.Context, principal identity.UserID) ([]apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []apikey.Key
	for _, rec := range s.records {
		switch {
		case rec.Principal != principal, s.defect == apiKeyListDropsExpired && expiredNow(rec):
		case s.defect == apiKeyListSharesSlices:
			out = append(out, rec)
		default:
			out = append(out, cloneKey(rec))
		}
	}
	return out, nil
}
