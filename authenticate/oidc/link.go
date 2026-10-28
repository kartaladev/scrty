package oidc

import (
	"context"
	"strings"
	"sync"

	"github.com/kartaladev/scrty/identity"
)

// linkKey is the identity of a link: provider, issuer and subject together.
// A struct key needs no separator, so no value of one part can be mistaken for
// a boundary between two.
type linkKey struct{ provider, issuer, subject string }

// linkKeyOf returns the key l is stored under.
func linkKeyOf(l Link) linkKey { return linkKey{l.Provider, l.Issuer, l.Subject} }

// emailDomain returns the part of email after its last "@", which is all of
// an email a log record may carry, or "" when there is none.
func emailDomain(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return ""
	}
	return email[at+1:]
}

// MemoryLinkStore is the LinkStore the library's broker uses when a consumer
// supplies none. It holds links in process memory, so they last for one
// process only and are not shared between replicas; a deployment with more
// than one replica, or one whose links must survive a restart, supplies a
// durable LinkStore instead.
//
// Every operation runs under one mutex, so the existence check and the write
// of an insert are indivisible: of concurrent inserts of one key exactly one
// succeeds. User references and usernames are stored and returned byte for
// byte. It is safe for concurrent use.
type MemoryLinkStore struct {
	mu    sync.Mutex
	links map[linkKey]Link
}

var _ LinkStore = (*MemoryLinkStore)(nil)

// NewMemoryLinkStore returns an empty in-memory link store.
func NewMemoryLinkStore() *MemoryLinkStore {
	return &MemoryLinkStore{links: make(map[linkKey]Link)}
}

// FindByExternal returns a copy of the link for the external identity, or
// ErrLinkNotFound.
func (s *MemoryLinkStore) FindByExternal(_ context.Context, provider, issuer, subject string) (*Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	l, ok := s.links[linkKey{provider, issuer, subject}]
	if !ok {
		return nil, ErrLinkNotFound
	}
	return &l, nil
}

// Insert stores l, or returns ErrLinkExists when its provider, issuer and
// subject are already linked, even to the same user, and leaves the stored
// link unchanged. A nil return therefore always means this call created it.
func (s *MemoryLinkStore) Insert(_ context.Context, l Link) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := linkKeyOf(l)
	if _, taken := s.links[k]; taken {
		return ErrLinkExists
	}
	s.links[k] = l
	return nil
}

// DeleteByUser removes every link to user, matched byte for byte, and returns
// how many it removed.
func (s *MemoryLinkStore) DeleteByUser(_ context.Context, user identity.UserID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for k, l := range s.links {
		if l.UserID == user {
			delete(s.links, k)
			n++
		}
	}
	return n, nil
}
