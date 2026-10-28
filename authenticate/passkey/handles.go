package passkey

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/kartaladev/scrty/identity"
)

// HandleSize is the length in bytes of a WebAuthn user handle the library
// assigns: 64 bytes from a cryptographically secure random source.
const HandleSize = 64

// HandleStore keeps each user's one WebAuthn user handle, mapped in both
// directions.
//
// The library uses NewMemoryHandleStore when a consumer supplies none. Any
// implementation of this contract may be used in its place.
type HandleStore interface {
	// Assign stores offered as user's handle only when user has none, in one
	// write, and returns the handle user holds afterwards, whether newly
	// stored or already present. Of concurrent assignments for one user, every
	// caller receives the same handle. An offer that is not HandleSize bytes
	// is refused with an error wrapping ErrConfig. An offered handle that another
	// user already holds is refused with a non-nil error that carries no
	// handle bytes.
	Assign(ctx context.Context, user identity.UserID, offered []byte) ([]byte, error)
	// UserFor returns the user holding handle, or false when no user does.
	UserFor(ctx context.Context, handle []byte) (identity.UserID, bool, error)
}

var _ HandleStore = (*MemoryHandleStore)(nil)

// MemoryHandleStore keeps user handles in process memory. It is the
// HandleStore the library uses when a consumer supplies none, and it is safe
// for concurrent use.
//
// Its limit is stated: it holds this process's handles only. A restart
// forgets them, so a returning user is given a new handle and their
// authenticators keep a second entry beside the old one; behind several
// replicas each assigns its own. Supply a durable, shared HandleStore for
// anything beyond a single process.
//
// It keeps its own copies of every handle, in and out.
type MemoryHandleStore struct {
	mu     sync.Mutex
	byUser map[identity.UserID][]byte
	byHash map[string]identity.UserID // handle bytes, as a string copy → user
}

// NewMemoryHandleStore returns an empty in-memory store.
func NewMemoryHandleStore() *MemoryHandleStore {
	return &MemoryHandleStore{
		byUser: make(map[identity.UserID][]byte),
		byHash: make(map[string]identity.UserID),
	}
}

// Assign stores a copy of offered as user's handle when user has none, and
// returns a copy of the handle user holds afterwards.
func (s *MemoryHandleStore) Assign(_ context.Context, user identity.UserID, offered []byte) ([]byte, error) {
	if len(offered) != HandleSize {
		return nil, fmt.Errorf("%w: a user handle is %d bytes", ErrConfig, HandleSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if h, ok := s.byUser[user]; ok {
		return bytes.Clone(h), nil
	}

	if _, taken := s.byHash[string(offered)]; taken {
		return nil, errHandleTaken
	}

	h := bytes.Clone(offered)
	s.byUser[user] = h
	s.byHash[string(h)] = user

	return bytes.Clone(h), nil
}

// errHandleTaken reports an offered handle another user already holds. With
// 64 random bytes it does not happen by chance; it names no part of the
// handle.
var errHandleTaken = errors.New("passkey: offered user handle is already held")

// UserFor returns the user holding handle, or false.
func (s *MemoryHandleStore) UserFor(_ context.Context, handle []byte) (identity.UserID, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.byHash[string(handle)]

	return user, ok, nil
}
