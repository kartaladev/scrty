package httpsec_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/password"
)

// This file backs TestChangePasswordEndpointReuseGuard (passwordchange_test.go)
// with an in-test identity.UserLoader/identity.UserProvisioner pair and an
// in-test password.History: httpsec tests may not import
// github.com/kartaladev/scrty/test, so the resolve endpoint's own consumer
// function — which the gate hands the whole exchange to — is given doubles of
// its own here, distinct from authHarness's h.users mock, which only backs the
// chain's bearer authentication.

// passwordReuseStore is a minimal identity.UserLoader and
// identity.UserProvisioner pair over one in-memory user, backing the reuse
// guard's Check-Change-write path.
type passwordReuseStore struct {
	mu   sync.Mutex
	user identity.Details
}

var (
	_ identity.UserLoader      = (*passwordReuseStore)(nil)
	_ identity.UserProvisioner = (*passwordReuseStore)(nil)
)

// newPasswordReuseStore returns a store holding one copy of d.
func newPasswordReuseStore(d *identity.Details) *passwordReuseStore {
	return &passwordReuseStore{user: *d}
}

func (s *passwordReuseStore) LoadByUsername(_ context.Context, username string) (*identity.Details, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.user.Username != username {
		return nil, identity.ErrUserNotFound
	}

	got := s.user

	return &got, nil
}

func (s *passwordReuseStore) LoadByUserID(_ context.Context, id identity.UserID) (*identity.Details, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.user.ID != id {
		return nil, identity.ErrUserNotFound
	}

	got := s.user

	return &got, nil
}

// Provision is unused by these tests; the store starts with its one user
// already provisioned.
func (s *passwordReuseStore) Provision(
	_ context.Context, _ string, _ ...identity.UserOption,
) (*identity.Details, error) {
	return nil, identity.ErrUserExists
}

// Update writes exactly the fields opts named, mirroring the contract
// UserProvisioner.Update documents, and returns the complete stored record.
func (s *passwordReuseStore) Update(
	_ context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.user.Username != username {
		return nil, identity.ErrUserNotFound
	}

	u := identity.ApplyUserOptions(opts...)
	if u.IsSet(identity.FieldPassword) {
		s.user.Password = u.Password
	}
	if u.IsSet(identity.FieldPasswordChangedAt) {
		s.user.PasswordChangedAt = u.PasswordChangedAt
	}

	got := s.user

	return &got, nil
}

// passwordReuseHistory is an in-memory password.History, holding one user's
// retired hashes, newest first. It is a small stand-in for the identity test
// module's own history double, which httpsec tests may not import.
type passwordReuseHistory struct {
	mu     sync.Mutex
	hashes [][]byte
}

var _ password.History = (*passwordReuseHistory)(nil)

func newPasswordReuseHistory() *passwordReuseHistory { return &passwordReuseHistory{} }

func (h *passwordReuseHistory) RecentPasswords(
	_ context.Context, _ identity.UserID, n int,
) ([][]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if n > len(h.hashes) {
		n = len(h.hashes)
	}

	out := make([][]byte, n)
	copy(out, h.hashes[:n])

	return out, nil
}

func (h *passwordReuseHistory) RetirePassword(
	_ context.Context, _ identity.UserID, hash []byte, keep int,
) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if keep <= 0 {
		h.hashes = nil

		return nil
	}

	if len(h.hashes) == 0 || !bytes.Equal(h.hashes[0], hash) {
		h.hashes = append([][]byte{hash}, h.hashes...)
	}

	if len(h.hashes) > keep {
		h.hashes = h.hashes[:keep]
	}

	return nil
}

func (h *passwordReuseHistory) ForgetPasswords(_ context.Context, _ identity.UserID) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.hashes = nil

	return nil
}

// fastReuseEncoder is Argon2id at its parameter floor, to keep the reuse-guard
// tests fast.
func fastReuseEncoder(t *testing.T) password.Encoder {
	t.Helper()

	enc, err := password.NewArgon2idEncoder(
		password.WithArgon2idIterations(2),
		password.WithArgon2idMemory(19*1024),
		password.WithArgon2idThreads(1),
	)
	require.NoError(t, err)

	return enc
}

func mustEncodeReuse(t *testing.T, enc password.Encoder, plain string) []byte {
	t.Helper()

	hash, err := enc.Encode(plain)
	require.NoError(t, err)

	return hash
}

// changePasswordFormRequest is an authorized POST to the resolve endpoint,
// carrying the new password as a form field the way the fixture ChangePassword
// functions in this file read it.
func changePasswordFormRequest(ctx context.Context, candidate string) *http.Request {
	body := url.Values{"password": {candidate}}.Encode()

	req := httptest.NewRequestWithContext(
		ctx, http.MethodPost, testChangePasswordPath, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer a-token")

	return req
}
