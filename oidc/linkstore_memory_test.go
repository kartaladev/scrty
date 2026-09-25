package oidc_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

// memLink returns a link for the corp provider's subject, naming user.
func memLink(issuer, subject string, user identity.UserID) oidc.Link {
	return oidc.Link{
		Provider: "corp", Issuer: issuer, Subject: subject,
		UserID: user, Username: "alice", Email: "alice@corp.example",
		CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestMemoryLinkStore(t *testing.T) {
	t.Parallel()

	const corpIssuer = "https://corp.example"

	type testCase struct {
		name   string
		act    func(ctx context.Context, s *oidc.MemoryLinkStore) error
		assert func(t *testing.T, ctx context.Context, s *oidc.MemoryLinkStore, err error)
	}

	cases := []testCase{
		{
			name: "a conflicting insert is refused and the stored link is unchanged",
			act: func(ctx context.Context, s *oidc.MemoryLinkStore) error {
				if err := s.Insert(ctx, memLink(corpIssuer, "s-1", "u-1")); err != nil {
					return err
				}
				return s.Insert(ctx, memLink(corpIssuer, "s-1", "u-2"))
			},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryLinkStore, err error) {
				require.ErrorIs(t, err, oidc.ErrLinkExists)
				got, ferr := s.FindByExternal(ctx, "corp", corpIssuer, "s-1")
				require.NoError(t, ferr)
				assert.Equal(t, identity.UserID("u-1"), got.UserID)
			},
		},
		{
			name: "an identical re-insert is refused",
			act: func(ctx context.Context, s *oidc.MemoryLinkStore) error {
				l := memLink(corpIssuer, "s-1", "u-1")
				if err := s.Insert(ctx, l); err != nil {
					return err
				}
				return s.Insert(ctx, l)
			},
			assert: func(t *testing.T, _ context.Context, _ *oidc.MemoryLinkStore, err error) {
				require.ErrorIs(t, err, oidc.ErrLinkExists)
			},
		},
		{
			name: "the same subject at another issuer is another key",
			act: func(ctx context.Context, s *oidc.MemoryLinkStore) error {
				if err := s.Insert(ctx, memLink("https://a.example", "12345", "u-1")); err != nil {
					return err
				}
				return s.Insert(ctx, memLink("https://b.example", "12345", "u-2"))
			},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryLinkStore, err error) {
				require.NoError(t, err)
				a, aerr := s.FindByExternal(ctx, "corp", "https://a.example", "12345")
				require.NoError(t, aerr)
				b, berr := s.FindByExternal(ctx, "corp", "https://b.example", "12345")
				require.NoError(t, berr)
				assert.Equal(t, identity.UserID("u-1"), a.UserID)
				assert.Equal(t, identity.UserID("u-2"), b.UserID)
			},
		},
		{
			name: "find of a missing key is link not found",
			act: func(ctx context.Context, s *oidc.MemoryLinkStore) error {
				_, err := s.FindByExternal(ctx, "corp", corpIssuer, "nobody")
				return err
			},
			assert: func(t *testing.T, _ context.Context, _ *oidc.MemoryLinkStore, err error) {
				require.ErrorIs(t, err, oidc.ErrLinkNotFound)
			},
		},
		{
			name: "deleting a user's links returns the count",
			act: func(ctx context.Context, s *oidc.MemoryLinkStore) error {
				other := memLink("https://social.example", "s-9", "u-1")
				other.Provider = "social"
				for _, l := range []oidc.Link{memLink(corpIssuer, "s-1", "u-1"), other, memLink(corpIssuer, "s-2", "u-2")} {
					if err := s.Insert(ctx, l); err != nil {
						return err
					}
				}
				return nil
			},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryLinkStore, err error) {
				require.NoError(t, err)
				n, derr := s.DeleteByUser(ctx, "u-1")
				require.NoError(t, derr)
				assert.Equal(t, 2, n)

				_, ferr := s.FindByExternal(ctx, "corp", corpIssuer, "s-1")
				assert.ErrorIs(t, ferr, oidc.ErrLinkNotFound)
				_, ferr = s.FindByExternal(ctx, "social", "https://social.example", "s-9")
				assert.ErrorIs(t, ferr, oidc.ErrLinkNotFound)

				kept, kerr := s.FindByExternal(ctx, "corp", corpIssuer, "s-2")
				require.NoError(t, kerr, "another user's link is untouched")
				assert.Equal(t, identity.UserID("u-2"), kept.UserID)
			},
		},
		{
			name: "references and usernames round-trip byte for byte",
			act: func(ctx context.Context, s *oidc.MemoryLinkStore) error {
				l := memLink(corpIssuer, "s-1", "U-1 ")
				l.Username = " Ada@Example.COM"
				return s.Insert(ctx, l)
			},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryLinkStore, err error) {
				require.NoError(t, err)
				got, ferr := s.FindByExternal(ctx, "corp", corpIssuer, "s-1")
				require.NoError(t, ferr)
				assert.Equal(t, identity.UserID("U-1 "), got.UserID)
				assert.Equal(t, " Ada@Example.COM", got.Username)
			},
		},
		{
			name: "a found link is the caller's own copy",
			act: func(ctx context.Context, s *oidc.MemoryLinkStore) error {
				if err := s.Insert(ctx, memLink(corpIssuer, "s-1", "u-1")); err != nil {
					return err
				}
				got, err := s.FindByExternal(ctx, "corp", corpIssuer, "s-1")
				if err != nil {
					return err
				}
				got.UserID = "u-2"
				return nil
			},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryLinkStore, err error) {
				require.NoError(t, err)
				got, ferr := s.FindByExternal(ctx, "corp", corpIssuer, "s-1")
				require.NoError(t, ferr)
				assert.Equal(t, identity.UserID("u-1"), got.UserID)
			},
		},
		{
			name: "refusal errors carry no identifying value",
			act: func(ctx context.Context, s *oidc.MemoryLinkStore) error {
				l := memLink(corpIssuer, "subject-xyz", "ref-777")
				l.Username, l.Email = "user-name-abc", "mail@secret.example"
				if err := s.Insert(ctx, l); err != nil {
					return err
				}
				return s.Insert(ctx, l)
			},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryLinkStore, err error) {
				require.ErrorIs(t, err, oidc.ErrLinkExists)
				_, ferr := s.FindByExternal(ctx, "corp", corpIssuer, "subject-missing")
				require.ErrorIs(t, ferr, oidc.ErrLinkNotFound)
				for _, e := range []error{err, ferr} {
					for _, v := range []string{"subject-xyz", "subject-missing", "user-name-abc", "mail@secret.example", "ref-777"} {
						assert.NotContains(t, e.Error(), v)
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			s := oidc.NewMemoryLinkStore()
			err := tc.act(ctx, s)
			tc.assert(t, ctx, s, err)
		})
	}
}
