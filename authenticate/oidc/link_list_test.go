package oidc_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

func TestMemoryLinkStore_ListByUser(t *testing.T) {
	t.Parallel()

	n := 0
	link := func(provider, issuer, subject string, user identity.UserID) oidc.Link {
		n++
		return oidc.Link{
			ID: id.MustParse(fmt.Sprintf("01926a4e-0000-7000-8000-%012x", n)), Provider: provider, Issuer: issuer, Subject: subject,
			UserID: user, Username: string(user) + "-name", Email: subject + "@corp.example",
		}
	}
	seeded := []oidc.Link{
		link("partner", "https://partner.example", "p-1", "u-7"),
		link("corp", brokerCorpIssuer, "s-2", "u-7"),
		link("corp", brokerCorpIssuer, "s-1", "u-7"),
		link("corp", brokerCorpIssuer, "s-3", "u-8"),
		// A user reference that differs from u-7 only in letter case is
		// another user.
		link("corp", brokerCorpIssuer, "s-4", "U-7"),
	}
	newStore := func(t *testing.T) *oidc.MemoryLinkStore {
		t.Helper()
		s := oidc.NewMemoryLinkStore()
		for _, l := range seeded {
			require.NoError(t, s.Insert(t.Context(), l))
		}
		return s
	}

	type testCase struct {
		name   string
		user   identity.UserID
		assert func(t *testing.T, s *oidc.MemoryLinkStore, got []oidc.Link, err error)
	}

	cases := []testCase{
		{
			name: "every link naming the user, across providers, sorted, fields unchanged",
			user: "u-7",
			assert: func(t *testing.T, _ *oidc.MemoryLinkStore, got []oidc.Link, err error) {
				require.NoError(t, err)
				assert.Equal(t, []oidc.Link{seeded[2], seeded[1], seeded[0]}, got)
			},
		},
		{
			name: "a user with no link is an empty list and no error",
			user: "u-9",
			assert: func(t *testing.T, _ *oidc.MemoryLinkStore, got []oidc.Link, err error) {
				require.NoError(t, err)
				assert.NotNil(t, got)
				assert.Empty(t, got)
			},
		},
		{
			name: "the returned slice is the caller's own",
			user: "u-8",
			assert: func(t *testing.T, s *oidc.MemoryLinkStore, got []oidc.Link, err error) {
				require.NoError(t, err)
				require.Len(t, got, 1)
				got[0].UserID = "u-9"
				again, err := s.ListByUser(t.Context(), "u-8")
				require.NoError(t, err)
				assert.Equal(t, []oidc.Link{seeded[3]}, again)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newStore(t)
			got, err := s.ListByUser(t.Context(), tc.user)
			tc.assert(t, s, got, err)
		})
	}
}

func TestMemoryLinkStore_DeleteLink(t *testing.T) {
	t.Parallel()

	corp := oidc.Link{
		ID: id.MustParse("01926a4e-0000-7000-8000-000000000001"), Provider: "corp", Issuer: brokerCorpIssuer, Subject: "s-1",
		UserID: "u-7", Username: "u-7-name", Email: "s-1@corp.example",
	}
	partner := oidc.Link{
		ID: id.MustParse("01926a4e-0000-7000-8000-000000000002"), Provider: "partner", Issuer: "https://partner.example", Subject: "p-1",
		UserID: "u-7", Username: "u-7-name", Email: "p-1@partner.example",
	}
	with := func(l oidc.Link, edit func(*oidc.Link)) oidc.Link { edit(&l); return l }

	zero := oidc.Link{
		Provider: "zero", Issuer: "https://zero.example", Subject: "z-1",
		UserID: "u-7", Username: "u-7-name", Email: "z-1@zero.example",
	}

	type testCase struct {
		name   string
		stored []oidc.Link
		delete oidc.Link
		assert func(t *testing.T, remaining []oidc.Link, removed bool, err error)
	}

	unchanged := func(t *testing.T, remaining []oidc.Link, removed bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.False(t, removed)
		assert.Equal(t, []oidc.Link{corp, partner}, remaining)
	}

	cases := []testCase{
		{
			name:   "a stored zero-ID link survives a zero-ID delete",
			stored: []oidc.Link{zero},
			delete: zero,
			assert: func(t *testing.T, remaining []oidc.Link, removed bool, err error) {
				assert.False(t, removed)
				assert.Equal(t, []oidc.Link{corp, partner, zero}, remaining)
			},
		},
		{
			name:   "the link with this ID and identity is removed and the user's other link stays",
			delete: corp,
			assert: func(t *testing.T, remaining []oidc.Link, removed bool, err error) {
				require.NoError(t, err)
				assert.True(t, removed)
				assert.Equal(t, []oidc.Link{partner}, remaining)
			},
		},
		{
			name:   "the ID with another subject removes nothing",
			delete: with(corp, func(l *oidc.Link) { l.Subject = "s-2" }),
			assert: unchanged,
		},
		{
			name:   "the identity with another ID removes nothing",
			delete: with(corp, func(l *oidc.Link) { l.ID = id.MustParse("01926a4e-0000-7000-8000-000000000009") }),
			assert: unchanged,
		},
		{
			name:   "the ID and subject under another provider remove nothing",
			delete: with(corp, func(l *oidc.Link) { l.Provider = "partner" }),
			assert: unchanged,
		},
		{
			name:   "the ID and subject under another issuer remove nothing",
			delete: with(corp, func(l *oidc.Link) { l.Issuer = "https://other.example" }),
			assert: unchanged,
		},
		{
			name: "the user reference and other recorded fields are not part of the match",
			delete: with(corp, func(l *oidc.Link) {
				l.UserID, l.Username, l.Email = "u-9", "", ""
			}),
			assert: func(t *testing.T, remaining []oidc.Link, removed bool, err error) {
				require.NoError(t, err)
				assert.True(t, removed)
				assert.Equal(t, []oidc.Link{partner}, remaining)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := oidc.NewMemoryLinkStore()
			require.NoError(t, s.Insert(t.Context(), corp))
			require.NoError(t, s.Insert(t.Context(), partner))
			for _, l := range tc.stored {
				require.NoError(t, s.Insert(t.Context(), l))
			}

			removed, err := s.DeleteLink(t.Context(), tc.delete)
			remaining, lerr := s.ListByUser(t.Context(), "u-7")
			require.NoError(t, lerr)
			tc.assert(t, remaining, removed, err)
		})
	}
}
