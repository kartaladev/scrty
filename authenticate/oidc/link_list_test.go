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
