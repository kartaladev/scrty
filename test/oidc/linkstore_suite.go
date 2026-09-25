package oidctest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

// linkSuiteIssuer is the issuer most rows link under.
const linkSuiteIssuer = "https://corp.example"

// linkSuiteRacers is how many concurrent inserts of one key the race row
// starts.
const linkSuiteRacers = 8

// linkSuiteLink returns a link for provider corp's subject at issuer, naming
// user.
func linkSuiteLink(issuer, subject string, user identity.UserID) oidc.Link {
	return oidc.Link{
		Provider: "corp", Issuer: issuer, Subject: subject,
		UserID: user, Username: "alice", Email: "alice@corp.example",
		CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// RunLinkStoreSuite checks a LinkStore against the contract the library's
// broker relies on: a link is found only by provider, issuer and subject
// together; an insert of a key that is already linked is refused with
// oidc.ErrLinkExists, identical re-inserts and concurrent inserts included,
// and leaves the stored link unchanged; deleting a user's links reports how
// many went and matches the reference byte for byte; references and usernames
// round-trip unchanged; and refusal errors quote no identifying value.
//
// newStore is called once per case and must return an empty store. A consumer
// implementing LinkStore over their own tables calls this from a test in their
// own module.
func RunLinkStoreSuite(t *testing.T, newStore func(t *testing.T) oidc.LinkStore) {
	t.Helper()

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, s oidc.LinkStore)
	}

	cases := []testCase{
		{
			name: "a conflicting insert is refused and the stored link is unchanged",
			assert: func(t *testing.T, ctx context.Context, s oidc.LinkStore) {
				require.NoError(t, s.Insert(ctx, linkSuiteLink(linkSuiteIssuer, "s-1", "u-1")))
				require.ErrorIs(t, s.Insert(ctx, linkSuiteLink(linkSuiteIssuer, "s-1", "u-2")), oidc.ErrLinkExists)

				got, err := s.FindByExternal(ctx, "corp", linkSuiteIssuer, "s-1")
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, identity.UserID("u-1"), got.UserID)
			},
		},
		{
			name: "an identical re-insert is refused",
			assert: func(t *testing.T, ctx context.Context, s oidc.LinkStore) {
				l := linkSuiteLink(linkSuiteIssuer, "s-1", "u-1")
				require.NoError(t, s.Insert(ctx, l))
				require.ErrorIs(t, s.Insert(ctx, l), oidc.ErrLinkExists)
			},
		},
		{
			name: "the same subject at another issuer is another key",
			assert: func(t *testing.T, ctx context.Context, s oidc.LinkStore) {
				require.NoError(t, s.Insert(ctx, linkSuiteLink("https://a.example", "12345", "u-1")))
				require.NoError(t, s.Insert(ctx, linkSuiteLink("https://b.example", "12345", "u-2")))

				a, err := s.FindByExternal(ctx, "corp", "https://a.example", "12345")
				require.NoError(t, err)
				b, err := s.FindByExternal(ctx, "corp", "https://b.example", "12345")
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-1"), a.UserID)
				assert.Equal(t, identity.UserID("u-2"), b.UserID)
			},
		},
		{
			name: "find of a missing key is link not found",
			assert: func(t *testing.T, ctx context.Context, s oidc.LinkStore) {
				require.NoError(t, s.Insert(ctx, linkSuiteLink(linkSuiteIssuer, "s-1", "u-1")))

				_, err := s.FindByExternal(ctx, "corp", linkSuiteIssuer, "s-2")
				require.ErrorIs(t, err, oidc.ErrLinkNotFound)
				_, err = s.FindByExternal(ctx, "corp", "https://other.example", "s-1")
				require.ErrorIs(t, err, oidc.ErrLinkNotFound)
			},
		},
		{
			name: "deleting a user's links returns the count",
			assert: func(t *testing.T, ctx context.Context, s oidc.LinkStore) {
				social := linkSuiteLink("https://social.example", "s-9", "u-1")
				social.Provider = "social"
				require.NoError(t, s.Insert(ctx, linkSuiteLink(linkSuiteIssuer, "s-1", "u-1")))
				require.NoError(t, s.Insert(ctx, social))
				require.NoError(t, s.Insert(ctx, linkSuiteLink(linkSuiteIssuer, "s-2", "u-2")))

				n, err := s.DeleteByUser(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 2, n)

				_, err = s.FindByExternal(ctx, "corp", linkSuiteIssuer, "s-1")
				assert.ErrorIs(t, err, oidc.ErrLinkNotFound)
				_, err = s.FindByExternal(ctx, "social", "https://social.example", "s-9")
				assert.ErrorIs(t, err, oidc.ErrLinkNotFound)

				kept, err := s.FindByExternal(ctx, "corp", linkSuiteIssuer, "s-2")
				require.NoError(t, err, "another user's link is untouched")
				assert.Equal(t, identity.UserID("u-2"), kept.UserID)
			},
		},
		{
			name: "deleting matches the user reference byte for byte",
			assert: func(t *testing.T, ctx context.Context, s oidc.LinkStore) {
				require.NoError(t, s.Insert(ctx, linkSuiteLink(linkSuiteIssuer, "s-1", "u-1")))
				require.NoError(t, s.Insert(ctx, linkSuiteLink(linkSuiteIssuer, "s-2", "U-1")))

				n, err := s.DeleteByUser(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 1, n)

				kept, err := s.FindByExternal(ctx, "corp", linkSuiteIssuer, "s-2")
				require.NoError(t, err, "a reference differing only in case is another user")
				assert.Equal(t, identity.UserID("U-1"), kept.UserID)
			},
		},
		{
			name: "references and usernames round-trip byte for byte",
			assert: func(t *testing.T, ctx context.Context, s oidc.LinkStore) {
				l := linkSuiteLink(linkSuiteIssuer, "s-1", "U-1 ")
				l.Username = " Ada@Example.COM"
				require.NoError(t, s.Insert(ctx, l))

				got, err := s.FindByExternal(ctx, "corp", linkSuiteIssuer, "s-1")
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("U-1 "), got.UserID)
				assert.Equal(t, " Ada@Example.COM", got.Username)
			},
		},
		{
			name: "refusal errors carry no identifying value",
			assert: func(t *testing.T, ctx context.Context, s oidc.LinkStore) {
				l := linkSuiteLink(linkSuiteIssuer, "subject-xyz", "ref-777")
				l.Username, l.Email = "user-name-abc", "mail@secret.example"
				require.NoError(t, s.Insert(ctx, l))

				exists := s.Insert(ctx, l)
				require.ErrorIs(t, exists, oidc.ErrLinkExists)
				_, missing := s.FindByExternal(ctx, "corp", linkSuiteIssuer, "subject-missing")
				require.ErrorIs(t, missing, oidc.ErrLinkNotFound)

				for _, e := range []error{exists, missing} {
					for _, v := range []string{"subject-xyz", "subject-missing", "user-name-abc", "mail@secret.example", "ref-777"} {
						assert.NotContains(t, e.Error(), v)
					}
				}
			},
		},
		{
			name: "concurrent inserts of one key: exactly one succeeds",
			assert: func(t *testing.T, ctx context.Context, s oidc.LinkStore) {
				var (
					start = make(chan struct{})
					wg    sync.WaitGroup
					errs  = make([]error, linkSuiteRacers)
				)
				for i := range linkSuiteRacers {
					wg.Go(func() {
						<-start
						// i ranges over linkSuiteRacers (0..7); %c formats 'a'+i as a
						// character without an explicit int->rune conversion.
						errs[i] = s.Insert(ctx, linkSuiteLink(linkSuiteIssuer, "s-1", identity.UserID(fmt.Sprintf("u-%c", 'a'+i))))
					})
				}
				close(start)
				wg.Wait()

				won, lost := -1, 0
				for i, err := range errs {
					switch {
					case err == nil:
						assert.Equal(t, -1, won, "a second insert of one key succeeded")
						won = i
					case errors.Is(err, oidc.ErrLinkExists):
						lost++
					default:
						t.Errorf("insert %d failed with %v, not the link-exists outcome", i, err)
					}
				}
				require.NotEqual(t, -1, won, "no insert succeeded")
				assert.Equal(t, linkSuiteRacers-1, lost)

				got, err := s.FindByExternal(ctx, "corp", linkSuiteIssuer, "s-1")
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-"+string(rune('a'+won))), got.UserID,
					"the stored link is the one whose insert succeeded")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			tc.assert(t, t.Context(), newStore(t))
		})
	}
}
