package apikey_test

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
)

func TestManagerIssue(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		principal identity.UserID
		lifetime  time.Duration
		random    io.Reader
		assert    func(t *testing.T, presented string, rec apikey.Key, err error, stored int)
	}

	cases := []testCase{
		{
			name:      "the presented key carries the prefix, the id and the secret",
			principal: "svc-billing",
			assert: func(t *testing.T, presented string, rec apikey.Key, err error, stored int) {
				require.NoError(t, err)
				assert.Equal(t, 1, stored)

				assert.True(t, strings.HasPrefix(presented, "sk_"), "got %q", presented)

				rest := strings.TrimPrefix(presented, "sk_")
				idPart, secretPart, found := strings.Cut(rest, ".")
				require.True(t, found)
				assert.Equal(t, rec.ID.String(), idPart)

				raw, decErr := base64.RawURLEncoding.DecodeString(secretPart)
				require.NoError(t, decErr)
				assert.Len(t, raw, 32, "32 bytes from the OS random source")

				assert.Equal(t, identity.UserID("svc-billing"), rec.Principal)
				assert.Equal(t, "nightly export", rec.Name)
				assert.Equal(t, []string{"invoices:read", "invoices:export"}, rec.Scopes)
				assert.NotContains(t, fmt.Sprintf("%+v", rec), secretPart,
					"the record must not carry the secret")

				assert.Nil(t, rec.ExpiresAt, "a lifetime of zero never expires")
				assert.Nil(t, rec.RevokedAt)
				assert.Nil(t, rec.LastUsedAt)
			},
		},
		{
			name:      "a positive lifetime expires at issue time plus it",
			principal: "svc-billing",
			lifetime:  7 * 24 * time.Hour,
			assert: func(t *testing.T, _ string, rec apikey.Key, err error, _ int) {
				require.NoError(t, err)
				require.NotNil(t, rec.ExpiresAt)
				assert.True(t, rec.ExpiresAt.Equal(rec.CreatedAt.Add(7*24*time.Hour)))
			},
		},
		{
			name:      "a negative lifetime never expires",
			principal: "svc-billing",
			lifetime:  -time.Hour,
			assert: func(t *testing.T, _ string, rec apikey.Key, err error, _ int) {
				require.NoError(t, err)
				assert.Nil(t, rec.ExpiresAt, "a lifetime of zero or less means no expiry")
			},
		},
		{
			name:      "an empty principal is refused and stores nothing",
			principal: "",
			assert: func(t *testing.T, presented string, _ apikey.Key, err error, stored int) {
				require.Error(t, err)
				assert.Empty(t, presented)
				assert.Zero(t, stored)
			},
		},
		{
			name:      "a random source failure stores nothing",
			principal: "svc-billing",
			random:    failingReader{},
			assert: func(t *testing.T, presented string, _ apikey.Key, err error, stored int) {
				require.Error(t, err)
				assert.Empty(t, presented)
				assert.Zero(t, stored, "the store must receive no write")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			store := &countingKeyStore{Store: apikey.NewMemoryStore()}

			opts := []apikey.Option{apikey.WithStore(store)}
			if tc.random != nil {
				opts = append(opts, apikey.WithRandom(tc.random))
			}

			m, err := apikey.NewManager(opts...)
			require.NoError(t, err)

			presented, rec, issueErr := m.Issue(ctx, tc.principal, "nightly export",
				[]string{"invoices:read", "invoices:export"}, tc.lifetime)

			tc.assert(t, presented, rec, issueErr, store.Writes())
		})
	}
}

func TestListRevealsNoSecret(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	m, err := apikey.NewManager()
	require.NoError(t, err)

	presented, _, err := m.Issue(ctx, "svc-billing", "nightly export", []string{"invoices:read"}, 0)
	require.NoError(t, err)

	_, secret, _ := strings.Cut(strings.TrimPrefix(presented, "sk_"), ".")
	require.NotEmpty(t, secret)

	keys, err := m.List(ctx, "svc-billing")
	require.NoError(t, err)
	require.Len(t, keys, 1)

	assert.NotContains(t, fmt.Sprintf("%+v", keys[0]), secret)
}

func TestIssuedScopesAreACopy(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	m, err := apikey.NewManager()
	require.NoError(t, err)

	scopes := []string{"invoices:read"}

	_, rec, err := m.Issue(ctx, "svc-billing", "nightly export", scopes, 0)
	require.NoError(t, err)

	scopes[0] = "invoices:write"

	assert.Equal(t, []string{"invoices:read"}, rec.Scopes,
		"the caller's slice must not reach into the issued record")
}
