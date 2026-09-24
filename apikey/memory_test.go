package apikey_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/pkg/id"
)

func TestMemoryKeyStore(t *testing.T) {
	t.Parallel()

	const unknownID = "01930000-0000-7000-8000-00000000ffff"

	rec := func() apikey.Key {
		return apikey.Key{
			ID:           id.MustParse("01930000-0000-7000-8000-000000000001"),
			Principal:    "svc-billing",
			Name:         "nightly export",
			Scopes:       []string{"invoices:read"},
			SecretDigest: []byte("digest"),
			CreatedAt:    time.Now(),
		}
	}

	type testCase struct {
		name   string
		run    func(t *testing.T, s apikey.Store) (any, error)
		assert func(t *testing.T, got any, err error)
	}

	notFound := func(t *testing.T, _ any, err error) {
		assert.ErrorIs(t, err, apikey.ErrKeyNotFound)
	}

	cases := []testCase{
		{
			name: "an unknown key is ErrKeyNotFound",
			run: func(t *testing.T, s apikey.Store) (any, error) {
				return s.Get(t.Context(), id.MustParse(unknownID))
			},
			assert: notFound,
		},
		{
			name: "revoking an unknown key is ErrKeyNotFound",
			run: func(t *testing.T, s apikey.Store) (any, error) {
				return nil, s.Revoke(t.Context(), id.MustParse(unknownID), time.Now())
			},
			assert: notFound,
		},
		{
			name: "touching an unknown key is ErrKeyNotFound",
			run: func(t *testing.T, s apikey.Store) (any, error) {
				return nil, s.TouchLastUsed(t.Context(), id.MustParse(unknownID), time.Now())
			},
			assert: notFound,
		},
		{
			name: "returned scopes are a copy",
			run: func(t *testing.T, s apikey.Store) (any, error) {
				k := rec()
				require.NoError(t, s.Put(t.Context(), k))

				got, err := s.Get(t.Context(), k.ID)
				require.NoError(t, err)
				got.Scopes[0] = "invoices:write"

				return s.Get(t.Context(), k.ID)
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"invoices:read"}, got.(apikey.Key).Scopes)
			},
		},
		{
			name: "returned digests are a copy",
			run: func(t *testing.T, s apikey.Store) (any, error) {
				k := rec()
				require.NoError(t, s.Put(t.Context(), k))

				got, err := s.Get(t.Context(), k.ID)
				require.NoError(t, err)
				got.SecretDigest[0] = 'X'

				return s.Get(t.Context(), k.ID)
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []byte("digest"), got.(apikey.Key).SecretDigest)
			},
		},
		{
			name: "stored scopes are a copy of what was passed in",
			run: func(t *testing.T, s apikey.Store) (any, error) {
				k := rec()
				require.NoError(t, s.Put(t.Context(), k))
				k.Scopes[0] = "invoices:write"

				return s.Get(t.Context(), k.ID)
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"invoices:read"}, got.(apikey.Key).Scopes)
			},
		},
		{
			name: "revocation records the time once and keeps the first",
			run: func(t *testing.T, s apikey.Store) (any, error) {
				k := rec()
				require.NoError(t, s.Put(t.Context(), k))

				first := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
				require.NoError(t, s.Revoke(t.Context(), k.ID, first))
				require.NoError(t, s.Revoke(t.Context(), k.ID, first.Add(time.Hour)))

				return s.Get(t.Context(), k.ID)
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)

				stored, ok := got.(apikey.Key)
				require.True(t, ok)
				require.NotNil(t, stored.RevokedAt)
				assert.True(t, stored.RevokedAt.Equal(time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)),
					"the first revocation is the one that happened")
			},
		},
		{
			name: "listing a principal with no keys is empty, not an error",
			run: func(t *testing.T, s apikey.Store) (any, error) {
				return s.List(t.Context(), "svc-nobody")
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
		{
			name: "listing returns only the principal's own keys, as copies",
			run: func(t *testing.T, s apikey.Store) (any, error) {
				mine := rec()
				require.NoError(t, s.Put(t.Context(), mine))

				theirs := rec()
				theirs.ID = id.MustParse("01930000-0000-7000-8000-000000000002")
				theirs.Principal = "svc-reporting"
				require.NoError(t, s.Put(t.Context(), theirs))

				listed, err := s.List(t.Context(), "svc-billing")
				require.NoError(t, err)
				require.Len(t, listed, 1)
				listed[0].Scopes[0] = "invoices:write"

				return s.List(t.Context(), "svc-billing")
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)

				listed, ok := got.([]apikey.Key)
				require.True(t, ok)
				require.Len(t, listed, 1)
				assert.Equal(t, []string{"invoices:read"}, listed[0].Scopes)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.run(t, apikey.NewMemoryStore())
			tc.assert(t, got, err)
		})
	}
}
