package apikey_test

import (
	"crypto/sha512"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/pkg/id"
)

// TestAPIKeyConsumerOverrides covers the other half of every default: that a
// consumer can replace it without forking the library, and that the
// replacement is what both issuance and verification then use.
//
// Each subtest wires a structurally different manager — two managers, a
// replaced digest, a counting store, a fixed clock — so these are subtests
// rather than rows of one table.
func TestAPIKeyConsumerOverrides(t *testing.T) {
	t.Parallel()

	t.Run("a consumer prefix, and a key from another prefix is refused without a lookup", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		def, err := apikey.NewManager()
		require.NoError(t, err)

		underDefault, _, err := def.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		store := &countingKeyStore{Store: apikey.NewMemoryStore()}

		acme, err := apikey.NewManager(apikey.WithPrefix("acme"), apikey.WithStore(store))
		require.NoError(t, err)

		underAcme, _, err := acme.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(underAcme, "acme_"), "got %q", underAcme)

		before := store.Reads()

		_, _, err = acme.Verify(ctx, underDefault)
		assert.ErrorIs(t, err, apikey.ErrVerificationFailed)
		assert.Equal(t, before, store.Reads(), "a wrong prefix costs no lookup")
	})

	t.Run("a consumer digest is used for issuance and verification", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		digest := func(b []byte) []byte {
			sum := sha512.Sum512(b)

			return sum[:]
		}

		store := apikey.NewMemoryStore()

		m, err := apikey.NewManager(apikey.WithStore(store), apikey.WithDigest(digest))
		require.NoError(t, err)

		presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		_, secret, _ := strings.Cut(strings.TrimPrefix(presented, "sk_"), ".")

		raw, err := base64.RawURLEncoding.DecodeString(secret)
		require.NoError(t, err)

		stored, err := store.Get(ctx, rec.ID)
		require.NoError(t, err)
		assert.Equal(t, digest(raw), stored.SecretDigest)

		_, _, err = m.Verify(ctx, presented)
		assert.NoError(t, err)
	})

	t.Run("the default digest is SHA-256 of the secret", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		store := apikey.NewMemoryStore()

		m, err := apikey.NewManager(apikey.WithStore(store))
		require.NoError(t, err)

		presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		_, secret, _ := strings.Cut(strings.TrimPrefix(presented, "sk_"), ".")

		raw, err := base64.RawURLEncoding.DecodeString(secret)
		require.NoError(t, err)

		stored, err := store.Get(ctx, rec.ID)
		require.NoError(t, err)

		want := sha256Of(raw)
		assert.Equal(t, want, stored.SecretDigest)
		assert.NotContains(t, string(stored.SecretDigest), secret)
	})

	t.Run("a consumer store serves every operation", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		store := &countingKeyStore{Store: apikey.NewMemoryStore()}

		m, err := apikey.NewManager(apikey.WithStore(store))
		require.NoError(t, err)

		presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		_, _, err = m.Verify(ctx, presented)
		require.NoError(t, err)

		_, err = m.List(ctx, "svc-billing")
		require.NoError(t, err)

		_, _, err = m.Rotate(ctx, rec.ID, 0)
		require.NoError(t, err)

		assert.Positive(t, store.Writes())
		assert.Positive(t, store.Reads())
		assert.Positive(t, store.Lists())
	})

	t.Run("a consumer identifier generator mints the record identifiers", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		want := id.MustParse("01930000-0000-7000-8000-0000000000aa")

		m, err := apikey.NewManager(apikey.WithIDGenerator(fixedIDs{want}))
		require.NoError(t, err)

		presented, rec, err := m.Issue(ctx, "svc-billing", "k", nil, 0)
		require.NoError(t, err)

		assert.Equal(t, want, rec.ID)
		assert.True(t, strings.HasPrefix(presented, "sk_"+want.String()+"."), "got %q", presented)
	})

	t.Run("a consumer clock decides issue time and expiry", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		at := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

		m, err := apikey.NewManager(apikey.WithClock(clockwork.NewFakeClockAt(at)))
		require.NoError(t, err)

		_, rec, err := m.Issue(ctx, "svc-billing", "k", nil, time.Hour)
		require.NoError(t, err)

		assert.True(t, rec.CreatedAt.Equal(at))
		require.NotNil(t, rec.ExpiresAt)
		assert.True(t, rec.ExpiresAt.Equal(at.Add(time.Hour)))
	})
}

// fixedIDs is a generator that always mints the same identifier.
type fixedIDs struct {
	value id.ID
}

func (g fixedIDs) NewID() (id.ID, error) { return g.value, nil }
