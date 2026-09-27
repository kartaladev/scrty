package seal_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
)

const idToken = "eyJhbGciOiJSUzI1NiJ9.ID-TOKEN-SENTINEL.signature" //nolint:gosec // G101: a fixture, not a credential

// federated returns a live session carrying a provider ID token.
func federated(id, token string) *session.Session {
	now := time.Now().UTC()

	return &session.Session{
		ID:                id,
		UserID:            "alice",
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(30 * time.Minute),
		AbsoluteExpiresAt: now.Add(12 * time.Hour),
		ExternalProvider:  "okta",
		ExternalIssuer:    "https://issuer.example",
		ExternalIDToken:   token,
	}
}

func TestSessionCipher(t *testing.T) {
	t.Parallel()

	c := mustCipher(t, seal.WithEncryptionKey("k2", keyTwo))

	type testCase struct {
		name   string
		cipher seal.Cipher
		assert func(t *testing.T, sealing session.Store, inner *session.MemoryStore, err error)
	}

	cases := []testCase{
		{
			name:   "a sealed ID token round-trips",
			cipher: c,
			assert: func(t *testing.T, sealing session.Store, _ *session.MemoryStore, err error) {
				require.NoError(t, err)
				require.NoError(t, sealing.Create(t.Context(), federated("sess-a", idToken)))

				got, err := sealing.Load(t.Context(), "sess-a")
				require.NoError(t, err)
				assert.Equal(t, idToken, got.ExternalIDToken)
			},
		},
		{
			name:   "the inner store holds a sealed value, not the token",
			cipher: c,
			assert: func(t *testing.T, sealing session.Store, inner *session.MemoryStore, err error) {
				require.NoError(t, err)
				require.NoError(t, sealing.Create(t.Context(), federated("sess-a", idToken)))

				raw, err := inner.Load(t.Context(), "sess-a")
				require.NoError(t, err)
				assert.NotEqual(t, idToken, raw.ExternalIDToken)
				assert.NotContains(t, raw.ExternalIDToken, "ID-TOKEN-SENTINEL")

				envelope, err := base64.RawURLEncoding.DecodeString(raw.ExternalIDToken)
				require.NoError(t, err)
				assert.NotContains(t, string(envelope), "ID-TOKEN-SENTINEL")
			},
		},
		{
			name:   "an ID token moved to another session is unreadable",
			cipher: c,
			assert: func(t *testing.T, sealing session.Store, inner *session.MemoryStore, err error) {
				require.NoError(t, err)
				require.NoError(t, sealing.Create(t.Context(), federated("sess-victim", idToken)))
				require.NoError(t, sealing.Create(t.Context(), federated("sess-attacker", "attacker-token")))

				victim, err := inner.Load(t.Context(), "sess-victim")
				require.NoError(t, err)
				attacker, err := inner.Load(t.Context(), "sess-attacker")
				require.NoError(t, err)

				// Written straight into the inner store, as someone with write
				// access to the table but no key would.
				attacker.ExternalIDToken = victim.ExternalIDToken
				require.NoError(t, inner.Save(t.Context(), attacker))

				got, err := sealing.Load(t.Context(), "sess-attacker")
				require.ErrorIs(t, err, session.ErrSessionUnreadable)
				assert.NotErrorIs(t, err, session.ErrSessionNotFound)
				assert.Nil(t, got)
				assert.NotContains(t, err.Error(), idToken)
			},
		},
		{
			name: "a nil cipher leaves the sealing store unbuilt",
			assert: func(t *testing.T, sealing session.Store, _ *session.MemoryStore, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, sealing)
			},
		},
		{
			name:   "a typed-nil cipher leaves the sealing store unbuilt",
			cipher: (*MockCipher)(nil),
			assert: func(t *testing.T, sealing session.Store, _ *session.MemoryStore, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, sealing)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inner := session.NewMemoryStore()
			sealing, err := session.NewEncryptedStore(inner, seal.SessionCipher(tc.cipher))
			tc.assert(t, sealing, inner, err)
		})
	}
}
