package session_test

import (
	"context"
	"encoding/base64"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// csrfPlaintext is the CSRF token the sealing cases carry: recognisable, so a
// token that passed through unsealed is obvious in a failure message.
const csrfPlaintext = "csrf-token-plaintext-0123456789abcdefghijklmn"

// csrfSession is a federated session that also carries a CSRF token.
func csrfSession(id string) *session.Session {
	s := federatedSession(id)
	s.CSRFToken = csrfPlaintext

	return s
}

// countingCipher counts the opens it serves, over fakeCipher.
type countingCipher struct {
	fakeCipher
	opens atomic.Int64
}

func (c *countingCipher) Open(ctx context.Context, ciphertext, additionalData []byte) ([]byte, error) {
	c.opens.Add(1)

	return c.fakeCipher.Open(ctx, ciphertext, additionalData)
}

func TestEncryptedStoreSealsTheCSRFToken(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		run  func(t *testing.T, sealing session.Store, inner *session.MemoryStore)
	}

	cases := []testCase{
		{
			name: "the stored token neither equals nor contains the token, and loads back as it was",
			run: func(t *testing.T, sealing session.Store, inner *session.MemoryStore) {
				created := csrfSession("csrf-sealed")
				require.NoError(t, sealing.Create(t.Context(), created))
				assert.Equal(t, csrfPlaintext, created.CSRFToken, "the caller's own record keeps its plaintext")

				stored, err := inner.Load(t.Context(), "csrf-sealed")
				require.NoError(t, err)
				assert.NotEqual(t, csrfPlaintext, stored.CSRFToken, "the CSRF token was stored in the clear")
				assert.NotContains(t, stored.CSRFToken, csrfPlaintext)
				_, err = base64.RawURLEncoding.DecodeString(stored.CSRFToken)
				require.NoError(t, err, "the envelope is unpadded base64url, so a text column can hold it")
				assert.NotEqual(t, stored.ExternalIDToken, stored.CSRFToken,
					"the token is sealed under its own additional data, apart from the ID token")

				loaded, err := sealing.Load(t.Context(), "csrf-sealed")
				require.NoError(t, err)
				assert.Equal(t, csrfPlaintext, loaded.CSRFToken)
				assert.Equal(t, federatedPlaintext, loaded.ExternalIDToken)
			},
		},
		{
			name: "a successor's copy is sealed for the successor's identifier and opens",
			run: func(t *testing.T, sealing session.Store, inner *session.MemoryStore) {
				require.NoError(t, sealing.Create(t.Context(), csrfSession("csrf-old")))

				successor := csrfSession("csrf-next")
				require.NoError(t, sealing.Supersede(t.Context(), firstRotation("csrf-old", successor)))
				assert.Equal(t, csrfPlaintext, successor.CSRFToken, "the caller's successor keeps its plaintext")

				oldRow, err := inner.Load(t.Context(), "csrf-old")
				require.NoError(t, err)
				nextRow, err := inner.Load(t.Context(), "csrf-next")
				require.NoError(t, err)
				assert.NotContains(t, nextRow.CSRFToken, csrfPlaintext, "the successor's token was stored in the clear")
				assert.NotEqual(t, oldRow.CSRFToken, nextRow.CSRFToken, "the successor's copy is sealed for its own identifier")

				loaded, err := sealing.Load(t.Context(), "csrf-next")
				require.NoError(t, err)
				assert.Equal(t, csrfPlaintext, loaded.CSRFToken)
			},
		},
		{
			name: "a token copied into another session's row is unreadable, and not returned",
			run: func(t *testing.T, sealing session.Store, inner *session.MemoryStore) {
				require.NoError(t, sealing.Create(t.Context(), csrfSession("csrf-victim")))
				victim, err := inner.Load(t.Context(), "csrf-victim")
				require.NoError(t, err)

				thief := familyOf("csrf-thief", storedFamily)
				thief.CSRFToken = victim.CSRFToken
				require.NoError(t, inner.Create(t.Context(), thief))

				loaded, err := sealing.Load(t.Context(), "csrf-thief")
				require.ErrorIs(t, err, session.ErrUnreadable)
				assert.Nil(t, loaded, "a session whose token will not open is not returned")
				assert.NotContains(t, err.Error(), csrfPlaintext)
				assert.NotContains(t, err.Error(), "csrf-thief", "the session identifier is never in an error")
			},
		},
		{
			name: "a stored token that is not an envelope is unreadable",
			run: func(t *testing.T, sealing session.Store, inner *session.MemoryStore) {
				s := familyOf("csrf-garbage", storedFamily)
				s.CSRFToken = "not base64url!"
				require.NoError(t, inner.Create(t.Context(), s))

				loaded, err := sealing.Load(t.Context(), "csrf-garbage")
				require.ErrorIs(t, err, session.ErrUnreadable)
				assert.Nil(t, loaded)
			},
		},
		{
			name: "no token is stored unsealed, as nothing",
			run: func(t *testing.T, sealing session.Store, inner *session.MemoryStore) {
				require.NoError(t, sealing.Create(t.Context(), federatedSession("csrf-none")))

				stored, err := inner.Load(t.Context(), "csrf-none")
				require.NoError(t, err)
				assert.Empty(t, stored.CSRFToken, "an envelope was written where there was nothing to seal")

				loaded, err := sealing.Load(t.Context(), "csrf-none")
				require.NoError(t, err)
				assert.Empty(t, loaded.CSRFToken)
			},
		},
		{
			name: "a save keeps the stored token, and never writes it in the clear",
			run: func(t *testing.T, sealing session.Store, inner *session.MemoryStore) {
				require.NoError(t, sealing.Create(t.Context(), csrfSession("csrf-save")))
				before, err := inner.Load(t.Context(), "csrf-save")
				require.NoError(t, err)

				changed := csrfSession("csrf-save")
				changed.CSRFToken = "another-token-in-the-clear"
				require.NoError(t, sealing.Save(t.Context(), changed))
				assert.Equal(t, "another-token-in-the-clear", changed.CSRFToken, "the caller's record is untouched")

				after, err := inner.Load(t.Context(), "csrf-save")
				require.NoError(t, err)
				assert.Equal(t, before.CSRFToken, after.CSRFToken)

				loaded, err := sealing.Load(t.Context(), "csrf-save")
				require.NoError(t, err)
				assert.Equal(t, csrfPlaintext, loaded.CSRFToken)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sealing, inner := sealingStore(t, 0x2a)
			tc.run(t, sealing, inner)
		})
	}
}

// TestEncryptedStoreListByUser pins that the sealing store lists through the
// inner store, opens no sealed field, and hands no envelope back.
func TestEncryptedStoreListByUser(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		key    byte
		assert func(t *testing.T, listed []*session.Session, opens int64, err error)
	}

	cases := []testCase{
		{
			name: "lists the inner store's sessions without opening anything",
			key:  0x2a,
			assert: func(t *testing.T, listed []*session.Session, opens int64, err error) {
				require.NoError(t, err)
				require.Len(t, listed, 1)
				assert.Equal(t, "csrf-listed", listed[0].ID)
				assert.Equal(t, int64(0), opens, "a listing opens no sealed field")
				assert.Empty(t, listed[0].CSRFToken, "no envelope is handed back as a token")
				assert.Empty(t, listed[0].ExternalIDToken, "no envelope is handed back as an ID token")
				assert.Equal(t, "okta", listed[0].ExternalProvider)
			},
		},
		{
			name: "lists even when the sealing key has been retired",
			key:  0x51,
			assert: func(t *testing.T, listed []*session.Session, opens int64, err error) {
				require.NoError(t, err)
				require.Len(t, listed, 1)
				assert.Equal(t, int64(0), opens)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			writer, inner := sealingStore(t, 0x2a)
			require.NoError(t, writer.Create(t.Context(), csrfSession("csrf-listed")))

			c := &countingCipher{fakeCipher: fakeCipher{key: tc.key}}
			reader := must.Must(session.NewEncryptedStore(inner, c))

			listed, err := reader.ListByUser(t.Context(), testUser, createdAt)
			tc.assert(t, listed, c.opens.Load(), err)
		})
	}
}
