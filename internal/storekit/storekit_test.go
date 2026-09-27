package storekit_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
)

func TestStorable(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		values []string
		assert func(t *testing.T, got bool)
	}

	cases := []testCase{
		{
			name:   "no values",
			assert: func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			name:   "plain and multi-byte text",
			values: []string{"alice", "", "résumé ✓"},
			assert: func(t *testing.T, got bool) { assert.True(t, got) },
		},
		{
			name:   "a nul byte in a later value",
			values: []string{"alice", "a\x00b"},
			assert: func(t *testing.T, got bool) { assert.False(t, got) },
		},
		{
			name:   "invalid utf-8",
			values: []string{"\xff"},
			assert: func(t *testing.T, got bool) { assert.False(t, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.Storable(tc.values...))
		})
	}
}

func TestCheckStorable(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		fields []storekit.Field
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:   "storable fields",
			fields: []storekit.Field{storekit.Text("provider", "acme"), storekit.Text("state", "")},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "names the first unstorable field and never its value",
			fields: []storekit.Field{
				storekit.Text("provider", "acme"),
				storekit.Text("user reference", "se\x00cret"),
				storekit.Text("state", "\xff"),
			},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the user reference holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
				assert.NotContains(t, err.Error(), "se\x00cret")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.CheckStorable(tc.fields...))
		})
	}
}

func TestCheckID(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		id     id.ID
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:   "a minted id",
			id:     id.MustParse("0190a6f1-7c3b-7e2a-9a4d-3c1f2b5e6d7f"),
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:   "the zero id",
			id:     id.Nil,
			assert: func(t *testing.T, err error) { require.EqualError(t, err, "the handoff id is zero") },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.CheckID(tc.id, "handoff"))
		})
	}
}

func TestCheckSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		sess   session.Session
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "a storable session",
			sess: session.Session{
				UserID: "alice", ExternalProvider: "acme", Data: map[string]string{"theme": "dark"},
			},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name: "the enrolment-origin marker",
			sess: session.Session{UserID: "alice", EnrolmentOriginDeadline: now},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err, "the enrolment-origin marker is not supported by this store")
			},
		},
		{
			name: "the enrolment generation",
			sess: session.Session{UserID: "alice", EnrolmentGeneration: id.MustParse("0190a6f1-7c3b-7e2a-9a4d-3c1f2b5e6d7f")},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err, "the enrolment generation is not supported by this store")
			},
		},
		{
			name: "an unstorable column",
			sess: session.Session{UserID: "alice", ExternalIDToken: "a\x00b"},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the external ID token holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
			},
		},
		{
			name: "an unstorable data key",
			sess: session.Session{UserID: "alice", Data: map[string]string{"\xff": "v"}},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the session data holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
			},
		},
		{
			name: "an unstorable data value",
			sess: session.Session{UserID: "alice", Data: map[string]string{"k": "v\x00"}},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the session data holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
			},
		},
		{
			name: "the marker together with the generation and a bad column names the marker",
			sess: session.Session{
				UserID:                  "a\x00b",
				EnrolmentOriginDeadline: now,
				EnrolmentGeneration:     id.MustParse("0190a6f1-7c3b-7e2a-9a4d-3c1f2b5e6d7f"),
			},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err, "the enrolment-origin marker is not supported by this store")
			},
		},
		{
			name: "the generation together with a bad column names the generation",
			sess: session.Session{
				UserID:              "a\x00b",
				EnrolmentGeneration: id.MustParse("0190a6f1-7c3b-7e2a-9a4d-3c1f2b5e6d7f"),
			},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err, "the enrolment generation is not supported by this store")
			},
		},
		{
			name: "two bad columns name the one checked first today: user reference before first factor",
			sess: session.Session{
				UserID:      "a\x00b",
				FirstFactor: "c\x00d",
			},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the user reference holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
			},
		},
		{
			name: "a bad column together with bad data names the column",
			sess: session.Session{
				UserID: "a\x00b",
				Data:   map[string]string{"k": "v\x00"},
			},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the user reference holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.CheckSession(&tc.sess))
		})
	}
}

// stubCipher is a seal.Cipher whose methods are never called: RequireCipher
// only judges whether it is nil.
type stubCipher struct{ seal.Cipher }

func TestRequireCipher(t *testing.T) {
	t.Parallel()

	errConfig := errors.New("adapter: invalid configuration")

	type testCase struct {
		name   string
		cipher seal.Cipher
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		require.ErrorIs(t, err, errConfig)
		assert.EqualError(t, err, "adapter: invalid configuration: the cipher is nil")
	}

	cases := []testCase{
		{
			name:   "a live cipher",
			cipher: &stubCipher{},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:   "a nil cipher",
			assert: refused,
		},
		{
			name:   "a typed nil cipher",
			cipher: (*stubCipher)(nil),
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.RequireCipher(tc.cipher, errConfig))
		})
	}
}

func TestOrEmpty(t *testing.T) {
	t.Parallel()

	got := storekit.OrEmpty(nil)
	require.NotNil(t, got)
	assert.Empty(t, got)

	given := []byte("key")
	assert.Equal(t, given, storekit.OrEmpty(given))
}

func TestOrNone(t *testing.T) {
	t.Parallel()

	got := storekit.OrNone(nil)
	require.NotNil(t, got)
	assert.Empty(t, got)

	given := []string{"read"}
	assert.Equal(t, given, storekit.OrNone(given))
}

func TestTime(t *testing.T) {
	t.Parallel()

	local := time.FixedZone("UTC+7", 7*60*60)
	given := time.Date(2026, 9, 27, 17, 0, 0, 123456789, local)

	got := storekit.Time(given)

	assert.Equal(t, time.UTC, got.Location())
	assert.Equal(t, time.Date(2026, 9, 27, 10, 0, 0, 123456000, time.UTC), got)
}

func TestSecretText(t *testing.T) {
	t.Parallel()

	sealed := []byte{0xfb, 0xff, 0x00, 'a'}

	text := storekit.SecretText(sealed)

	assert.Equal(t, "-_8AYQ", text, "base64url without padding")
	back, err := storekit.SecretFromText(text)
	require.NoError(t, err)
	assert.Equal(t, sealed, back)
}

func TestSecretFromText(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		text   string
		assert func(t *testing.T, got []byte, err error)
	}

	cases := []testCase{
		{
			name: "base64url",
			text: "-_8AYQ",
			assert: func(t *testing.T, got []byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, []byte{0xfb, 0xff, 0x00, 'a'}, got)
			},
		},
		{
			name: "padded or standard base64 is not the stored form",
			text: "+/8AYQ==",
			assert: func(t *testing.T, got []byte, err error) {
				require.EqualError(t, err, "the stored secret is not base64url")
				assert.Nil(t, got)
			},
		},
		{
			name: "padded base64url is refused, not accepted by trimming the padding",
			text: "-_8AYQ==",
			assert: func(t *testing.T, got []byte, err error) {
				require.EqualError(t, err, "the stored secret is not base64url")
				assert.Nil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := storekit.SecretFromText(tc.text)
			tc.assert(t, got, err)
		})
	}
}

func TestNewFlowHandle(t *testing.T) {
	t.Parallel()

	first, err := storekit.NewFlowHandle()
	require.NoError(t, err)
	second, err := storekit.NewFlowHandle()
	require.NoError(t, err)

	raw, err := base64.RawURLEncoding.DecodeString(first)
	require.NoError(t, err, "base64url without padding")
	assert.Len(t, raw, 32)
	assert.NotEqual(t, first, second)
}

func TestSessionDigest(t *testing.T) {
	t.Parallel()

	want := sha256.Sum256([]byte("session-id"))

	assert.Equal(t, want[:], storekit.SessionDigest("session-id"))
}
