package storekit_test

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/seal"
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
			name:   "a session carrying the enrolment-origin marker is accepted",
			sess:   session.Session{UserID: "alice", EnrolmentOriginDeadline: now},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:   "a session carrying an enrolment generation is accepted",
			sess:   session.Session{UserID: "alice", EnrolmentGeneration: id.MustParse("0190a6f1-7c3b-7e2a-9a4d-3c1f2b5e6d7f")},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
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
			name: "the marker and the generation together with a bad column name the column",
			sess: session.Session{
				UserID:                  "a\x00b",
				EnrolmentOriginDeadline: now,
				EnrolmentGeneration:     id.MustParse("0190a6f1-7c3b-7e2a-9a4d-3c1f2b5e6d7f"),
			},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the user reference holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
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
			name: "an amr value PostgreSQL cannot store is refused by field",
			sess: session.Session{UserID: "alice", FederatedAMR: []string{"pwd", "m\x00fa"}},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the federated amr holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
			},
		},
		{
			name: "an acr PostgreSQL cannot store is refused by field",
			sess: session.Session{UserID: "alice", FederatedACR: "\xff"},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the federated acr holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
			},
		},
		{
			name:   "storable assurance is accepted",
			sess:   session.Session{UserID: "alice", FederatedAMR: []string{"pwd", "mfa"}, FederatedACR: "urn:corp:loa:2"},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
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

func TestCheckAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		prefix string
		amr    []string
		acr    string
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "no assurance is storable",
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "an amr and an acr of plain text are storable",
			amr:  []string{"pwd"},
			acr:  "urn:x",
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "an amr holding a NUL byte is refused, naming the field",
			amr:  []string{"a\x00"},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the amr holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
			},
		},
		{
			name: "an acr holding a NUL byte is refused, naming the field",
			acr:  "a\x00",
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the acr holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
			},
		},
		{
			name:   "the prefix leads the refused field's name",
			prefix: "federated ",
			acr:    "a\x00",
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the federated acr holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.CheckAssurance(tc.prefix, tc.amr, tc.acr))
		})
	}
}

func TestAMRColumn(t *testing.T) {
	t.Parallel()

	for _, none := range [][]string{nil, {}} {
		encoded, err := storekit.EncodeAMR(none)
		require.NoError(t, err)
		assert.Equal(t, "[]", encoded, "no values are the empty array, never null")
	}

	encoded, err := storekit.EncodeAMR([]string{"pwd", "mfa"})
	require.NoError(t, err)
	assert.Equal(t, `["pwd","mfa"]`, encoded)

	got, err := storekit.DecodeAMR([]byte(encoded))
	require.NoError(t, err)
	assert.Equal(t, []string{"pwd", "mfa"}, got, "order is kept")

	got, err = storekit.DecodeAMR([]byte("[]"))
	require.NoError(t, err)
	assert.Nil(t, got, "an empty array reads back as none, nil")

	_, err = storekit.DecodeAMR([]byte(`{"a":1}`))
	require.EqualError(t, err, "the stored amr is not a JSON array of strings")
}

func TestParseUserID(t *testing.T) {
	t.Parallel()

	const canonical = "0190a5b2-7c3e-7d4f-8a1b-2c3d4e5f6a7b"

	type testCase struct {
		name   string
		ref    identity.UserID
		assert func(t *testing.T, got id.ID, ok bool)
	}

	cases := []testCase{
		{
			name: "canonical lowercase UUID",
			ref:  canonical,
			assert: func(t *testing.T, got id.ID, ok bool) {
				require.True(t, ok)
				assert.Equal(t, canonical, got.String())
			},
		},
		{
			name: "uppercase spelling of a valid UUID names no user",
			ref:  "0190A5B2-7C3E-7D4F-8A1B-2C3D4E5F6A7B",
			assert: func(t *testing.T, got id.ID, ok bool) {
				assert.False(t, ok)
				assert.Equal(t, id.Nil, got)
			},
		},
		{
			name: "malformed text",
			ref:  "not-a-uuid",
			assert: func(t *testing.T, got id.ID, ok bool) {
				assert.False(t, ok)
				assert.Equal(t, id.Nil, got)
			},
		},
		{
			name: "empty reference",
			ref:  "",
			assert: func(t *testing.T, got id.ID, ok bool) {
				assert.False(t, ok)
				assert.Equal(t, id.Nil, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := storekit.ParseUserID(tc.ref)
			tc.assert(t, got, ok)
		})
	}
}

func TestCheckUser(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		username string
		change   *identity.UserChange
		assert   func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:     "storable text",
			username: "alice",
			change:   &identity.UserChange{Name: "Alice", Roles: []string{"admin", "editor"}},
			assert:   func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			name:     "no roles",
			username: "alice",
			change:   &identity.UserChange{},
			assert:   func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			name:     "username with a NUL byte",
			username: "bob\x00x",
			change:   &identity.UserChange{Name: "Alice"},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the username holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
			},
		},
		{
			name:     "name with invalid UTF-8",
			username: "alice",
			change:   &identity.UserChange{Name: "\xff"},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the name holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
			},
		},
		{
			name:     "role with a NUL byte",
			username: "alice",
			change:   &identity.UserChange{Name: "Alice", Roles: []string{"admin", "ed\x00itor"}},
			assert: func(t *testing.T, err error) {
				require.EqualError(t, err,
					"the role holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.CheckUser(tc.username, tc.change))
		})
	}
}

func TestSurvivingRoles(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		names  []string
		assert func(t *testing.T, got []string)
	}

	cases := []testCase{
		{
			name:   "nil input yields an empty, non-nil slice",
			assert: func(t *testing.T, got []string) { assert.Equal(t, []string{}, got) },
		},
		{
			name:   "order is kept",
			names:  []string{"viewer", "admin", "editor"},
			assert: func(t *testing.T, got []string) { assert.Equal(t, []string{"viewer", "admin", "editor"}, got) },
		},
		{
			name:   "empty names are dropped",
			names:  []string{"", "admin", ""},
			assert: func(t *testing.T, got []string) { assert.Equal(t, []string{"admin"}, got) },
		},
		{
			name:   "a repeated name collapses to its first occurrence",
			names:  []string{"admin", "editor", "admin"},
			assert: func(t *testing.T, got []string) { assert.Equal(t, []string{"admin", "editor"}, got) },
		},
		{
			name:   "only empty names leave no survivor",
			names:  []string{"", ""},
			assert: func(t *testing.T, got []string) { assert.Empty(t, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.SurvivingRoles(tc.names))
		})
	}
}

func TestDetachedText(t *testing.T) {
	t.Parallel()

	errDriver := errors.New("driver: secret detail")
	errKept := errors.New("kept sentinel")
	errOther := errors.New("other sentinel")

	type testCase struct {
		name   string
		err    error
		kept   []error
		assert func(t *testing.T, got error)
	}

	cases := []testCase{
		{
			name: "a matching sentinel stays matchable and the driver error is cut",
			err:  fmt.Errorf("%w: %w", errKept, errDriver),
			kept: []error{errKept, errOther},
			assert: func(t *testing.T, got error) {
				assert.Equal(t, "safe text", got.Error())
				assert.ErrorIs(t, got, errKept)
				assert.NotErrorIs(t, got, errOther)
				assert.NotErrorIs(t, got, errDriver)
			},
		},
		{
			name: "several matching sentinels all stay matchable",
			err:  errors.Join(errKept, errOther, errDriver),
			kept: []error{errKept, errOther},
			assert: func(t *testing.T, got error) {
				assert.ErrorIs(t, got, errKept)
				assert.ErrorIs(t, got, errOther)
				assert.NotErrorIs(t, got, errDriver)
			},
		},
		{
			name: "an error matching none of kept is fully detached",
			err:  errDriver,
			kept: []error{errKept},
			assert: func(t *testing.T, got error) {
				assert.Equal(t, "safe text", got.Error())
				assert.NotErrorIs(t, got, errDriver)
				assert.NotErrorIs(t, got, errKept)
			},
		},
		{
			name: "no kept list detaches everything",
			err:  errKept,
			assert: func(t *testing.T, got error) {
				assert.NotErrorIs(t, got, errKept)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, storekit.DetachedText(tc.err, "safe text", tc.kept))
		})
	}
}

func TestDetachedError_Unwrap(t *testing.T) {
	t.Parallel()

	errA := errors.New("a")
	errB := errors.New("b")

	type testCase struct {
		name   string
		err    error
		kept   []error
		assert func(t *testing.T, got []error)
	}

	cases := []testCase{
		{
			name:   "the matched sentinels in kept order",
			err:    errors.Join(errB, errA),
			kept:   []error{errA, errB},
			assert: func(t *testing.T, got []error) { assert.Equal(t, []error{errA, errB}, got) },
		},
		{
			name:   "nothing matched",
			err:    errors.New("x"),
			kept:   []error{errA},
			assert: func(t *testing.T, got []error) { assert.Empty(t, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var de *storekit.DetachedError
			require.ErrorAs(t, storekit.DetachedText(tc.err, "t", tc.kept), &de)
			tc.assert(t, de.Unwrap())
		})
	}
}

// sqlStateErr is a driver error reporting code through a SQLState method,
// with msg as its text.
type sqlStateErr struct{ code, msg string }

func (e *sqlStateErr) Error() string    { return e.msg }
func (e *sqlStateErr) SQLState() string { return e.code }

func TestValidSQLState(t *testing.T) {
	type testCase struct {
		name   string
		code   string
		assert func(t *testing.T, got bool)
	}

	accepted := func(t *testing.T, got bool) { assert.True(t, got) }
	refused := func(t *testing.T, got bool) { assert.False(t, got) }

	cases := []testCase{
		{name: "five digits", code: "23505", assert: accepted},
		{name: "upper-case letters and digits", code: "P0001", assert: accepted},
		{name: "four characters", code: "2350", assert: refused},
		{name: "six characters", code: "235050", assert: refused},
		{name: "a lower-case letter", code: "p0001", assert: refused},
		{name: "a space", code: "23 05", assert: refused},
		{name: "empty", code: "", assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, storekit.ValidSQLState(tc.code))
		})
	}
}

func TestDetached(t *testing.T) {
	cancelled := &sqlStateErr{code: "57014", msg: "secret value"}

	type testCase struct {
		name   string
		err    error
		kept   []error
		assert func(t *testing.T, got error)
	}

	cases := []testCase{
		{
			name: "a valid SQLSTATE is kept and the driver text is not",
			err:  &sqlStateErr{code: "40001", msg: "secret value"},
			assert: func(t *testing.T, got error) {
				assert.EqualError(t, got, "database failure (SQLSTATE 40001)")
			},
		},
		{
			name: "a SQLSTATE deeper in the chain is kept",
			err:  fmt.Errorf("query: %w", &sqlStateErr{code: "23505", msg: "secret value"}),
			assert: func(t *testing.T, got error) {
				assert.EqualError(t, got, "database failure (SQLSTATE 23505)")
			},
		},
		{
			name: "a code that is not a SQLSTATE adds no text",
			err:  &sqlStateErr{code: "bad!!", msg: "secret value"},
			assert: func(t *testing.T, got error) {
				assert.EqualError(t, got, "database failure")
			},
		},
		{
			name: "an error reporting no SQLSTATE",
			err:  errors.New("secret value"),
			assert: func(t *testing.T, got error) {
				assert.EqualError(t, got, "database failure")
			},
		},
		{
			name: "a kept sentinel err matched stays matchable and the driver error is cut",
			err:  fmt.Errorf("%w: %w", context.Canceled, cancelled),
			kept: []error{context.Canceled, context.DeadlineExceeded},
			assert: func(t *testing.T, got error) {
				assert.EqualError(t, got, "database failure (SQLSTATE 57014)")
				assert.ErrorIs(t, got, context.Canceled)
				assert.NotErrorIs(t, got, cancelled)
			},
		},
		{
			name: "a kept sentinel err does not match is not matchable",
			err:  fmt.Errorf("%w: %w", context.Canceled, cancelled),
			kept: []error{context.DeadlineExceeded},
			assert: func(t *testing.T, got error) {
				assert.EqualError(t, got, "database failure (SQLSTATE 57014)")
				assert.NotErrorIs(t, got, context.DeadlineExceeded)
				assert.NotErrorIs(t, got, context.Canceled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, storekit.Detached(tc.err, tc.kept))
		})
	}
}

func TestLookupMiss(t *testing.T) {
	type testCase struct {
		name   string
		value  string
		err    error
		assert func(t *testing.T, got bool)
	}

	miss := func(t *testing.T, got bool) { assert.True(t, got) }
	failure := func(t *testing.T, got bool) { assert.False(t, got) }

	const euro = "ada\u20ac"

	cases := []testCase{
		{
			name:   "a character outside the repertoire",
			value:  euro,
			err:    &sqlStateErr{code: "22021", msg: "invalid byte sequence"},
			assert: miss,
		},
		{
			name:   "an untranslatable character",
			value:  euro,
			err:    &sqlStateErr{code: "22P05", msg: "character has no equivalent"},
			assert: miss,
		},
		{
			name:   "a character outside the repertoire, wrapped",
			value:  euro,
			err:    fmt.Errorf("query: %w", &sqlStateErr{code: "22021"}),
			assert: miss,
		},
		{
			name:   "an untranslatable character, wrapped twice",
			value:  euro,
			err:    fmt.Errorf("scan: %w", fmt.Errorf("query: %w", &sqlStateErr{code: "22P05"})),
			assert: miss,
		},
		{
			name:   "an ASCII value cannot cause an untranslatable character",
			value:  "ada",
			err:    &sqlStateErr{code: "22P05", msg: "character has no equivalent"},
			assert: failure,
		},
		{
			name:   "an ASCII value cannot cause a character outside the repertoire",
			value:  "ada",
			err:    &sqlStateErr{code: "22021", msg: "invalid byte sequence"},
			assert: failure,
		},
		{
			name:   "an empty value cannot cause an untranslatable character",
			err:    &sqlStateErr{code: "22P05", msg: "character has no equivalent"},
			assert: failure,
		},
		{
			name:   "a lost connection",
			value:  euro,
			err:    &sqlStateErr{code: "08006", msg: "connection failure"},
			assert: failure,
		},
		{
			name:   "a serialization failure, wrapped",
			value:  euro,
			err:    fmt.Errorf("query: %w", &sqlStateErr{code: "40001"}),
			assert: failure,
		},
		{
			name:   "a message that merely names a code",
			value:  euro,
			err:    &sqlStateErr{code: "XX000", msg: "22021 and 22P05"},
			assert: failure,
		},
		{
			name:   "a canceled context",
			value:  euro,
			err:    context.Canceled,
			assert: failure,
		},
		{
			name:   "an error reporting no SQLSTATE",
			value:  euro,
			err:    errors.New("22021"),
			assert: failure,
		},
		{
			name:   "no error",
			value:  euro,
			assert: failure,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, storekit.LookupMiss(tc.value, tc.err))
		})
	}
}

func TestUpdateUserQuery(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	changedAt := now.Add(-time.Hour)
	userID := "user-1"

	// columns are the users columns the named fields write, the only way a
	// caller outside the package makes one.
	columns := func(opts ...identity.UserOption) []storekit.Column {
		return storekit.UserColumns(identity.ApplyUserOptions(opts...), "org-1",
			func(time.Time) any { return changedAt })
	}

	type testCase struct {
		name   string
		set    []storekit.Column
		userID any // the bound identifier; userID when nil
		assert func(t *testing.T, query string, args []any)
	}

	cases := []testCase{
		{
			name: "no column writes updated_at alone",
			assert: func(t *testing.T, query string, args []any) {
				assert.Equal(t, "UPDATE users SET updated_at = $1 WHERE id = $2", query)
				assert.Equal(t, []any{now, userID}, args)
			},
		},
		{
			name: "one column precedes updated_at",
			set:  columns(identity.WithUserName("Ada")),
			assert: func(t *testing.T, query string, args []any) {
				assert.Equal(t, "UPDATE users SET name = $1, updated_at = $2 WHERE id = $3", query)
				assert.Equal(t, []any{"Ada", now, userID}, args)
			},
		},
		{
			name: "four columns bind in the order given",
			set: columns(
				identity.WithUserName("Ada"),
				identity.WithUserPassword([]byte("hash")),
				identity.WithUserOrganization(nil),
				identity.WithUserPasswordChangedAt(changedAt),
			),
			assert: func(t *testing.T, query string, args []any) {
				assert.Equal(t,
					"UPDATE users SET name = $1, password = $2, organization_id = $3, "+
						"password_changed_at = $4, updated_at = $5 WHERE id = $6", query)
				assert.Equal(t, []any{"Ada", []byte("hash"), "org-1", changedAt, now, userID}, args)
			},
		},
		{
			name:   "role column",
			set:    []storekit.Column{storekit.RoleColumn("admin")},
			userID: 7,
			assert: func(t *testing.T, query string, args []any) {
				assert.Equal(t, "UPDATE users SET role = $1, updated_at = $2 WHERE id = $3", query)
				assert.Equal(t, []any{"admin", now, 7}, args)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query, args := storekit.UpdateUserQuery(tc.set, now, cmp.Or(tc.userID, any(userID)))
			tc.assert(t, query, args)
		})
	}
}

func TestColumnExportsNoField(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeOf(storekit.Column{})
	for i := range typ.NumField() {
		if f := typ.Field(i); f.IsExported() {
			t.Errorf("storekit.Column exports %s, so a caller can put any text into the SQL", f.Name)
		}
	}
}

func TestUserColumns(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	changedAt := now.Add(-time.Hour)
	const org = "org-1"
	const marker = "ts-marker"
	ts := func(time.Time) any { return marker }

	// The columns hide their names, so each case reads them through the
	// UPDATE they write: the SET list before updated_at, and the bound values.
	type testCase struct {
		name   string
		opts   []identity.UserOption
		assert func(t *testing.T, query string, args []any)
	}

	cases := []testCase{
		{
			name: "nothing named writes no column",
			assert: func(t *testing.T, query string, args []any) {
				assert.Equal(t, "UPDATE users SET updated_at = $1 WHERE id = $2", query)
				assert.Equal(t, []any{now, "u"}, args)
			},
		},
		{
			name: "the name alone",
			opts: []identity.UserOption{identity.WithUserName("Ada")},
			assert: func(t *testing.T, query string, args []any) {
				assert.Equal(t, "UPDATE users SET name = $1, updated_at = $2 WHERE id = $3", query)
				assert.Equal(t, []any{"Ada", now, "u"}, args)
			},
		},
		{
			name: "the password alone, nil written as empty",
			opts: []identity.UserOption{identity.WithUserPassword(nil)},
			assert: func(t *testing.T, query string, args []any) {
				assert.Equal(t, "UPDATE users SET password = $1, updated_at = $2 WHERE id = $3", query)
				assert.Equal(t, []any{[]byte{}, now, "u"}, args)
			},
		},
		{
			name: "the organization alone binds org",
			opts: []identity.UserOption{identity.WithUserOrganization(nil)},
			assert: func(t *testing.T, query string, args []any) {
				assert.Equal(t, "UPDATE users SET organization_id = $1, updated_at = $2 WHERE id = $3", query)
				assert.Equal(t, []any{org, now, "u"}, args)
			},
		},
		{
			name: "the password-changed-at time alone goes through ts",
			opts: []identity.UserOption{identity.WithUserPasswordChangedAt(changedAt)},
			assert: func(t *testing.T, query string, args []any) {
				assert.Equal(t, "UPDATE users SET password_changed_at = $1, updated_at = $2 WHERE id = $3", query)
				assert.Equal(t, []any{marker, now, "u"}, args)
			},
		},
		{
			name: "every field in the fixed order, ts only for password_changed_at",
			opts: []identity.UserOption{
				identity.WithUserPasswordChangedAt(changedAt),
				identity.WithUserOrganization(nil),
				identity.WithUserPassword([]byte("hash")),
				identity.WithUserEmail("ada@example.com"),
				identity.WithUserRoles("admin"),
				identity.WithUserName("Ada"),
			},
			assert: func(t *testing.T, query string, args []any) {
				assert.Equal(t,
					"UPDATE users SET name = $1, password = $2, organization_id = $3, "+
						"password_changed_at = $4, updated_at = $5 WHERE id = $6", query)
				assert.Equal(t, []any{"Ada", []byte("hash"), org, marker, now, "u"}, args)
			},
		},
		{
			name: "the email has no column",
			opts: []identity.UserOption{identity.WithUserEmail("ada@example.com")},
			assert: func(t *testing.T, query string, args []any) {
				assert.Equal(t, "UPDATE users SET updated_at = $1 WHERE id = $2", query)
				assert.Equal(t, []any{now, "u"}, args)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := storekit.UserColumns(identity.ApplyUserOptions(tc.opts...), org, ts)
			query, args := storekit.UpdateUserQuery(set, now, "u")
			tc.assert(t, query, args)
		})
	}
}
