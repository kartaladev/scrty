package pgschema_test

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

func TestClientSecretsCodec(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte("a client secret"))
	expires := time.Date(2030, 1, 1, 10, 0, 0, 123456000, time.UTC)

	cases := []struct {
		name   string
		in     []oidcprovider.ClientSecret
		assert func(t *testing.T, encoded string, got []oidcprovider.ClientSecret)
	}{
		{
			name: "none is an empty array, and reads back as none",
			assert: func(t *testing.T, encoded string, got []oidcprovider.ClientSecret) {
				assert.JSONEq(t, "[]", encoded)
				assert.Nil(t, got)
			},
		},
		{
			name: "a digest and a deadline survive, and the redacted form is never stored",
			in: []oidcprovider.ClientSecret{
				{Digest: digest[:], ExpiresAt: expires},
				{Digest: digest[:]},
			},
			assert: func(t *testing.T, encoded string, got []oidcprovider.ClientSecret) {
				assert.NotContains(t, encoded, "REDACTED")
				require.Len(t, got, 2)
				assert.Equal(t, digest[:], []byte(got[0].Digest))
				assert.True(t, expires.Equal(got[0].ExpiresAt))
				assert.Equal(t, digest[:], []byte(got[1].Digest))
				assert.True(t, got[1].ExpiresAt.IsZero(), "no deadline stays none")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := pgschema.EncodeClientSecrets(tc.in)
			require.NoError(t, err)
			got, err := pgschema.DecodeClientSecrets([]byte(encoded))
			require.NoError(t, err)
			tc.assert(t, encoded, got)
		})
	}
}

// TestDecodeClientSecrets_RefusesWhatHoldsNoDigest pins what happens if a redacted form
// ever reaches the column: an error, never a client that silently matches nothing.
func TestDecodeClientSecrets_RefusesWhatHoldsNoDigest(t *testing.T) {
	t.Parallel()

	marshalled, err := json.Marshal([]oidcprovider.ClientSecret{{Digest: []byte("some digest")}})
	require.NoError(t, err)

	for name, raw := range map[string][]byte{
		"a ClientSecret marshalled as it is": marshalled,
		"a redacted digest":                  []byte(`[{"digest":"[REDACTED]"}]`),
		"an empty digest":                    []byte(`[{"digest":""}]`),
		"not an array":                       []byte(`{}`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := pgschema.DecodeClientSecrets(raw)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "REDACTED")
		})
	}
}

func TestEncodeSignIn(t *testing.T) {
	t.Parallel()

	family := id.MustParse("01926a4e-0000-7000-8000-000000000001")
	at := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

	cases := []struct {
		name   string
		in     *oidcprovider.SignIn
		assert func(t *testing.T, got any, err error)
	}{
		{
			name: "no sign-in is NULL",
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.Nil(t, got)
			},
		},
		{
			name: "text PostgreSQL cannot hold is refused, and not repeated",
			in:   &oidcprovider.SignIn{User: "u-1", AMR: []string{"bad\x00value"}},
			assert: func(t *testing.T, _ any, err error) {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "bad")
			},
		},
		{
			name: "a sign-in is an object of its own fields",
			in: &oidcprovider.SignIn{
				User: "u-1", Family: family, AuthenticatedAt: at, AMR: []string{"pwd"}, ACR: "loa2",
				AbsoluteExpiresAt: at.Add(time.Hour), ExternalIssuer: "https://idp.example.com", ExternalSessionID: "x-9",
			},
			assert: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				assert.JSONEq(t, `{"user":"u-1","family":"01926a4e-0000-7000-8000-000000000001",
					"authenticated_at":"2030-01-01T10:00:00Z","amr":["pwd"],"acr":"loa2",
					"absolute_expires_at":"2030-01-01T11:00:00Z","external_issuer":"https://idp.example.com",
					"external_session_id":"x-9"}`, got.(string))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := pgschema.EncodeSignIn(tc.in)
			tc.assert(t, got, err)
		})
	}
}

// TestStageMoveAllowed lists every move, so a stage added to the order fails here until
// the adapters' judgement follows the in-memory store's.
func TestStageMoveAllowed(t *testing.T) {
	t.Parallel()

	stages := []oidcprovider.Stage{
		oidcprovider.StageLogin, oidcprovider.StageConsent, oidcprovider.StageLogout, oidcprovider.StageDone,
	}
	allowed := map[[2]oidcprovider.Stage]bool{
		{oidcprovider.StageLogin, oidcprovider.StageConsent}: true,
		{oidcprovider.StageLogin, oidcprovider.StageDone}:    true,
		{oidcprovider.StageConsent, oidcprovider.StageDone}:  true,
		{oidcprovider.StageLogout, oidcprovider.StageDone}:   true,
	}

	for _, from := range stages {
		for _, to := range stages {
			assert.Equal(t, allowed[[2]oidcprovider.Stage{from, to}], pgschema.StageMoveAllowed(from, to), "%d to %d", from, to)
		}
	}
}

func TestSelectorStatements(t *testing.T) {
	t.Parallel()

	family := id.MustParse("01926a4e-0000-7000-8000-000000000001")

	cases := []struct {
		name   string
		sel    oidcprovider.SignInSelector
		assert func(t *testing.T, statement string, args []any)
	}{
		{
			name: "one family",
			sel:  oidcprovider.SignInSelector{Family: family},
			assert: func(t *testing.T, statement string, args []any) {
				assert.Contains(t, statement, "sign_in_family = $1")
				assert.Equal(t, []any{family.String()}, args)
			},
		},
		{
			name: "every family but one reads NULL as different",
			sel:  oidcprovider.SignInSelector{User: "u-1", ExceptFamily: family},
			assert: func(t *testing.T, statement string, args []any) {
				assert.Contains(t, statement, "user_ref = $1 AND sign_in_family IS DISTINCT FROM $2")
				assert.Equal(t, []any{"u-1", family.String()}, args)
			},
		},
		{
			name: "a user",
			sel:  oidcprovider.SignInSelector{User: "u-1"},
			assert: func(t *testing.T, statement string, args []any) {
				assert.Contains(t, statement, "WHERE user_ref = $1")
				assert.NotContains(t, statement, "$2")
				assert.Equal(t, []any{"u-1"}, args)
			},
		},
		{
			name: "a user and an upstream issuer",
			sel:  oidcprovider.SignInSelector{User: "u-1", ExternalIssuer: "https://idp"},
			assert: func(t *testing.T, statement string, args []any) {
				assert.Contains(t, statement, "user_ref = $1 AND external_issuer = $2")
				assert.Equal(t, []any{"u-1", "https://idp"}, args)
			},
		},
		{
			name: "one upstream session",
			sel:  oidcprovider.SignInSelector{ExternalIssuer: "https://idp", ExternalSessionID: "x-9"},
			assert: func(t *testing.T, statement string, args []any) {
				assert.Contains(t, statement, "external_issuer = $1 AND external_session_id = $2")
				assert.Equal(t, []any{"https://idp", "x-9"}, args)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			statement, args := pgschema.BrowserSessionDeleteBySignIn(tc.sel)
			tc.assert(t, statement, args)
		})
	}
}

func TestCheckSelector(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		sel    oidcprovider.SignInSelector
		assert func(t *testing.T, err error)
	}{
		{
			name:   "a valid shape",
			sel:    oidcprovider.SignInSelector{User: "u-1"},
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:   "the empty selector can never mean everyone",
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, oidcprovider.ErrConfig) },
		},
		{
			name: "text no row could hold",
			sel:  oidcprovider.SignInSelector{User: "bad\x00value"},
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "bad")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, pgschema.CheckSelector(tc.sel))
		})
	}
}

func TestFamilySet(t *testing.T) {
	t.Parallel()

	a := id.MustParse("01926a4e-0000-7000-8000-000000000001")
	b := id.MustParse("01926a4e-0000-7000-8000-000000000002")

	_, ok := pgschema.FamilySet(nil)
	assert.False(t, ok, "none is nothing to write")

	set, ok := pgschema.FamilySet([]id.ID{b, a, b})
	require.True(t, ok)
	assert.JSONEq(t, `["`+a.String()+`","`+b.String()+`"]`, set, "ordered, and without a repeat")
}

// TestCodeSource holds the join to what GrantStore.UseCodes promises.
func TestCodeSource(t *testing.T) {
	t.Parallel()

	codes, err := oidcprovider.NewMemoryCodeStore()
	require.NoError(t, err)
	other, err := oidcprovider.NewMemoryCodeStore()
	require.NoError(t, err)

	var source pgschema.CodeSource
	_, err = source.Read()
	require.ErrorIs(t, err, oidcprovider.ErrConfig, "a source never joined is refused")

	require.NoError(t, source.Join(codes))
	require.NoError(t, source.Join(codes), "the same one again changes nothing")
	require.ErrorIs(t, source.Join(other), oidcprovider.ErrConfig, "another is refused")

	got, err := source.Read()
	require.NoError(t, err)
	assert.Same(t, codes, got, "and the first stays")
}

// TestLineageStatement covers every shape of session statement: the table's name moves
// in each place it appears, and a column name holding the word as part of it does not.
func TestLineageStatement(t *testing.T) {
	t.Parallel()

	for _, statement := range []string{
		pgschema.SessionInsert, pgschema.SessionUpdate, pgschema.SessionSelect, pgschema.SessionExists,
		pgschema.SessionRecordActivity, pgschema.SessionLockSupersession, pgschema.SessionSupersedeOld,
		pgschema.SessionSupersedePrevious, pgschema.SessionMarkPresented, pgschema.SessionPresentationRefusal,
		pgschema.SessionDeleteFamily, pgschema.SessionDelete, pgschema.SessionDeleteByUser,
		pgschema.SessionDeleteByUserExcept, pgschema.SessionCountActive, pgschema.SessionDeleteExpired,
		pgschema.SessionDeleteByExternal, pgschema.SessionDeleteByUserIssuer, pgschema.SessionListByUser,
		pgschema.SessionSuccessorPresented, pgschema.SessionSupersedeRefusal,
	} {
		bound := pgschema.LineageStatement(statement)
		assert.Contains(t, bound, pgschema.RefreshTokenTable)
		assert.NotRegexp(t, `\bsessions\b`, bound)
	}

	assert.Equal(t, "SELECT sessions_x, op_refresh_tokens.a FROM op_refresh_tokens",
		pgschema.LineageStatement("SELECT sessions_x, sessions.a FROM sessions"))
}
