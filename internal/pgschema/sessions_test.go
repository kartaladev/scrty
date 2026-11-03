package pgschema_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/session"
)

func TestSessionSignInArgs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		sess   session.Session
		assert func(t *testing.T, args []any, err error)
	}

	cases := []testCase{
		{
			name: "every column holds its value, a DPoP binding as jkt",
			sess: session.Session{
				ClientIP: "203.0.113.7", UserAgent: "agent/1", CSRFToken: "sealed-token",
				KeyBinding: session.KeyBinding{JKT: "thumb-a"},
			},
			assert: func(t *testing.T, args []any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []any{"203.0.113.7", "agent/1", pgschema.SessionBindingJKT, "thumb-a", "sealed-token"}, args)
			},
		},
		{
			name: "a certificate binding is x5t#S256",
			sess: session.Session{KeyBinding: session.KeyBinding{X5TS256: "thumb-b"}},
			assert: func(t *testing.T, args []any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []any{nil, nil, pgschema.SessionBindingX5TS256, "thumb-b", nil}, args)
			},
		},
		{
			name: "a session with no sign-in state is all NULL",
			assert: func(t *testing.T, args []any, err error) {
				require.NoError(t, err)
				assert.Equal(t, []any{nil, nil, nil, nil, nil}, args)
			},
		},
		{
			name: "a binding naming both keys is refused",
			sess: session.Session{KeyBinding: session.KeyBinding{JKT: "thumb-a", X5TS256: "thumb-b"}},
			assert: func(t *testing.T, _ []any, err error) {
				require.ErrorIs(t, err, pgschema.ErrSessionSignInUnstorable)
				assert.NotContains(t, err.Error(), "thumb-")
			},
		},
		{
			name: "a NUL in the user agent is refused without the value",
			sess: session.Session{UserAgent: "agent\x00secret"},
			assert: func(t *testing.T, _ []any, err error) {
				require.ErrorIs(t, err, pgschema.ErrSessionSignInUnstorable)
				assert.NotContains(t, err.Error(), "secret")
			},
		},
		{
			name: "invalid UTF-8 in the client address is refused",
			sess: session.Session{ClientIP: "203.0.113.7\xff"},
			assert: func(t *testing.T, _ []any, err error) {
				require.ErrorIs(t, err, pgschema.ErrSessionSignInUnstorable)
			},
		},
		{
			name: "a NUL in the thumbprint is refused",
			sess: session.Session{KeyBinding: session.KeyBinding{JKT: "thumb\x00"}},
			assert: func(t *testing.T, _ []any, err error) {
				require.ErrorIs(t, err, pgschema.ErrSessionSignInUnstorable)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args, err := pgschema.SessionSignInArgs(&tc.sess)
			tc.assert(t, args, err)
		})
	}
}

func TestParseSessionBinding(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		kind       string
		thumbprint string
		assert     func(t *testing.T, b session.KeyBinding, err error)
	}

	cases := []testCase{
		{
			name: "jkt is a DPoP binding", kind: pgschema.SessionBindingJKT, thumbprint: "thumb-a",
			assert: func(t *testing.T, b session.KeyBinding, err error) {
				require.NoError(t, err)
				assert.Equal(t, session.KeyBinding{JKT: "thumb-a"}, b)
			},
		},
		{
			name: "x5t#S256 is a certificate binding", kind: pgschema.SessionBindingX5TS256, thumbprint: "thumb-b",
			assert: func(t *testing.T, b session.KeyBinding, err error) {
				require.NoError(t, err)
				assert.Equal(t, session.KeyBinding{X5TS256: "thumb-b"}, b)
			},
		},
		{
			name: "no kind and no thumbprint is unbound",
			assert: func(t *testing.T, b session.KeyBinding, err error) {
				require.NoError(t, err)
				assert.True(t, b.IsZero())
			},
		},
		{
			name: "an unknown kind is an error without the stored values", kind: "spki", thumbprint: "thumb-c",
			assert: func(t *testing.T, _ session.KeyBinding, err error) {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "spki")
				assert.NotContains(t, err.Error(), "thumb-c")
			},
		},
		{
			name: "a kind with no thumbprint is an error", kind: pgschema.SessionBindingJKT,
			assert: func(t *testing.T, _ session.KeyBinding, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "a thumbprint with no kind is an error", thumbprint: "thumb-d",
			assert: func(t *testing.T, _ session.KeyBinding, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, err := pgschema.ParseSessionBinding(tc.kind, tc.thumbprint)
			tc.assert(t, b, err)
		})
	}
}
