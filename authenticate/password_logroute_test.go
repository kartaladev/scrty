package authenticate_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

// TestLogRoute_PasswordAuthenticator pins where the provider's refusal record
// goes: its own logger when given, else the logger of the chain handling the
// request, else slog.Default() as it is when the record is written. It swaps
// the default logger, so it does not run in parallel.
func TestLogRoute_PasswordAuthenticator(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		opts   func(own *slog.Logger) []authenticate.PasswordOption
		chain  bool
		assert func(t *testing.T, err error, own, chain, def *bytes.Buffer)
	}

	cases := []testCase{
		{
			name:  "no option, inside a configured chain",
			chain: true,
			assert: func(t *testing.T, err error, _, chain, def *bytes.Buffer) {
				require.NoError(t, err)
				assert.Contains(t, chain.String(), "authentication refused")
				assert.Empty(t, def.String(), "the default logger must see nothing")
			},
		},
		{
			name: "own option wins",
			opts: func(own *slog.Logger) []authenticate.PasswordOption {
				return []authenticate.PasswordOption{authenticate.WithPasswordLogger(own)}
			},
			chain: true,
			assert: func(t *testing.T, err error, own, chain, def *bytes.Buffer) {
				require.NoError(t, err)
				assert.Contains(t, own.String(), "authentication refused")
				assert.Empty(t, chain.String())
				assert.Empty(t, def.String())
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, err error, _, _, def *bytes.Buffer) {
				require.NoError(t, err)
				assert.Contains(t, def.String(), "authentication refused", "the default as swapped at record time")
			},
		},
		{
			name: "nil option",
			opts: func(*slog.Logger) []authenticate.PasswordOption {
				return []authenticate.PasswordOption{authenticate.WithPasswordLogger(nil)}
			},
			assert: func(t *testing.T, err error, _, _, _ *bytes.Buffer) {
				require.ErrorIs(t, err, authenticate.ErrConfig)
				assert.ErrorContains(t, err, "WithPasswordLogger")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var own, chain, def bytes.Buffer

			previous := slog.Default()
			slog.SetDefault(debugLogger(&def))
			t.Cleanup(func() { slog.SetDefault(previous) })

			ctrl := gomock.NewController(t)
			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).Return(nil, identity.ErrUserNotFound).AnyTimes()
			enc := NewMockEncoder(ctrl)
			enc.EXPECT().Encode(gomock.Any()).Return([]byte("$fake$reference"), nil).AnyTimes()
			enc.EXPECT().Match(gomock.Any(), gomock.Any()).Return(false).AnyTimes()

			opts := []authenticate.PasswordOption{authenticate.WithPasswordEncoder(enc)}
			if tc.opts != nil {
				opts = append(opts, tc.opts(debugLogger(&own))...)
			}

			auth, err := authenticate.NewUsernamePasswordAuthenticator(users, opts...)
			if err != nil {
				tc.assert(t, err, &own, &chain, &def)

				return
			}

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, debugLogger(&chain))
			}

			_, authErr := auth.Authenticate(ctx, &identity.UsernamePassword{Username: "ghost", Password: []byte("pw")})
			require.ErrorIs(t, authErr, authenticate.ErrAuthenticationFailed)

			tc.assert(t, nil, &own, &chain, &def)
		})
	}
}
