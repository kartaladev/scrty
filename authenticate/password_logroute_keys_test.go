package authenticate_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

// summaryLines returns the lines of buf that carry msg as their message.
func summaryLines(buf *bytes.Buffer, msg string) []string {
	var out []string

	for line := range strings.SplitSeq(buf.String(), "\n") {
		if strings.Contains(line, `"msg":"`+msg+`"`) {
			out = append(out, line)
		}
	}

	return out
}

// TestLogRoute_PasswordAuthenticator_SummaryPerKey pins that each reason's
// summary goes to the chain that reason's records went to, never to another
// chain's log. It swaps the default logger, so it does not run in parallel.
func TestLogRoute_PasswordAuthenticator_SummaryPerKey(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const msg = "authentication refusals suppressed"

	type testCase struct {
		name string
		own  bool
		// run writes refusals through refuse(ctx, user): "ghost" is the
		// unknown-user reason, "broken" the user-loader reason.
		run    func(bare, a, b context.Context, refuse func(context.Context, string))
		assert func(t *testing.T, a, b, def, own *bytes.Buffer)
	}

	three := func(ctx context.Context, refuse func(context.Context, string), user string) {
		for range 3 {
			refuse(ctx, user)
		}
	}

	cases := []testCase{
		{
			name: "two chains: each summary stays on its own chain",
			run: func(_, a, b context.Context, refuse func(context.Context, string)) {
				three(a, refuse, "ghost")
				three(b, refuse, "broken")
			},
			assert: func(t *testing.T, a, b, def, _ *bytes.Buffer) {
				require.Len(t, summaryLines(a, msg), 1)
				assert.Contains(t, summaryLines(a, msg)[0], `"reason":"unknown-user"`)
				require.Len(t, summaryLines(b, msg), 1)
				assert.Contains(t, summaryLines(b, msg)[0], `"reason":"user-loader"`)
				assert.Empty(t, summaryLines(def, msg))
			},
		},
		{
			name: "key written under A then suppressed under B: summary on A only",
			run: func(_, a, b context.Context, refuse func(context.Context, string)) {
				three(a, refuse, "ghost")
				three(b, refuse, "ghost")
			},
			assert: func(t *testing.T, a, b, def, _ *bytes.Buffer) {
				require.Len(t, summaryLines(a, msg), 1)
				assert.Contains(t, summaryLines(a, msg)[0], `"reason":"unknown-user"`)
				assert.Empty(t, b.String())
				assert.Empty(t, summaryLines(def, msg))
			},
		},
		{
			name: "no chain: the default logger",
			run: func(bare, _, _ context.Context, refuse func(context.Context, string)) {
				three(bare, refuse, "ghost")
			},
			assert: func(t *testing.T, a, b, def, _ *bytes.Buffer) {
				assert.Len(t, summaryLines(def, msg), 1)
				assert.Empty(t, a.String())
				assert.Empty(t, b.String())
			},
		},
		{
			name: "own option wins",
			own:  true,
			run: func(_, a, _ context.Context, refuse func(context.Context, string)) {
				three(a, refuse, "ghost")
			},
			assert: func(t *testing.T, a, _, def, own *bytes.Buffer) {
				assert.Len(t, summaryLines(own, msg), 1)
				assert.Empty(t, a.String())
				assert.Empty(t, def.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var a, b, def, own bytes.Buffer

			previous := slog.Default()
			slog.SetDefault(debugLogger(&def))
			t.Cleanup(func() { slog.SetDefault(previous) })

			ctrl := gomock.NewController(t)
			users := NewMockUserLoader(ctrl)
			users.EXPECT().LoadByUsername(gomock.Any(), "ghost").Return(nil, identity.ErrUserNotFound).AnyTimes()
			users.EXPECT().LoadByUsername(gomock.Any(), "broken").Return(nil, errors.New("db down")).AnyTimes()
			enc := NewMockEncoder(ctrl)
			enc.EXPECT().Encode(gomock.Any()).Return([]byte("$fake$reference"), nil)
			enc.EXPECT().Match(gomock.Any(), gomock.Any()).Return(false).AnyTimes()

			opts := []authenticate.PasswordOption{
				authenticate.WithPasswordEncoder(enc), authenticate.WithPasswordLogInterval(time.Hour),
			}
			if tc.own {
				opts = append(opts, authenticate.WithPasswordLogger(debugLogger(&own)))
			}

			auth, err := authenticate.NewUsernamePasswordAuthenticator(users, opts...)
			require.NoError(t, err)

			refuse := func(ctx context.Context, user string) {
				_, authErr := auth.Authenticate(ctx, &identity.UsernamePassword{Username: user, Password: []byte("pw")})
				require.Error(t, authErr)
			}

			tc.run(t.Context(),
				ctxlog.With(t.Context(), debugLogger(&a)), ctxlog.With(t.Context(), debugLogger(&b)), refuse)

			require.NoError(t, auth.FlushRefusalLogs())
			tc.assert(t, &a, &b, &def, &own)
		})
	}
}
