package authenticate_test

import (
	"bytes"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

// TestLogRoute_PasswordAuthenticator_Summary pins that the suppressed-count
// summary, which has no request context, goes to the chain logger the last
// refusal was written to, and none to the default. It swaps the default
// logger, so it does not run in parallel.
func TestLogRoute_PasswordAuthenticator_Summary(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	var chain, def bytes.Buffer

	previous := slog.Default()
	slog.SetDefault(debugLogger(&def))
	t.Cleanup(func() { slog.SetDefault(previous) })

	ctrl := gomock.NewController(t)
	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).Return(nil, identity.ErrUserNotFound).AnyTimes()
	enc := NewMockEncoder(ctrl)
	enc.EXPECT().Encode(gomock.Any()).Return([]byte("$fake$reference"), nil)
	enc.EXPECT().Match(gomock.Any(), gomock.Any()).Return(false).AnyTimes()

	auth, err := authenticate.NewUsernamePasswordAuthenticator(users,
		authenticate.WithPasswordEncoder(enc), authenticate.WithPasswordLogInterval(time.Hour))
	require.NoError(t, err)

	ctx := ctxlog.With(t.Context(), debugLogger(&chain))
	for range 3 {
		_, authErr := auth.Authenticate(ctx, &identity.UsernamePassword{Username: "ghost", Password: []byte("pw")})
		require.ErrorIs(t, authErr, authenticate.ErrAuthenticationFailed)
	}

	require.NoError(t, auth.FlushRefusalLogs())
	assert.Contains(t, chain.String(), "authentication refusals suppressed")
	assert.Empty(t, def.String(), "the default logger must see nothing")
}
