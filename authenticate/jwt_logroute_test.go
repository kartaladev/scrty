package authenticate_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token"
)

// TestLogRoute_JWTAuthenticator pins where the abort record of a hostile
// identifier-generator error goes. The JWT authenticator has no logger option,
// so the record goes to the logger of the chain handling the request, else to
// slog.Default() as it is when the record is written. It swaps the default
// logger, so it does not run in parallel.
func TestLogRoute_JWTAuthenticator(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		chain  bool
		assert func(t *testing.T, chain, def *bytes.Buffer)
	}

	cases := []testCase{
		{
			name:  "inside a configured chain",
			chain: true,
			assert: func(t *testing.T, chain, def *bytes.Buffer) {
				assert.Contains(t, chain.String(), msgPortErrAborted)
				assert.Empty(t, def.String(), "the default logger must see nothing")
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, _, def *bytes.Buffer) {
				assert.Contains(t, def.String(), msgPortErrAborted, "the default as swapped at record time")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var chain, def bytes.Buffer

			previous := slog.Default()
			slog.SetDefault(debugLogger(&def))
			t.Cleanup(func() { slog.SetDefault(previous) })

			ctrl := gomock.NewController(t)
			verifier := NewMockVerifier(ctrl)
			verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).
				Return(token.NewClaims("ada", "opaque-issuer-reference"), nil)
			ids := NewMockGenerator(ctrl)
			ids.EXPECT().NewID().Return(id.Nil, jwtPanicUnwrap{})

			auth, err := authenticate.NewJWTAuthenticator(
				authenticate.WithJWTVerifier(verifier), authenticate.WithJWTIDGenerator(ids))
			require.NoError(t, err)

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, debugLogger(&chain))
			}

			_, err = auth.Authenticate(ctx, authenticate.NewBearerToken("a.b.c"))
			require.Error(t, err)

			tc.assert(t, &chain, &def)
		})
	}
}
