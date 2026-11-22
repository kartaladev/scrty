package oidcprovider_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/oidcprovider"
)

// TestLogRoute_VerifyJWTKeys pins where the abort record of a hostile key
// source goes when it fails while a JWT access token is verified: the
// provider's own logger when given, else the chain's, else slog.Default() as
// it is when the record is written. It replaces slog.Default(), so it does not
// run in parallel.
func TestLogRoute_VerifyJWTKeys(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		own    bool
		chain  bool
		assert func(t *testing.T, own, chain, def *lockedBuffer)
	}

	cases := []testCase{
		{
			name: "own option wins", own: true, chain: true,
			assert: func(t *testing.T, own, chain, def *lockedBuffer) {
				t.Helper()
				assert.Len(t, lrAborts(t, own), 1, "the provider's own logger takes the record")
				assert.Empty(t, lrAborts(t, chain))
				assert.Empty(t, lrAborts(t, def))
			},
		},
		{
			name: "no option, inside a configured chain", chain: true,
			assert: func(t *testing.T, own, chain, def *lockedBuffer) {
				t.Helper()
				assert.Empty(t, lrAborts(t, own))
				assert.Len(t, lrAborts(t, chain), 1, "the chain's logger takes the record")
				assert.Empty(t, lrAborts(t, def), "the default logger must see no abort record")
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, own, chain, def *lockedBuffer) {
				t.Helper()
				assert.Empty(t, lrAborts(t, own))
				assert.Empty(t, lrAborts(t, chain))
				assert.Len(t, lrAborts(t, def), 1, "slog.Default() takes the record")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			own, chain, def := &lockedBuffer{}, &lockedBuffer{}, &lockedBuffer{}

			previous := slog.Default()
			slog.SetDefault(lrJSON(def))
			t.Cleanup(func() { slog.SetDefault(previous) })

			var opts []oidcprovider.Option
			if tc.own {
				opts = append(opts, oidcprovider.WithLogger(lrJSON(own)))
			}

			keys := newExchangeKeys(t)
			f := pe7bFixtureKeys(t, keys, activeUsers(t), opts...)
			c := issueCodeFor(t, f, "billing-web", nil, testSignIn(f, "u-1"), "openid", "profile")

			res, err := f.p.Token(t.Context(), billingExchange(c, nil))
			require.NoError(t, err, "precondition: the exchange issues a JWT access token")

			keys.failVerifying(func(context.Context) error { return &pe7bCycleOne{} })

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, lrJSON(chain))
			}

			_, err = f.p.VerifyAccessToken(ctx, res.AccessToken)
			require.Error(t, err, "the key source failed, so the token is not verified")

			tc.assert(t, own, chain, def)
		})
	}
}
