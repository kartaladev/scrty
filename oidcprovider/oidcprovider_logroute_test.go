package oidcprovider_test

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/id"
)

// TestLogRoute_Provider pins where the provider's records go: its own logger
// when given, else the logger of the chain handling the request, else
// slog.Default() as it is when the record is written. The record is the abort
// record of a hostile identifier generator on the access token's jti. It swaps
// the default logger, so it does not run in parallel.
func TestLogRoute_Provider(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name    string
		own     bool
		chain   bool
		refused bool
		opts    []oidcprovider.Option
		assert  func(t *testing.T, err error, own, chain, def *lockedBuffer)
	}

	cases := []testCase{
		{
			name:  "no option, inside a configured chain",
			chain: true,
			assert: func(t *testing.T, err error, _, chain, def *lockedBuffer) {
				require.NoError(t, err)
				assert.Len(t, lrAborts(t, chain), 1, "the chain's logger takes the record")
				assert.Empty(t, lrAborts(t, def), "the default logger must see no abort record")
			},
		},
		{
			name:  "own option wins",
			own:   true,
			chain: true,
			assert: func(t *testing.T, err error, own, chain, def *lockedBuffer) {
				require.NoError(t, err)
				assert.Len(t, lrAborts(t, own), 1)
				assert.Empty(t, lrAborts(t, chain))
				assert.Empty(t, lrAborts(t, def))
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, err error, _, _, def *lockedBuffer) {
				require.NoError(t, err)
				assert.Len(t, lrAborts(t, def), 1, "the default as swapped at record time")
			},
		},
		{
			name:    "nil option",
			refused: true,
			opts:    []oidcprovider.Option{oidcprovider.WithLogger(nil)},
			assert: func(t *testing.T, err error, _, _, _ *lockedBuffer) {
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "WithLogger")
			},
		},
		{
			name:    "typed nil option",
			refused: true,
			opts:    []oidcprovider.Option{oidcprovider.WithLogger((*slog.Logger)(nil))},
			assert: func(t *testing.T, err error, _, _, _ *lockedBuffer) {
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "WithLogger")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			own, chain, def := &lockedBuffer{}, &lockedBuffer{}, &lockedBuffer{}
			ids := &pe7nIDs{err: &pe7bCycleOne{}}

			opts := append([]oidcprovider.Option{oidcprovider.WithIDGenerator(ids)}, tc.opts...)
			if tc.own {
				opts = append(opts, oidcprovider.WithLogger(lrJSON(own)))
			}

			previous := slog.Default()
			t.Cleanup(func() { slog.SetDefault(previous) })

			if tc.refused {
				_, err := oidcprovider.New(validDeps(t), opts...)
				tc.assert(t, err, own, chain, def)

				return
			}

			f := pe7bFixtureKeys(t, newExchangeKeys(t), activeUsers(t), opts...)

			// Swapped after construction: the destination is read per record.
			slog.SetDefault(lrJSON(def))

			c := issueCodeFor(t, f, "billing-web", nil, testSignIn(f, "u-1"), "openid", "profile")
			ids.armed.Store(true)

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, lrJSON(chain))
			}

			_, exchangeErr := f.p.Token(ctx, billingExchange(c, nil))
			require.Error(t, exchangeErr, "the identifier failed, so no token")
			require.Positive(t, ids.calls.Load(), "the exchange reached the token's identifier")

			tc.assert(t, nil, own, chain, def)
		})
	}
}

// TestLogRoute_Outbound pins the default case of the provider's two outbound
// calls, the client-keys fetch and the back-channel logout delivery, whose
// abort record for a hostile transport error is written through the logger the
// provider attaches to the request's context: with no logger option given, the
// chain's logger stays on the context, and with no chain the record goes to
// slog.Default() as it is when the record is written. (An explicit option
// winning is pinned by the existing hostile-transport tests.) It swaps the
// default logger, so it does not run in parallel.
func TestLogRoute_Outbound(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	hostile := &http.Client{Transport: ckHostileTransport{}}

	type testCase struct {
		name  string
		chain bool
		// run makes the call, on ctx, with no logger option given.
		run func(t *testing.T, ctx context.Context)
	}

	keySet := func(t *testing.T, ctx context.Context) {
		t.Helper()

		f := newKeysFixture(t, keysOptions{
			outbound: func(*keysFixture) []outbound.Option { return []outbound.Option{outbound.WithHTTPClient(hostile)} },
		})

		rc, err := f.authenticate(ctx, keyClientID, esKid)
		assert.Nil(t, rc)
		require.ErrorIs(t, err, oidcprovider.ErrDependency)
	}

	logout := func(t *testing.T, ctx context.Context) {
		t.Helper()

		store, err := oidcprovider.NewMemoryGrantStore()
		require.NoError(t, err)

		grants := &endingGrants{GrantStore: store}
		deps := validDeps(t)
		deps.Keys = newExchangeKeys(t)
		deps.Clients = []oidcprovider.Client{listeningClient("billing-web", billingBackChannel)}

		p, err := oidcprovider.New(deps, oidcprovider.WithGrantStore(grants), oidcprovider.WithLogoutOutbound(outbound.WithHTTPClient(hostile)))
		require.NoError(t, err)

		family, err := id.NewV7Generator().NewID()
		require.NoError(t, err)
		grants.push(family, []oidcprovider.Grant{{ClientID: "billing-web", User: "u-1", SignInFamily: family}})

		_, err = p.EndSignIn(ctx, oidcprovider.SignInSelector{Family: family})
		require.NoError(t, err)

		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Second)
		defer cancel()
		require.NoError(t, p.Shutdown(shutdown))
	}

	var cases []testCase

	for name, run := range map[string]func(*testing.T, context.Context){"client-keys fetch": keySet, "logout delivery": logout} {
		cases = append(cases,
			testCase{name: name + ", no option, inside a configured chain", chain: true, run: run},
			testCase{name: name + ", no chain", run: run},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain, def := &ckLockedBuffer{}, &ckLockedBuffer{}

			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(def, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, slog.New(slog.NewJSONHandler(chain, nil)))
			}

			tc.run(t, ctx)

			if tc.chain {
				assert.Equal(t, 1, chain.aborts(), "the chain's logger takes the record")
				assert.Zero(t, def.aborts(), "none on slog.Default()")

				return
			}

			assert.Equal(t, 1, def.aborts(), "the default as swapped at record time")
		})
	}
}

// lrJSON is a debug-level JSON logger writing to w.
func lrJSON(w *lockedBuffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// lrAborts are the walk-abort records w holds.
func lrAborts(t *testing.T, w *lockedBuffer) []map[string]any {
	t.Helper()

	aborts, _ := pe7eAbortsAndLogs(t, w.String(), "")

	return aborts
}
