package oidc_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

// keyedSummaries counts the lines of out that are summaries (carry msg) and
// name marker.
func keyedSummaries(out *bytes.Buffer, msg, marker string) int {
	n := 0

	for line := range strings.SplitSeq(out.String(), "\n") {
		if strings.Contains(line, `"msg":"`+msg+`"`) && strings.Contains(line, marker) {
			n++
		}
	}

	return n
}

// runSummaryPerKey pins, for one component, that a sampler key's summary goes
// to the chain the key's records went to and to no other. build makes the
// component, with own as its logger option when non-nil, and returns refuse,
// which writes three records for key 1 or 2 on a context, and the flush.
// markerOne and markerTwo identify each key in its summary.
func runSummaryPerKey(
	t *testing.T,
	msg, markerOne, markerTwo string,
	build func(t *testing.T, own *slog.Logger) (refuse func(ctx context.Context, key int), flush func()),
) {
	t.Helper()

	type testCase struct {
		name   string
		own    bool
		run    func(bare, a, b context.Context, refuse func(context.Context, int))
		assert func(t *testing.T, a, b, def, own *bytes.Buffer)
	}

	cases := []testCase{
		{
			name: "two chains: each summary stays on its own chain",
			run: func(_, a, b context.Context, refuse func(context.Context, int)) {
				refuse(a, 1)
				refuse(b, 2)
			},
			assert: func(t *testing.T, a, b, def, _ *bytes.Buffer) {
				assert.Equal(t, 1, keyedSummaries(a, msg, markerOne))
				assert.Zero(t, keyedSummaries(a, msg, markerTwo))
				assert.Equal(t, 1, keyedSummaries(b, msg, markerTwo))
				assert.Zero(t, keyedSummaries(b, msg, markerOne))
				assert.Zero(t, keyedSummaries(def, msg, ""))
			},
		},
		{
			name: "key written under A then suppressed under B: summary on A only",
			run: func(_, a, b context.Context, refuse func(context.Context, int)) {
				refuse(a, 1)
				refuse(b, 1)
			},
			assert: func(t *testing.T, a, b, def, _ *bytes.Buffer) {
				assert.Equal(t, 1, keyedSummaries(a, msg, markerOne))
				assert.Empty(t, b.String())
				assert.Zero(t, keyedSummaries(def, msg, ""))
			},
		},
		{
			name: "no chain: the default logger",
			run: func(bare, _, _ context.Context, refuse func(context.Context, int)) {
				refuse(bare, 1)
			},
			assert: func(t *testing.T, a, b, def, _ *bytes.Buffer) {
				assert.Equal(t, 1, keyedSummaries(def, msg, markerOne))
				assert.Empty(t, a.String())
				assert.Empty(t, b.String())
			},
		},
		{
			name: "own option wins",
			own:  true,
			run: func(_, a, _ context.Context, refuse func(context.Context, int)) {
				refuse(a, 1)
			},
			assert: func(t *testing.T, a, _, def, own *bytes.Buffer) {
				assert.Equal(t, 1, keyedSummaries(own, msg, markerOne))
				assert.Empty(t, a.String())
				assert.Empty(t, def.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := routeBufs{chain: &bytes.Buffer{}, own: &bytes.Buffer{}, def: &bytes.Buffer{}}
			chainB := &bytes.Buffer{}

			previous := slog.Default()
			slog.SetDefault(b.logger(b.def))
			t.Cleanup(func() { slog.SetDefault(previous) })

			var own *slog.Logger
			if tc.own {
				own = b.logger(b.own)
			}

			refuse, flush := build(t, own)

			tc.run(t.Context(),
				ctxlog.With(t.Context(), b.logger(b.chain)), ctxlog.With(t.Context(), b.logger(chainB)), refuse)
			flush()

			tc.assert(t, b.chain, chainB, b.def, b.own)
		})
	}
}

// TestLogRoute_SummaryPerKey_Broker pins the broker's summaries per key.
func TestLogRoute_SummaryPerKey_Broker(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runSummaryPerKey(t, "oidc broker refusals suppressed", `:corp"`, `:corp2"`,
		func(t *testing.T, own *slog.Logger) (func(context.Context, int), func()) {
			t.Helper()

			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, identity.ErrUserNotFound).AnyTimes()

			links := brokerSeededLinks(t)
			require.NoError(t, links.Insert(t.Context(), oidc.Link{
				Provider: "corp2", Issuer: brokerCorpIssuer, Subject: "s-1",
				UserID: "u-1", Username: "alice", Email: "alice@corp.example",
			}))

			var opts []oidc.BrokerOption
			if own != nil {
				opts = append(opts, oidc.WithBrokerLogger(own))
			}

			b, err := oidc.NewBroker(links, users, opts...)
			require.NoError(t, err)

			return func(ctx context.Context, key int) {
					id := brokerCorpIdentity()
					if key == 2 {
						id.Provider = "corp2"
					}

					for range 3 {
						_, err := b.Broker(ctx, id)
						require.Error(t, err)
					}
				}, func() {
					require.NoError(t, b.FlushRefusalLogs())
				}
		})
}

// TestLogRoute_SummaryPerKey_Handoff pins the handoff manager's summaries per
// key.
func TestLogRoute_SummaryPerKey_Handoff(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runSummaryPerKey(t, "oidc handoff refusals suppressed", `oidc.handoff.malformed"`, `oidc.handoff.unknown"`,
		func(t *testing.T, own *slog.Logger) (func(context.Context, int), func()) {
			t.Helper()

			var opts []oidc.HandoffOption
			if own != nil {
				opts = append(opts, oidc.WithHandoffLogger(own))
			}

			h, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(gomock.NewController(t)), opts...)
			require.NoError(t, err)

			return func(ctx context.Context, key int) {
					code := "not-a-handoff-code"
					if key == 2 {
						code = strings.Repeat("A", 22) + "." + strings.Repeat("A", 43)
					}

					for range 3 {
						_, err := h.Redeem(ctx, code)
						require.Error(t, err)
					}
				}, func() {
					require.NoError(t, h.FlushRefusalLogs())
				}
		})
}

// TestLogRoute_SummaryPerKey_RelyingParty pins the relying party's summaries
// per key.
func TestLogRoute_SummaryPerKey_RelyingParty(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runSummaryPerKey(t, "oidc refusals suppressed", `:corp"`, `:corp2"`,
		func(t *testing.T, own *slog.Logger) (func(context.Context, int), func()) {
			t.Helper()

			p := newTestProvider(t)
			reg, err := oidc.NewRegistry(p.Provider("corp"), p.Provider("corp2"))
			require.NoError(t, err)

			flows := NewMockFlowStore(gomock.NewController(t))
			flows.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(oidc.Flow{}, errDBDown).AnyTimes()

			opts := []oidc.Option{oidc.WithFlowStore(flows)}
			if own != nil {
				opts = append(opts, oidc.WithLogger(own))
			}

			m, err := oidc.NewRelyingParty(reg, NewMockIdentityBroker(gomock.NewController(t)), opts...)
			require.NoError(t, err)

			return func(ctx context.Context, key int) {
					provider := "corp"
					if key == 2 {
						provider = "corp2"
					}

					for range 3 {
						_, err := m.Callback(ctx, provider, "code", "state", "unknown-handle")
						require.Error(t, err)
					}
				}, func() {
					require.NoError(t, m.FlushRefusalLogs())
				}
		})
}
