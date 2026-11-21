package oidc_test

// The TestLogRoute_ tests replace slog.Default() for their duration, so they do
// not run in parallel, and they restore the logger they found.

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/outbound"
)

// routeBufs are the three destinations a record can reach.
type routeBufs struct{ chain, own, def *bytes.Buffer }

func (b routeBufs) logger(w *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// runLogRoute runs the three routing rows and the nil-option row of one
// component. trigger makes the component write one record, with own as its
// logger option when non-nil and none otherwise, on a context carrying ctx's
// chain; nilOption builds the component with a nil logger option.
func runLogRoute(
	t *testing.T,
	trigger func(t *testing.T, ctx context.Context, own *slog.Logger),
	nilOption func(t *testing.T) error,
) {
	t.Helper()

	type testCase struct {
		name   string
		chain  bool
		own    bool
		assert func(t *testing.T, b routeBufs)
	}

	cases := []testCase{
		{
			name: "no option, inside a configured chain", chain: true,
			assert: func(t *testing.T, b routeBufs) {
				assert.NotEmpty(t, b.chain.String(), "the record did not reach the chain's logger")
				assert.Empty(t, b.def.String())
			},
		},
		{
			name: "own option wins", chain: true, own: true,
			assert: func(t *testing.T, b routeBufs) {
				assert.NotEmpty(t, b.own.String())
				assert.Empty(t, b.chain.String())
				assert.Empty(t, b.def.String())
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, b routeBufs) {
				assert.NotEmpty(t, b.def.String(), "the record did not reach slog.Default()")
				assert.Empty(t, b.chain.String())
				assert.Empty(t, b.own.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := routeBufs{chain: &bytes.Buffer{}, own: &bytes.Buffer{}, def: &bytes.Buffer{}}

			previous := slog.Default()
			slog.SetDefault(b.logger(b.def))
			t.Cleanup(func() { slog.SetDefault(previous) })

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, b.logger(b.chain))
			}

			var own *slog.Logger
			if tc.own {
				own = b.logger(b.own)
			}

			trigger(t, ctx, own)
			tc.assert(t, b)
		})
	}

	t.Run("nil option", func(t *testing.T) {
		err := nilOption(t)

		require.ErrorIs(t, err, oidc.ErrConfig)
	})
}

func TestLogRoute_Broker(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runLogRoute(t,
		func(t *testing.T, ctx context.Context, own *slog.Logger) {
			t.Helper()

			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, identity.ErrUserNotFound).AnyTimes()

			var opts []oidc.BrokerOption
			if own != nil {
				opts = append(opts, oidc.WithBrokerLogger(own))
			}

			b, err := oidc.NewBroker(brokerSeededLinks(t), users, opts...)
			require.NoError(t, err)

			_, err = b.Broker(ctx, brokerCorpIdentity())
			require.Error(t, err)
		},
		func(t *testing.T) error {
			t.Helper()

			_, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(gomock.NewController(t)),
				oidc.WithBrokerLogger(nil))

			return err
		})
}

func TestLogRoute_Handoff(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runLogRoute(t,
		func(t *testing.T, ctx context.Context, own *slog.Logger) {
			t.Helper()

			var opts []oidc.HandoffOption
			if own != nil {
				opts = append(opts, oidc.WithHandoffLogger(own))
			}

			h, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(gomock.NewController(t)), opts...)
			require.NoError(t, err)

			_, err = h.Redeem(ctx, "not-a-handoff-code")
			require.Error(t, err)
		},
		func(t *testing.T) error {
			t.Helper()

			_, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(gomock.NewController(t)),
				oidc.WithHandoffLogger(nil))

			return err
		})
}

func TestLogRoute_RelyingParty(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	// The discovery fetch fails with a hostile error, so the sanitizer writes
	// an abort record. The record is the relying party's, and the outbound
	// client it calls with the context reports to the same destination.
	runLogRoute(t,
		func(t *testing.T, ctx context.Context, own *slog.Logger) {
			t.Helper()

			p := newTestProvider(t)
			reg, err := oidc.NewRegistry(p.Provider("corp"), p.Provider("partner"))
			require.NoError(t, err)

			inner := p.srv.Client()
			hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/.well-known/openid-configuration" {
					return nil, &obCycle{}
				}

				return inner.Transport.RoundTrip(r)
			})}
			out, err := outbound.New(outbound.WithHTTPClient(hc))
			require.NoError(t, err)

			opts := []oidc.Option{oidc.WithOutboundClient(out)}
			if own != nil {
				opts = append(opts, oidc.WithLogger(own))
			}

			m, err := oidc.NewRelyingParty(reg, NewMockIdentityBroker(gomock.NewController(t)), opts...)
			require.NoError(t, err)

			_, err = m.Authorize(ctx, "corp", "/after")
			require.Error(t, err)
		},
		func(t *testing.T) error {
			t.Helper()

			p := newTestProvider(t)
			reg, err := oidc.NewRegistry(p.Provider("corp"))
			require.NoError(t, err)

			_, err = oidc.NewRelyingParty(reg, NewMockIdentityBroker(gomock.NewController(t)), oidc.WithLogger(nil))

			return err
		})
}

// TestLogRoute_RelyingPartyAbortRecordCount pins that the hostile discovery
// error writes exactly one abort record, on the one destination the relying
// party resolves: the outbound client's own call, handed the same context,
// does not write a second one.
func TestLogRoute_RelyingPartyAbortRecordCount(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	chain, def := &bytes.Buffer{}, &bytes.Buffer{}

	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(def, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	p := newTestProvider(t)
	reg, err := oidc.NewRegistry(p.Provider("corp"))
	require.NoError(t, err)

	hc := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &obCycle{}
	})}
	out, err := outbound.New(outbound.WithHTTPClient(hc))
	require.NoError(t, err)

	m, err := oidc.NewRelyingParty(reg, NewMockIdentityBroker(gomock.NewController(t)), oidc.WithOutboundClient(out))
	require.NoError(t, err)

	ctx := ctxlog.With(t.Context(), slog.New(slog.NewJSONHandler(chain, nil)))
	_, err = m.Authorize(ctx, "corp", "/after")
	require.Error(t, err)

	assert.Equal(t, 1, bytes.Count(chain.Bytes(), []byte(porterr.MsgClassificationAborted)),
		"one abort record on the chain's logger")
	assert.Zero(t, bytes.Count(def.Bytes(), []byte(porterr.MsgClassificationAborted)), "none on slog.Default()")
}

// TestLogRoute_SuppressedSummary pins that a sampler's suppressed-count summary,
// which has no request of its own, is written to the chain whose record the
// sampler last held back and not to slog.Default(). It replaces the default
// logger, so it does not run in parallel.
func TestLogRoute_SuppressedSummary(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name string
		// refuse makes the component refuse three times on ctx, then flush.
		refuse  func(t *testing.T, ctx context.Context)
		summary string
	}

	cases := []testCase{
		{
			name:    "the broker",
			summary: "oidc broker refusals suppressed",
			refuse: func(t *testing.T, ctx context.Context) {
				t.Helper()

				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, identity.ErrUserNotFound).AnyTimes()

				b, err := oidc.NewBroker(brokerSeededLinks(t), users)
				require.NoError(t, err)

				for range 3 {
					_, err = b.Broker(ctx, brokerCorpIdentity())
					require.Error(t, err)
				}

				require.NoError(t, b.FlushRefusalLogs())
			},
		},
		{
			name:    "the handoff",
			summary: "oidc handoff refusals suppressed",
			refuse: func(t *testing.T, ctx context.Context) {
				t.Helper()

				h, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(gomock.NewController(t)))
				require.NoError(t, err)

				for range 3 {
					_, err = h.Redeem(ctx, "not-a-handoff-code")
					require.Error(t, err)
				}

				require.NoError(t, h.FlushRefusalLogs())
			},
		},
		{
			name:    "the relying party",
			summary: "oidc refusals suppressed",
			refuse: func(t *testing.T, ctx context.Context) {
				t.Helper()

				p := newTestProvider(t)
				reg, err := oidc.NewRegistry(p.Provider("corp"))
				require.NoError(t, err)

				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidc.Flow{}, errDBDown).AnyTimes()

				m, err := oidc.NewRelyingParty(reg, NewMockIdentityBroker(gomock.NewController(t)),
					oidc.WithFlowStore(flows))
				require.NoError(t, err)

				for range 3 {
					_, err = m.Callback(ctx, "corp", "code", "state", "unknown-handle")
					require.Error(t, err)
				}

				require.NoError(t, m.FlushRefusalLogs())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain, def := &bytes.Buffer{}, &bytes.Buffer{}

			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(def, &slog.HandlerOptions{Level: slog.LevelDebug})))
			t.Cleanup(func() { slog.SetDefault(previous) })

			chainLog := slog.New(slog.NewJSONHandler(chain, &slog.HandlerOptions{Level: slog.LevelDebug}))
			tc.refuse(t, ctxlog.With(t.Context(), chainLog))

			assert.Contains(t, chain.String(), tc.summary)
			assert.NotContains(t, def.String(), tc.summary)
		})
	}
}
