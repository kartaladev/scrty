package oidc_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/outbound"
)

// obCycle contains itself through Unwrap() error.
type obCycle struct{}

func (*obCycle) Error() string   { return "outbound transport: hostile" }
func (c *obCycle) Unwrap() error { return c }

// TestRelyingParty_HostileProviderTransportRecordsOnItsLogger pins that the abort
// record of a hostile error from the provider transport, at the discovery, the
// token exchange and the key set fetch, lands exactly once on the relying party's
// logger and none on slog.Default(). It replaces the default logger, so it does
// not run in parallel.
func TestRelyingParty_HostileProviderTransportRecordsOnItsLogger(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name string
		// hostilePath is the request path whose transport fails.
		hostilePath string
		// callback is whether the failing call is the callback's, after a genuine Authorize.
		callback bool
	}

	cases := []testCase{
		{name: "the discovery fetch", hostilePath: "/.well-known/openid-configuration"},
		{name: "the token exchange", hostilePath: "/token", callback: true},
		{name: "the key set fetch", hostilePath: "/jwks", callback: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def := &bytes.Buffer{}
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(def, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })

			p := newTestProvider(t)
			reg, err := oidc.NewRegistry(p.Provider("corp"), p.Provider("partner"))
			require.NoError(t, err)

			var armed atomic.Bool
			armed.Store(!tc.callback)

			real := p.srv.Client()
			hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if armed.Load() && r.URL.Path == tc.hostilePath {
					return nil, &obCycle{}
				}

				return real.Transport.RoundTrip(r)
			})}
			out, err := outbound.New(outbound.WithHTTPClient(hc))
			require.NoError(t, err)

			logs := &bytes.Buffer{}
			now := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)
			broker := NewMockIdentityBroker(gomock.NewController(t))
			m, err := oidc.NewRelyingParty(reg, broker,
				oidc.WithOutboundClient(out),
				oidc.WithClock(clockwork.NewFakeClockAt(now)),
				oidc.WithLogger(slog.New(slog.NewJSONHandler(logs, nil))))
			require.NoError(t, err)

			if tc.callback {
				env := &callbackEnv{m: m, p: p, broker: broker, logs: &bytes.Buffer{}, now: now}
				env.auth, err = m.Authorize(t.Context(), "corp", "/after")
				require.NoError(t, err)
				env.flow = authorizeFlow(t, m, env.auth.Handle)
				env.reissue(t, nil)
				logs.Reset()
				armed.Store(true)

				_, err = env.genuine(t)
			} else {
				_, err = m.Authorize(t.Context(), "corp", "/after")
			}

			require.Error(t, err)
			assert.Equal(t, 1, strings.Count(logs.String(), porterr.MsgClassificationAborted),
				"one abort record on the relying party's logger")
			assert.Zero(t, strings.Count(def.String(), porterr.MsgClassificationAborted), "none on slog.Default()")
		})
	}
}
