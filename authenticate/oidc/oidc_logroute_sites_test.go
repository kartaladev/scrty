package oidc_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

// siteChains runs write under chain A and then again under chain B, with the
// default logger swapped for a third buffer, and returns what each received
// after flush. The second write falls in the first one's sampling window, so
// the sampler suppresses it: its summary belongs to A, where the record that
// opened the window went, and B receives none. It does not run in parallel.
func siteChains(t *testing.T, write func(ctx context.Context), flush func()) (a, b, def *bytes.Buffer) {
	t.Helper()

	a, b, def = &bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{}
	logger := func(w *bytes.Buffer) *slog.Logger {
		return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	previous := slog.Default()
	slog.SetDefault(logger(def))
	t.Cleanup(func() { slog.SetDefault(previous) })

	write(ctxlog.With(t.Context(), logger(a)))
	write(ctxlog.With(t.Context(), logger(b)))
	flush()

	return a, b, def
}

// TestLogRoute_SummaryOtherSites_Callback pins, for the relying party's
// callback, exchange and assurance records, that a key written under chain A
// and suppressed under chain B is summarised on A and on no other destination.
func TestLogRoute_SummaryOtherSites_Callback(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const summary = "oidc refusals suppressed"

	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

	type testCase struct {
		name string
		// token is the token endpoint's answer, given the provider's issuer
		// and a signer for ID tokens.
		token func(t *testing.T, p *testProvider) (int, string)
		key   string
	}

	signed := func(t *testing.T, p *testProvider, extra map[string]any) string {
		t.Helper()

		claims := map[string]any{
			"iss": p.Issuer(), "aud": "client-corp", "sub": "subject-1",
			"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": "n",
			"email": "alice@corp.example", "email_verified": true,
		}
		for k, v := range extra {
			claims[k] = v
		}

		return p.Sign(t, claims)
	}

	cases := []testCase{
		{
			name: "logCallbackRefusal: an invalid ID token",
			token: func(t *testing.T, p *testProvider) (int, string) {
				return http.StatusOK, `{"id_token":"` + signed(t, p, map[string]any{"nonce": "an-earlier-flow"}) + `"}`
			},
			key: "oidc.callback:invalid-id-token:corp",
		},
		{
			name: "logExchangeFailure: the provider refuses the code",
			token: func(*testing.T, *testProvider) (int, string) {
				return http.StatusBadRequest, `{"error":"invalid_grant"}`
			},
			key: "oidc.exchange:",
		},
		{
			name: "logMalformedAssurance: an amr that asserts nothing",
			token: func(t *testing.T, p *testProvider) (int, string) {
				return http.StatusOK, `{"id_token":"` + signed(t, p, map[string]any{"amr": "mfa"}) + `"}`
			},
			key: "oidc.callback:malformed-assurance-claim:corp",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProvider(t)
			reg, err := oidc.NewRegistry(p.Provider("corp"))
			require.NoError(t, err)

			p.SetTokenResponse(func(*http.Request) (int, string) { return tc.token(t, p) })

			ctrl := gomock.NewController(t)
			flows := NewMockFlowStore(ctrl)
			flows.EXPECT().Complete(gomock.Any(), "h", "corp", "s").
				Return(oidc.Flow{Provider: "corp", State: "s", Nonce: "n", Verifier: "v"}, nil).AnyTimes()

			broker := NewMockIdentityBroker(ctrl)
			broker.EXPECT().Broker(gomock.Any(), gomock.Any()).Return(alice(), nil).AnyTimes()

			m, err := oidc.NewRelyingParty(reg, broker,
				oidc.WithOutboundClient(p.Outbound(t)),
				oidc.WithClock(clockwork.NewFakeClockAt(now)),
				oidc.WithFlowStore(flows))
			require.NoError(t, err)

			a, b, def := siteChains(t,
				func(ctx context.Context) { _, _ = m.Callback(ctx, "corp", "the-code", "s", "h") },
				func() { require.NoError(t, m.FlushRefusalLogs()) })

			assert.Equal(t, 1, keyedSummaries(a, summary, tc.key), "the summary is on the chain that wrote the record")
			assert.Zero(t, keyedSummaries(b, summary, ""), "chain B received the key's summary")
			assert.Zero(t, keyedSummaries(def, summary, ""), "the default received the key's summary")
		})
	}
}

// TestLogRoute_SummaryOtherSites_Broker pins, for the broker's mirror-update
// and ignored-password-claim records, that a key written under chain A and
// suppressed under chain B is summarised on A and on no other destination.
func TestLogRoute_SummaryOtherSites_Broker(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const summary = "oidc broker refusals suppressed"

	type testCase struct {
		name string
		// build makes the broker and the call that writes the key's record.
		build func(t *testing.T) (write func(ctx context.Context), flush func() error)
		key   string
	}

	cases := []testCase{
		{
			name: "mirror-update-failed: the provisioner cannot update the user",
			build: func(t *testing.T) (func(context.Context), func() error) {
				ctrl := gomock.NewController(t)
				prov := NewMockUserProvisioner(ctrl)
				prov.EXPECT().Update(gomock.Any(), "alice", gomock.Any()).Return(nil, errMirrorUpdate).AnyTimes()

				b, err := oidc.NewBroker(brokerSeededLinks(t), mirrorUsers(ctrl),
					oidc.WithBrokerProvisioner(prov),
					oidc.WithBrokerNameClaim("corp", "name"),
					oidc.WithBrokerClaimMirror("corp", true),
					oidc.WithBrokerClock(clockwork.NewFakeClockAt(provisionClock)))
				require.NoError(t, err)

				return func(ctx context.Context) {
					_, err := b.Broker(ctx, mirrorIdentity("Alice B.", hashCost12))
					require.NoError(t, err, "a failed mirror update does not fail the login")
				}, b.FlushRefusalLogs
			},
			key: "oidc.broker:mirror-update-failed:corp",
		},
		{
			name: "passwordClaimIgnored: a claim that is not a bcrypt hash",
			build: func(t *testing.T) (func(context.Context), func() error) {
				ctrl := gomock.NewController(t)
				prov := NewMockUserProvisioner(ctrl)
				prov.EXPECT().Provision(gomock.Any(), "bob@corp.example", gomock.Any()).
					Return(&identity.Details{ID: "u-9", Username: "bob@corp.example", Active: true}, nil).AnyTimes()

				b, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(ctrl),
					oidc.WithBrokerProvisioner(prov),
					oidc.WithBrokerJIT("corp"),
					oidc.WithBrokerPasswordClaim("corp", "credentials.password_hash"),
					oidc.WithBrokerPasswordEncoder(fastBcryptEncoder(t)),
					oidc.WithBrokerClock(clockwork.NewFakeClockAt(provisionClock)))
				require.NoError(t, err)

				subject := 0

				return func(ctx context.Context) {
					// Each login is a new subject, so each provisions; the first
					// occurrence of the reason is a WARN outside the sampler,
					// the later ones are sampled.
					for range 2 {
						subject++

						_, err := b.Broker(ctx, passwordClaimIdentity("s-"+string(rune('a'+subject)), "hunter2")) //nolint:gosec // G115: a small test index
						require.NoError(t, err)
					}
				}, b.FlushRefusalLogs
			},
			key: "oidc.broker.password-claim:",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			write, flush := tc.build(t)

			a, b, def := siteChains(t, write, func() { require.NoError(t, flush()) })

			assert.Equal(t, 1, keyedSummaries(a, summary, tc.key), "the summary is on the chain that wrote the record")
			assert.Zero(t, keyedSummaries(b, summary, ""), "chain B received the key's summary")
			assert.Zero(t, keyedSummaries(def, summary, ""), "the default received the key's summary")
		})
	}
}

// mirrorUsers loads u-1 as the stored user every mirror row resolves.
func mirrorUsers(ctrl *gomock.Controller) *MockUserLoader {
	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(mirrorStored(), nil).AnyTimes()

	return users
}
