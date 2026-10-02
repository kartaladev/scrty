package httpsec_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// sessionWrites records what a session store was asked to write, copied at
// the moment of the write, so a case can tell what a session held when it was
// first stored from what it holds now.
type sessionWrites struct {
	mu      sync.Mutex
	created []session.Session
	saved   []session.Session
}

func (w *sessionWrites) creates() []session.Session {
	w.mu.Lock()
	defer w.mu.Unlock()

	return append([]session.Session(nil), w.created...)
}

func (w *sessionWrites) saves() []session.Session {
	w.mu.Lock()
	defer w.mu.Unlock()

	return append([]session.Session(nil), w.saved...)
}

// spiedSessions is a session manager over an in-memory store whose writes are
// recorded.
func spiedSessions(t *testing.T) (*session.Manager, *sessionWrites) {
	t.Helper()

	mem := session.NewMemoryStore()
	w := &sessionWrites{}

	store := NewMockStore(gomock.NewController(t))
	store.EXPECT().Create(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, s *session.Session) error {
			w.mu.Lock()
			w.created = append(w.created, *s)
			w.mu.Unlock()

			return mem.Create(ctx, s)
		})
	store.EXPECT().Save(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, s *session.Session) error {
			w.mu.Lock()
			w.saved = append(w.saved, *s)
			w.mu.Unlock()

			return mem.Save(ctx, s)
		})
	store.EXPECT().Load(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.Load)
	store.EXPECT().CountActiveByUser(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.CountActiveByUser)

	m, err := session.NewManager(session.WithStore(store))
	require.NoError(t, err)

	return m, w
}

// oidcMFAEngine holds both library MFA policies over a method the linked user
// is enrolled on whenever enrolled reports so, requiring a second factor of
// everyone. With exempt, a consumer exemption rule marks an OIDC login exempt,
// which is a total exemption; without it, the library's default classification
// applies, under which an OIDC login is not exempt.
func oidcMFAEngine(t *testing.T, exempt bool, enrolled func() bool) *policy.Engine {
	t.Helper()

	method := NewMockMFAMethodLookup(gomock.NewController(t))
	method.EXPECT().Name().Return("totp").AnyTimes()
	method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (bool, error) { return enrolled(), nil })

	var (
		challengeOpts []policy.MFAOption
		// The source answers the handoffs' unasserted assurance as unmet;
		// OIDC login refuses to assemble a requirement policy without one.
		requirementOpts = []policy.MFARequirementOption{
			policy.WithMFARequiredForAll(),
			policy.WithFederatedAssuranceSource(newTestOIDCManager(t)),
		}
	)

	if exempt {
		classification := policy.WithMFAExemption(func(k factor.Kind) bool {
			return k == factor.OIDC || k.MFAExempt()
		})
		challengeOpts = append(challengeOpts, classification)
		requirementOpts = append(requirementOpts, classification)
	}

	challenge, err := policy.NewMFAPolicy([]policy.MFAMethodLookup{method}, challengeOpts...)
	require.NoError(t, err)

	requirement, err := policy.NewMFARequirementPolicy(nil, []policy.MFAMethodLookup{method}, requirementOpts...)
	require.NoError(t, err)

	return engineOf(t, challenge, requirement)
}

// TestOIDCRedeemSession pins what a successful redemption leaves behind: a
// session carrying the federated login from the write that creates it, the
// login document plus an allowlisted destination, and a challenge when the
// policy raises one.
func TestOIDCRedeemSession(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// opts configure the chain beside the harness's required wiring.
		opts []httpsec.OIDCOption

		// chainOpts configure the chain beside EnableOIDCLogin.
		chainOpts func(t *testing.T) []httpsec.Option

		// handoff adjusts the login the redeemed code is issued for.
		handoff func(h *oidcHarness, res *oidc.CallbackResult)

		assert func(t *testing.T, h *oidcHarness, w *sessionWrites, code string, out served)
	}

	mfaWired := func(exempt bool) func(t *testing.T) []httpsec.Option {
		return func(t *testing.T) []httpsec.Option {
			t.Helper()

			return []httpsec.Option{
				httpsec.WithPolicyEngine(oidcMFAEngine(t, exempt, func() bool { return true })),
				enableMFAFor(t),
			}
		}
	}

	decode := func(t *testing.T, out served) map[string]any {
		t.Helper()

		var body map[string]any
		require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))

		return body
	}

	cases := []testCase{
		{
			name: "the session carries the OIDC first factor and the federated fields from its first write",
			assert: func(t *testing.T, h *oidcHarness, w *sessionWrites, _ string, out served) {
				require.NoError(t, out.err)

				created := w.creates()
				require.Len(t, created, 1)
				assert.Equal(t, factor.OIDC, created[0].FirstFactor)
				assert.Equal(t, testOIDCProvider, created[0].ExternalProvider)
				assert.Equal(t, h.provider.srv.URL, created[0].ExternalIssuer)
				assert.Equal(t, oidcTestSessionID, created[0].ExternalSessionID)
				assert.Equal(t, oidcTestIDToken, created[0].ExternalIDToken)
				assert.Equal(t, oidcTestUserID, created[0].UserID)
				assert.Empty(t, w.saves(), "nothing is added to the session after it was created")
			},
		},
		{
			name: "a provider without session ids records an empty one and the login succeeds",
			handoff: func(_ *oidcHarness, res *oidc.CallbackResult) {
				res.SessionID = ""
			},
			assert: func(t *testing.T, h *oidcHarness, w *sessionWrites, _ string, out served) {
				require.NoError(t, out.err)

				created := w.creates()
				require.Len(t, created, 1)
				assert.Empty(t, created[0].ExternalSessionID)
				assert.Equal(t, h.provider.srv.URL, created[0].ExternalIssuer)
			},
		},
		{
			name: "the response is the login document plus the allowlisted next",
			opts: []httpsec.OIDCOption{httpsec.WithOIDCAllowedRedirects("/welcome")},
			handoff: func(_ *oidcHarness, res *oidc.CallbackResult) {
				res.Next = "/welcome"
			},
			assert: func(t *testing.T, _ *oidcHarness, w *sessionWrites, _ string, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, "application/json", out.rec.Header().Get("Content-Type"))
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
				assert.Equal(t, "no-referrer", out.rec.Header().Get("Referrer-Policy"))

				body := decode(t, out)
				assert.Equal(t, "issued-token", body["access_token"])
				assert.Contains(t, body, "refresh_token", "the same members a form login answers with")
				assert.Equal(t, "/welcome", body["next"])

				created := w.creates()
				require.Len(t, created, 1)
				require.IsType(t, "", body["valid_until"])
				validUntil, err := time.Parse(time.RFC3339Nano, body["valid_until"].(string))
				require.NoError(t, err)
				assert.True(t, created[0].IdleExpiresAt.Equal(validUntil),
					"valid_until is the session's idle expiry")
			},
		},
		{
			name: "a recorded next the allowlist does not hold becomes the root",
			opts: []httpsec.OIDCOption{httpsec.WithOIDCAllowedRedirects("/welcome")},
			handoff: func(_ *oidcHarness, res *oidc.CallbackResult) {
				res.Next = "https://evil.example/welcome"
			},
			assert: func(t *testing.T, _ *oidcHarness, _ *sessionWrites, _ string, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, "/", decode(t, out)["next"], "the recorded destination is never echoed raw")
			},
		},
		{
			name:      "a challenge consumes the code and returns the challenge",
			chainOpts: mfaWired(false),
			assert: func(t *testing.T, h *oidcHarness, w *sessionWrites, code string, out served) {
				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &challenge)
				assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
				require.NotNil(t, challenge.Session)
				assert.Equal(t, session.MFAPending, challenge.Session.MFA, "the session is pending the challenge")
				assert.Equal(t, factor.OIDC, challenge.Session.FirstFactor)
				assert.Equal(t, "no-referrer", out.rec.Header().Get("Referrer-Policy"))
				assert.Equal(t, 1, h.activeSessions(t))
				assert.Len(t, w.creates(), 1)

				again := serve(t, h.chain(t), handoffRequest(t.Context(), oidcAnotherSource, code))
				require.ErrorIs(t, again.err, oidc.ErrInvalidHandoff, "the code was spent")
			},
		},
		{
			name:      "a consumer exemption of oidc creates a session without a challenge",
			chainOpts: mfaWired(true),
			assert: func(t *testing.T, h *oidcHarness, w *sessionWrites, _ string, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)

				created := w.creates()
				require.Len(t, created, 1)
				assert.Equal(t, session.MFANone, created[0].MFA)
				assert.Empty(t, w.saves(), "no challenge was marked")
				assert.Equal(t, 1, h.activeSessions(t))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			h.issueTokens()

			var w *sessionWrites
			h.sessions, w = spiedSessions(t)

			if tc.chainOpts != nil {
				h.chainOpts = tc.chainOpts(t)
			}

			res := h.handoffResult()
			if tc.handoff != nil {
				tc.handoff(h, &res)
			}

			code := h.issueHandoffFor(t, res)

			out := serve(t, h.chain(t, tc.opts...), handoffRequest(t.Context(), oidcTestSource, code))

			tc.assert(t, h, w, code, out)
		})
	}
}
