package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

// jsonRoundTrip marshals v and decodes it back into a fresh map[string]any,
// the same shape encoding/json produces reading an arbitrary token payload
// (numbers as float64, objects and arrays generically typed). It gives a
// test the expected claims exactly as the library will have decoded them,
// rather than as the test authored them.
func jsonRoundTrip(t *testing.T, v map[string]any) map[string]any {
	t.Helper()

	b, err := json.Marshal(v)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

// TestConsumerBroker verifies the "Consumer broker" scenario of the
// identity-linking spec: a consumer IdentityBroker, given to NewManager in
// place of the library's own *oidc.Broker, replaces linking, provisioning
// and mirroring entirely. It receives every claim of the verified ID token
// unchanged — including a nested claim and one the library does not
// recognise — and its returned principal, provider and session become the
// callback's result. The consumer broker is NewManager's broker argument
// directly, so the library's own broker collaborators — a link store and a
// user provisioner — are never constructed and never sit in the call path.
func TestConsumerBroker(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

	p := newTestProvider(t)
	reg, err := oidc.NewRegistry(p.Provider("corp"))
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	consumerBroker := NewMockIdentityBroker(ctrl)

	m, err := oidc.NewManager(reg, consumerBroker,
		oidc.WithOutboundClient(p.Outbound(t)),
		oidc.WithClock(clockwork.NewFakeClockAt(now)),
	)
	require.NoError(t, err)

	auth, err := m.Authorize(t.Context(), "corp", "/after")
	require.NoError(t, err)
	flow := authorizeFlow(t, m, auth.Handle)

	signedClaims := map[string]any{
		"iss": p.Issuer(), "aud": "client-corp", "sub": "subject-1",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		"nonce": flow.Nonce, "sid": "provider-session",
		"email": "alice@corp.example", "email_verified": true,
		"department":       "R&D",
		"realm_access":     map[string]any{"roles": []any{"editor", "viewer"}},
		"x_unknown_claim1": "kept-unchanged",
	}
	idTok := p.Sign(t, signedClaims)
	verifier := flow.Verifier
	p.SetTokenResponse(func(r *http.Request) (int, string) {
		if r.ParseForm() != nil || r.PostForm.Get("code") != "the-code" || r.PostForm.Get("code_verifier") != verifier {
			return http.StatusBadRequest, `{"error":"invalid_grant"}`
		}
		return http.StatusOK, `{"access_token":"at","id_token":"` + idTok + `"}`
	})

	wantClaims := jsonRoundTrip(t, signedClaims)

	want := &identity.Principal{ID: "user-alice", Username: "alice"}
	consumerBroker.EXPECT().Broker(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, ext oidc.ExternalIdentity) (*identity.Principal, error) {
			assert.Equal(t, "corp", ext.Provider)
			assert.Equal(t, p.Issuer(), ext.Issuer)
			assert.Equal(t, "subject-1", ext.Subject)
			assert.Equal(t, "alice@corp.example", ext.Email)
			assert.True(t, ext.EmailVerified)
			// The whole map, not a handful of hand-picked keys: a dropped
			// claim, an added one or a type change would go unnoticed by
			// the targeted checks above but not by this one.
			assert.Equal(t, wantClaims, ext.Claims)
			return want, nil
		})

	got, err := m.Callback(t.Context(), "corp", "the-code", flow.State, auth.Handle)
	require.NoError(t, err)
	assert.Same(t, want, got.Principal)
	assert.Equal(t, "corp", got.Provider)
	assert.Equal(t, "provider-session", got.SessionID)
	assert.Equal(t, "/after", got.Next)
}
