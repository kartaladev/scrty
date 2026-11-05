package oidcprovider_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/oidcprovider"
)

func TestConsentNeeded(t *testing.T) {
	t.Parallel()

	const clientID = "billing-web"
	web := oidcprovider.Client{ID: clientID, ApplicationType: oidcprovider.Web}
	firstParty := oidcprovider.Client{ID: clientID, ApplicationType: oidcprovider.Web, FirstParty: true}
	preAuthorized := oidcprovider.Client{
		ID:              clientID,
		ApplicationType: oidcprovider.Native,
		FirstParty:      true,
		OfflineAccess:   oidcprovider.OfflinePreAuthorized,
	}
	remembered := func(offline bool, scopes ...string) *oidcprovider.Consent {
		return &oidcprovider.Consent{ClientID: clientID, Scopes: scopes, Offline: offline}
	}

	needed := func(t *testing.T, got bool) {
		t.Helper()
		assert.True(t, got, "the consent stage is shown")
	}
	skipped := func(t *testing.T, got bool) {
		t.Helper()
		assert.False(t, got, "no consent stage is shown")
	}

	cases := []struct {
		name       string
		client     oidcprovider.Client
		scopes     []string
		prompt     []string
		remembered *oidcprovider.Consent
		assert     func(t *testing.T, got bool)
	}{
		{name: "first time", client: web, scopes: []string{"openid"}, assert: needed},
		{name: "covered", client: web, scopes: []string{"openid", "profile"}, remembered: remembered(false, "openid", "profile"), assert: skipped},
		{name: "covered, with more remembered", client: web, scopes: []string{"openid"}, remembered: remembered(false, "openid", "profile"), assert: skipped},
		{name: "a new scope", client: web, scopes: []string{"openid", "profile", "email"}, remembered: remembered(false, "openid", "profile"), assert: needed},
		{name: "remembered with no scopes", client: web, scopes: []string{"openid"}, remembered: remembered(false), assert: needed},
		{name: "a lost scope is simply no longer asked", client: web, scopes: []string{"openid"}, remembered: remembered(false, "profile"), assert: needed},
		{name: "prompt=consent, covered", client: web, scopes: []string{"openid"}, prompt: []string{"consent"}, remembered: remembered(true, "openid"), assert: needed},
		{name: "prompt=consent, beside another value", client: web, scopes: []string{"openid"}, prompt: []string{"login", "consent"}, remembered: remembered(false, "openid"), assert: needed},
		{name: "another prompt value does not ask", client: web, scopes: []string{"openid"}, prompt: []string{"login"}, remembered: remembered(false, "openid"), assert: skipped},
		{name: "prompt=consent, first-party", client: firstParty, scopes: []string{"openid"}, prompt: []string{"consent"}, assert: needed},
		{name: "prompt=consent, pre-authorized", client: preAuthorized, scopes: []string{"openid", "offline_access"}, prompt: []string{"consent"}, assert: needed},
		{name: "first-party with ordinary scopes", client: firstParty, scopes: []string{"openid", "profile"}, assert: skipped},
		{name: "first-party with offline_access", client: firstParty, scopes: []string{"openid", "offline_access"}, assert: needed},
		{name: "first-party with offline_access remembered", client: firstParty, scopes: []string{"openid", "offline_access"}, remembered: remembered(true), assert: skipped},
		{name: "first-party with other consent, asked for offline_access", client: firstParty, scopes: []string{"openid", "offline_access"}, remembered: remembered(false, "openid"), assert: needed},
		{name: "remembered Offline", client: web, scopes: []string{"openid", "offline_access"}, remembered: remembered(true, "openid"), assert: skipped},
		{name: "remembered Offline, with a new ordinary scope", client: web, scopes: []string{"openid", "email", "offline_access"}, remembered: remembered(true, "openid"), assert: needed},
		{name: "other consent only, asked for offline_access", client: web, scopes: []string{"openid", "profile", "offline_access"}, remembered: remembered(false, "openid", "profile"), assert: needed},
		{name: "offline_access among remembered scopes is not explicit consent", client: web, scopes: []string{"openid", "offline_access"}, remembered: remembered(false, "openid", "offline_access"), assert: needed},
		{name: "remembered Offline does not cover ordinary scopes", client: web, scopes: []string{"openid"}, remembered: remembered(true), assert: needed},
		{name: "pre-authorized native", client: preAuthorized, scopes: []string{"openid", "offline_access"}, assert: skipped},
		{name: "pre-authorized native, ordinary scopes only", client: preAuthorized, scopes: []string{"openid"}, assert: skipped},
		{name: "consent of another client", client: web, scopes: []string{"openid"}, remembered: &oidcprovider.Consent{ClientID: "crm-web", Scopes: []string{"openid"}, Offline: true}, assert: needed},
		{name: "offline consent of another client", client: firstParty, scopes: []string{"offline_access"}, remembered: &oidcprovider.Consent{ClientID: "crm-web", Offline: true}, assert: needed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := oidcprovider.ConsentNeededForTest(
				&oidcprovider.RegisteredClient{Client: tc.client},
				&oidcprovider.PendingRequest{ClientID: tc.client.ID, Scopes: tc.scopes, Prompt: tc.prompt},
				tc.remembered,
			)
			tc.assert(t, got)
		})
	}
}
