package oidcprovider_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/oidcprovider"
)

// TokenRequest, AuthorizeInput and ResumeInput print redacted because they hold secrets. These
// hold the same secrets, and print redacted under every verb and in a log line.
func TestInputsHoldingSecrets_PrintRedacted(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-value"
	cases := []struct {
		name  string
		value any
	}{
		{"ClientCredentials header", oidcprovider.ClientCredentials{Authorization: "Basic " + secret}},
		{"ClientCredentials form", oidcprovider.ClientCredentials{Form: url.Values{"client_secret": {secret}}}},
		{"ClientCredentials query", oidcprovider.ClientCredentials{Query: url.Values{"client_secret": {secret}}}},
		{"EndSessionInput hint", oidcprovider.EndSessionInput{Params: url.Values{"id_token_hint": {secret}}}},
		{"EndSessionInput flow", oidcprovider.EndSessionInput{FlowSecret: secret}},
		{"EndSessionInput browser", oidcprovider.EndSessionInput{BrowserSessionSecret: secret}},
		{"EndSessionResult flow", oidcprovider.EndSessionResult{FlowSecret: secret}},
		{"EndSessionResult location", oidcprovider.EndSessionResult{Location: "https://id.example.com/logout?req=" + secret}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logs := &bytes.Buffer{}
			slog.New(slog.NewTextHandler(logs, nil)).Info("value", "value", tc.value)
			for _, printed := range []string{
				fmt.Sprintf("%v", tc.value), fmt.Sprintf("%+v", tc.value), fmt.Sprintf("%#v", tc.value),
				fmt.Sprintf("%s", tc.value), logs.String(),
			} {
				assert.NotContains(t, printed, secret)
			}
		})
	}
}
