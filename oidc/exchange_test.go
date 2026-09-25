package oidc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
)

// tokenRequest is what the test provider's token endpoint received.
type tokenRequest struct {
	form   url.Values
	header http.Header
}

// recordTokenRequests makes p's token endpoint answer status and body, and
// returns a function reporting the last request it received.
func recordTokenRequests(t *testing.T, p *testProvider, status int, body string) func() tokenRequest {
	t.Helper()

	var (
		mu   sync.Mutex
		last tokenRequest
	)
	p.SetTokenResponse(func(r *http.Request) (int, string) {
		err := r.ParseForm()
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			last = tokenRequest{form: r.PostForm, header: r.Header.Clone()}
		}
		return status, body
	})

	return func() tokenRequest {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

func TestExchange(t *testing.T) {
	t.Parallel()

	const (
		code     = "the-code"
		verifier = "the-verifier"
		idToken  = "header.payload.signature"
		redirect = "https://app.example/login/oauth2/callback/"
	)
	okBody := `{"access_token":"at-secret","refresh_token":"rt-secret","token_type":"Bearer","id_token":"` + idToken + `"}`
	longTail := "TAIL-BEYOND-THE-BOUND"

	type testCase struct {
		name     string
		provider string
		status   int
		body     string
		ctx      func(ctx context.Context) context.Context
		assert   func(t *testing.T, got string, err error, req tokenRequest, logs string)
	}

	cases := []testCase{
		{
			name: "client_secret_post sends credentials in the form", provider: "corp",
			status: http.StatusOK, body: okBody,
			assert: func(t *testing.T, got string, err error, req tokenRequest, _ string) {
				require.NoError(t, err)
				assert.Equal(t, idToken, got)
				assert.Equal(t, url.Values{
					"grant_type":    {"authorization_code"},
					"code":          {code},
					"redirect_uri":  {redirect + "corp"},
					"code_verifier": {verifier},
					"client_id":     {"client-corp"},
					"client_secret": {"secret-corp"},
				}, req.form)
				assert.Empty(t, req.header.Get("Authorization"))
			},
		},
		{
			name: "client_secret_basic sends a Basic header and no secret field", provider: "basic",
			status: http.StatusOK, body: okBody,
			assert: func(t *testing.T, got string, err error, req tokenRequest, _ string) {
				require.NoError(t, err)
				assert.Equal(t, idToken, got)
				want := "Basic " + base64.StdEncoding.EncodeToString(
					[]byte(url.QueryEscape("client:basic")+":"+url.QueryEscape("s3cr t/+%")))
				assert.Equal(t, want, req.header.Get("Authorization"))
				assert.False(t, req.form.Has("client_secret"))
				assert.False(t, req.form.Has("client_id"))
				assert.Equal(t, code, req.form.Get("code"))
				assert.Equal(t, verifier, req.form.Get("code_verifier"))
				assert.Equal(t, "authorization_code", req.form.Get("grant_type"))
				assert.Equal(t, redirect+"basic", req.form.Get("redirect_uri"))
			},
		},
		{
			name: "invalid_grant is a provider failure that hides the description", provider: "corp",
			status: http.StatusBadRequest,
			body:   `{"error":"invalid_grant","error_description":"code reused by 203.0.113.9"}`,
			assert: func(t *testing.T, got string, err error, _ tokenRequest, logs string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.Empty(t, got)
				assert.NotContains(t, err.Error(), "203.0.113.9")
				assert.NotContains(t, err.Error(), "invalid_grant")
				assert.Contains(t, logs, "203.0.113.9", "the provider's answer is logged")
				assert.Contains(t, logs, "level=WARN")
			},
		},
		{
			name: "a long error body is logged truncated", provider: "corp",
			status: http.StatusBadRequest,
			body:   `{"error":"invalid_grant","error_description":"` + strings.Repeat("x", 300) + longTail + `"}`,
			assert: func(t *testing.T, _ string, err error, _ tokenRequest, logs string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.Contains(t, logs, "xxxxxxxx")
				assert.NotContains(t, logs, longTail)
				assert.NotContains(t, err.Error(), "xxxxxxxx")
			},
		},
		{
			name: "a response without an ID token is a provider failure", provider: "corp",
			status: http.StatusOK, body: `{"access_token":"at-secret","token_type":"Bearer"}`,
			assert: func(t *testing.T, got string, err error, _ tokenRequest, _ string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.Empty(t, got)
				assert.NotContains(t, err.Error(), "at-secret")
			},
		},
		{
			name: "an empty ID token is a provider failure", provider: "corp",
			status: http.StatusOK, body: `{"id_token":""}`,
			assert: func(t *testing.T, got string, err error, _ tokenRequest, _ string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.Empty(t, got)
			},
		},
		{
			name: "a malformed JSON response is a provider failure", provider: "corp",
			status: http.StatusOK, body: `<html>gateway says 203.0.113.9</html>`,
			assert: func(t *testing.T, got string, err error, _ tokenRequest, _ string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.Empty(t, got)
				assert.NotContains(t, err.Error(), "203.0.113.9")
			},
		},
		{
			name: "a success status with an error member is a provider failure", provider: "corp",
			status: http.StatusOK, body: `{"error":"server_error","id_token":"` + idToken + `"}`,
			assert: func(t *testing.T, got string, err error, _ tokenRequest, _ string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				assert.Empty(t, got)
			},
		},
		{
			name: "the provider's access and refresh tokens are discarded", provider: "corp",
			status: http.StatusOK, body: okBody,
			assert: func(t *testing.T, got string, err error, _ tokenRequest, logs string) {
				require.NoError(t, err)
				assert.Equal(t, idToken, got, "the raw ID token is the only output")
				assert.NotContains(t, logs, "at-secret")
				assert.NotContains(t, logs, "rt-secret")
			},
		},
		{
			name: "a canceled context sends nothing usable", provider: "corp",
			status: http.StatusOK, body: okBody,
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithCancel(ctx)
				cancel()
				return c
			},
			assert: func(t *testing.T, got string, err error, _ tokenRequest, _ string) {
				require.ErrorIs(t, err, oidc.ErrExchangeFailed)
				require.ErrorIs(t, err, context.Canceled)
				assert.Empty(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTestProvider(t)
			basic := p.Provider("basic")
			basic.ClientID = "client:basic"
			basic.ClientSecret = "s3cr t/+%"
			basic.ClientAuth = oidc.ClientSecretBasic
			reg, err := oidc.NewRegistry(p.Provider("corp"), basic)
			require.NoError(t, err)

			var logs bytes.Buffer
			m, err := oidc.NewManager(reg, stubBroker{},
				oidc.WithOutboundClient(p.Outbound(t)), oidc.WithLogger(testTextLogger(&logs)))
			require.NoError(t, err)
			// Discovery first, on a live context, so the canceled-context row
			// reaches the exchange itself.
			_, err = oidc.MetadataForTest(m, t.Context(), tc.provider)
			require.NoError(t, err)

			last := recordTokenRequests(t, p, tc.status, tc.body)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			got, err := oidc.ExchangeForTest(ctx, m, tc.provider, code, verifier)

			out := logs.String()
			for _, secret := range []string{code, verifier, "secret-corp", "s3cr t/+%"} {
				assert.NotContains(t, out, secret, "no credential reaches a log")
			}
			tc.assert(t, got, err, last(), out)
		})
	}
}
