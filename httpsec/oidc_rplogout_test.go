package httpsec_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/session"
)

// The OIDC manager's end-session step is what EnableOIDCLogin hands logout, so
// it has to satisfy logout's port.
var _ httpsec.EndSessionBuilder = (&oidc.Manager{}).EndSessionBuilder()

// consumerEndSessionURL is the URL a consumer's own end-session step answers.
const consumerEndSessionURL = "https://consumer.example/bye"

// TestOIDCRPInitiatedLogout pins how EnableOIDCLogin wires RP-initiated logout
// into EnableLogout: on by default, off on request, never over a consumer's
// own end-session step, and in whichever order the two options are given.
func TestOIDCRPInitiatedLogout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// oidcFirst gives EnableOIDCLogin before EnableLogout.
		oidcFirst bool
		// noLogout leaves EnableLogout off the chain.
		noLogout bool
		// consumer supplies LogoutDeps.EndSession.
		consumer bool
		opts     []httpsec.OIDCOption
		assert   func(t *testing.T, provider *oidcTestProvider, s served)
	}

	answersProviderURL := func(t *testing.T, p *oidcTestProvider, s served) {
		t.Helper()

		require.NoError(t, s.err)
		assert.Equal(t, http.StatusOK, s.rec.Code)
		assert.Equal(t, "no-store", s.rec.Header().Get("Cache-Control"))

		var doc struct {
			EndSessionURL string `json:"end_session_url"`
		}
		require.NoError(t, json.Unmarshal(s.rec.Body.Bytes(), &doc))

		u, err := url.Parse(doc.EndSessionURL)
		require.NoError(t, err)
		assert.Equal(t, p.srv.URL+"/logout", u.Scheme+"://"+u.Host+u.Path)
		assert.Equal(t, "app", u.Query().Get("client_id"))
		assert.Equal(t, oidcTestIDToken, u.Query().Get("id_token_hint"))
		assert.False(t, s.handlerRan)
	}

	answersConsumerURL := func(t *testing.T, _ *oidcTestProvider, s served) {
		t.Helper()

		require.NoError(t, s.err)
		assert.JSONEq(t, `{"end_session_url":"`+consumerEndSessionURL+`"}`, s.rec.Body.String())
	}

	cases := []testCase{
		{
			name:   "on by default when OIDC login is wired after logout",
			assert: answersProviderURL,
		},
		{
			name:      "on by default when OIDC login is wired before logout",
			oidcFirst: true,
			assert:    answersProviderURL,
		},
		{
			name: "the consumer turns it off",
			opts: []httpsec.OIDCOption{httpsec.WithOIDCRPInitiatedLogout(false)},
			assert: func(t *testing.T, _ *oidcTestProvider, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assert.Empty(t, s.rec.Body.String())
				assert.Empty(t, s.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name:      "the consumer turns it off with OIDC login wired first",
			oidcFirst: true,
			opts:      []httpsec.OIDCOption{httpsec.WithOIDCRPInitiatedLogout(false)},
			assert: func(t *testing.T, _ *oidcTestProvider, s served) {
				require.NoError(t, s.err)
				assert.Empty(t, s.rec.Body.String())
			},
		},
		{
			name:     "a consumer end-session step takes precedence",
			consumer: true,
			assert:   answersConsumerURL,
		},
		{
			name:      "a consumer end-session step takes precedence with OIDC login wired first",
			oidcFirst: true,
			consumer:  true,
			assert:    answersConsumerURL,
		},
		{
			name:     "a consumer end-session step is kept when RP-initiated logout is off",
			consumer: true,
			opts:     []httpsec.OIDCOption{httpsec.WithOIDCRPInitiatedLogout(false)},
			assert:   answersConsumerURL,
		},
		{
			name:     "a chain without logout is unaffected",
			noLogout: true,
			assert: func(t *testing.T, _ *oidcTestProvider, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan, "with no logout wired the path is the application's")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ah := newAuthHarness(t)
			ah.expectVerified()

			s := federatedSession()
			s.ExternalProvider = testOIDCProvider
			s.ExternalIDToken = oidcTestIDToken
			ah.expectResolvedSession(s)

			if tc.noLogout {
				ah.acceptsActivityWriteBack()
			} else {
				ah.store.EXPECT().Delete(gomock.Any(), testJTI).Return(nil)
			}

			oh := newOIDCHarness(t)
			manager := oh.managerWith(t, NewMockIdentityBroker(gomock.NewController(t)),
				func(p *oidc.Provider) { p.EndSessionEndpoint = oh.provider.srv.URL + "/logout" })

			deps := httpsec.LogoutDeps{Sessions: ah.sessions}
			if tc.consumer {
				b := NewMockEndSessionBuilder(gomock.NewController(t))
				b.EXPECT().EndSessionURL(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(context.Context, *session.Session, string) (string, error) {
						return consumerEndSessionURL, nil
					})
				deps.EndSession = b
			}

			enableOIDC := httpsec.EnableOIDCLogin(manager, oh.handoffs, append([]httpsec.OIDCOption{
				httpsec.WithOIDCTokens(ah.tokens),
				httpsec.WithOIDCSessions(ah.sessions),
			}, tc.opts...)...)

			opts := []httpsec.Option{
				httpsec.WithLogger(ah.logger()),
				httpsec.EnableBearerToken(ah.bearerTokenDeps()),
			}

			switch {
			case tc.noLogout:
				opts = append(opts, enableOIDC)
			case tc.oidcFirst:
				opts = append(opts, enableOIDC, httpsec.EnableLogout(deps))
			default:
				opts = append(opts, httpsec.EnableLogout(deps), enableOIDC)
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, oh.provider, serve(t, chain, logoutFormRequest(t.Context(), url.Values{})))
		})
	}
}
