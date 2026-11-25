package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// TestLogout_AccessTokenCaller pins that logout refuses a caller a resource server authenticated,
// visibly, with the authentication-required error, and ends nothing: an access token is ended by
// token revocation or the provider's end-session endpoint, never by a 200 that says "signed out"
// while its grant stays live. An anonymous request keeps its settled answer.
func TestLogout_AccessTokenCaller(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name          string
		authorization string
		assert        func(t *testing.T, out served, sink *eventRecorder, sessions *session.Sessions, live *session.Session)
	}

	cases := []testCase{
		{
			name:          "an access-token caller is refused and no session or grant is ended",
			authorization: "Bearer " + rsToken,
			assert: func(t *testing.T, out served, sink *eventRecorder, sessions *session.Sessions, live *session.Session) {
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
				assert.Empty(t, out.rec.Header().Values("Clear-Site-Data"), "nothing claims a sign-out")

				got, err := sessions.Load(t.Context(), live.ID)
				require.NoError(t, err, "the user's session is untouched")
				assert.Equal(t, live.ID, got.ID)

				for _, e := range sink.all() {
					assert.NotEqual(t, event.SessionLogout, e.Name, "no event claims a logout")
					assert.NotEqual(t, event.AuthnTokenRevoked, e.Name, "no event claims a revocation")
				}
			},
		},
		{
			name: "an anonymous request keeps its settled refusal",
			assert: func(t *testing.T, out served, _ *eventRecorder, _ *session.Sessions, _ *session.Session) {
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.False(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessions, err := session.New()
			require.NoError(t, err)

			live, err := sessions.Create(t.Context(), "u-1")
			require.NoError(t, err)

			sink := &eventRecorder{}
			src := &httpsec.StubSource{Name: "provider", Provider: true, Unbound: true}

			c, err := httpsec.New(
				httpsec.EnableSecurityEvents(sink.sink),
				httpsec.EnableResourceServer("urn:api", httpsec.WithPathPrefix("/"), httpsec.WithStubSource(src)),
				httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}),
			)
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/sign-out", nil)
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}

			tc.assert(t, serve(t, c, req), sink, sessions, live)
		})
	}
}
