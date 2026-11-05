package httpsec_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// The chain has one session manager, the built-in bearer's, and the resume reads the sign-in from it.
// A consumer's own bearer resumes when it publishes a session that manager holds, and a session from
// any other manager reads as ended: nothing is handed out, and the page is told to sign in again.
func TestOIDCResume_ConsumerBearerSessionsAreReadFromTheChainsManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// own reports whether the consumer's bearer publishes sessions of a manager of its own.
		own    bool
		assert func(t *testing.T, a flowAnswer)
	}

	cases := []testCase{
		{
			name: "a session of the chain's manager resumes",
			assert: func(t *testing.T, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.Contains(t, a.body, "redirect_to")
			},
		},
		{
			name: "a session of another manager reads as an ended sign-in",
			own:  true,
			assert: func(t *testing.T, a flowAnswer) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrOIDCReauthenticate)
				assert.Equal(t, http.StatusUnauthorized, a.status)
				nothingHandedOut(t, a)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var own *session.Sessions

			w := newOPFlow(t, flowSetup{chain: func(t *testing.T, w *opFlow) []httpsec.Option {
				t.Helper()

				manager := w.sessions
				if tc.own {
					own = must.Must(session.New(session.WithStore(must.Must(session.NewMemoryStore())), session.WithClock(w.clk)))
					manager = own
				}

				return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					presented := ex.Request.Header(flowConsumerSessionHeader)
					if presented == "" {
						return next(ex)
					}

					s, err := manager.Load(ex.Context(), presented)
					if err != nil {
						return err
					}

					if err := ex.PublishSession(&authenticate.Authentication{
						Principal: &identity.Principal{ID: s.UserID},
						Time:      w.clk.Now(),
					}, s); err != nil {
						return err
					}

					ex.RecordPresentedToken(presented)

					return next(ex)
				}), httpsec.OrderBearerToken)}
			}})

			manager := w.sessions
			if tc.own {
				manager = own
			}

			s, err := manager.Create(t.Context(), "u-1")
			require.NoError(t, err)

			handle, flow := w.park(t, flowWeb)
			a := w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow), flowConsumerAuthorization(s.ID))
			tc.assert(t, a)
		})
	}
}
