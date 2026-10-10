package httpsec_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// TestHeld pins that an identifier held by a capped lockout policy is refused
// by the password logins exactly as any locked one is: concealed as a failed
// authentication with one decoy spent by default, answered 429 when locks are
// disclosed, identifiable as a hold either way, and alike for a username with
// no account. The password is never checked while the hold stands.
func TestHeld(t *testing.T) {
	t.Parallel()

	const heldCap = 20

	form := func(ctx context.Context, user string) *http.Request {
		return formRequest(ctx, httpsec.DefaultLoginPath, "username="+user+"&password=correct")
	}
	basic := func(ctx context.Context, user string) *http.Request {
		return basicRequest(ctx, user, "correct")
	}

	type testCase struct {
		name   string
		opts   []httpsec.Option
		users  []string
		send   func(ctx context.Context, user string) *http.Request
		assert func(t *testing.T, out map[string]served, spent map[string]int)
	}

	cases := []testCase{
		{
			name:  "Held by default: refused as a failed authentication, one decoy spent",
			users: []string{"ada"},
			send:  form,
			assert: func(t *testing.T, out map[string]served, spent map[string]int) {
				got := out["ada"]

				assert.False(t, got.handlerRan)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(got.err))
				require.ErrorIs(t, got.err, authenticate.ErrAuthenticationFailed)
				require.ErrorIs(t, got.err, policy.ErrAccountLocked)
				require.ErrorIs(t, got.err, policy.ErrAccountHeld)
				assert.Equal(t, 1, spent["ada"], "one decoy verification is spent")
			},
		},
		{
			name:  "Held by default: Basic is refused as a failed authentication with the challenge, one decoy spent",
			users: []string{"ada"},
			send:  basic,
			assert: func(t *testing.T, out map[string]served, spent map[string]int) {
				got := out["ada"]

				assert.False(t, got.handlerRan)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(got.err))
				assert.Equal(t, `Basic realm="Restricted"`, got.rec.Header().Get("WWW-Authenticate"))
				require.ErrorIs(t, got.err, authenticate.ErrAuthenticationFailed)
				require.ErrorIs(t, got.err, policy.ErrAccountHeld)
				assert.Equal(t, 1, spent["ada"], "one decoy verification is spent")
			},
		},
		{
			name:  "Held, disclosure chosen: Basic is answered 429 with no challenge header",
			opts:  []httpsec.Option{httpsec.WithLockDisclosure()},
			users: []string{"ada"},
			send:  basic,
			assert: func(t *testing.T, out map[string]served, spent map[string]int) {
				got := out["ada"]

				assert.False(t, got.handlerRan)
				assert.Equal(t, http.StatusTooManyRequests, httpsec.StatusForError(got.err))
				require.ErrorIs(t, got.err, policy.ErrAccountLocked)
				require.ErrorIs(t, got.err, policy.ErrAccountHeld)
				assert.NotErrorIs(t, got.err, authenticate.ErrAuthenticationFailed)
				assert.Empty(t, got.rec.Header().Get("WWW-Authenticate"))
				assert.Zero(t, spent["ada"], "a disclosed lock spends no decoy")
			},
		},
		{
			name:  "Unknown username held alike: same error and status, one decoy each",
			users: []string{"ada", "nobody"},
			send:  form,
			assert: func(t *testing.T, out map[string]served, spent map[string]int) {
				known, unknown := out["ada"], out["nobody"]

				for _, got := range []served{known, unknown} {
					assert.False(t, got.handlerRan)
					require.ErrorIs(t, got.err, authenticate.ErrAuthenticationFailed)
					require.ErrorIs(t, got.err, policy.ErrAccountHeld)
				}

				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(known.err))
				assert.Equal(t, httpsec.StatusForError(known.err), httpsec.StatusForError(unknown.err))
				assert.Equal(t, known.err.Error(), unknown.err.Error())
				assert.Equal(t, 1, spent["ada"], "ada: decoys spent")
				assert.Equal(t, 1, spent["nobody"], "nobody: decoys spent")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lockout, err := policy.NewAccountLockoutPolicy(
				policy.WithAttemptStore(policy.NewMemoryAttemptStore()), policy.WithLockoutCap(heldCap))
			require.NoError(t, err)

			// Each identifier is held before any request: heldCap failures
			// recorded through the policy's view, as the logins record them.
			at := time.Now().Add(-time.Hour)
			for _, user := range tc.users {
				for i := range heldCap {
					require.NoError(t, lockout.Attempts().RecordFailure(t.Context(), user,
						at.Add(time.Duration(i)*time.Second)))
				}
			}

			sessions, err := session.NewManager(session.WithStore(session.NewMemoryStore()))
			require.NoError(t, err)

			// No Authenticate expectation: the password is never checked while
			// the hold stands, and a call fails the test.
			spent := map[string]int{}
			authn := NewMockDecoyAuthenticator(gomock.NewController(t))
			authn.EXPECT().VerifyDecoy(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, c identity.Credentials) bool {
					up, ok := c.(*identity.UsernamePassword)
					require.True(t, ok, "decoys are spent on username and password credentials")

					spent[up.Username]++

					return true
				}).AnyTimes()

			chain, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithPolicyEngine(engineOf(t, lockout)),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: authn, Sessions: sessions,
					Tokens: NewMockGenerator(gomock.NewController(t)), Attempts: lockout.Attempts(),
				}),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: lockout.Attempts()}),
			}, tc.opts...)...)
			require.NoError(t, err)

			out := map[string]served{}
			for _, user := range tc.users {
				out[user] = serve(t, chain, tc.send(t.Context(), user))
			}

			tc.assert(t, out, spent)
		})
	}
}
