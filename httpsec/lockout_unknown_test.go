package httpsec_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

//go:generate mockgen -source=lockout_unknown_test.go -package=httpsec_test -destination=decoyauthenticator_mock_test.go -typed -mock_names=DecoyAuthenticator=MockDecoyAuthenticator

// DecoyAuthenticator is an authenticator that can also spend decoy password
// verifications, as the chain's lock refusal looks for.
type DecoyAuthenticator interface {
	authenticate.Authenticator
	authenticate.DecoyVerifier
}

// TestUnknownUsernameLock pins that a username with no account is locked
// exactly like one with an account, over Basic and over form login, and that
// each refused attempt spends one decoy password verification when locks are
// concealed and none when they are disclosed.
func TestUnknownUsernameLock(t *testing.T) {
	t.Parallel()

	basic := func(ctx context.Context, user string) *http.Request {
		return basicRequest(ctx, user, "wrong")
	}
	form := func(ctx context.Context, user string) *http.Request {
		return formRequest(ctx, httpsec.DefaultLoginPath, "username="+user+"&password=wrong")
	}

	type testCase struct {
		name   string
		opts   []httpsec.Option
		send   func(ctx context.Context, user string) *http.Request
		assert func(t *testing.T, known, unknown served, spent map[string]int)
	}

	alike := func(t *testing.T, known, unknown served, spent map[string]int) {
		t.Helper()

		assert.Equal(t, 1, spent["ada"], "ada: decoys spent by the locked attempt")
		assert.Equal(t, 1, spent["nobody"], "nobody: decoys spent by the locked attempt")

		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(known.err))
		assert.Equal(t, httpsec.StatusForError(known.err), httpsec.StatusForError(unknown.err))
		require.ErrorIs(t, known.err, policy.ErrAccountLocked)
		require.ErrorIs(t, unknown.err, policy.ErrAccountLocked)
		require.ErrorIs(t, known.err, authenticate.ErrAuthenticationFailed)
		require.ErrorIs(t, unknown.err, authenticate.ErrAuthenticationFailed)
		assert.Equal(t, known.err.Error(), unknown.err.Error())
		assert.Equal(t, known.rec.Header().Get("WWW-Authenticate"), unknown.rec.Header().Get("WWW-Authenticate"))
	}

	disclosed := func(t *testing.T, known, unknown served, spent map[string]int) {
		t.Helper()

		assert.Zero(t, spent["ada"], "ada: a disclosed lock spends no decoy")
		assert.Zero(t, spent["nobody"], "nobody: a disclosed lock spends no decoy")

		for _, out := range []served{known, unknown} {
			require.ErrorIs(t, out.err, policy.ErrAccountLocked)
			assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
			assert.Equal(t, http.StatusTooManyRequests, httpsec.StatusForError(out.err))
		}
	}

	cases := []testCase{
		{name: "over Basic, both are refused alike", send: basic, assert: alike},
		{name: "over form login, both are refused alike, one decoy each", send: form, assert: alike},
		{
			name: "over Basic with locks disclosed, both are answered 429",
			opts: []httpsec.Option{httpsec.WithLockDisclosure()}, send: basic, assert: disclosed,
		},
		{
			name: "over form login with locks disclosed, both are answered 429",
			opts: []httpsec.Option{httpsec.WithLockDisclosure()}, send: form, assert: disclosed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			attempts := policy.NewMemoryAttemptStore()
			lockout, err := policy.NewAccountLockoutPolicy(policy.WithAttemptStore(attempts))
			require.NoError(t, err)

			sessions, err := session.NewManager(session.WithStore(session.NewMemoryStore()))
			require.NoError(t, err)

			// Each user's sixth, locked, attempt is the only one that may spend a
			// decoy, and a spend is told apart by the username it was asked for.
			spent := map[string]int{}
			authn := NewMockDecoyAuthenticator(gomock.NewController(t))
			authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
				Return(nil, authenticate.ErrAuthenticationFailed).AnyTimes()
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
					Authenticator: authn, Sessions: sessions, Tokens: NewMockGenerator(gomock.NewController(t)), Attempts: attempts,
				}),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: attempts}),
			}, tc.opts...)...)
			require.NoError(t, err)

			sixth := map[string]served{}

			for _, user := range []string{"ada", "nobody"} {
				for range 5 {
					out := serve(t, chain, tc.send(t.Context(), user))
					require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
					require.NotErrorIs(t, out.err, policy.ErrAccountLocked, "five failures are still free")
				}

				require.Zero(t, spent[user], "the five free failures spend no decoy")

				sixth[user] = serve(t, chain, tc.send(t.Context(), user))
			}

			tc.assert(t, sixth["ada"], sixth["nobody"], spent)
		})
	}
}

// TestUnknownUsernameLockRealAuthenticator pins that a username the real
// password authenticator cannot find (the loader answers identity.ErrUserNotFound)
// is locked after the same five failures as one it can, and that both locked
// attempts are refused alike. It has its own table because the SUT is wired
// with the real authenticator rather than a mocked one.
func TestUnknownUsernameLockRealAuthenticator(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		send   func(ctx context.Context, user string) *http.Request
		assert func(t *testing.T, known, unknown served)
	}

	alike := func(t *testing.T, known, unknown served) {
		t.Helper()

		for _, out := range []served{known, unknown} {
			require.ErrorIs(t, out.err, policy.ErrAccountLocked)
			require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		}

		assert.Equal(t, httpsec.StatusForError(known.err), httpsec.StatusForError(unknown.err))
		assert.Equal(t, known.err.Error(), unknown.err.Error())
		assert.Equal(t, known.rec.Header().Get("WWW-Authenticate"), unknown.rec.Header().Get("WWW-Authenticate"))
	}

	cases := []testCase{
		{
			name:   "over Basic, an unknown username is refused like a known one",
			send:   func(ctx context.Context, user string) *http.Request { return basicRequest(ctx, user, "wrong") },
			assert: alike,
		},
		{
			name: "over form login, an unknown username is refused like a known one",
			send: func(ctx context.Context, user string) *http.Request {
				return formRequest(ctx, httpsec.DefaultLoginPath, "username="+user+"&password=wrong")
			},
			assert: alike,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			// ada exists with a hash that never matches; nobody has no account.
			loader := NewMockUserLoader(ctrl)
			loader.EXPECT().LoadByUsername(gomock.Any(), "ada").
				Return(&identity.Details{Username: "ada", Password: []byte("stored"), Active: true}, nil).AnyTimes()
			loader.EXPECT().LoadByUsername(gomock.Any(), "nobody").
				Return(nil, identity.ErrUserNotFound).AnyTimes()

			enc := NewMockEncoder(ctrl)
			enc.EXPECT().Encode(gomock.Any()).Return([]byte("reference"), nil).AnyTimes()
			enc.EXPECT().Match(gomock.Any(), gomock.Any()).Return(false).AnyTimes()

			authn, err := authenticate.NewUsernamePasswordAuthenticator(loader, authenticate.WithPasswordEncoder(enc))
			require.NoError(t, err)

			attempts := policy.NewMemoryAttemptStore()
			lockout, err := policy.NewAccountLockoutPolicy(policy.WithAttemptStore(attempts))
			require.NoError(t, err)

			sessions, err := session.NewManager(session.WithStore(session.NewMemoryStore()))
			require.NoError(t, err)

			chain, err := httpsec.New(
				httpsec.WithPolicyEngine(engineOf(t, lockout)),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: authn, Sessions: sessions, Tokens: NewMockGenerator(ctrl), Attempts: attempts,
				}),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: attempts}),
			)
			require.NoError(t, err)

			sixth := map[string]served{}

			for _, user := range []string{"ada", "nobody"} {
				for range 5 {
					out := serve(t, chain, tc.send(t.Context(), user))
					require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
					require.NotErrorIs(t, out.err, policy.ErrAccountLocked, "five failures are still free")
				}

				sixth[user] = serve(t, chain, tc.send(t.Context(), user))
			}

			tc.assert(t, sixth["ada"], sixth["nobody"])
		})
	}
}
