package httpsec_test

//go:generate mockgen -destination=emailloader_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/identity EmailLoader
//go:generate mockgen -destination=identifierresolver_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/authenticate IdentifierResolver

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

// The identifiers and passwords the email-login tests present. Ada's verified
// email is emailLoginAddress, and her username is emailLoginUsername.
const (
	emailLoginUsername = "ada"
	emailLoginAddress  = "ada@example.com"

	//nolint:gosec // G101: a fixture password, not a credential
	emailLoginRight = "the right password"
	emailLoginWrong = "a wrong password"
)

// errEmailStoreDown is an email loader's outage.
var errEmailStoreDown = errors.New("test: email store unavailable")

var (
	// emailLoginHash is ada's stored hash: only non-empty matters, since the
	// encoder is a double.
	emailLoginHash = []byte("$fake$ada")
	// emailLoginReference is the provider's reference hash, the one an
	// unknown identifier and a concealed lock are verified against.
	emailLoginReference = []byte("$fake$reference")
)

// emailUserLoader is a user loader that also loads by email, built from the
// two generated mocks, as a consumer's store implementing both ports is.
type emailUserLoader struct {
	*MockUserLoader
	*MockEmailLoader
}

// emailLoginFixture is a chain whose form login and Basic share one password
// provider, over typed user and email loader mocks and a counting encoder, and
// one lockout policy.
type emailLoginFixture struct {
	users  *MockUserLoader
	emails *MockEmailLoader
	enc    *MockEncoder

	// matched counts the password comparisons against ada's own hash.
	matched atomic.Int32
	// referenced counts the comparisons against the reference hash.
	referenced atomic.Int32

	attempts *lockout.MemoryAttemptStore
	lockout  *lockout.Policy

	// allowLogin lets form login complete a login: a memory session store and
	// a token generator that issues. Without it, both are strict mocks that
	// fail any login a row did not expect to complete.
	allowLogin bool
}

// ada is the stored user, whose verified email is emailLoginAddress.
func emailLoginAda() *identity.Details {
	return &identity.Details{
		ID:              "u-1",
		Username:        emailLoginUsername,
		Active:          true,
		Password:        emailLoginHash,
		Email:           emailLoginAddress,
		EmailVerifiedAt: time.Date(2024, time.May, 2, 10, 0, 0, 0, time.UTC),
	}
}

// newEmailLoginFixture builds the loaders, the counting encoder and the
// lockout policy, with lockOpts applied to the policy over a memory store.
func newEmailLoginFixture(t *testing.T, lockOpts ...lockout.Option) *emailLoginFixture {
	t.Helper()

	ctrl := gomock.NewController(t)
	f := &emailLoginFixture{
		users:    NewMockUserLoader(ctrl),
		emails:   NewMockEmailLoader(ctrl),
		enc:      NewMockEncoder(ctrl),
		attempts: must.Must(lockout.NewMemoryAttemptStore()),
	}

	f.enc.EXPECT().Encode(gomock.Any()).Return(emailLoginReference, nil).Times(1)
	f.enc.EXPECT().Match(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(input string, encoded []byte) bool {
			if bytes.Equal(encoded, emailLoginReference) {
				f.referenced.Add(1)

				return false
			}
			f.matched.Add(1)

			return bytes.Equal(encoded, emailLoginHash) && input == emailLoginRight
		})

	lp, err := lockout.New(append([]lockout.Option{lockout.WithAttemptStore(f.attempts)}, lockOpts...)...)
	require.NoError(t, err)
	f.lockout = lp

	return f
}

// knowsAda answers every lookup ada's username and email make, any number of
// times: the username as ada, the email as no username but ada's email.
func (f *emailLoginFixture) knowsAda() {
	f.users.EXPECT().LoadByUsername(gomock.Any(), emailLoginUsername).Return(emailLoginAda(), nil).AnyTimes()
	f.users.EXPECT().LoadByUsername(gomock.Any(), emailLoginAddress).Return(nil, identity.ErrUserNotFound).AnyTimes()
	f.emails.EXPECT().LoadByEmail(gomock.Any(), emailLoginAddress).Return(emailLoginAda(), nil).AnyTimes()
}

// chain builds form login and Basic over one password provider, with login by
// email on or off, judged by the fixture's lockout and recording through its
// view, with opts applied last.
func (f *emailLoginFixture) chain(t *testing.T, emailLogin bool, opts ...httpsec.Option) *httpsec.Chain {
	t.Helper()

	pwOpts := []authenticate.PasswordOption{
		authenticate.WithPasswordEncoder(f.enc),
		authenticate.WithPasswordLogger(slog.New(slog.DiscardHandler)),
	}
	if emailLogin {
		pwOpts = append(pwOpts, authenticate.WithEmailLogin())
	}

	provider, err := authenticate.NewUsernamePasswordAuthenticator(
		emailUserLoader{MockUserLoader: f.users, MockEmailLoader: f.emails}, pwOpts...)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)

	var store session.Store = NewMockStore(ctrl)
	tokens := newMockGenerator(ctrl)

	if f.allowLogin {
		store = must.Must(session.NewMemoryStore())
		tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("a-token", nil).AnyTimes()
	}

	sessions, err := session.New(session.WithStore(store))
	require.NoError(t, err)

	base := []httpsec.Option{
		httpsec.WithLogger(slog.New(slog.DiscardHandler)),
		httpsec.WithPolicyEngine(engineOf(t, f.lockout)),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: provider, Sessions: sessions, Tokens: tokens, Attempts: f.lockout.Attempts(),
		}),
		httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: provider, Attempts: f.lockout.Attempts()}),
	}

	c, err := httpsec.New(append(base, opts...)...)
	require.NoError(t, err)

	return c
}

// emailLoginEndpoint is one of the two password endpoints, as a way to present
// an identifier and a password to it, on a request whose context is ctx.
type emailLoginEndpoint struct {
	name       string
	presentCtx func(ctx context.Context, t *testing.T, c *httpsec.Chain, identifier, password string) served
}

// present is presentCtx on the test's own context.
func (e emailLoginEndpoint) present(t *testing.T, c *httpsec.Chain, identifier, password string) served {
	t.Helper()

	return e.presentCtx(t.Context(), t, c, identifier, password)
}

var emailLoginEndpoints = []emailLoginEndpoint{
	{name: "form login", presentCtx: func(ctx context.Context, t *testing.T, c *httpsec.Chain, identifier, password string) served {
		t.Helper()

		return serveContext(ctx, t, c, fromSource(formRequest(ctx, httpsec.DefaultLoginPath,
			"username="+identifier+"&password="+password), loginGuardSource))
	}},
	{name: "Basic", presentCtx: func(ctx context.Context, t *testing.T, c *httpsec.Chain, identifier, password string) served {
		t.Helper()

		return serveContext(ctx, t, c, fromSource(basicRequest(ctx, identifier, password), loginGuardSource))
	}},
}

// TestLogin_EmailSharesLockout pins that, with login by email on, an account's
// username and verified email share one lockout budget, at both endpoints and
// in either order: three failures under one and two under the other lock the
// account under both.
func TestLogin_EmailSharesLockout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		endpoint emailLoginEndpoint
		// first takes three failures, second two.
		first, second string
		// byEmail is how many of the five were presented as the email.
		byEmail int
		assert  func(t *testing.T, f *emailLoginFixture, c *httpsec.Chain, endpoint emailLoginEndpoint, byEmail int)
	}

	// lockedBothWays is the shared invariant: the account is locked whichever
	// identifier is presented next, every failure counts under the username,
	// and the email carries only its own, for the automation challenge.
	lockedBothWays := func(t *testing.T, f *emailLoginFixture, c *httpsec.Chain, endpoint emailLoginEndpoint, byEmail int) {
		t.Helper()

		for _, identifier := range []string{emailLoginAddress, emailLoginUsername} {
			out := endpoint.present(t, c, identifier, emailLoginRight)
			require.ErrorIs(t, out.err, lockout.ErrAccountLocked, "%s is not locked after five failures", identifier)
			assert.False(t, out.handlerRan)
		}

		since := time.Now().Add(-time.Hour)
		n, err := f.attempts.FailureCount(t.Context(), emailLoginUsername, since)
		require.NoError(t, err)
		assert.Equal(t, 5, n, "every failure counts under the account's username")

		n, err = f.attempts.FailureCount(t.Context(), emailLoginAddress, since)
		require.NoError(t, err)
		assert.Equal(t, byEmail, n, "only the failures presented as the email count under it")
	}

	var cases []testCase
	for _, ep := range emailLoginEndpoints {
		cases = append(cases,
			testCase{
				name: ep.name + ": three by username, two by email", endpoint: ep,
				first: emailLoginUsername, second: emailLoginAddress, byEmail: 2, assert: lockedBothWays,
			},
			testCase{
				name: ep.name + ": three by email, two by username", endpoint: ep,
				first: emailLoginAddress, second: emailLoginUsername, byEmail: 3, assert: lockedBothWays,
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEmailLoginFixture(t, lockout.WithSliding(5, time.Hour))
			f.knowsAda()
			c := f.chain(t, true)

			for i, identifier := range []string{tc.first, tc.first, tc.first, tc.second, tc.second} {
				out := tc.endpoint.present(t, c, identifier, emailLoginWrong)
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "failure %d", i+1)
				require.NotErrorIs(t, out.err, lockout.ErrAccountLocked, "failure %d is within the budget", i+1)
			}

			tc.assert(t, f, c, tc.endpoint, tc.byEmail)
		})
	}
}

// TestLogin_HeldAccountByEmail pins that an account held by the failure-streak
// cap is refused as held when its verified email is presented, before any
// password is compared with the account's hash.
func TestLogin_HeldAccountByEmail(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		endpoint emailLoginEndpoint
		opts     []httpsec.Option
		assert   func(t *testing.T, f *emailLoginFixture, out served)
	}

	var cases []testCase
	for _, ep := range emailLoginEndpoints {
		cases = append(cases,
			testCase{
				name: ep.name + ": disclosed, the hold itself and no password work", endpoint: ep,
				opts: []httpsec.Option{httpsec.WithLockDisclosure()},
				assert: func(t *testing.T, f *emailLoginFixture, out served) {
					require.ErrorIs(t, out.err, lockout.ErrAccountHeld)
					assert.Equal(t, http.StatusTooManyRequests, httpsec.StatusForError(out.err))
					assert.Zero(t, f.matched.Load(), "no password is compared with the account's hash")
					assert.Zero(t, f.referenced.Load(), "a disclosed hold spends no decoy")
				},
			},
			testCase{
				name: ep.name + ": concealed, a wrong password after the decoy alone", endpoint: ep,
				assert: func(t *testing.T, f *emailLoginFixture, out served) {
					require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
					require.ErrorIs(t, out.err, lockout.ErrAccountHeld)
					assert.Zero(t, f.matched.Load(), "no password is compared with the account's hash")
					assert.Equal(t, int32(1), f.referenced.Load(), "the concealment costs one decoy verification")
				},
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEmailLoginFixture(t, lockout.WithSliding(5, time.Hour), lockout.WithFailureStreakLimit(6))

			// Held under the username, through the policy's own view.
			for range 6 {
				require.NoError(t, f.lockout.RecordFailure(t.Context(), emailLoginUsername))
			}

			// The resolution is the only load: the hold is judged on its
			// key, before the provider would load or compare anything.
			f.users.EXPECT().LoadByUsername(gomock.Any(), emailLoginAddress).Return(nil, identity.ErrUserNotFound).Times(1)
			f.emails.EXPECT().LoadByEmail(gomock.Any(), emailLoginAddress).Return(emailLoginAda(), nil).Times(1)

			c := f.chain(t, true, tc.opts...)
			tc.assert(t, f, tc.endpoint.present(t, c, emailLoginAddress, emailLoginRight))
		})
	}
}

// TestLogin_ResolvesOnce pins that each lookup is made once per attempt: the
// resolution the endpoint runs before its pre-authentication phase is what
// the provider authenticates, without a second load. With login by email off,
// nothing is resolved: the provider's own username lookup is the only one.
func TestLogin_ResolvesOnce(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		endpoint   emailLoginEndpoint
		emailLogin bool
		identifier string
		expect     func(f *emailLoginFixture)
		assert     func(t *testing.T, f *emailLoginFixture, out served)
	}

	refusedOnce := func(t *testing.T, f *emailLoginFixture, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		assert.Equal(t, int32(1), f.matched.Load()+f.referenced.Load(), "one password verification per attempt")
	}

	var cases []testCase
	for _, ep := range emailLoginEndpoints {
		cases = append(cases,
			testCase{
				name: ep.name + ": found by email, each lookup once", endpoint: ep,
				emailLogin: true, identifier: emailLoginAddress,
				expect: func(f *emailLoginFixture) {
					f.users.EXPECT().LoadByUsername(gomock.Any(), emailLoginAddress).Return(nil, identity.ErrUserNotFound).Times(1)
					f.emails.EXPECT().LoadByEmail(gomock.Any(), emailLoginAddress).Return(emailLoginAda(), nil).Times(1)
				},
				assert: func(t *testing.T, f *emailLoginFixture, out served) {
					refusedOnce(t, f, out)
					assert.Equal(t, int32(1), f.matched.Load(), "verified against ada's hash")
				},
			},
			testCase{
				name: ep.name + ": found by username, one lookup", endpoint: ep,
				emailLogin: true, identifier: emailLoginUsername,
				expect: func(f *emailLoginFixture) {
					f.users.EXPECT().LoadByUsername(gomock.Any(), emailLoginUsername).Return(emailLoginAda(), nil).Times(1)
				},
				assert: refusedOnce,
			},
			testCase{
				name: ep.name + ": unknown, each lookup once", endpoint: ep,
				emailLogin: true, identifier: "nobody@example.com",
				expect: func(f *emailLoginFixture) {
					f.users.EXPECT().LoadByUsername(gomock.Any(), "nobody@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
					f.emails.EXPECT().LoadByEmail(gomock.Any(), "nobody@example.com").Return(nil, identity.ErrUserNotFound).Times(1)
				},
				assert: func(t *testing.T, f *emailLoginFixture, out served) {
					refusedOnce(t, f, out)

					n, err := f.attempts.FailureCount(t.Context(), "nobody@example.com", time.Now().Add(-time.Hour))
					require.NoError(t, err)
					assert.Equal(t, 1, n, "an unknown identifier is counted as presented")
				},
			},
			testCase{
				name: ep.name + ": an email lookup outage is unavailable, each lookup once, nothing recorded", endpoint: ep,
				emailLogin: true, identifier: emailLoginAddress,
				expect: func(f *emailLoginFixture) {
					f.users.EXPECT().LoadByUsername(gomock.Any(), emailLoginAddress).Return(nil, identity.ErrUserNotFound).Times(1)
					f.emails.EXPECT().LoadByEmail(gomock.Any(), emailLoginAddress).Return(nil, errEmailStoreDown).Times(1)
				},
				assert: func(t *testing.T, f *emailLoginFixture, out served) {
					require.ErrorIs(t, out.err, authenticate.ErrUnavailable)
					assert.NotErrorIs(t, out.err, errEmailStoreDown, "the store's own error stays inside the provider")
					assert.Equal(t, int32(1), f.referenced.Load(), "the same password work as an unknown identifier")
					assert.Zero(t, f.matched.Load())

					for _, id := range []string{emailLoginAddress, emailLoginUsername} {
						n, err := f.attempts.FailureCount(t.Context(), id, time.Now().Add(-time.Hour))
						require.NoError(t, err)
						assert.Zero(t, n, "an outage judged no credential, so nothing counts under %s", id)
					}
				},
			},
			testCase{
				name: ep.name + ": email login off, the provider's username lookup alone", endpoint: ep,
				identifier: emailLoginAddress,
				expect: func(f *emailLoginFixture) {
					f.users.EXPECT().LoadByUsername(gomock.Any(), emailLoginAddress).Return(nil, identity.ErrUserNotFound).Times(1)
				},
				assert: func(t *testing.T, f *emailLoginFixture, out served) {
					refusedOnce(t, f, out)
					assert.Equal(t, int32(1), f.referenced.Load(), "an email is an unknown username")

					n, err := f.attempts.FailureCount(t.Context(), emailLoginAddress, time.Now().Add(-time.Hour))
					require.NoError(t, err)
					assert.Equal(t, 1, n, "counted under the identifier as typed, as before")
				},
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Strict loaders: any lookup the row does not expect fails it.
			f := newEmailLoginFixture(t, lockout.WithSliding(5, time.Hour))
			tc.expect(f)
			c := f.chain(t, tc.emailLogin)

			tc.assert(t, f, tc.endpoint.present(t, c, tc.identifier, emailLoginWrong))
		})
	}
}

// TestLogin_UnknownEmailLocksAfterFiveFailures pins that an email no account
// holds is locked like any identifier: five failures spend its budget, and the
// sixth attempt is refused as locked, before the handler runs, with the lock
// recorded under the identifier as presented.
func TestLogin_UnknownEmailLocksAfterFiveFailures(t *testing.T) {
	t.Parallel()

	const unknownEmail = "nobody@example.com"

	type testCase struct {
		name     string
		endpoint emailLoginEndpoint
		assert   func(t *testing.T, f *emailLoginFixture, sixth served)
	}

	locked := func(t *testing.T, f *emailLoginFixture, sixth served) {
		t.Helper()

		require.ErrorIs(t, sixth.err, lockout.ErrAccountLocked, "the sixth attempt is not refused by the lockout")
		assert.False(t, sixth.handlerRan)

		n, err := f.attempts.FailureCount(t.Context(), unknownEmail, time.Now().Add(-time.Hour))
		require.NoError(t, err)
		assert.Equal(t, 5, n, "only the five judged failures count under the presented identifier")
	}

	var cases []testCase
	for _, ep := range emailLoginEndpoints {
		cases = append(cases, testCase{name: ep.name, endpoint: ep, assert: locked})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEmailLoginFixture(t, lockout.WithSliding(5, time.Hour))
			f.users.EXPECT().LoadByUsername(gomock.Any(), unknownEmail).Return(nil, identity.ErrUserNotFound).AnyTimes()
			f.emails.EXPECT().LoadByEmail(gomock.Any(), unknownEmail).Return(nil, identity.ErrUserNotFound).AnyTimes()
			c := f.chain(t, true)

			for i := range 5 {
				out := tc.endpoint.present(t, c, unknownEmail, emailLoginWrong)
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "failure %d", i+1)
				require.NotErrorIs(t, out.err, lockout.ErrAccountLocked, "failure %d is within the budget", i+1)
			}

			tc.assert(t, f, tc.endpoint.present(t, c, unknownEmail, emailLoginWrong))
		})
	}
}

// TestLogin_EmailSuccessClearsAccount pins that a success by email, at either
// endpoint, clears the failures recorded under the account's username: the
// success is keyed on the account, as the failures were. It clears those the
// email carries for the automation challenge too.
func TestLogin_EmailSuccessClearsAccount(t *testing.T) {
	t.Parallel()

	for _, ep := range emailLoginEndpoints {
		t.Run(ep.name, func(t *testing.T) {
			t.Parallel()

			f := newEmailLoginFixture(t, lockout.WithSliding(5, time.Hour))
			f.allowLogin = true
			f.knowsAda()
			c := f.chain(t, true)

			for i, identifier := range []string{emailLoginUsername, emailLoginUsername, emailLoginAddress, emailLoginAddress} {
				out := ep.present(t, c, identifier, emailLoginWrong)
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "failure %d", i+1)
			}

			out := ep.present(t, c, emailLoginAddress, emailLoginRight)
			require.NoError(t, out.err)

			for _, id := range []string{emailLoginUsername, emailLoginAddress} {
				n, err := f.attempts.FailureCount(t.Context(), id, time.Now().Add(-time.Hour))
				require.NoError(t, err)
				assert.Zero(t, n, "the success by email supersedes the failures under %s", id)
			}
		})
	}
}

// consumerResolvingAuthenticator is a consumer's authenticator that exposes an
// identifier resolver, built from the two generated mocks.
type consumerResolvingAuthenticator struct {
	*MockAuthenticator
	*MockIdentifierResolver
}

// TestLogin_ResolverGate pins when the endpoints run the resolution and what
// they key the lockout on, against a consumer's resolver: never when it
// reports email login off; once, keyed on its Key, when on, with the
// identifier as typed counted too; and, when the resolution fails, refused as
// an outage without asking the authenticator and with nothing counted.
func TestLogin_ResolverGate(t *testing.T) {
	t.Parallel()

	errResolverDown := errors.New("test: resolver unavailable")

	type testCase struct {
		name     string
		endpoint emailLoginEndpoint
		expect   func(r *MockIdentifierResolver, a *MockAuthenticator)
		assert   func(t *testing.T, attempts *lockout.MemoryAttemptStore, out served)
	}

	countedUnder := func(t *testing.T, attempts *lockout.MemoryAttemptStore, keys ...string) {
		t.Helper()

		since := time.Now().Add(-time.Hour)
		for _, id := range []string{emailLoginUsername, emailLoginAddress} {
			n, err := attempts.FailureCount(t.Context(), id, since)
			require.NoError(t, err)
			if slices.Contains(keys, id) {
				assert.Equal(t, 1, n, "the failure counts under %s", id)

				continue
			}
			assert.Zero(t, n, "nothing counts under %s", id)
		}
	}

	var cases []testCase
	for _, ep := range emailLoginEndpoints {
		cases = append(cases,
			testCase{
				name: ep.name + ": email login off, nothing resolved", endpoint: ep,
				expect: func(r *MockIdentifierResolver, a *MockAuthenticator) {
					r.EXPECT().EmailLogin().Return(false).AnyTimes()
					r.EXPECT().ResolveIdentifier(gomock.Any(), gomock.Any()).Times(0)
					a.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Return(nil, authenticate.ErrAuthenticationFailed).Times(1)
				},
				assert: func(t *testing.T, attempts *lockout.MemoryAttemptStore, out served) {
					require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
					countedUnder(t, attempts, emailLoginAddress)
				},
			},
			testCase{
				name: ep.name + ": email login on, resolved once and keyed on its Key", endpoint: ep,
				expect: func(r *MockIdentifierResolver, a *MockAuthenticator) {
					r.EXPECT().EmailLogin().Return(true).AnyTimes()
					r.EXPECT().ResolveIdentifier(gomock.Any(), emailLoginAddress).
						Return(authenticate.ResolvedIdentifier{Key: emailLoginUsername}, nil).Times(1)
					a.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
						DoAndReturn(func(_ context.Context, c identity.Credentials) (*authenticate.Authentication, error) {
							up, ok := c.(*identity.UsernamePassword)
							require.True(t, ok)
							assert.Equal(t, emailLoginAddress, up.Username, "the authenticator is asked about the identifier as typed")

							return nil, authenticate.ErrAuthenticationFailed
						}).Times(1)
				},
				assert: func(t *testing.T, attempts *lockout.MemoryAttemptStore, out served) {
					require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
					countedUnder(t, attempts, emailLoginUsername, emailLoginAddress)
				},
			},
			testCase{
				name: ep.name + ": a failed resolution is an outage, the authenticator is never asked", endpoint: ep,
				expect: func(r *MockIdentifierResolver, a *MockAuthenticator) {
					r.EXPECT().EmailLogin().Return(true).AnyTimes()
					r.EXPECT().ResolveIdentifier(gomock.Any(), emailLoginAddress).
						Return(authenticate.ResolvedIdentifier{}, errResolverDown).Times(1)
					a.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Times(0)
				},
				assert: func(t *testing.T, attempts *lockout.MemoryAttemptStore, out served) {
					require.ErrorIs(t, out.err, authenticate.ErrUnavailable)
					assert.NotErrorIs(t, out.err, errResolverDown, "the resolver's own error stays out of the refusal")
					countedUnder(t, attempts)
				},
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			r := NewMockIdentifierResolver(ctrl)
			a := NewMockAuthenticator(ctrl)
			tc.expect(r, a)

			attempts := must.Must(lockout.NewMemoryAttemptStore())
			lp, err := lockout.New(lockout.WithAttemptStore(attempts), lockout.WithSliding(5, time.Hour))
			require.NoError(t, err)

			sessions, err := session.New(session.WithStore(NewMockStore(ctrl)))
			require.NoError(t, err)

			authn := consumerResolvingAuthenticator{MockAuthenticator: a, MockIdentifierResolver: r}
			c, err := httpsec.New(
				httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.WithPolicyEngine(engineOf(t, lp)),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: authn, Sessions: sessions, Tokens: newMockGenerator(ctrl), Attempts: lp.Attempts(),
				}),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: lp.Attempts()}),
			)
			require.NoError(t, err)

			tc.assert(t, attempts, tc.endpoint.present(t, c, emailLoginAddress, emailLoginWrong))
		})
	}
}

// TestLogin_ChallengeSignalSameForKnownAndUnknownEmail pins that the
// automation challenge cannot tell a registered email from an unknown one:
// after two wrong passwords under either, the identifier as typed is reported
// as having failures, at both endpoints. Lockout keys on the resolved account,
// so a registered email's failures are also recorded under the email as typed.
func TestLogin_ChallengeSignalSameForKnownAndUnknownEmail(t *testing.T) {
	t.Parallel()

	const unknownEmail = "nobody@example.com"

	type testCase struct {
		name       string
		endpoint   emailLoginEndpoint
		identifier string
	}

	var cases []testCase
	for _, ep := range emailLoginEndpoints {
		cases = append(cases,
			testCase{name: ep.name + ": a registered email", endpoint: ep, identifier: emailLoginAddress},
			testCase{name: ep.name + ": an unknown email", endpoint: ep, identifier: unknownEmail},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEmailLoginFixture(t, lockout.WithSliding(5, time.Hour))
			f.knowsAda()
			f.users.EXPECT().LoadByUsername(gomock.Any(), unknownEmail).Return(nil, identity.ErrUserNotFound).AnyTimes()
			f.emails.EXPECT().LoadByEmail(gomock.Any(), unknownEmail).Return(nil, identity.ErrUserNotFound).AnyTimes()

			var seen atomic.Pointer[httpsec.ChallengeSignals]

			verifier := NewMockChallengeVerifier(gomock.NewController(t))
			verifier.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, _ httpsec.Request, s httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
					seen.Store(&s)

					return httpsec.ChallengeNotNeeded, nil
				})

			c := f.chain(t, true, httpsec.EnableAutomationChallenge(verifier,
				httpsec.WithChallengeFlows(httpsec.ChallengeFlowFormLogin, httpsec.ChallengeFlowBasicAuth)))

			for i := range 2 {
				out := tc.endpoint.present(t, c, tc.identifier, emailLoginWrong)
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "failure %d", i+1)
			}

			tc.endpoint.present(t, c, tc.identifier, emailLoginWrong)

			// Every row's invariant: the third attempt's identifier is
			// reported as having failures, whether or not it is registered.
			got := seen.Load()
			require.NotNil(t, got, "the verifier was asked")
			assert.True(t, got.IdentifierHasFailures,
				"two failures under the identifier as typed are reported, registered or not")
		})
	}
}

// TestLogin_LockedAccountRefusedWhenResolverFails pins that a consumer's
// identifier resolver that fails refuses the login, at both endpoints, before
// the authenticator is asked: the account the identifier names is unknown, so
// its lock cannot be judged, and authenticating would bypass it. The refusal
// is an outage, after one decoy verification, and nothing is recorded.
func TestLogin_LockedAccountRefusedWhenResolverFails(t *testing.T) {
	t.Parallel()

	errResolverDown := errors.New("test: resolver unavailable")

	type testCase struct {
		name     string
		endpoint emailLoginEndpoint
		// resolveErr is what the resolver fails with. With hangUp, the
		// request's context is cancelled while it resolves, as a client that
		// leaves.
		resolveErr error
		hangUp     bool
		assert     func(t *testing.T, attempts *lockout.MemoryAttemptStore, out served)
	}

	refusedAsOutage := func(t *testing.T, attempts *lockout.MemoryAttemptStore, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, authenticate.ErrUnavailable)
		assert.NotErrorIs(t, out.err, errResolverDown, "the resolver's own error stays out of the refusal")
		assert.False(t, out.handlerRan)

		since := time.Now().Add(-time.Hour)
		n, err := attempts.FailureCount(t.Context(), emailLoginAddress, since)
		require.NoError(t, err)
		assert.Zero(t, n, "an outage judged no credential")

		n, err = attempts.FailureCount(t.Context(), emailLoginUsername, since)
		require.NoError(t, err)
		assert.Equal(t, 5, n, "the account's own failures are untouched")
	}

	refusedAsHangUp := func(t *testing.T, attempts *lockout.MemoryAttemptStore, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		require.ErrorIs(t, out.err, context.Canceled, "a client that left is refused as one")
		assert.NotErrorIs(t, out.err, authenticate.ErrUnavailable, "a hang-up is not an outage")
		assert.False(t, out.handlerRan)

		n, err := attempts.FailureCount(t.Context(), emailLoginAddress, time.Now().Add(-time.Hour))
		require.NoError(t, err)
		assert.Zero(t, n, "no password was compared")
	}

	var cases []testCase
	for _, ep := range emailLoginEndpoints {
		cases = append(cases,
			testCase{
				name: ep.name + ": a consumer's error is an outage", endpoint: ep,
				resolveErr: errResolverDown, assert: refusedAsOutage,
			},
			testCase{
				name: ep.name + ": an outage stays an outage", endpoint: ep,
				resolveErr: authenticate.ErrUnavailable, assert: refusedAsOutage,
			},
			testCase{
				name: ep.name + ": a hang-up stays a hang-up", endpoint: ep,
				resolveErr: errors.Join(authenticate.ErrAuthenticationFailed, context.Canceled), hangUp: true,
				assert: refusedAsHangUp,
			},
			testCase{
				name: ep.name + ": a consumer's bare context error is a hang-up", endpoint: ep,
				resolveErr: context.Canceled, hangUp: true, assert: refusedAsHangUp,
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			r := NewMockIdentifierResolver(ctrl)
			a := NewMockDecoyAuthenticator(ctrl)

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			r.EXPECT().EmailLogin().Return(true).AnyTimes()
			r.EXPECT().ResolveIdentifier(gomock.Any(), emailLoginAddress).
				DoAndReturn(func(context.Context, string) (authenticate.ResolvedIdentifier, error) {
					if tc.hangUp {
						cancel()
					}

					return authenticate.ResolvedIdentifier{}, tc.resolveErr
				}).Times(1)
			// The account would log in: the lock is the only thing standing
			// in its way, so asking the authenticator is the bypass.
			a.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Times(0).
				Return(&authenticate.Authentication{Principal: &identity.Principal{ID: "u-1", Username: emailLoginUsername}}, nil)
			a.EXPECT().VerifyDecoy(gomock.Any(), gomock.Any()).Return(true).Times(1)

			attempts := must.Must(lockout.NewMemoryAttemptStore())
			lp, err := lockout.New(lockout.WithAttemptStore(attempts), lockout.WithSliding(5, time.Hour))
			require.NoError(t, err)

			// Locked under the account's username.
			for range 5 {
				require.NoError(t, lp.RecordFailure(t.Context(), emailLoginUsername))
			}

			sessions, err := session.New(session.WithStore(NewMockStore(ctrl)))
			require.NoError(t, err)

			authn := consumerResolvingDecoyAuthenticator{MockDecoyAuthenticator: a, MockIdentifierResolver: r}
			c, err := httpsec.New(
				httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.WithPolicyEngine(engineOf(t, lp)),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: authn, Sessions: sessions, Tokens: newMockGenerator(ctrl), Attempts: lp.Attempts(),
				}),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: lp.Attempts()}),
			)
			require.NoError(t, err)

			tc.assert(t, attempts, tc.endpoint.presentCtx(ctx, t, c, emailLoginAddress, emailLoginRight))
		})
	}
}

// consumerResolvingDecoyAuthenticator is a consumer's authenticator that
// exposes an identifier resolver and spends decoy verifications, built from
// the generated mocks.
type consumerResolvingDecoyAuthenticator struct {
	*MockDecoyAuthenticator
	*MockIdentifierResolver
}
