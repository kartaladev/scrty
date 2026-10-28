package httpsec_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestChain_MFAEnabledTwice pins that one chain has one MFA configuration: a
// second EnableMFA is a configuration error naming the option, whatever
// prefixes or methods it carries, because the challenge a refused request
// carries lists the methods of one configuration only, so a method given to
// the other would never be offered.
func TestChain_MFAEnabledTwice(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T, h *mfaHarness) []httpsec.Option
		assert  func(t *testing.T, c *httpsec.Chain, err error)
	}

	enable := func(h *mfaHarness, methods []mfa.Method, opts ...httpsec.MFAOption) httpsec.Option {
		return httpsec.EnableMFA(methods, append([]httpsec.MFAOption{
			httpsec.WithMFAVerifyLimiter(h.limiter), httpsec.WithMFATokens(h.tokens),
		}, opts...)...)
	}

	cases := []testCase{
		{
			name: "MFA enabled twice",
			options: func(t *testing.T, h *mfaHarness) []httpsec.Option {
				h.channel(factor.AuthenticatorApp)
				email := emailCodeMethod(t)

				return []httpsec.Option{
					enable(h, []mfa.Method{h.method}),
					enable(h, []mfa.Method{email},
						httpsec.WithMFAVerifyPrefix("/x/verify"),
						httpsec.WithMFABeginPrefix("/x/begin")),
				}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "EnableMFA", "the error names the option given twice")
				assert.Contains(t, err.Error(), "given twice")
				assert.Nil(t, c)
			},
		},
		{
			name: "MFA enabled once with every method",
			options: func(t *testing.T, h *mfaHarness) []httpsec.Option {
				h.channel(factor.AuthenticatorApp)

				return []httpsec.Option{enable(h, []mfa.Method{h.method, emailCodeMethod(t)})}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, c)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			sessions := httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions})

			c, err := httpsec.New(append(tc.options(t, h), sessions)...)
			tc.assert(t, c, err)
		})
	}
}

// TestEnableMFA pins what the chain refuses to be built with. Every one of
// these is a wiring mistake whose symptom would otherwise appear far from its
// cause: a method with no channel refuses every verification as same-channel,
// and a limiter that is not there counts no guesses at all.
//
// Its own table: its rows build the chain from bare methods and options,
// without the MFA harness the other tables here use.
func TestEnableMFA(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		methods func(t *testing.T) []mfa.Method
		opts    []httpsec.MFAOption
		// noTokens leaves the token generator out entirely, which is how a
		// case pins what happens to a chain that was never given one.
		noTokens bool
		build    func(t *testing.T, opt httpsec.Option) (*httpsec.Chain, error)
		assert   func(t *testing.T, c *httpsec.Chain, err error)
	}

	// withSessions is the ordinary chain: one wired to a session manager, which
	// is what every deployment running a first factor has.
	withSessions := func(t *testing.T, opt httpsec.Option) (*httpsec.Chain, error) {
		t.Helper()

		sessions, err := session.New()
		require.NoError(t, err)

		return httpsec.New(opt, httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}))
	}

	// one is a set of the single method m makes.
	one := func(m func(t *testing.T) mfa.Method) func(t *testing.T) []mfa.Method {
		return func(t *testing.T) []mfa.Method { return []mfa.Method{m(t)} }
	}

	authenticator := one(func(t *testing.T) mfa.Method { return mfaMethod(t, factor.AuthenticatorApp) })

	// authenticatorAnd is the authenticator plus a second method named name.
	authenticatorAnd := func(name string) func(t *testing.T) []mfa.Method {
		return func(t *testing.T) []mfa.Method {
			second := NewMockMethod(gomock.NewController(t))
			second.EXPECT().Name().Return(name).AnyTimes()
			second.EXPECT().Channel().Return(factor.Email).AnyTimes()
			second.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()

			return []mfa.Method{mfaMethod(t, factor.AuthenticatorApp), second}
		}
	}

	configError := func(t *testing.T, c *httpsec.Chain, err error) {
		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Nil(t, c, "a chain that cannot be configured is not half-built")
	}

	built := func(t *testing.T, c *httpsec.Chain, err error) {
		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	cases := []testCase{
		{
			name:    "a method with a channel, and nothing else configured",
			methods: authenticator,
			assert:  built,
		},
		{
			name:    "a consumer's limiter, prefix and log interval",
			methods: authenticator,
			opts: []httpsec.MFAOption{
				httpsec.WithMFAVerifyPrefix("/auth/second-factor"),
				httpsec.WithMFAVerifyLimiter(NewMockLimiter(gomock.NewController(t))),
				httpsec.WithMFALogInterval(5 * time.Minute),
			},
			assert: built,
		},
		{
			name:    "an empty channel",
			methods: one(func(t *testing.T) mfa.Method { return mfaMethod(t, "") }),
			assert:  configError,
		},
		{
			name:    "a nil method",
			methods: one(func(*testing.T) mfa.Method { return nil }),
			assert:  configError,
		},
		{
			name:    "a typed-nil method",
			methods: one(func(*testing.T) mfa.Method { return (*MockMethod)(nil) }),
			assert:  configError,
		},
		{
			name:    "a nil limiter",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyLimiter(nil)},
			assert:  configError,
		},
		{
			name:    "a limiter interface holding a nil pointer",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyLimiter((*ratelimit.MemoryLimiter)(nil))},
			assert:  configError,
		},
		{
			name:    "two methods on different paths",
			methods: authenticatorAnd("email-code"),
			assert:  built,
		},
		{
			name:    "no methods",
			methods: func(*testing.T) []mfa.Method { return nil },
			assert:  configError,
		},
		{
			name:    "two methods sharing a name",
			methods: authenticatorAnd("totp"),
			assert:  configError,
		},
		{
			// A format with no room for a response could never be read, so
			// every verification on the method would be refused as too large.
			name: "a method declaring a malformed response format",
			methods: one(func(t *testing.T) mfa.Method {
				m := NewMockMethod(gomock.NewController(t))
				m.EXPECT().Name().Return("totp").AnyTimes()
				m.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
				m.EXPECT().Response().Return(mfa.FormField("code", 0)).AnyTimes()

				return m
			}),
			assert: configError,
		},
		{
			name:    "an empty verify prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix("")},
			assert:  configError,
		},
		{
			name:    "the root as the verify prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix("/")},
			assert:  configError,
		},
		{
			name:    "a verify prefix without a leading slash",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix("mfa")},
			assert:  configError,
		},
		{
			// The verify endpoint would answer the logout request first, so a
			// pending session could never log out.
			name:    "a verify prefix that is the logout path",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix(httpsec.DefaultLogoutPath)},
			assert:  configError,
		},
		{
			name:    "a logout path under the verify prefix",
			methods: authenticator,
			build: func(t *testing.T, opt httpsec.Option) (*httpsec.Chain, error) {
				t.Helper()

				sessions, err := session.New()
				require.NoError(t, err)

				return httpsec.New(opt, httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions},
					httpsec.WithLogoutRequestPath(httpsec.DefaultMFAVerifyPrefix+"/logout")))
			},
			assert: configError,
		},
		{
			name:    "a consumer's begin prefix, challenge lifetime, store and responder",
			methods: authenticator,
			opts: []httpsec.MFAOption{
				httpsec.WithMFABeginPrefix("/auth/second-factor/begin"),
				httpsec.WithMFAChallengeTTL(2 * time.Minute),
				httpsec.WithMFAChallengeStore(onetime.NewMemoryStore()),
				httpsec.WithMFABeginResponder(func(*httpsec.Exchange, json.RawMessage) error { return nil }),
			},
			assert: built,
		},
		{
			name:    "an empty begin prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix("")},
			assert:  configError,
		},
		{
			name:    "the root as the begin prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix("/")},
			assert:  configError,
		},
		{
			name:    "a begin prefix without a leading slash",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix("mfa/begin")},
			assert:  configError,
		},
		{
			// Every POST under the verify prefix is the verify endpoint's, so
			// no begin could ever be reached.
			name:    "a begin prefix equal to the verify prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix(httpsec.DefaultMFAVerifyPrefix + "/")},
			assert:  configError,
		},
		{
			name:    "a verify prefix moved onto the begin prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix(httpsec.DefaultMFABeginPrefix)},
			assert:  configError,
		},
		{
			name:    "a begin prefix under the verify prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix(httpsec.DefaultMFAVerifyPrefix + "/begin")},
			assert:  configError,
		},
		{
			// The verify prefix sits under this one, so every begin POST
			// there would be the verify endpoint's.
			name:    "a begin prefix above the verify prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix("/mfa")},
			assert:  configError,
		},
		{
			name:    "a begin prefix that is the logout path",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix(httpsec.DefaultLogoutPath)},
			assert:  configError,
		},
		{
			name:    "a consumer challenge limit",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeLimit(3)},
			assert:  built,
		},
		{
			name:    "a challenge limit of zero",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeLimit(0)},
			assert:  configError,
		},
		{
			name:    "a negative challenge limit",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeLimit(-1)},
			assert:  configError,
		},
		{
			name:    "a challenge lifetime of zero",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeTTL(0)},
			assert:  configError,
		},
		{
			name:    "a negative challenge lifetime",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeTTL(-time.Minute)},
			assert:  configError,
		},
		{
			name:    "a nil challenge store",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeStore(nil)},
			assert:  configError,
		},
		{
			name:    "a challenge store interface holding a nil pointer",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeStore((*onetime.MemoryStore)(nil))},
			assert:  configError,
		},
		{
			name:    "a nil begin responder",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginResponder(nil)},
			assert:  configError,
		},
		{
			name:     "no token generator",
			methods:  authenticator,
			noTokens: true,
			assert:   configError,
		},
		{
			name:    "a nil token generator",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFATokens(nil)},
			assert:  configError,
		},
		{
			name:    "a token generator interface holding a nil pointer",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFATokens((*MockGenerator)(nil))},
			assert:  configError,
		},
		{
			name:    "a chain with no session manager",
			methods: authenticator,
			build: func(t *testing.T, opt httpsec.Option) (*httpsec.Chain, error) {
				t.Helper()

				return httpsec.New(opt)
			},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			build := tc.build
			if build == nil {
				build = withSessions
			}

			// Every chain that is expected to build needs a generator, because
			// a rotated handle has to be handed back as a credential. A row
			// that configures the generator itself still applies after this
			// one, so its own refusal is what the case sees.
			opts := tc.opts
			if !tc.noTokens {
				opts = append([]httpsec.MFAOption{
					httpsec.WithMFATokens(NewMockGenerator(gomock.NewController(t))),
				}, opts...)
			}

			c, err := build(t, httpsec.EnableMFA(tc.methods(t), opts...))
			tc.assert(t, c, err)
		})
	}
}

// TestMFAMethodListingConstruction pins the listing's wiring mistakes: a
// setting given explicitly with no value, and a path another endpoint of the
// chain already answers.
//
// Not rows of TestMFAMethodListing: its rows only build the chain, with
// logout's options beside MFA's, and serve nothing; nor of TestEnableMFA, which
// builds without the MFA harness.
func TestMFAMethodListingConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		mfaOpts    []httpsec.MFAOption
		logoutOpts []httpsec.LogoutOption
		assert     func(t *testing.T, c *httpsec.Chain, err error)
	}

	refused := func(names ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, c)

			for _, n := range names {
				assert.ErrorContains(t, err, n, "the error names what is at fault")
			}
		}
	}

	assembles := func(t *testing.T, c *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	with := func(settings ...httpsec.ListingSetting) []httpsec.MFAOption {
		return []httpsec.MFAOption{httpsec.WithMFAMethodListing(settings...)}
	}

	cases := []testCase{
		{
			name:    "every default",
			mfaOpts: with(),
			assert:  assembles,
		},
		{
			name:    "an explicitly empty path",
			mfaOpts: with(httpsec.ListingPath("")),
			assert:  refused("ListingPath"),
		},
		{
			name:    "a path that matches no request",
			mfaOpts: with(httpsec.ListingPath("mfa/methods")),
			assert:  refused("ListingPath"),
		},
		{
			name:    "an absent responder",
			mfaOpts: with(httpsec.ListingResponder(nil)),
			assert:  refused("ListingResponder"),
		},
		{
			name:    "a path under the verify prefix",
			mfaOpts: with(httpsec.ListingPath(httpsec.DefaultMFAVerifyPrefix + "/totp")),
			assert:  refused("WithMFAMethodListing", httpsec.DefaultMFAVerifyPrefix),
		},
		{
			name:    "the verify prefix itself",
			mfaOpts: with(httpsec.ListingPath(httpsec.DefaultMFAVerifyPrefix)),
			assert:  refused("WithMFAMethodListing", httpsec.DefaultMFAVerifyPrefix),
		},
		{
			name:    "a path under the begin prefix",
			mfaOpts: with(httpsec.ListingPath(httpsec.DefaultMFABeginPrefix + "/passkey")),
			assert:  refused("WithMFAMethodListing", httpsec.DefaultMFABeginPrefix),
		},
		{
			name: "a path under a consumer's verify prefix",
			mfaOpts: append(with(httpsec.ListingPath("/2fa/check/totp")),
				httpsec.WithMFAVerifyPrefix("/2fa/check")),
			assert: refused("WithMFAMethodListing", "/2fa/check"),
		},
		{
			name: "the default verify path once the verify prefix has moved",
			mfaOpts: append(with(httpsec.ListingPath(httpsec.DefaultMFAVerifyPrefix+"/totp")),
				httpsec.WithMFAVerifyPrefix("/2fa/check")),
			assert: assembles,
		},
		{
			name:    "the logout path",
			mfaOpts: with(httpsec.ListingPath(httpsec.DefaultLogoutPath)),
			assert:  refused("WithMFAMethodListing", httpsec.DefaultLogoutPath),
		},
		{
			name:       "a consumer's logout path",
			mfaOpts:    with(httpsec.ListingPath("/auth/sign-out")),
			logoutOpts: []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/auth/sign-out")},
			assert:     refused("WithMFAMethodListing", "/auth/sign-out"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)

			c, err := httpsec.New(
				httpsec.EnableMFA([]mfa.Method{h.method}, append([]httpsec.MFAOption{
					httpsec.WithMFAVerifyLimiter(h.limiter),
					httpsec.WithMFATokens(h.tokens),
				}, tc.mfaOpts...)...),
				httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}, tc.logoutOpts...),
			)

			tc.assert(t, c, err)
		})
	}
}
