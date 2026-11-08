package httpsec_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// featureEndpoint is one built-in endpoint of the second-factor, enrolment,
// passkey, magic-link and recovery features, with the option that places it.
type featureEndpoint struct {
	name   string
	method string

	// option names the option that sets the path, as a configuration error
	// names it.
	option string

	// defaultPath is a request path the endpoint answers with no setting of the
	// consumer's, and setting is the value the consumer gives the option, with
	// served the request path that answers under it. Both are without the base.
	defaultPath string
	setting     string
	served      string

	// options enables the feature with the endpoint placed at setting, at its
	// default when setting is "". The chain it builds carries any session the
	// endpoint needs.
	options func(t *testing.T, setting string) []httpsec.Option
}

// answeredByChain reports whether the chain answered the request itself. A
// request the gates stop with a challenge was passed through the endpoints to
// the gate, so it was not answered by one.
func answeredByChain(t *testing.T, c *httpsec.Chain, method, path string) bool {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	req.RemoteAddr = "203.0.113.7:51000"

	out := serve(t, c, req)

	var challenge *httpsec.ChallengeError

	return !out.handlerRan && !errors.As(out.err, &challenge)
}

// featureEndpoints lists the endpoints of the features that move under a base
// path next, one row per path setting.
func featureEndpoints() []featureEndpoint {
	mfaRow := func(name, method, option, def, setting, served string,
		opt func(setting string) httpsec.MFAOption, withDefault ...httpsec.MFAOption,
	) featureEndpoint {
		return featureEndpoint{
			name: name, method: method, option: option,
			defaultPath: def, setting: setting, served: served,
			options: func(t *testing.T, s string) []httpsec.Option {
				h := newEnrolHarness(t)
				h.mfaOpts = append(h.mfaOpts, withDefault...)

				if s != "" {
					h.mfaOpts = append(h.mfaOpts, opt(s))
				}

				return h.options(t, nil)
			},
		}
	}

	enrolRow := func(name, option, def, setting, served string,
		opt func(setting string) httpsec.EnrolmentOption,
	) featureEndpoint {
		return featureEndpoint{
			name: name, method: http.MethodPost, option: option,
			defaultPath: def, setting: setting, served: served,
			options: func(t *testing.T, s string) []httpsec.Option {
				h := newEnrolHarness(t)
				if s != "" {
					h.enrolOpts = append(h.enrolOpts, opt(s))
				}

				return h.options(t, h.enrolmentOnly(t, factor.Password))
			},
		}
	}

	passkeyRow := func(name, method, option, def, setting, served string,
		opt func(setting string) httpsec.PasskeyOption, passwordless bool,
	) featureEndpoint {
		return featureEndpoint{
			name: name, method: method, option: option,
			defaultPath: def, setting: setting, served: served,
			options: func(t *testing.T, s string) []httpsec.Option {
				h := newPasskeyHarness(t)
				if passwordless {
					h.withPasswordless()
				}

				if s != "" {
					h.passkeyOpts = append(h.passkeyOpts, opt(s))
				}

				return h.chainOptions(t, h.sessionIn(t, factor.Password, session.MFANone))
			},
		}
	}

	linkRow := func(name, option, def, setting string, opt func(setting string) httpsec.MagicLinkOption) featureEndpoint {
		return featureEndpoint{
			name: name, method: http.MethodPost, option: option,
			defaultPath: def, setting: setting, served: setting,
			options: func(t *testing.T, s string) []httpsec.Option {
				h := newMagicLinkHarness(t)
				if s != "" {
					h.linkOpts = append(h.linkOpts, opt(s))
				}

				return []httpsec.Option{httpsec.EnableMagicLink(h.manager, h.options()...)}
			},
		}
	}

	recoveryRow := func(name, method, option, def, setting string, opt func(setting string) httpsec.RecoveryOption) featureEndpoint {
		return featureEndpoint{
			name: name, method: method, option: option,
			defaultPath: def, setting: setting, served: setting,
			options: func(t *testing.T, s string) []httpsec.Option {
				h := newRecoveryHarness(t)
				// A hold delay is what makes the finish and cancel endpoints exist.
				h.coreOpts = append(h.coreOpts,
					recovery.WithHoldDelay(time.Hour), recovery.WithCancelLink("https://app.example.com/cancel"))

				if s != "" {
					h.recOpts = append(h.recOpts, opt(s))
				}

				return h.options(t)
			},
		}
	}

	return []featureEndpoint{
		mfaRow("MFA verify", http.MethodPost, "WithMFAVerifyPrefix",
			httpsec.DefaultMFAVerifyPrefix+"/totp", "/second-factor", "/second-factor/totp",
			httpsec.WithMFAVerifyPrefix),
		mfaRow("MFA challenge", http.MethodPost, "WithMFABeginPrefix",
			httpsec.DefaultMFABeginPrefix+"/totp", "/second-factor-begin", "/second-factor-begin/totp",
			httpsec.WithMFABeginPrefix),
		mfaRow("MFA method listing", http.MethodGet, "ListingPath",
			httpsec.DefaultMFAMethodListingPath, "/second-factor-methods", "/second-factor-methods",
			func(s string) httpsec.MFAOption { return httpsec.WithMFAMethodListing(httpsec.ListingPath(s)) },
			httpsec.WithMFAMethodListing()),

		enrolRow("enrolment begin", "WithEnrolmentBeginPrefix",
			httpsec.DefaultEnrolmentBeginPrefix+"/totp", "/enrol-begin", "/enrol-begin/totp",
			httpsec.WithEnrolmentBeginPrefix),
		enrolRow("enrolment confirm", "WithEnrolmentConfirmPrefix",
			httpsec.DefaultEnrolmentConfirmPrefix+"/totp", "/enrol-confirm", "/enrol-confirm/totp",
			httpsec.WithEnrolmentConfirmPrefix),
		enrolRow("enrolment email confirm", "WithEnrolmentEmailConfirmPrefix",
			httpsec.DefaultEnrolmentEmailConfirmPrefix+"/totp", "/enrol-email", "/enrol-email/totp",
			httpsec.WithEnrolmentEmailConfirmPrefix),

		passkeyRow("passkey registration", http.MethodPost, "WithPasskeyRegistrationPrefix",
			httpsec.DefaultPasskeyRegistrationPrefix+"/begin", "/pk-register", "/pk-register/begin",
			httpsec.WithPasskeyRegistrationPrefix, false),
		passkeyRow("passkey list", http.MethodGet, "WithPasskeyCredentialsPrefix",
			httpsec.DefaultPasskeyCredentialsPrefix, "/my-passkeys", "/my-passkeys",
			httpsec.WithPasskeyCredentialsPrefix, false),
		passkeyRow("passwordless login", http.MethodPost, "WithPasskeyPasswordlessPrefix",
			httpsec.DefaultPasswordlessPrefix+"/begin", "/passkey-login", "/passkey-login/begin",
			httpsec.WithPasskeyPasswordlessPrefix, true),

		linkRow("magic-link request", "WithMagicLinkRequestPath",
			httpsec.DefaultMagicLinkRequestPath, "/link-request", httpsec.WithMagicLinkRequestPath),
		linkRow("magic-link redeem", "WithMagicLinkConsumePath",
			httpsec.DefaultMagicLinkConsumePath, "/link-redeem", httpsec.WithMagicLinkConsumePath),

		recoveryRow("recovery complete", http.MethodPost, "WithRecoveryCompletePath",
			httpsec.DefaultRecoveryCompletePath, "/rec-complete", httpsec.WithRecoveryCompletePath),
		recoveryRow("recovery start", http.MethodPost, "WithRecoveryStartPath",
			httpsec.DefaultRecoveryStartPath, "/rec-start", httpsec.WithRecoveryStartPath),
		recoveryRow("recovery finish", http.MethodPost, "WithRecoveryFinishPath",
			httpsec.DefaultRecoveryFinishPath, "/rec-finish", httpsec.WithRecoveryFinishPath),
		recoveryRow("recovery cancel", http.MethodPost, "WithRecoveryCancelPath",
			httpsec.DefaultRecoveryCancelPath, "/rec-cancel", httpsec.WithRecoveryCancelPath),
		recoveryRow("recovery codes", http.MethodPost, "WithRecoveryCodesPath",
			httpsec.DefaultRecoveryCodesPath, "/rec-codes", httpsec.WithRecoveryCodesPath),
	}
}

// TestBasePath_ResolvesFeatureEndpoints pins where each second-factor,
// enrolment, passkey, magic-link and recovery endpoint answers under a base
// path: at the base followed by its own path, the default or the consumer's,
// wherever the base path option stands among the others, and never at the path
// without the base.
func TestBasePath_ResolvesFeatureEndpoints(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		endpoint featureEndpoint

		// setting is the consumer's value for the endpoint's option, "" for
		// the default.
		setting string

		// before and after are the base path options given before and after
		// the feature's own options.
		before, after []httpsec.Option

		assert func(t *testing.T, e featureEndpoint, c *httpsec.Chain, err error)
	}

	answersAt := func(at string, passes ...string) func(t *testing.T, e featureEndpoint, c *httpsec.Chain, err error) {
		return func(t *testing.T, e featureEndpoint, c *httpsec.Chain, err error) {
			require.NoError(t, err)
			require.NotNil(t, c)

			assert.True(t, answeredByChain(t, c, e.method, at), "%s %s is answered by the chain", e.method, at)

			for _, p := range passes {
				assert.False(t, answeredByChain(t, c, e.method, p), "%s %s passes through to the handler", e.method, p)
			}
		}
	}

	var cases []testCase

	for _, e := range featureEndpoints() {
		cases = append(cases,
			testCase{
				name:     e.name + ": no base path leaves the default where it was",
				endpoint: e,
				assert:   answersAt(e.defaultPath, "/auth"+e.defaultPath),
			},
			testCase{
				name:     e.name + ": no base path leaves the consumer's path where it was",
				endpoint: e,
				setting:  e.setting,
				assert:   answersAt(e.served, "/auth"+e.served),
			},
			testCase{
				name:     e.name + ": the base path given first moves the default",
				endpoint: e,
				before:   []httpsec.Option{httpsec.WithBasePath("/auth")},
				assert:   answersAt("/auth"+e.defaultPath, e.defaultPath, "/auth/auth"+e.defaultPath),
			},
			testCase{
				name:     e.name + ": the base path given last moves the default the same",
				endpoint: e,
				after:    []httpsec.Option{httpsec.WithBasePath("/auth")},
				assert:   answersAt("/auth"+e.defaultPath, e.defaultPath, "/auth/auth"+e.defaultPath),
			},
			testCase{
				name:     e.name + ": the consumer's path answers within the base",
				endpoint: e,
				setting:  e.setting,
				before:   []httpsec.Option{httpsec.WithBasePath("/auth")},
				assert:   answersAt("/auth"+e.served, e.served, "/auth"+e.defaultPath),
			},
			testCase{
				name:     e.name + ": the consumer's path answers within the base given last",
				endpoint: e,
				setting:  e.setting,
				after:    []httpsec.Option{httpsec.WithBasePath("/auth/")},
				assert:   answersAt("/auth"+e.served, e.served, "/auth"+e.defaultPath),
			},
			testCase{
				name:     e.name + ": given twice, the last base path moves it",
				endpoint: e,
				before:   []httpsec.Option{httpsec.WithBasePath("/a")},
				after:    []httpsec.Option{httpsec.WithBasePath("/b")},
				assert:   answersAt("/b"+e.defaultPath, "/a"+e.defaultPath, e.defaultPath),
			},
			testCase{
				name:     e.name + ": a default under a segment the base shares is not a repeat",
				endpoint: e,
				before:   []httpsec.Option{httpsec.WithBasePath("/" + strings.SplitN(e.defaultPath, "/", 3)[1])},
				assert: func(t *testing.T, e featureEndpoint, c *httpsec.Chain, err error) {
					require.NoError(t, err)
					require.NotNil(t, c)

					first := "/" + strings.SplitN(e.defaultPath, "/", 3)[1]
					assert.True(t, answeredByChain(t, c, e.method, first+e.defaultPath))
				},
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := append([]httpsec.Option{}, tc.before...)
			opts = append(opts, tc.endpoint.options(t, tc.setting)...)
			opts = append(opts, tc.after...)

			c, err := httpsec.New(opts...)
			tc.assert(t, tc.endpoint, c, err)
		})
	}
}

// TestBasePath_MFAVerifyMethodSegment pins that the method a second-factor
// submission names is still read from the path under the moved prefix: a known
// method reaches its verification and an unknown one is refused as unknown,
// and the unmoved prefix is not the endpoint's any more.
func TestBasePath_MFAVerifyMethodSegment(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string
		assert func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name: "a known method under the moved prefix reaches its verification",
			path: "/auth/mfa/verify/totp",
			assert: func(t *testing.T, out served) {
				assert.False(t, out.handlerRan)
				require.Error(t, out.err)
				assert.NotErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod)
			},
		},
		{
			name: "an unknown method under the moved prefix is refused as unknown",
			path: "/auth/mfa/verify/nonesuch",
			assert: func(t *testing.T, out served) {
				assert.False(t, out.handlerRan)
				assert.ErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod)
			},
		},
		{
			name: "the prefix without the base is not the endpoint's",
			path: "/mfa/verify/nonesuch",
			assert: func(t *testing.T, out served) {
				assert.NotErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			pending := h.sessionIn(t, factor.Password, session.MFAPending)

			c, err := httpsec.New(append(h.options(t, pending), httpsec.WithBasePath("/auth"))...)
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tc.path,
				strings.NewReader(url.Values{"code": {"000000"}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = "203.0.113.7:51000"

			tc.assert(t, serve(t, c, req))
		})
	}
}

// TestMagicLink_ConfirmPageNotMovedByBasePath pins that a base path moves the
// endpoints the chain answers and not the consumer's confirmation page the
// emailed link points at: the link still names the confirm page, and
// redemption answers under the base.
func TestMagicLink_ConfirmPageNotMovedByBasePath(t *testing.T) {
	t.Parallel()

	const (
		confirmPage = "/sign-in/magic-link/confirm"
		redeemPath  = "/auth/sign-in/magic-link/redeem"
	)

	h := newMagicLinkHarness(t)
	h.chainOpts = []httpsec.Option{httpsec.WithBasePath("/auth")}
	c := h.chain(t)

	asked := serve(t, c, formRequest(t.Context(), "/auth"+httpsec.DefaultMagicLinkRequestPath,
		url.Values{"email": {magicLinkKnown}}.Encode()))
	require.NoError(t, asked.err)

	link, err := url.Parse(h.sender.lastLink(t))
	require.NoError(t, err)

	t.Run("the emailed link names the confirm page", func(t *testing.T) {
		assert.Equal(t, "app.example.com", link.Host)
		assert.Equal(t, confirmPage, link.Path, "the confirm page is the consumer's own and stays where it was")
	})

	t.Run("the confirm page is not answered by the chain", func(t *testing.T) {
		for _, p := range []string{confirmPage, "/auth" + confirmPage} {
			assert.False(t, answeredByChain(t, c, http.MethodGet, p), "GET %s passes through to the application", p)
		}
	})

	t.Run("redemption answers under the base and not without it", func(t *testing.T) {
		assert.False(t, answeredByChain(t, c, http.MethodPost, httpsec.DefaultMagicLinkConsumePath))

		req := postValues(t.Context(), redeemPath, magicLinkSource, url.Values{"token": {h.sender.lastToken(t)}})
		if binding := cookieNamed(asked.rec, httpsec.DefaultBindingCookieName); binding != nil {
			req.AddCookie(bindingCookie(binding.Value))

			assert.Equal(t, redeemPath, binding.Path, "the binding cookie is scoped to the path redemption answers at")
		}

		redeemed := serve(t, c, req)
		require.NoError(t, redeemed.err)
		assert.False(t, redeemed.handlerRan, "redemption is answered by the chain")
		assert.Equal(t, 1, h.activeSessions(t), "the redemption established the session")
	})
}

// TestBasePath_FeaturePathRepeatingBaseIsRefused pins that a path the consumer
// set for any of these endpoints that repeats the base is refused, naming the
// option and the doubled path, and that the same endpoint left at its default is
// not judged.
func TestBasePath_FeaturePathRepeatingBaseIsRefused(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T) []httpsec.Option
		assert  func(t *testing.T, c *httpsec.Chain, err error)
	}

	refused := func(option, doubled string) func(t *testing.T, c *httpsec.Chain, err error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, c)
			assert.ErrorContains(t, err, option)
			assert.ErrorContains(t, err, doubled)
		}
	}

	var cases []testCase

	for _, e := range featureEndpoints() {
		cases = append(cases, testCase{
			name: e.name + ": a path repeating the base is refused",
			options: func(t *testing.T) []httpsec.Option {
				return append(e.options(t, "/auth"+e.setting), httpsec.WithBasePath("/auth"))
			},
			assert: refused(e.option, "/auth/auth"+e.setting),
		})
	}

	// The paths the 3.2 endpoints took, whose repeat is judged by the same rule.
	for _, e := range coreEndpoints() {
		var option string

		switch e.name {
		case "logout":
			option = "WithLogoutRequestPath"
		case "session renewal":
			option = "WithRenewalPath"
		case "password change":
			option = "WithPasswordChangeEndpoint"
		case "session management":
			option = "WithSessionManagementPrefix"
		case "signal stream":
			option = "SessionSignals.Path"
		default:
			continue
		}

		cases = append(cases, testCase{
			name: e.name + ": a path repeating the base is refused",
			options: func(t *testing.T) []httpsec.Option {
				return append(e.options(t, "/auth"+e.consumerPath), httpsec.WithBasePath("/auth"))
			},
			assert: refused(option, "/auth/auth"+strings.TrimSuffix(e.consumerPath, "/")),
		})
	}

	// A path left unset is not a declaration, so a base that happens to share
	// its first segment with a default is no repeat.
	for _, e := range coreEndpoints() {
		if e.name != "signal stream" {
			continue
		}

		cases = append(cases, testCase{
			name: "signal stream: an unset path is not judged as declared",
			options: func(t *testing.T) []httpsec.Option {
				return append(e.options(t, ""), httpsec.WithBasePath("/session"))
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.True(t, answered(t, c, e.method, "/session"+httpsec.DefaultSessionSignalsPath))
			},
		})
	}

	// The last call of the listing option is the one judged: a path an earlier
	// call set does not count once a later call keeps the default.
	cases = append(cases,
		testCase{
			name: "MFA method listing: a later call keeping the default withdraws an earlier path",
			options: func(t *testing.T) []httpsec.Option {
				h := newEnrolHarness(t)
				h.mfaOpts = append(h.mfaOpts,
					httpsec.WithMFAMethodListing(httpsec.ListingPath("/auth/methods")),
					httpsec.WithMFAMethodListing())

				return append(h.options(t, nil), httpsec.WithBasePath("/auth"))
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.True(t, answeredByChain(t, c, http.MethodGet, "/auth"+httpsec.DefaultMFAMethodListingPath))
			},
		},
		testCase{
			name: "MFA method listing: an unset path is not judged as declared",
			options: func(t *testing.T) []httpsec.Option {
				h := newEnrolHarness(t)
				h.mfaOpts = append(h.mfaOpts, httpsec.WithMFAMethodListing())

				return append(h.options(t, nil), httpsec.WithBasePath("/mfa"))
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.True(t, answeredByChain(t, c, http.MethodGet, "/mfa"+httpsec.DefaultMFAMethodListingPath))
			},
		},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.options(t)...)
			tc.assert(t, c, err)
		})
	}
}
