package httpsec_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

const opIssuer = "https://id.example.com"

// opFixture holds what every chain in these tests is built from. The signing
// keys are shared, because generating them is the slow part and nothing here
// signs: the tests read only who holds which.
type opFixture struct {
	keys, otherKeys *signingkey.Keys
}

func newOPFixture(t *testing.T) *opFixture {
	t.Helper()

	return &opFixture{
		keys:      must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))),
		otherKeys: must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))),
	}
}

// provider builds a provider over the fixture's keys, with one client.
func (f *opFixture) provider(t *testing.T, opts ...oidcprovider.Option) *oidcprovider.Provider {
	t.Helper()

	return f.providerFor(t, nil, opts...)
}

// providerFor builds a provider over the fixture's keys. With clients it holds
// them, besides the one every other provider has.
func (f *opFixture) providerFor(t *testing.T, clients []oidcprovider.Client, opts ...oidcprovider.Option) *oidcprovider.Provider {
	t.Helper()

	return f.providerOver(t, opIssuer, f.keys, clients, opts...)
}

// providerOver builds a provider for issuer over keys, which need not be the
// fixture's own, so a test can hand it a wrapper or an issuer with a path.
func (f *opFixture) providerOver(t *testing.T, issuer string, keys signingkey.KeySource, clients []oidcprovider.Client, opts ...oidcprovider.Option) *oidcprovider.Provider {
	t.Helper()

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: issuer,
		Clients: append([]oidcprovider.Client{{
			ID:           "billing-web",
			Type:         oidcprovider.Confidential,
			Secret:       []byte("0123456789abcdef0123456789abcdef"),
			RedirectURIs: []string{"https://rp.example.com/cb"},
		}}, clients...),
		Keys:         keys,
		Users:        NewMockUserLoader(gomock.NewController(t)),
		LoginURL:     opIssuer + "/login",
		ConsentURL:   opIssuer + "/consent",
		LogoutURL:    opIssuer + "/logout-page",
		LoggedOutURL: opIssuer + "/bye",
	}, opts...)
	require.NoError(t, err)

	return p
}

// wrappedKeys decorates a signing-key manager, as a consumer adding metrics or
// tracing would: the same keys behind another value.
type wrappedKeys struct{ *signingkey.Keys }

// reporting is a session manager that reports each sign-in's end to p.
func reporting(t *testing.T, p *oidcprovider.Provider) *session.Sessions {
	t.Helper()

	return must.Must(session.New(session.WithEndObserver(p)))
}

// requiring is a client whose tokens must carry the sender constraint b.
func requiring(id string, b oidcprovider.BindingRequirement) oidcprovider.Client {
	return oidcprovider.Client{
		ID:             id,
		Type:           oidcprovider.Confidential,
		Secret:         []byte("0123456789abcdef0123456789abcdef"),
		RedirectURIs:   []string{"https://rp.example.com/cb"},
		RequireBinding: b,
	}
}

// The chain's other endpoints, each built over a session manager that reports to
// the provider, so that only a path can refuse the chain.

func magicLinkOn(t *testing.T, m *session.Sessions) []httpsec.Option {
	t.Helper()

	h := newMagicLinkHarness(t)

	return []httpsec.Option{httpsec.EnableMagicLink(h.manager,
		httpsec.WithMagicLinkSessions(m))}
}

func oidcLoginOn(t *testing.T, m *session.Sessions) []httpsec.Option {
	t.Helper()

	flows, err := oidc.NewMemoryFlowStore()
	require.NoError(t, err)

	return []httpsec.Option{httpsec.EnableOIDCLogin(
		httpsec.OIDCDeps{RelyingParty: oidcManagerOver(t, flows), Handoff: newTestHandoffManager(t)},
		httpsec.WithOIDCSessions(m))}
}

// totpLike is an enrolled second factor, for a chain that only needs one.
func totpLike(t *testing.T) mfa.Method {
	t.Helper()

	method := NewMockMethod(gomock.NewController(t))
	method.EXPECT().Name().Return("totp").AnyTimes()
	method.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
	method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

	return method
}

func mfaOn(t *testing.T, opts ...httpsec.MFAOption) httpsec.Option {
	t.Helper()

	return httpsec.EnableMFA([]mfa.Method{totpLike(t)}, opts...)
}

func reauthOn(t *testing.T, _ *session.Sessions) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{
		mfaOn(t),
		httpsec.EnableReauthentication(),
	}
}

func managementOn(t *testing.T, _ *session.Sessions) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{httpsec.EnableSessionManagement()}
}

func mfaListingOn(t *testing.T, _ *session.Sessions) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{mfaOn(t, httpsec.WithMFAMethodListing())}
}

func formLoginOn(t *testing.T, m *session.Sessions) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{httpsec.EnableFormLogin(httpsec.FormLoginDeps{
		Authenticator: NewMockAuthenticator(gomock.NewController(t)),
		Sessions:      m,
		Attempts:      must.Must(lockout.NewMemoryAttemptStore()),
	})}
}

func renewalOn(t *testing.T, _ *session.Sessions) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{
		Users: NewMockUserLoader(gomock.NewController(t)),
	})}
}

const opPasswordChangePath = "/account/password"

func passwordChangeOn(t *testing.T, m *session.Sessions) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{httpsec.EnablePasswordChangeGate(m,
		httpsec.WithPasswordChangeEndpoint(opPasswordChangePath, func(*httpsec.Exchange) error { return nil }))}
}

func recoveryOn(t *testing.T, m *session.Sessions) []httpsec.Option {
	t.Helper()

	totp := must.Must(mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Co"))
	reset := must.Must(recovery.MFAEnrolments(totp))
	codes := must.Must(recovery.NewCodes())

	return append(passwordChangeOn(t, m), httpsec.EnableAccountRecovery(httpsec.RecoveryDeps{
		Users:    exampleUserLoader{details: &identity.Details{ID: "u-1", Username: "grace@example.com", Active: true}},
		Sessions: m,
		Sender:   exampleSender{},
		Codes:    codes,
	},
		httpsec.WithRecoveryCore(
			recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued),
			recovery.WithRepudiationContact("Contact support@example.com if you did not request this."),
			recovery.WithAuthenticatorKinds(reset),
		)))
}

func passkeysOn(t *testing.T, m *session.Sessions) []httpsec.Option {
	t.Helper()

	users := NewMockUserLoader(gomock.NewController(t))
	pm := must.Must(passkey.New(passkey.Deps{
		Verifier: newPasskeyVerifierStub(t).mock,
		Users:    users,
		Sender:   exampleSender{},
		Sessions: m,
	}, passkey.WithRepudiationContact("help@example.com")))

	return []httpsec.Option{httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: pm, Sessions: m, Users: users})}
}

func enrolmentOn(t *testing.T, _ *session.Sessions) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{
		mfaOn(t),
		httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{
			Users:  NewMockUserLoader(gomock.NewController(t)),
			Sender: exampleSender{},
		}),
	}
}

func mfaPrefixesOn(t *testing.T, _ *session.Sessions) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{mfaOn(t)}
}

func (f *opFixture) bearer(t *testing.T, m *session.Sessions) httpsec.Option {
	t.Helper()

	return httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{
		Sessions: m,
		Users:    NewMockUserLoader(gomock.NewController(t)),
	})
}

// signedBearer is a signed-token bearer over m, under scheme.
func (f *opFixture) signedBearer(t *testing.T, m *session.Sessions, scheme string) httpsec.Option {
	t.Helper()

	gen, err := token.NewGenerator(f.keys, token.WithoutIssuer(), token.WithoutAudience())
	require.NoError(t, err)

	return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
		Verifier: gen,
		Sessions: m,
		Users:    NewMockUserLoader(gomock.NewController(t)),
	}, httpsec.WithBearerScheme(scheme))
}

// twoBearers is two signed-token bearers under schemes of their own, over first and second.
func twoBearers(t *testing.T, f *opFixture, first, second *session.Sessions) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{f.signedBearer(t, first, httpsec.DefaultBearerScheme), f.signedBearer(t, second, "Partner")}
}

// pages is what a provider needs beside itself and its bearer.
func (f *opFixture) pages(t *testing.T) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{
		httpsec.EnableJWKSEndpoint(f.keys),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
	}
}

// wired is every option a provider needs beside itself, over the provider's own
// keys and a manager that reports to it.
func (f *opFixture) wired(t *testing.T, p *oidcprovider.Provider) []httpsec.Option {
	t.Helper()

	return []httpsec.Option{
		f.bearer(t, reporting(t, p)),
		httpsec.EnableJWKSEndpoint(f.keys),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
	}
}

func TestOIDCProvider_Construction(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		build  func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refused := func(names ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, chain)
			for _, name := range names {
				assert.ErrorContains(t, err, name)
			}
		}
	}

	built := func(t *testing.T, chain *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, chain)
	}

	// opts is a provider on an otherwise complete chain, with the provider's
	// own options.
	withOptions := func(t *testing.T, popts []oidcprovider.Option, opts ...httpsec.OIDCProviderOption) []httpsec.Option {
		t.Helper()

		p := f.provider(t, popts...)

		return append(f.wired(t, p), httpsec.EnableOIDCProvider(p, opts...))
	}

	// withHeaders is a provider on a chain whose security headers take opts.
	withHeaders := func(t *testing.T, opts ...httpsec.HeaderOption) []httpsec.Option {
		t.Helper()

		p := f.provider(t)

		return []httpsec.Option{
			f.bearer(t, reporting(t, p)),
			httpsec.EnableJWKSEndpoint(f.keys),
			httpsec.EnableSecurityHeaders(opts...),
			httpsec.EnableCSRFProtection(),
			httpsec.EnableOIDCProvider(p),
		}
	}

	// formLogin issues the session reference, as a chain under the session
	// bearer must; a chain with no bearer mode still needs a generator to build.
	formLogin := func(t *testing.T, m *session.Sessions, tokens token.Generator) httpsec.Option {
		t.Helper()

		return httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: NewMockAuthenticator(gomock.NewController(t)),
			Sessions:      m,
			Tokens:        tokens,
			Attempts:      must.Must(lockout.NewMemoryAttemptStore()),
		})
	}

	const endpointAudience = oidcprovider.AudienceIssuerOrTokenEndpoint

	cases := []testCase{
		{
			name:   "a fully wired provider builds",
			build:  func(t *testing.T) []httpsec.Option { t.Helper(); return withOptions(t, nil) },
			assert: built,
		},
		{
			name: "no provider",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return append(f.wired(t, f.provider(t)), httpsec.EnableOIDCProvider(nil))
			},
			assert: refused("EnableOIDCProvider"),
		},
		{
			name: "form login and no bearer mode",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					formLogin(t, reporting(t, p), newMockGenerator(gomock.NewController(t))),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: refused("EnableOIDCProvider", "bearer"),
		},
		{
			name: "no JWKS endpoint",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: refused("EnableOIDCProvider", "EnableJWKSEndpoint"),
		},
		{
			name: "enabled twice",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(f.wired(t, p), httpsec.EnableOIDCProvider(p), httpsec.EnableOIDCProvider(p))
			},
			assert: refused("EnableOIDCProvider", "twice"),
		},
		{
			name: "the end-session path set to the chain's logout path",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(f.wired(t, p),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: reporting(t, p)}),
					httpsec.EnableOIDCProvider(p, httpsec.WithOIDCProviderPath(httpsec.OIDCEndSession, httpsec.DefaultLogoutPath)))
			},
			assert: refused("EnableOIDCProvider", httpsec.DefaultLogoutPath),
		},
		{
			name: "a chain endpoint under the consents path, which answers every path below it",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(f.wired(t, p),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: reporting(t, p)},
						httpsec.WithLogoutRequestPath("/consents/out")),
					httpsec.EnableOIDCProvider(p, httpsec.WithOIDCProviderPath(httpsec.OIDCConsents, "/consents")))
			},
			assert: refused("EnableOIDCProvider", "/consents/out", "/consents"),
		},
		{
			name: "a chain prefix under the consents path",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(f.wired(t, p),
					httpsec.EnableSessionManagement(httpsec.WithSessionManagementPrefix("/consents/sessions")),
					httpsec.EnableOIDCProvider(p, httpsec.WithOIDCProviderPath(httpsec.OIDCConsents, "/consents")))
			},
			assert: refused("EnableOIDCProvider", "/consents/sessions", "/consents"),
		},
		{
			name: "the token path set to the JWKS path, whichever came first",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPath(httpsec.OIDCToken, httpsec.DefaultJWKSPath))
			},
			assert: refused("EnableOIDCProvider", httpsec.DefaultJWKSPath),
		},
		{
			name: "two provider paths equal",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPath(httpsec.OIDCRevoke, "/oauth2/token"))
			},
			assert: refused("EnableOIDCProvider", "/oauth2/token"),
		},
		{
			name: "a prefix naming no path",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPrefix("op"))
			},
			assert: refused("WithOIDCProviderPrefix"),
		},
		{
			name: "an empty prefix",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPrefix(""))
			},
			assert: refused("WithOIDCProviderPrefix"),
		},
		{
			name: "a prefix ending in a slash",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPrefix("/op/"))
			},
			assert: refused("WithOIDCProviderPrefix"),
		},
		{
			name: "a path naming no path",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "token"))
			},
			assert: refused("WithOIDCProviderPath"),
		},
		{
			name: "a path holding a query",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/tokens?x=1"))
			},
			assert: refused("WithOIDCProviderPath"),
		},
		{
			name: "a path holding a fragment",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/tokens#x"))
			},
			assert: refused("WithOIDCProviderPath"),
		},
		{
			name: "a path holding a percent sign",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/a%20b"))
			},
			assert: refused("WithOIDCProviderPath"),
		},
		{
			name: "a path holding a space",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/a b"))
			},
			assert: refused("WithOIDCProviderPath"),
		},
		{
			name: "a path holding a non-ASCII letter",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/caf\u00e9"))
			},
			assert: refused("WithOIDCProviderPath"),
		},
		{
			name: "a prefix holding a space",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPrefix("/o p"))
			},
			assert: refused("WithOIDCProviderPrefix"),
		},
		{
			name: "an assertion endpoint under an issuer path needing escaping, behind a stripping router, builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				issuer := opIssuer + "/a%20b"
				p := f.providerOver(t, issuer, f.keys, nil,
					oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
					oidcprovider.WithAssertionTokenEndpoint(issuer+"/oauth2/token"))

				return append(f.wired(t, p), httpsec.EnableOIDCProvider(p))
			},
			assert: built,
		},
		{
			name: "a prefix holding a query",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPrefix("/op?x"))
			},
			assert: refused("WithOIDCProviderPrefix"),
		},
		{
			name: "a prefix holding a fragment",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPrefix("/op#x"))
			},
			assert: refused("WithOIDCProviderPrefix"),
		},
		{
			name: "a prefix holding a percent sign",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPrefix("/op%20x"))
			},
			assert: refused("WithOIDCProviderPrefix"),
		},
		{
			name: "a path for an endpoint that does not exist",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPath(httpsec.OIDCEndpoint(200), "/x"))
			},
			assert: refused("WithOIDCProviderPath"),
		},
		{
			name: "two bearers over two managers, the provider enabled last",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(append(f.pages(t), twoBearers(t, f, reporting(t, p), reporting(t, p))...), httpsec.EnableOIDCProvider(p))
			},
			assert: refused("EnableOIDCProvider", "EnableBearerToken", "one session manager"),
		},
		{
			name: "two bearers over two managers, the provider enabled first",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(append([]httpsec.Option{httpsec.EnableOIDCProvider(p)}, f.pages(t)...), twoBearers(t, f, reporting(t, p), reporting(t, p))...)
			},
			assert: refused("EnableOIDCProvider", "EnableBearerToken", "one session manager"),
		},
		{
			name: "two bearers over one manager, the provider enabled last",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)
				m := reporting(t, p)

				return append(append(f.pages(t), twoBearers(t, f, m, m)...), httpsec.EnableOIDCProvider(p))
			},
			assert: built,
		},
		{
			name: "two bearers over one manager, the provider enabled first",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)
				m := reporting(t, p)

				return append(append([]httpsec.Option{httpsec.EnableOIDCProvider(p)}, f.pages(t)...), twoBearers(t, f, m, m)...)
			},
			assert: built,
		},
		{
			// A bearer with no manager is refused by its own option, whichever came first: the provider's
			// check neither panics over it nor reads it as a second manager.
			name: "a bearer with no manager beside one that has one, the provider enabled first",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(append([]httpsec.Option{httpsec.EnableOIDCProvider(p)}, f.pages(t)...), twoBearers(t, f, nil, reporting(t, p))...)
			},
			assert: refused("EnableBearerToken", "needs a session manager"),
		},
		{
			name: "a bearer with no manager behind one that has one, the provider enabled first",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(append([]httpsec.Option{httpsec.EnableOIDCProvider(p)}, f.pages(t)...), twoBearers(t, f, reporting(t, p), nil)...)
			},
			assert: refused("EnableBearerToken", "needs a session manager"),
		},
		{
			name: "a bearer with no manager between two over two managers, the provider enabled first",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(append([]httpsec.Option{httpsec.EnableOIDCProvider(p)}, f.pages(t)...),
					f.signedBearer(t, reporting(t, p), httpsec.DefaultBearerScheme),
					f.signedBearer(t, nil, "Between"),
					f.signedBearer(t, reporting(t, p), "Partner"))
			},
			assert: refused("EnableOIDCProvider", "one session manager"),
		},
		{
			// Each mode reads only its own credentials, and the option refusing the pair runs behind this
			// check when the provider comes first.
			name: "a session bearer and a signed bearer over two managers, the provider enabled first",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(append([]httpsec.Option{httpsec.EnableOIDCProvider(p)}, f.pages(t)...),
					f.bearer(t, reporting(t, p)),
					f.signedBearer(t, reporting(t, p), "Partner"))
			},
			assert: refused("EnableOIDCProvider", "one session manager"),
		},
		{
			name: "a bearer with no manager beside one that has one, the provider enabled last",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(append(f.pages(t), twoBearers(t, f, reporting(t, p), nil)...), httpsec.EnableOIDCProvider(p))
			},
			assert: refused("EnableBearerToken", "needs a session manager"),
		},
		{
			// With the provider first its check is the one that runs: no nil stands between it and the two
			// real managers behind.
			name: "a bearer with no manager ahead of two over two managers, the provider enabled first",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(append(append([]httpsec.Option{httpsec.EnableOIDCProvider(p)}, f.pages(t)...),
					f.signedBearer(t, nil, "First")),
					twoBearers(t, f, reporting(t, p), reporting(t, p))...)
			},
			assert: refused("EnableOIDCProvider", "one session manager"),
		},
		{
			name: "the bearer's session manager does not report to the provider",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					f.bearer(t, must.Must(session.New())),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(f.provider(t)),
				}
			},
			assert: refused("EnableOIDCProvider", "session.WithEndObserver"),
		},
		{
			name: "the logout's session manager does not report to the provider",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(f.wired(t, p),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: must.Must(session.New())}),
					httpsec.EnableOIDCProvider(p))
			},
			assert: refused("EnableOIDCProvider", "session.WithEndObserver"),
		},
		{
			name: "a passkey manager over a session manager that does not report to the provider",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)
				users := NewMockUserLoader(gomock.NewController(t))
				pm := must.Must(passkey.New(passkey.Deps{
					Verifier: newPasskeyVerifierStub(t).mock,
					Users:    users,
					Sender:   exampleSender{},
					Sessions: must.Must(session.New()),
				}, passkey.WithRepudiationContact("help@example.com"), passkey.WithoutCloneGrantRevocation()))

				return append(f.wired(t, p),
					httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: pm, Sessions: reporting(t, p), Users: users}),
					httpsec.EnableOIDCProvider(p))
			},
			assert: refused("EnableOIDCProvider", "EnablePasskeys", "session.WithEndObserver"),
		},
		{
			name: "a passkey manager ending no session, over a session manager that does not report, builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)
				users := NewMockUserLoader(gomock.NewController(t))
				pm := must.Must(passkey.New(passkey.Deps{
					Verifier: newPasskeyVerifierStub(t).mock,
					Users:    users,
					Sender:   exampleSender{},
					Sessions: must.Must(session.New()),
				}, passkey.WithRepudiationContact("help@example.com"), passkey.WithoutCloneGrantRevocation(),
					passkey.WithoutSessionRevocationOnRemoval(), passkey.WithoutSessionRevocationOnClone()))

				return append(f.wired(t, p),
					httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: pm, Sessions: reporting(t, p), Users: users}),
					httpsec.EnableOIDCProvider(p))
			},
			assert: built,
		},
		{
			name: "form login's session manager does not report to the provider",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(f.wired(t, p), formLogin(t, must.Must(session.New()), nil), httpsec.EnableOIDCProvider(p))
			},
			assert: refused("EnableOIDCProvider", "session.WithEndObserver"),
		},
		{
			name: "a renewal over the bearer's reporting manager builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)
				m := reporting(t, p)

				return []httpsec.Option{
					f.bearer(t, m),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Sessions: m, Users: NewMockUserLoader(gomock.NewController(t))}),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: built,
		},
		{
			name: "reporting is judged after the chain's wiring, wherever the step stands",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				var wired bool

				t.Cleanup(func() { assert.True(t, wired, "the wiring step had not run when the chain was refused") })

				return []httpsec.Option{
					f.bearer(t, must.Must(session.New())),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(f.provider(t)),
					httpsec.WiredStep(func() { wired = true }),
				}
			},
			assert: refused("EnableOIDCProvider", "session.WithEndObserver"),
		},
		{
			name: "the provider says DPoP is on and the chain has no EnableDPoP",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, []oidcprovider.Option{oidcprovider.WithDPoP()})
			},
			assert: refused("EnableOIDCProvider", "WithDPoP"),
		},
		{
			name: "the chain has EnableDPoP and the provider does not say so",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return append(withOptions(t, nil), httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer}))
			},
			assert: refused("EnableOIDCProvider", "WithDPoP"),
		},
		{
			name: "a provider-only chain enables DPoP",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return append(withOptions(t, []oidcprovider.Option{oidcprovider.WithDPoP()}),
					httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer}))
			},
			assert: built,
		},
		{
			// EnableDPoP's own check runs first here, as it came first. Were the
			// provider not among the features verifying bound credentials, it
			// would report having none, and hide the provider's real fault.
			name: "the provider counts as verifying bound credentials, so DPoP does not report having none",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t, oidcprovider.WithDPoP())

				return []httpsec.Option{
					httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer}),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: refused("EnableOIDCProvider", "bearer"),
		},
		{
			name: "an assertion endpoint the prefix moved away from",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(endpointAudience)},
					httpsec.WithOIDCProviderPrefix("/op"))
			},
			assert: refused("EnableOIDCProvider", "WithAssertionTokenEndpoint"),
		},
		{
			name: "an assertion endpoint a per-path option moved away from",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(endpointAudience)},
					httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/tokens"))
			},
			assert: refused("EnableOIDCProvider", "WithAssertionTokenEndpoint"),
		},
		{
			name: "an assertion endpoint stating the moved path builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, []oidcprovider.Option{
					oidcprovider.WithClientAssertionAudience(endpointAudience),
					oidcprovider.WithAssertionTokenEndpoint(opIssuer + "/op/token"),
				}, httpsec.WithOIDCProviderPrefix("/op"))
			},
			assert: built,
		},
		{
			name: "an assertion endpoint on the default path builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, []oidcprovider.Option{oidcprovider.WithClientAssertionAudience(endpointAudience)})
			},
			assert: built,
		},
		{
			name: "no assertion endpoint, under the issuer-only rule, is free of the path",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, nil, httpsec.WithOIDCProviderPrefix("/op"))
			},
			assert: built,
		},
		{
			name: "a JWKS endpoint publishing another signing-key manager",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.otherKeys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: refused("EnableOIDCProvider", "EnableJWKSEndpoint"),
		},
		{
			name: "no security headers",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: refused("EnableOIDCProvider", "EnableSecurityHeaders", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "no security headers, the consumer stating its pages carry frame-ancestors",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(p, httpsec.WithOIDCPagesCarryFrameAncestors()),
				}
			},
			assert: built,
		},
		{
			name: "a wrapped JWKS provider, which cannot be compared, builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(NewMockKeySetProvider(gomock.NewController(t))),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: built,
		},
		{
			name: "a wrapper of the manager as the provider's keys, over the manager's own key set, builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.providerOver(t, opIssuer, wrappedKeys{f.keys}, nil)

				return append(f.wired(t, p), httpsec.EnableOIDCProvider(p))
			},
			assert: built,
		},
		{
			name: "a wrapper of the manager as the key set, beside a provider signing with the manager, builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(wrappedKeys{f.keys}),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: built,
		},
		{
			name: "an issuer with a path, served behind a stripping router, builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.providerOver(t, opIssuer+"/auth", f.keys, nil, oidcprovider.WithClientAssertionAudience(endpointAudience))

				return append(f.wired(t, p), httpsec.EnableOIDCProvider(p))
			},
			assert: built,
		},
		{
			name: "an issuer with a path, the prefix holding the issuer's path, builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.providerOver(t, opIssuer+"/auth", f.keys, nil, oidcprovider.WithClientAssertionAudience(endpointAudience))

				return append(f.wired(t, p), httpsec.EnableOIDCProvider(p, httpsec.WithOIDCProviderPrefix("/auth/oauth2")))
			},
			assert: built,
		},
		{
			name: "an issuer with a path, the assertion endpoint stated elsewhere",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.providerOver(t, opIssuer+"/auth", f.keys, nil,
					oidcprovider.WithClientAssertionAudience(endpointAudience),
					oidcprovider.WithAssertionTokenEndpoint(opIssuer+"/auth/elsewhere/token"))

				return append(f.wired(t, p), httpsec.EnableOIDCProvider(p))
			},
			assert: refused("EnableOIDCProvider", "WithAssertionTokenEndpoint"),
		},
		{
			name: "an assertion endpoint naming the token path percent-encoded",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withOptions(t, []oidcprovider.Option{
					oidcprovider.WithClientAssertionAudience(endpointAudience),
					oidcprovider.WithAssertionTokenEndpoint(opIssuer + "/oauth2/%74oken"),
				})
			},
			assert: refused("EnableOIDCProvider", "WithAssertionTokenEndpoint"),
		},
		{
			name: "security headers with the policy removed",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithoutHeader("Content-Security-Policy"))
			},
			assert: refused("EnableOIDCProvider", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "security headers with the policy only reported",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithCSPReportOnly())
			},
			assert: refused("EnableOIDCProvider", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "security headers opening frame-ancestors to anyone",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("frame-ancestors", "*"))))
			},
			assert: refused("EnableOIDCProvider", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "security headers with a policy naming no frame-ancestors",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("frame-ancestors"))))
			},
			assert: refused("EnableOIDCProvider", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "security headers limiting frame-ancestors to the origin itself build",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("frame-ancestors", "'self'"))))
			},
			assert: built,
		},
		{
			name: "frame-ancestors keyword in upper case builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("frame-ancestors", "'SELF'"))))
			},
			assert: built,
		},
		{
			name: "frame-ancestors naming an https origin builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("frame-ancestors", "https://ext.example.org:8000"))))
			},
			assert: built,
		},
		{
			name: "frame-ancestors of self and an https origin builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("frame-ancestors", "'self'", "https://ext.example.org"))))
			},
			assert: built,
		},
		{
			name: "frame-ancestors with a scheme-only source is refused",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("frame-ancestors", "https:"))))
			},
			assert: refused("EnableOIDCProvider", "forbid framing", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "frame-ancestors with a wildcard host is refused",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("frame-ancestors", "https://*.example.com"))))
			},
			assert: refused("EnableOIDCProvider", "forbid framing", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "frame-ancestors with an http origin is refused",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("frame-ancestors", "http://ext.example.org"))))
			},
			assert: refused("EnableOIDCProvider", "forbid framing", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "frame-ancestors with self and a wildcard is refused",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("frame-ancestors", "'self'", "*"))))
			},
			assert: refused("EnableOIDCProvider", "forbid framing", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "a raw policy forbidding framing builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"))
			},
			assert: built,
		},
		{
			name: "a raw policy with the directive name in upper case builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithHeader("Content-Security-Policy", "default-src 'self'; FRAME-ANCESTORS 'self'"))
			},
			assert: built,
		},
		{
			name: "a raw policy with no frame-ancestors is refused",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithHeader("Content-Security-Policy", "default-src 'self'"))
			},
			assert: refused("EnableOIDCProvider", "forbid framing", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "a raw policy opening frame-ancestors is refused",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors *"))
			},
			assert: refused("EnableOIDCProvider", "forbid framing", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "a raw policy with an empty frame-ancestors is refused",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors"))
			},
			assert: refused("EnableOIDCProvider", "forbid framing", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "a raw policy only mentioning frame-ancestors in another directive is refused",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithHeader("Content-Security-Policy", "default-src frame-ancestors"))
			},
			assert: refused("EnableOIDCProvider", "forbid framing", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "security headers forbidding all framing build",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return withHeaders(t, httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("frame-ancestors", "'none'"))))
			},
			assert: built,
		},
		{
			name: "security headers allowing framing, the consumer stating its pages carry frame-ancestors, build",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(httpsec.WithoutHeader("Content-Security-Policy")),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(p, httpsec.WithOIDCPagesCarryFrameAncestors()),
				}
			},
			assert: built,
		},

		{
			name: "the provider given before everything it needs builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append([]httpsec.Option{httpsec.EnableOIDCProvider(p)}, f.wired(t, p)...)
			},
			assert: built,
		},
		{
			name: "the provider given before the logout it collides with",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append([]httpsec.Option{
					httpsec.EnableOIDCProvider(p, httpsec.WithOIDCProviderPath(httpsec.OIDCEndSession, httpsec.DefaultLogoutPath)),
				}, append(f.wired(t, p), httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: reporting(t, p)}))...)
			},
			assert: refused("EnableOIDCProvider", httpsec.DefaultLogoutPath),
		},
		{
			name: "the provider given before the key set endpoint its token path collides with",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append([]httpsec.Option{
					httpsec.EnableOIDCProvider(p, httpsec.WithOIDCProviderPath(httpsec.OIDCToken, httpsec.DefaultJWKSPath)),
				}, f.wired(t, p)...)
			},
			assert: refused("EnableOIDCProvider", httpsec.DefaultJWKSPath),
		},
		{
			name: "the provider given before the key set endpoint publishing other keys",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					httpsec.EnableOIDCProvider(p),
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.otherKeys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
				}
			},
			assert: refused("EnableOIDCProvider", "EnableJWKSEndpoint"),
		},
		{
			name: "the provider given before the bearer, which comes without a session manager of its own reporting",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					httpsec.EnableOIDCProvider(p),
					f.bearer(t, must.Must(session.New())),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
				}
			},
			assert: refused("EnableOIDCProvider", "session.WithEndObserver"),
		},
		{
			name: "the provider given before the security headers that leave pages frameable",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					httpsec.EnableOIDCProvider(p),
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(httpsec.WithoutHeader("Content-Security-Policy")),
					httpsec.EnableCSRFProtection(),
				}
			},
			assert: refused("EnableOIDCProvider", "WithOIDCPagesCarryFrameAncestors"),
		},
		{
			name: "browser sessions on and no CSRF protection",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: refused("EnableOIDCProvider", "EnableCSRFProtection", "WithoutBrowserSessions"),
		},
		{
			name: "browser sessions on and CSRF protection opted out of",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.WithoutCSRFProtection(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: refused("EnableOIDCProvider", "EnableCSRFProtection"),
		},
		{
			name: "no browser sessions and no CSRF protection builds",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t, oidcprovider.WithoutBrowserSessions())

				return []httpsec.Option{
					f.bearer(t, reporting(t, p)),
					httpsec.EnableJWKSEndpoint(f.keys),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableOIDCProvider(p),
				}
			},
			assert: built,
		},
		{
			name: "a client requiring DPoP and no EnableDPoP",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.providerFor(t, []oidcprovider.Client{requiring("dpop-app", oidcprovider.BindingDPoP)})

				return append(f.wired(t, p), httpsec.EnableOIDCProvider(p))
			},
			assert: refused("EnableOIDCProvider", "EnableDPoP"),
		},
		{
			name: "a client requiring DPoP, with DPoP on the provider and the chain",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.providerFor(t, []oidcprovider.Client{requiring("dpop-app", oidcprovider.BindingDPoP)},
					oidcprovider.WithDPoP())

				return append(f.wired(t, p), httpsec.EnableOIDCProvider(p),
					httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer}))
			},
			assert: built,
		},
		{
			name: "a client requiring a certificate binding and no EnableCertificateBinding",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.providerFor(t, []oidcprovider.Client{requiring("mtls-app", oidcprovider.BindingMTLS)})

				return append(f.wired(t, p), httpsec.EnableOIDCProvider(p))
			},
			assert: refused("EnableOIDCProvider", "EnableCertificateBinding"),
		},
		{
			name: "a client requiring a certificate binding, with it enabled",
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.providerFor(t, []oidcprovider.Client{requiring("mtls-app", oidcprovider.BindingMTLS)})

				return append(f.wired(t, p), httpsec.EnableOIDCProvider(p), httpsec.EnableCertificateBinding())
			},
			assert: built,
		},
	}

	// Each endpoint family of the chain that the provider's paths must stay clear of,
	// whatever the order of the options: the provider is given the family's path.
	for _, fam := range []struct {
		name     string
		endpoint httpsec.OIDCEndpoint
		path     string
		enable   func(t *testing.T, m *session.Sessions) []httpsec.Option
	}{
		{"the magic-link request path", httpsec.OIDCToken, httpsec.DefaultMagicLinkRequestPath, magicLinkOn},
		{"the magic-link consume path", httpsec.OIDCRevoke, httpsec.DefaultMagicLinkConsumePath, magicLinkOn},
		{"an OIDC login authorization path", httpsec.OIDCToken, httpsec.DefaultOIDCAuthorizePath + "idp", oidcLoginOn},
		{"an OIDC login callback path", httpsec.OIDCToken, httpsec.DefaultOIDCCallbackPath + "idp", oidcLoginOn},
		{"an OIDC login back-channel logout path", httpsec.OIDCToken, httpsec.DefaultOIDCBackchannelPath + "idp", oidcLoginOn},
		{"the OIDC login handoff path", httpsec.OIDCToken, httpsec.DefaultOIDCHandoffPath, oidcLoginOn},
		{"the re-authentication listing path", httpsec.OIDCToken, httpsec.DefaultReauthenticationPrefix + "/methods", reauthOn},
		{"a re-authentication begin path", httpsec.OIDCToken, httpsec.DefaultReauthenticationPrefix + "/begin/totp", reauthOn},
		{"a re-authentication verify path", httpsec.OIDCToken, httpsec.DefaultReauthenticationPrefix + "/verify/totp", reauthOn},
		{"the re-authentication password path", httpsec.OIDCToken, httpsec.DefaultReauthenticationPrefix + "/password", reauthOn},
		{"the session management prefix", httpsec.OIDCToken, httpsec.DefaultSessionManagementPrefix, managementOn},
		{"a session management path under its prefix", httpsec.OIDCToken, httpsec.DefaultSessionManagementPrefix + "/s-1", managementOn},
		{"the MFA method listing path", httpsec.OIDCToken, httpsec.DefaultMFAMethodListingPath, mfaListingOn},
		{"the login path", httpsec.OIDCToken, httpsec.DefaultLoginPath, formLoginOn},
		{"the session renewal path", httpsec.OIDCToken, httpsec.DefaultSessionRenewalPath, renewalOn},
		{"the password-change resolve path", httpsec.OIDCToken, opPasswordChangePath, passwordChangeOn},
		{"a recovery path", httpsec.OIDCToken, httpsec.DefaultRecoveryStartPath, recoveryOn},
		{"a passkey path", httpsec.OIDCToken, httpsec.DefaultPasskeyCredentialsPrefix, passkeysOn},
		{"a second-factor begin path", httpsec.OIDCToken, httpsec.DefaultMFABeginPrefix + "/totp", mfaPrefixesOn},
		{"a second-factor verify path", httpsec.OIDCToken, httpsec.DefaultMFAVerifyPrefix + "/totp", mfaPrefixesOn},
		{"an enrolment begin path", httpsec.OIDCToken, httpsec.DefaultEnrolmentBeginPrefix + "/totp", enrolmentOn},
		{"an enrolment confirm path", httpsec.OIDCToken, httpsec.DefaultEnrolmentConfirmPrefix + "/totp", enrolmentOn},
	} {
		cases = append(cases, testCase{
			name: "the provider's path set to " + fam.name,
			build: func(t *testing.T) []httpsec.Option {
				t.Helper()

				p := f.provider(t)

				return append(f.wired(t, p), append(fam.enable(t, reporting(t, p)),
					httpsec.EnableOIDCProvider(p, httpsec.WithOIDCProviderPath(fam.endpoint, fam.path)))...)
			},
			assert: refused("EnableOIDCProvider", fam.path),
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.build(t)...)
			tc.assert(t, chain, err)
		})
	}
}

// opAnswer is what a chain made of a request, and whether the request reached the
// application behind the chain.
type opAnswer struct {
	status   int
	passedOn bool
}

// serveOP runs one request through a chain with the application behind it.
func serveOP(t *testing.T, chain *httpsec.Chain, r *http.Request) opAnswer {
	t.Helper()

	var passedOn bool

	h := chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { passedOn = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	return opAnswer{status: rec.Code, passedOn: passedOn}
}

func TestOIDCProvider_Routes(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	type testCase struct {
		name   string
		opts   []httpsec.OIDCProviderOption
		method string
		path   string
		assert func(t *testing.T, a opAnswer)
	}

	passesThrough := func(t *testing.T, a opAnswer) {
		t.Helper()
		assert.True(t, a.passedOn, "the request should have reached the application")
	}

	// answered holds whichever handler serves the endpoint, a stub or a real one,
	// so it says only that the provider took the request.
	answered := func(t *testing.T, a opAnswer) {
		t.Helper()
		assert.False(t, a.passedOn, "the request should have been answered by the provider")
	}

	prefix := []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix("/op")}
	moved := []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/tokens")}

	cases := []testCase{
		{name: "another path passes through", method: http.MethodGet, path: "/api/orders", assert: passesThrough},
		{name: "a path under the prefix naming no endpoint passes through", method: http.MethodGet, path: "/oauth2/other", assert: passesThrough},
		{name: "a path below an endpoint passes through", method: http.MethodGet, path: "/oauth2/token/x", assert: passesThrough},

		{name: "authorization", method: http.MethodGet, path: "/oauth2/authorize", assert: answered},
		{name: "resume", method: http.MethodPost, path: "/oauth2/authorize/resume", assert: answered},
		{name: "token", method: http.MethodPost, path: "/oauth2/token", assert: answered},
		{name: "UserInfo", method: http.MethodGet, path: "/oauth2/userinfo", assert: answered},
		{name: "revocation", method: http.MethodPost, path: "/oauth2/revoke", assert: answered},
		{name: "introspection", method: http.MethodPost, path: "/oauth2/introspect", assert: answered},
		{name: "end-session", method: http.MethodGet, path: "/oauth2/logout", assert: answered},
		{name: "logout confirmation", method: http.MethodPost, path: "/oauth2/logout/confirm", assert: answered},
		{name: "consents", method: http.MethodGet, path: "/oauth2/consents", assert: answered},

		{name: "a prefix moves the token endpoint", opts: prefix, method: http.MethodPost, path: "/op/token", assert: answered},
		{name: "a prefix moves the resume endpoint", opts: prefix, method: http.MethodPost, path: "/op/authorize/resume", assert: answered},
		{name: "the default path passes through under a prefix", opts: prefix, method: http.MethodPost, path: "/oauth2/token", assert: passesThrough},

		{name: "a per-path option moves one endpoint", opts: moved, method: http.MethodPost, path: "/tokens", assert: answered},
		{name: "the moved endpoint's default passes through", opts: moved, method: http.MethodPost, path: "/oauth2/token", assert: passesThrough},
		{name: "a per-path option leaves the others", opts: moved, method: http.MethodPost, path: "/oauth2/revoke", assert: answered},
		{
			name:   "a per-path option holds under a prefix, whichever came first",
			opts:   []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPath(httpsec.OIDCToken, "/tokens"), httpsec.WithOIDCProviderPrefix("/op")},
			method: http.MethodPost, path: "/tokens", assert: answered,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := f.provider(t)
			chain, err := httpsec.New(append(f.wired(t, p), httpsec.EnableOIDCProvider(p, tc.opts...))...)
			require.NoError(t, err)

			r := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil)
			tc.assert(t, serveOP(t, chain, r))
		})
	}
}

// TestOIDCProvider_Routes_Groups pins the seam each endpoint group plugs into,
// with a group of the test's own, so it holds when the stubs are gone.
func TestOIDCProvider_Routes_Groups(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	errSettle := errors.New("settling failed")
	errFlush := errors.New("flushing failed")

	type testCase struct {
		name   string
		group  *httpsec.TestOIDCGroup
		header string
		assert func(t *testing.T, g *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, r *http.Request, bearer *session.Sessions)
	}

	cases := []testCase{
		{
			name:   "an outer route is answered ahead of the bearer, whatever credential it carries",
			group:  &httpsec.TestOIDCGroup{Path: "/g"},
			header: "Bearer not-a-session",
			assert: func(t *testing.T, g *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, r *http.Request, _ *session.Sessions) {
				t.Helper()
				require.NoError(t, err)

				a := serveOP(t, chain, r)
				assert.False(t, a.passedOn)
				assert.Equal(t, 1, g.Calls())
			},
		},
		{
			name:   "an inner route sits behind the bearer, which refuses a bad credential",
			group:  &httpsec.TestOIDCGroup{Path: "/g", Inner: true},
			header: "Bearer not-a-session",
			assert: func(t *testing.T, g *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, r *http.Request, _ *session.Sessions) {
				t.Helper()
				require.NoError(t, err)

				a := serveOP(t, chain, r)
				assert.Equal(t, http.StatusUnauthorized, a.status)
				assert.Zero(t, g.Calls())
			},
		},
		{
			name:  "an inner route is answered with no credential at all",
			group: &httpsec.TestOIDCGroup{Path: "/g", Inner: true},
			assert: func(t *testing.T, g *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, r *http.Request, _ *session.Sessions) {
				t.Helper()
				require.NoError(t, err)

				a := serveOP(t, chain, r)
				assert.False(t, a.passedOn)
				assert.Equal(t, 1, g.Calls())
			},
		},
		{
			name:  "a route another group holds is refused",
			group: &httpsec.TestOIDCGroup{Path: "/oauth2/token"},
			assert: func(t *testing.T, _ *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, _ *http.Request, _ *session.Sessions) {
				t.Helper()
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "/oauth2/token")
				assert.Nil(t, chain)
			},
		},
		{
			name:  "a group that cannot settle refuses the chain",
			group: &httpsec.TestOIDCGroup{Path: "/g", SettleErr: errSettle},
			assert: func(t *testing.T, _ *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, _ *http.Request, _ *session.Sessions) {
				t.Helper()
				require.ErrorIs(t, err, errSettle)
				assert.Nil(t, chain)
			},
		},
		{
			name:  "a group settles with the bearer's manager to hand, and is wired with the chain",
			group: &httpsec.TestOIDCGroup{Path: "/g"},
			assert: func(t *testing.T, g *httpsec.TestOIDCGroup, _ *httpsec.Chain, err error, _ *http.Request, _ *session.Sessions) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, g.SettledWithManager())
				assert.True(t, g.WiredWithLogger())
			},
		},
		{
			name:  "a group settles with the very manager the bearer resolves sessions through",
			group: &httpsec.TestOIDCGroup{Path: "/g"},
			assert: func(t *testing.T, g *httpsec.TestOIDCGroup, _ *httpsec.Chain, err error, _ *http.Request, bearer *session.Sessions) {
				t.Helper()
				require.NoError(t, err)
				assert.Same(t, bearer, g.SettledSessions())
			},
		},
		{
			name:  "a group settles before CSRF protection reads the chain's settings",
			group: &httpsec.TestOIDCGroup{Path: "/g"},
			assert: func(t *testing.T, g *httpsec.TestOIDCGroup, _ *httpsec.Chain, err error, _ *http.Request, _ *session.Sessions) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, g.SawCSRFSettled())
			},
		},
		{
			name:  "a group's refusal logs are flushed with the chain's",
			group: &httpsec.TestOIDCGroup{Path: "/g", FlushErr: errFlush},
			assert: func(t *testing.T, _ *httpsec.TestOIDCGroup, chain *httpsec.Chain, err error, _ *http.Request, _ *session.Sessions) {
				t.Helper()
				require.NoError(t, err)
				assert.ErrorIs(t, chain.FlushRefusalLogs(), errFlush)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := f.provider(t)
			m := reporting(t, p)
			chain, err := httpsec.New(
				f.bearer(t, m),
				httpsec.EnableJWKSEndpoint(f.keys),
				httpsec.EnableSecurityHeaders(),
				httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{"https://app.example.com"}}),
				httpsec.EnableCSRFProtection(),
				httpsec.EnableOIDCProvider(p, httpsec.WithTestOIDCGroup(tc.group)),
			)

			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tc.group.Path, nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}

			tc.assert(t, tc.group, chain, err, r, m)
		})
	}
}

// TestOIDCProvider_Slots pins where each slot stands among the chain's layers by
// which of them a request reaches before a route answers it. A probe sits at each
// order just inside or just outside a layer the slot is named against.
func TestOIDCProvider_Slots(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)

	// The probes: one inside CSRF protection (75), one either side of the outer
	// slot (250), one behind the gates and the bearer (up to 675), one behind
	// the session-touch step (800), and one either side of the inner slot (850).
	probes := []httpsec.Order{76, 249, 251, 676, 801, 849, 851}

	type testCase struct {
		name  string
		inner bool
		ran   []httpsec.Order
		didnt []httpsec.Order
	}

	cases := []testCase{
		{
			name:  "the outer slot is inside CSRF protection and outside the bearer and Basic",
			ran:   []httpsec.Order{76, 249},
			didnt: []httpsec.Order{251, 676, 801, 849, 851},
		},
		{
			name:  "the inner slot is behind the gates and the session touch, and outside authorization",
			inner: true,
			ran:   []httpsec.Order{76, 249, 251, 676, 801, 849},
			didnt: []httpsec.Order{851},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var reached []httpsec.Order

			opts := make([]httpsec.Option, 0, len(probes)+6)

			for _, at := range probes {
				opts = append(opts, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					reached = append(reached, at)

					return next(ex)
				}), at))
			}

			g := &httpsec.TestOIDCGroup{Path: "/g", Inner: tc.inner}
			p := f.provider(t)

			chain, err := httpsec.New(append(append(f.wired(t, p), opts...),
				httpsec.EnableOIDCProvider(p, httpsec.WithTestOIDCGroup(g)))...)
			require.NoError(t, err)

			serveOP(t, chain, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/g", nil))

			require.Equal(t, 1, g.Calls())

			for _, at := range tc.ran {
				assert.Contains(t, reached, at, "the request should have passed the probe at %d", at)
			}

			for _, at := range tc.didnt {
				assert.NotContains(t, reached, at, "the request should have been answered before the probe at %d", at)
			}
		})
	}
}
