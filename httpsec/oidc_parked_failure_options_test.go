package httpsec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
)

// parkedFailureChain builds a chain that completes sign-ins on the server, with opts
// on EnableOIDCLogin; completion off leaves out WithOIDCProviderCompletion and the
// user loader only it reads.
func parkedFailureChain(t *testing.T, completion bool, opts ...httpsec.OIDCOption) error {
	t.Helper()

	provider := completionProvider(t, completionLoginURL)
	deps := httpsec.OIDCDeps{
		RelyingParty: completionRP(t, newOIDCTestProvider(t), opIssuer),
		Handoff:      newTestHandoffManager(t),
	}

	if completion {
		deps.Users = NewMockUserLoader(gomock.NewController(t))
		opts = append([]httpsec.OIDCOption{httpsec.WithOIDCProviderCompletion()}, opts...)
	}

	_, err := httpsec.New(
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{
			Sessions: reporting(t, provider), Users: NewMockUserLoader(gomock.NewController(t)),
		}),
		httpsec.EnableJWKSEndpoint(tokenKeys()),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableOIDCLogin(deps, opts...),
		httpsec.EnableOIDCProvider(provider),
	)

	return err
}

// TestParkedFailureOptions_Construction pins the wiring of the options that govern a
// failed login for a parked request: the error parameter refuses an empty name, the
// names the login page reads (req, handoff) and a name that is not a plain query key
// (Review Focus 4), and the straight-to-client override refuses a chain without
// completion (F23).
func TestParkedFailureOptions_Construction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		completion bool
		opts       []httpsec.OIDCOption
		assert     func(t *testing.T, err error)
	}

	builds := func(t *testing.T, err error) {
		t.Helper()

		require.NoError(t, err)
	}

	refused := func(option string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.ErrorContains(t, err, option)
		}
	}

	param := refused("WithOIDCLoginErrorParam")

	cases := []testCase{
		{name: "the defaults build", completion: true, assert: builds},
		{
			name: "a renamed parameter builds", completion: true,
			opts: []httpsec.OIDCOption{httpsec.WithOIDCLoginErrorParam("sso_error")}, assert: builds,
		},
		{
			name: "an empty parameter", completion: true,
			opts: []httpsec.OIDCOption{httpsec.WithOIDCLoginErrorParam("")}, assert: param,
		},
		{
			name: "the handle's parameter req", completion: true,
			opts: []httpsec.OIDCOption{httpsec.WithOIDCLoginErrorParam("req")}, assert: param,
		},
		{
			name: "the handoff code's parameter", completion: true,
			opts:   []httpsec.OIDCOption{httpsec.WithOIDCLoginErrorParam(httpsec.DefaultOIDCHandoffParam)},
			assert: param,
		},
		{
			name: "a parameter that is not a plain query key", completion: true,
			opts: []httpsec.OIDCOption{httpsec.WithOIDCLoginErrorParam("a b")}, assert: param,
		},
		{
			name: "a parameter carrying a separator", completion: true,
			opts: []httpsec.OIDCOption{httpsec.WithOIDCLoginErrorParam("a&req")}, assert: param,
		},
		{
			name: "the straight-to-client override with completion builds", completion: true,
			opts: []httpsec.OIDCOption{httpsec.WithOIDCFailToClient()}, assert: builds,
		},
		{
			name:   "the straight-to-client override without completion",
			opts:   []httpsec.OIDCOption{httpsec.WithOIDCFailToClient()},
			assert: refused("WithOIDCFailToClient"),
		},
		{
			name:   "a renamed parameter without completion",
			opts:   []httpsec.OIDCOption{httpsec.WithOIDCLoginErrorParam("sso_error")},
			assert: refused("WithOIDCLoginErrorParam"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, parkedFailureChain(t, tc.completion, tc.opts...))
		})
	}
}
