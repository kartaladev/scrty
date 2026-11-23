package oidcprovider_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
)

func TestWithDeviceAuthorization(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		issuer string
		opts   []oidcprovider.Option
		assert func(t *testing.T, p *oidcprovider.Provider, err error)
	}

	// refused asserts the refusal names the option and repeats none of the given
	// fragments, which stand for the parts of the entry URL that could hold a credential.
	refused := func(leaks ...string) func(t *testing.T, p *oidcprovider.Provider, err error) {
		return func(t *testing.T, p *oidcprovider.Provider, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.ErrorContains(t, err, "WithDeviceAuthorization")
			assert.Nil(t, p)
			for _, leak := range leaks {
				assert.NotContains(t, err.Error(), leak)
			}
		}
	}
	enabled := func(t *testing.T, p *oidcprovider.Provider, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.True(t, p.DeviceEnabled())
	}

	cases := []testCase{
		{
			name: "off when the option is not given",
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, p.DeviceEnabled())
			},
		},
		{
			name:   "a same-origin https entry URL with a query",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/activate?src=tv")},
			assert: enabled,
		},
		{
			name:   "a nil device option is skipped",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer+"/activate", nil)},
			assert: enabled,
		},
		{
			name:   "an entry URL on another origin",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization("https://other.example.com/activate")},
			assert: refused("other.example.com"),
		},
		{
			name:   "an entry URL on the same host with another port",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization("https://id.example.com:8443/activate")},
			assert: refused("8443"),
		},
		{
			name:   "an entry URL with a fragment",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/activate#x")},
			assert: refused("#x"),
		},
		{
			name:   "a relative entry URL",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization("/activate")},
			assert: refused(),
		},
		{
			name:   "an empty entry URL",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization("")},
			assert: refused(),
		},
		{
			name:   "an unparsable entry URL",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization("https://id.example.com/%zz")},
			assert: refused("%zz"),
		},
		{
			name:   "an entry URL with user information",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization("https://user:pw@id.example.com/activate")},
			assert: refused("user:pw"),
		},
		{
			name:   "http on an https issuer",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization("http://id.example.com/activate")},
			assert: refused(),
		},
		{
			name:   "a scheme-relative entry URL",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization("//id.example.com/activate")},
			assert: refused("//id.example.com"),
		},
		{
			name:   "an entry URL with another scheme",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization("ftp://id.example.com/activate")},
			assert: refused("ftp"),
		},
		{
			name:   "an entry URL with a trailing space",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/activate ")},
			assert: refused(),
		},
		{
			name:   "an entry URL with an interior space",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/act ivate")},
			assert: refused("ivate"),
		},
		{
			name:   "an entry URL with invalid UTF-8",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/activate\xff")},
			assert: refused(),
		},
		{
			name:   "an entry URL with a malformed query escape",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/activate?a=%zz")},
			assert: refused("%zz"),
		},
		{
			name:   "an entry URL with a tab",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/act\tivate")},
			assert: refused("ivate"),
		},
		{
			name:   "an entry URL with a newline",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/activate\n")},
			assert: refused(),
		},
		{
			name: "an entry URL with a user_code in the query",
			opts: []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/activate?user_code=x")},
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				refused("user_code=x")(t, p, err)
				assert.ErrorContains(t, err, "user_code")
			},
		},
		{
			name: "an entry URL with an empty user_code in a longer query",
			opts: []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/activate?a=1&user_code=")},
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				refused()(t, p, err)
				assert.ErrorContains(t, err, "user_code")
			},
		},
		{
			name: "an entry URL with a result in the query",
			opts: []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/activate?result=approved")},
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				refused("result=approved")(t, p, err)
				assert.ErrorContains(t, err, oidcprovider.DeviceResultParam)
			},
		},
		{
			name:   "an entry URL with an empty result in a longer query",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/activate?a=1&result=")},
			assert: refused(),
		},
		{
			name:   "an entry URL with a parameter only named like result",
			opts:   []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/activate?results=1&a=result")},
			assert: enabled,
		},
		{
			name: "given twice, the last one wins over an invalid first",
			opts: []oidcprovider.Option{
				oidcprovider.WithDeviceAuthorization("https://other.example.com/activate"),
				oidcprovider.WithDeviceAuthorization(issuer + "/activate"),
			},
			assert: enabled,
		},
		{
			name: "given twice, the last one wins over a valid first",
			opts: []oidcprovider.Option{
				oidcprovider.WithDeviceAuthorization(issuer + "/activate"),
				oidcprovider.WithDeviceAuthorization("https://other.example.com/activate"),
			},
			assert: refused("other.example.com"),
		},
		{
			name:   "http on a loopback http issuer",
			issuer: "http://localhost:8080",
			opts: []oidcprovider.Option{
				oidcprovider.WithLoopbackHTTPIssuer(),
				oidcprovider.WithDeviceAuthorization("http://localhost:8080/activate"),
			},
			assert: enabled,
		},
		{
			name:   "https on a loopback http issuer is another origin",
			issuer: "http://localhost:8080",
			opts: []oidcprovider.Option{
				oidcprovider.WithLoopbackHTTPIssuer(),
				oidcprovider.WithDeviceAuthorization("https://localhost:8080/activate"),
			},
			assert: refused(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := validDeps(t)
			if tc.issuer != "" {
				d.Issuer = tc.issuer
				d.LoginURL, d.ConsentURL = tc.issuer+"/login", tc.issuer+"/consent"
				d.LogoutURL, d.LoggedOutURL = tc.issuer+"/logout", tc.issuer+"/bye"
			}

			p, err := oidcprovider.New(d, tc.opts...)
			tc.assert(t, p, err)
		})
	}
}

// A registry client listing the grant, or a device setting that needs it, on a
// provider that cannot honour it reads as unknown, and the log names the settings. On
// a provider that can, it reads.
func TestRegistry_DeviceClientOnProviderWithout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		client func(c *oidcprovider.Client)
		opts   []oidcprovider.Option
		assert func(t *testing.T, got *oidcprovider.RegisteredClient, err error, logs string)
	}

	unknown := func(settings ...string) func(*testing.T, *oidcprovider.RegisteredClient, error, string) {
		return func(t *testing.T, got *oidcprovider.RegisteredClient, err error, logs string) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrClientNotFound)
			assert.Nil(t, got)
			assert.Contains(t, logs, "tv-app")
			for _, s := range settings {
				assert.Contains(t, logs, s)
			}
		}
	}
	read := func(t *testing.T, got *oidcprovider.RegisteredClient, err error, logs string) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Empty(t, logs)
	}
	enable := []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer + "/activate")}
	deviceGrant := func(c *oidcprovider.Client) { c.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantDeviceCode} }

	cases := []testCase{
		{name: "the provider did not enable the grant", client: deviceGrant, assert: unknown("GrantTypes")},
		{name: "the provider enabled the grant", client: deviceGrant, opts: enable, assert: read},
		{
			name: "the complete URI without the grant",
			client: func(c *oidcprovider.Client) {
				c.DeviceCompleteURI = true
				c.RedirectURIs = []string{"https://rp.example.com/cb"}
			},
			opts:   enable,
			assert: unknown("DeviceCompleteURI", "GrantDeviceCode"),
		},
		{
			name: "outliving the sign-in without the grant",
			client: func(c *oidcprovider.Client) {
				c.DeviceGrantsOutliveSignIn = true
				c.RedirectURIs = []string{"https://rp.example.com/cb"}
			},
			opts:   enable,
			assert: unknown("DeviceGrantsOutliveSignIn", "GrantDeviceCode"),
		},
		{
			name: "outliving the sign-in while ending grants with it",
			client: func(c *oidcprovider.Client) {
				deviceGrant(c)
				c.DeviceGrantsOutliveSignIn, c.EndGrantsWithSignIn = true, true
			},
			opts:   enable,
			assert: unknown("DeviceGrantsOutliveSignIn", "EndGrantsWithSignIn"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rc := &oidcprovider.RegisteredClient{
				Client: oidcprovider.Client{
					ID:              "tv-app",
					Type:            oidcprovider.Public,
					ApplicationType: oidcprovider.Native,
				},
			}
			tc.client(&rc.Client)
			registry := NewMockClientRegistry(gomock.NewController(t))
			registry.EXPECT().Client(gomock.Any(), "tv-app").Return(rc, nil)

			var logs bytes.Buffer
			d := validDeps(t)
			d.Clients = nil
			d.Registry = registry
			opts := append([]oidcprovider.Option{oidcprovider.WithLogger(slog.New(slog.NewTextHandler(&logs, nil)))}, tc.opts...)
			p, err := oidcprovider.New(d, opts...)
			require.NoError(t, err)

			got, err := p.ClientForTest(t.Context(), "tv-app")
			tc.assert(t, got, err, logs.String())
		})
	}
}
