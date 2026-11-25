package httpsec_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/httpsec"
)

const linkFormType = "application/x-www-form-urlencoded"

// askLink posts body to the request endpoint and returns the answer and the
// binding value it set.
func askLink(t *testing.T, c *httpsec.Chain, contentType, body string) (served, string) {
	t.Helper()

	out := serve(t, c, postBody(t.Context(), httpsec.DefaultMagicLinkRequestPath,
		contentType, strings.NewReader(body)))
	require.NoError(t, out.err)

	var nonce string
	if cookie := cookieNamed(out.rec, httpsec.DefaultBindingCookieName); cookie != nil {
		nonce = cookie.Value
	}

	return out, nonce
}

// redeemBody posts body to the redeem endpoint, carrying the binding cookie.
func redeemBody(t *testing.T, c *httpsec.Chain, body, nonce string) served {
	t.Helper()

	req := postBody(t.Context(), httpsec.DefaultMagicLinkConsumePath, linkFormType, strings.NewReader(body))
	if nonce != "" {
		req.AddCookie(bindingCookie(nonce))
	}

	return serve(t, c, req)
}

// TestMagicLink_Params pins that the names the endpoints read are the
// consumer's to choose, and that a value sent under any other name is no value
// at all.
func TestMagicLink_Params(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.MagicLinkOption
		assert func(t *testing.T, h *magicLinkHarness, err error)
	}

	configError := func(t *testing.T, _ *magicLinkHarness, err error) {
		require.ErrorIs(t, err, httpsec.ErrConfig)
	}

	// request asserts how many links a request body caused to be sent.
	request := func(contentType, body string, sent int) func(*testing.T, *magicLinkHarness, error) {
		return func(t *testing.T, h *magicLinkHarness, err error) {
			require.NoError(t, err)

			out, _ := askLink(t, h.chain(t), contentType, body)

			assert.Equal(t, http.StatusAccepted, out.rec.Code, "the answer is uniform")
			assert.Empty(t, out.rec.Body.String())
			assert.Equal(t, sent, h.sender.count())
		}
	}

	known := url.Values{"email": {magicLinkKnown}}.Encode()
	login := url.Values{"login": {magicLinkKnown}}.Encode()
	renamed := httpsec.WithMagicLinkParams("login", "to", "code")

	cases := []testCase{
		{name: "the default form field", assert: request(linkFormType, known, 1)},
		{
			name:   "the default JSON member",
			assert: request("application/json", `{"email":"`+magicLinkKnown+`"}`, 1),
		},
		{
			name:   "a consumer's address field in a form",
			opts:   []httpsec.MagicLinkOption{renamed},
			assert: request(linkFormType, login, 1),
		},
		{
			name:   "a consumer's address member in JSON",
			opts:   []httpsec.MagicLinkOption{renamed},
			assert: request("application/json", `{"login":"`+magicLinkKnown+`"}`, 1),
		},
		{
			name:   "the old default name is no longer read",
			opts:   []httpsec.MagicLinkOption{renamed},
			assert: request(linkFormType, known, 0),
		},
		{
			name:   "the old default JSON member is no longer read",
			opts:   []httpsec.MagicLinkOption{renamed},
			assert: request("application/json", `{"email":"`+magicLinkKnown+`"}`, 0),
		},
		{
			name:   "a JSON address of the wrong type is no address",
			opts:   []httpsec.MagicLinkOption{renamed},
			assert: request("application/json", `{"login":5,"to":["x"]}`, 0),
		},
		{
			name:   "a wrong-typed redirect member does not void a valid address",
			assert: request("application/json", `{"email":"`+magicLinkKnown+`","next":5}`, 1),
		},
		{
			name:   "a wrong-typed address member is no address, whatever the redirect",
			assert: request("application/json", `{"email":5,"next":"/dash"}`, 0),
		},
		{
			name: "the request endpoint reads the destination from the default field",
			opts: []httpsec.MagicLinkOption{httpsec.WithMagicLinkAllowedRedirects("/dash")},
			assert: func(t *testing.T, h *magicLinkHarness, err error) {
				require.NoError(t, err)

				_, _ = askLink(t, h.chain(t), linkFormType,
					url.Values{"email": {magicLinkKnown}, "next": {"/dash"}}.Encode())

				require.Equal(t, 1, h.sender.count())
				assert.Equal(t, "/dash", h.sender.lastNext(t))
			},
		},
		{
			name: "the request endpoint ignores the default destination field under a consumer's name",
			opts: []httpsec.MagicLinkOption{renamed, httpsec.WithMagicLinkAllowedRedirects("/dash")},
			assert: func(t *testing.T, h *magicLinkHarness, err error) {
				require.NoError(t, err)

				_, _ = askLink(t, h.chain(t), linkFormType,
					url.Values{"login": {magicLinkKnown}, "next": {"/dash"}}.Encode())

				require.Equal(t, 1, h.sender.count())
				assert.Equal(t, "/", h.sender.lastNext(t))
			},
		},
		{
			name: "a duplicated token field reads its first value and spends nothing",
			assert: func(t *testing.T, h *magicLinkHarness, err error) {
				require.NoError(t, err)

				c := h.chain(t)
				_, nonce := askLink(t, c, linkFormType, known)
				good := h.sender.lastToken(t)

				out := redeemBody(t, c, "token=bad&token="+url.QueryEscape(good), nonce)
				require.ErrorIs(t, out.err, magiclink.ErrInvalidLink)
				assert.Zero(t, h.activeSessions(t))

				again := redeemBody(t, c, url.Values{"token": {good}}.Encode(), nonce)
				require.NoError(t, again.err, "the link was not spent")
				assert.Equal(t, 1, h.activeSessions(t))
			},
		},
		{
			name:   "a JSON array body is no address",
			opts:   []httpsec.MagicLinkOption{renamed},
			assert: request("application/json", `[1,2]`, 0),
		},
		{
			name:   "a malformed JSON body is no address",
			opts:   []httpsec.MagicLinkOption{renamed},
			assert: request("application/json", `{{{`, 0),
		},
		{
			name: "a consumer's token field redeems",
			opts: []httpsec.MagicLinkOption{renamed},
			assert: func(t *testing.T, h *magicLinkHarness, err error) {
				require.NoError(t, err)

				c := h.chain(t)
				_, nonce := askLink(t, c, linkFormType, login)

				out := redeemBody(t, c, url.Values{"code": {h.sender.lastToken(t)}}.Encode(), nonce)
				require.NoError(t, out.err)
				assert.Equal(t, 1, h.activeSessions(t))
			},
		},
		{
			name: "a token under the old default name is a failed redemption and spends nothing",
			opts: []httpsec.MagicLinkOption{renamed},
			assert: func(t *testing.T, h *magicLinkHarness, err error) {
				require.NoError(t, err)

				c := h.chain(t)
				_, nonce := askLink(t, c, linkFormType, login)
				token := h.sender.lastToken(t)

				out := redeemBody(t, c, url.Values{"token": {token}}.Encode(), nonce)
				require.ErrorIs(t, out.err, magiclink.ErrInvalidLink)
				assert.Zero(t, h.activeSessions(t))

				again := redeemBody(t, c, url.Values{"code": {token}}.Encode(), nonce)
				require.NoError(t, again.err, "the link was not spent")
				assert.Equal(t, 1, h.activeSessions(t))
			},
		},
		{
			name: "a consumer's redirect field is resolved against the allowlist",
			opts: []httpsec.MagicLinkOption{renamed, httpsec.WithMagicLinkAllowedRedirects("/dash")},
			assert: func(t *testing.T, h *magicLinkHarness, err error) {
				require.NoError(t, err)

				c := h.chain(t)
				_, nonce := askLink(t, c, linkFormType, login)

				out := redeemBody(t, c,
					url.Values{"code": {h.sender.lastToken(t)}, "to": {"/dash"}}.Encode(), nonce)
				require.NoError(t, out.err)
				assert.Contains(t, out.rec.Body.String(), `"next":"/dash"`)
			},
		},
		{
			name: "the default redirect field is not read under a consumer's name",
			opts: []httpsec.MagicLinkOption{renamed, httpsec.WithMagicLinkAllowedRedirects("/dash")},
			assert: func(t *testing.T, h *magicLinkHarness, err error) {
				require.NoError(t, err)

				c := h.chain(t)
				_, nonce := askLink(t, c, linkFormType, login)

				out := redeemBody(t, c,
					url.Values{"code": {h.sender.lastToken(t)}, "next": {"/dash"}}.Encode(), nonce)
				require.NoError(t, out.err)
				assert.Contains(t, out.rec.Body.String(), `"next":"/"`)
			},
		},
		{
			name:   "an empty address name",
			opts:   []httpsec.MagicLinkOption{httpsec.WithMagicLinkParams("", "next", "token")},
			assert: configError,
		},
		{
			name:   "an empty redirect name",
			opts:   []httpsec.MagicLinkOption{httpsec.WithMagicLinkParams("email", "", "token")},
			assert: configError,
		},
		{
			name:   "an empty token name",
			opts:   []httpsec.MagicLinkOption{httpsec.WithMagicLinkParams("email", "next", "")},
			assert: configError,
		},
		{
			name:   "address and token with one name",
			opts:   []httpsec.MagicLinkOption{httpsec.WithMagicLinkParams("value", "next", "value")},
			assert: configError,
		},
		{
			name:   "address and redirect with one name",
			opts:   []httpsec.MagicLinkOption{httpsec.WithMagicLinkParams("value", "value", "token")},
			assert: configError,
		},
		{
			name:   "redirect and token with one name",
			opts:   []httpsec.MagicLinkOption{httpsec.WithMagicLinkParams("email", "value", "value")},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMagicLinkHarness(t)
			h.linkOpts = tc.opts

			_, err := h.build()
			tc.assert(t, h, err)
		})
	}
}

// TestMagicLink_BodyLimit pins that the bound on a body is the consumer's to
// set, and that a body over it is read as carrying nothing, which neither
// reveals whether an address exists nor spends a link.
func TestMagicLink_BodyLimit(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.MagicLinkOption
		assert func(t *testing.T, h *magicLinkHarness, err error)
	}

	configError := func(t *testing.T, _ *magicLinkHarness, err error) {
		require.ErrorIs(t, err, httpsec.ErrConfig)
	}

	pad := func(n int) string { return "&pad=" + strings.Repeat("a", n) }

	// oversizedRequest shows an over-bound request is answered as a normal
	// one is, and sends nothing.
	oversizedRequest := func(size int) func(*testing.T, *magicLinkHarness, error) {
		return func(t *testing.T, h *magicLinkHarness, err error) {
			require.NoError(t, err)

			c := h.chain(t)
			address := url.Values{"email": {magicLinkKnown}}.Encode()

			normal, _ := askLink(t, c, linkFormType, address)
			require.Equal(t, 1, h.sender.count())

			big, _ := askLink(t, c, linkFormType, address+pad(size))

			assert.Equal(t, normal.rec.Code, big.rec.Code)
			assert.Equal(t, normal.rec.Body.String(), big.rec.Body.String())
			assert.Equal(t, 1, h.sender.count(), "no link was issued for the oversized body")
		}
	}

	// oversizedRedemption shows an over-bound redemption fails and leaves the
	// link redeemable.
	oversizedRedemption := func(size int) func(*testing.T, *magicLinkHarness, error) {
		return func(t *testing.T, h *magicLinkHarness, err error) {
			require.NoError(t, err)

			c := h.chain(t)
			token, nonce := h.link(t, c)

			out := redeemBody(t, c, url.Values{"token": {token}}.Encode()+pad(size), nonce)
			require.ErrorIs(t, out.err, magiclink.ErrInvalidLink)
			assert.Zero(t, h.activeSessions(t))

			again := h.redeem(t, c, token, nonce)
			require.NoError(t, again.err, "the link was not spent")
			assert.Equal(t, 1, h.activeSessions(t))
		}
	}

	cases := []testCase{
		{name: "a 65 KiB request under the default", assert: oversizedRequest(65 << 10)},
		{name: "a 65 KiB redemption under the default", assert: oversizedRedemption(65 << 10)},
		{
			name:   "a 5 KiB redemption under a 4 KiB limit",
			opts:   []httpsec.MagicLinkOption{httpsec.WithMagicLinkBodyLimit(4 << 10)},
			assert: oversizedRedemption(5 << 10),
		},
		{
			name:   "a 5 KiB request under a 4 KiB limit",
			opts:   []httpsec.MagicLinkOption{httpsec.WithMagicLinkBodyLimit(4 << 10)},
			assert: oversizedRequest(5 << 10),
		},
		{
			name: "a body inside a raised limit is read",
			opts: []httpsec.MagicLinkOption{httpsec.WithMagicLinkBodyLimit(128 << 10)},
			assert: func(t *testing.T, h *magicLinkHarness, err error) {
				require.NoError(t, err)

				_, _ = askLink(t, h.chain(t), linkFormType,
					url.Values{"email": {magicLinkKnown}}.Encode()+pad(65<<10))

				assert.Equal(t, 1, h.sender.count())
			},
		},
		{
			name:   "a limit of zero",
			opts:   []httpsec.MagicLinkOption{httpsec.WithMagicLinkBodyLimit(0)},
			assert: configError,
		},
		{
			name:   "a negative limit",
			opts:   []httpsec.MagicLinkOption{httpsec.WithMagicLinkBodyLimit(-1)},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMagicLinkHarness(t)
			h.linkOpts = tc.opts

			_, err := h.build()
			tc.assert(t, h, err)
		})
	}
}
