package httpsec_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
)

// errMagicLinkResponder is what a consumer's responder refuses with, so a test
// can assert the chain returned that error and not one of its own.
var errMagicLinkResponder = errors.New("magiclinkresponder_test: the client cannot be answered")

// TestMagicLinkResponder pins what writes the response to a successful
// redemption, and what happens when it will not.
func TestMagicLinkResponder(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.MagicLinkOption
		assert func(t *testing.T, out served, buildErr error)
	}

	cases := []testCase{
		{
			// A regression pin on what already shipped, not a new claim: this
			// document is a documented contract and the responder must not
			// have moved it.
			name: "the default document is unchanged",
			assert: func(t *testing.T, out served, buildErr error) {
				require.NoError(t, buildErr)
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)

				var got map[string]any
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &got))
				assert.NotEmpty(t, got["access_token"])
				assert.Equal(t, "", got["refresh_token"], "present and empty, never absent")
				assert.NotEmpty(t, got["valid_until"])
				assert.Equal(t, "/", got["next"])
			},
		},
		{
			name: "a responder error refuses the request",
			opts: []httpsec.MagicLinkOption{httpsec.WithMagicLinkResponder(
				func(*httpsec.Exchange, httpsec.MagicLinkResult) error {
					return errMagicLinkResponder
				},
			)},
			assert: func(t *testing.T, out served, buildErr error) {
				require.NoError(t, buildErr)
				require.ErrorIs(t, out.err, errMagicLinkResponder,
					"the consumer's error is the refusal, unchanged")
			},
		},
		{
			name: "a nil responder is a configuration error",
			opts: []httpsec.MagicLinkOption{httpsec.WithMagicLinkResponder(nil)},
			assert: func(t *testing.T, _ served, buildErr error) {
				require.ErrorIs(t, buildErr, httpsec.ErrConfig,
					"a responder that is not there would leave the caller with no credential")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMagicLinkHarness(t)
			h.linkOpts = tc.opts

			c, buildErr := h.build()
			if buildErr != nil {
				tc.assert(t, served{}, buildErr)

				return
			}

			token, nonce := h.link(t, c)

			tc.assert(t, h.redeem(t, c, token, nonce), nil)
		})
	}
}

// TestMagicLinkConsumerResponder pins that a consumer's responder replaces the
// default entirely and is handed the session the redemption opened.
func TestMagicLinkConsumerResponder(t *testing.T) {
	t.Parallel()

	var seen httpsec.MagicLinkResult

	h := newMagicLinkHarness(t)
	h.linkOpts = []httpsec.MagicLinkOption{httpsec.WithMagicLinkResponder(
		func(ex *httpsec.Exchange, r httpsec.MagicLinkResult) error {
			seen = r
			ex.Writer.SetCookie(&http.Cookie{
				Name:     "session",
				Value:    r.Token,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})

			return nil
		})}

	c := h.chain(t)
	token, nonce := h.link(t, c)

	out := h.redeem(t, c, token, nonce)
	require.NoError(t, out.err)

	assert.Empty(t, out.rec.Body.String(),
		"the consumer's responder replaces the default entirely")
	assert.Equal(t, "no-referrer", out.rec.Header().Get("Referrer-Policy"),
		"and cannot forget the header that keeps the token out of the referrer")

	require.NotNil(t, seen.Session)
	assert.Equal(t, factor.MagicLink, seen.Session.FirstFactor)
	assert.Equal(t, magicLinkUserID, seen.Session.UserID)
	assert.Equal(t, "issued-token", seen.Token)

	cookie := cookieNamed(out.rec, "session")
	require.NotNil(t, cookie, "and its own response reached the client")
	assert.Equal(t, seen.Token, cookie.Value)
}

// TestMagicLinkResponderSeesResolvedTarget pins the constraint that is not
// cosmetic: a responder receives the target the allowlist resolved, never the
// one the caller submitted. Handing over the submitted value would let the
// obvious redirect in a consumer's responder reopen exactly what the allowlist
// refused.
func TestMagicLinkResponderSeesResolvedTarget(t *testing.T) {
	t.Parallel()

	var seen httpsec.MagicLinkResult

	// No WithAllowedRedirects, so every submitted target resolves to "/".
	h := newMagicLinkHarness(t)
	h.linkOpts = []httpsec.MagicLinkOption{httpsec.WithMagicLinkResponder(
		func(_ *httpsec.Exchange, r httpsec.MagicLinkResult) error {
			seen = r

			return nil
		})}

	c := h.chain(t)

	out := serve(t, c, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath,
		magicLinkSource, urlValues("email", magicLinkKnown, "next", "/dashboard")))
	require.NoError(t, out.err)

	nonce := cookieNamed(out.rec, httpsec.DefaultBindingCookieName).Value

	redeemed := serve(t, c, consumeWithNext(t, h.sender.lastToken(t), nonce, "/dashboard"))
	require.NoError(t, redeemed.err)

	assert.Equal(t, "/", seen.Next,
		"a responder receives the resolved target; handing it the submitted one would "+
			"reopen the redirect the allowlist refused")
}
