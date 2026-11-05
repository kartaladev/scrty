package oidcprovider_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A confidential client relying on the nonce in place of a challenge gets an ID token carrying it.
func TestProvider_Token_NonceClientIDTokenCarriesTheNonce(t *testing.T) {
	t.Parallel()

	x := newExchangeFixture(t)
	c := x.issueNonceOnly(t)

	res, err := x.p.Token(t.Context(), confidentialExchange("nonce-web", nonceRedirect, c, func(v url.Values) { v.Del("code_verifier") }))
	require.NoError(t, err)

	_, claims := decodeJWT(t, res.IDToken)
	assert.Equal(t, "n-1", claims["nonce"])
	assert.Equal(t, "nonce-web", claims["azp"])
}
