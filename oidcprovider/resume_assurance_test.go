package oidcprovider_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// acr_values is shown to the consumer's pages and acted on by no one else: a sign-in that does not
// reach the requested assurance still gets its code, and the code names the assurance that was reached.
func TestProvider_Resume_RequestedAssuranceNotMetStillSucceeds(t *testing.T) {
	t.Parallel()

	x := newExchangeFixture(t)
	r := park(t, x.parkFixture, func(v url.Values) { v.Set("acr_values", "urn:example:high") })

	view, err := x.p.PendingRequest(t.Context(), r.handle, r.flow)
	require.NoError(t, err)
	assert.Equal(t, []string{"urn:example:high"}, view.ACRValues, "the page may ask for more")

	signIn := testSignIn(x.parkFixture, "u-1")
	require.NotEqual(t, "urn:example:high", signIn.ACR, "the sign-in does not meet the request")
	require.NoError(t, x.consents.Give(t.Context(), signIn.User, "billing-web", []string{"openid", "profile"}, true, x.clk.Now()))

	res, err := x.p.Resume(t.Context(), r.input(&signIn))
	require.NoError(t, err)
	answer := queryOf(t, res.RedirectTo)
	assert.NotEmpty(t, answer.Get("code"), res.RedirectTo)
	assert.Empty(t, answer.Get("error"), res.RedirectTo)
}
