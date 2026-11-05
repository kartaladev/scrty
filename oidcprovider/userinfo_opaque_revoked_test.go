package oidcprovider_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// An opaque access token has its grant revoked: UserInfo refuses it at once, though it is unexpired.
func TestProvider_UserInfo_OpaqueTokenOfARevokedGrantIsRefused(t *testing.T) {
	t.Parallel()

	f := newRefreshFixture(t)
	s := startOpaque(t, f)
	at := verified(t, f, s.first.AccessToken)
	require.True(t, at.Opaque)

	answer, err := f.p.UserInfo(t.Context(), at)
	require.NoError(t, err, "live before the revocation")
	assert.Equal(t, "u-1", answer["sub"])

	revokeWhole(t, f, s)

	answer, err = f.p.UserInfo(t.Context(), at)
	assertRefused(t, err, oidcprovider.CodeInvalidToken)
	assert.Nil(t, answer)
}
