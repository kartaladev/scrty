package magiclink_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/magiclink"
)

// requestReturnsNoError pins the one thing about Request's signature the whole
// capability rests on: there is no error beside the result, so a caller has
// nothing to branch on and cannot leak which addresses have accounts.
var requestReturnsNoError func(*magiclink.Manager, context.Context, string, string) magiclink.RequestResult = (*magiclink.Manager).Request

func TestMagicLinkSurface(t *testing.T) {
	t.Parallel()

	require.NotNil(t, requestReturnsNoError)

	sender := &recordingSender{}

	m, err := magiclink.NewManager(testTokens(t), activeByID(), sender, "https://app.example.com")
	require.NoError(t, err)

	got := m.Request(t.Context(), "ada@example.com", "/")

	assert.Len(t, got.BindingNonce, magiclink.BindingNonceLength,
		"BindingNonceLength is the length a caller builds a decoy to match")
	assert.Equal(t, 1, sender.Count())
}
