package magiclink_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/magiclink"
)

func TestDefaultRenderer(t *testing.T) {
	t.Parallel()

	sender := &recordingSender{}

	m, err := magiclink.NewManager(testTokens(t), activeLoader(), sender, "https://app.example.com")
	require.NoError(t, err)

	m.Request(t.Context(), "ada@example.com", "/")

	require.Equal(t, 1, sender.Count())
	msg := sender.Last()

	assert.Contains(t, msg.TextBody, "https://app.example.com/login/magic/confirm?")
	assert.Regexp(t, `(?i)expires`, msg.TextBody)
	assert.Regexp(t, `(?i)once`, msg.TextBody)
	assert.Empty(t, msg.From, "the sender's own configured address is used")

	for _, brand := range []string{"scrty", "kartala", "Payroll", "Acme"} {
		assert.NotContains(t, strings.ToLower(msg.Subject), strings.ToLower(brand))
		assert.NotContains(t, strings.ToLower(msg.TextBody), strings.ToLower(brand))
	}
}
