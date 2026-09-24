package magiclink_test

import (
	"net/url"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/notify"
)

var linkPattern = regexp.MustCompile(`https?://\S+`)

func extractLink(t *testing.T, body string) string {
	t.Helper()

	link := linkPattern.FindString(body)
	require.NotEmpty(t, link, "the message carries no link")

	return link
}

func TestRequestBuildsLink(t *testing.T) {
	t.Parallel()

	t.Run("the link joins the base, the confirm path, the token and the target", func(t *testing.T) {
		t.Parallel()

		sender := &recordingSender{}

		m, err := magiclink.NewManager(testTokens(t), activeLoader(), sender, "https://app.example.com")
		require.NoError(t, err)

		m.Request(t.Context(), "ada@example.com", "/dashboard?tab=a&b=c")

		require.Equal(t, 1, sender.Count())
		link := extractLink(t, sender.Last().TextBody)

		u, err := url.Parse(link)
		require.NoError(t, err)

		assert.Equal(t, "https", u.Scheme)
		assert.Equal(t, "app.example.com", u.Host)
		assert.Equal(t, "/login/magic/confirm", u.Path)
		assert.NotEmpty(t, u.Query().Get("token"))
		assert.Equal(t, "/dashboard?tab=a&b=c", u.Query().Get("next"),
			"the target is query-escaped, so its own separators survive")
	})

	t.Run("a consumer confirm path is used", func(t *testing.T) {
		t.Parallel()

		sender := &recordingSender{}

		m, err := magiclink.NewManager(testTokens(t), activeLoader(), sender, "https://app.example.com:8443",
			magiclink.WithConfirmPath("/auth/link"))
		require.NoError(t, err)

		m.Request(t.Context(), "ada@example.com", "/")

		require.Equal(t, 1, sender.Count())

		u, err := url.Parse(extractLink(t, sender.Last().TextBody))
		require.NoError(t, err)

		assert.Equal(t, "app.example.com:8443", u.Host)
		assert.Equal(t, "/auth/link", u.Path)
	})

	t.Run("a consumer renderer chooses the subject but not the recipient", func(t *testing.T) {
		t.Parallel()

		sender := &recordingSender{}

		renderer := func(link, _ string) notify.Message {
			return notify.Message{
				To:       "other@example.com", // must be overridden
				Subject:  "Sign in to Payroll",
				TextBody: "Go to " + link,
			}
		}

		m, err := magiclink.NewManager(testTokens(t), activeLoader(), sender, "https://app.example.com",
			magiclink.WithRenderer(renderer))
		require.NoError(t, err)

		m.Request(t.Context(), "ada@example.com", "/")

		require.Equal(t, 1, sender.Count())
		assert.Equal(t, "Sign in to Payroll", sender.Last().Subject)
		assert.Equal(t, "ada@example.com", sender.Last().To,
			"the recipient is the submitted address, whatever the renderer returns")
	})

	t.Run("the renderer receives the redirect target", func(t *testing.T) {
		t.Parallel()

		sender := &recordingSender{}

		var seen string
		renderer := func(link, next string) notify.Message {
			seen = next

			return notify.Message{Subject: "s", TextBody: link}
		}

		m, err := magiclink.NewManager(testTokens(t), activeLoader(), sender, "https://app.example.com",
			magiclink.WithRenderer(renderer))
		require.NoError(t, err)

		m.Request(t.Context(), "ada@example.com", "/dashboard")

		require.Equal(t, 1, sender.Count())
		assert.Equal(t, "/dashboard", seen)
	})
}
