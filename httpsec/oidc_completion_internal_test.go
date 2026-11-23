package httpsec

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// TestParkedHandle pins the recognition of a parked request's destination: the login
// URL by exact scheme, host, port and raw path, with one non-empty req as its whole
// query. Every look-alike is not one, so it keeps the ordinary conveyance (F27).
func TestParkedHandle(t *testing.T) {
	t.Parallel()

	loginURL, err := url.Parse("https://id.example/login")
	require.NoError(t, err)

	type testCase struct {
		name string
		// login is the login URL the row compares against; empty is the default.
		login  string
		next   string
		assert func(t *testing.T, handle string, ok bool)
	}

	recognised := func(want string) func(t *testing.T, handle string, ok bool) {
		return func(t *testing.T, handle string, ok bool) {
			t.Helper()

			assert.True(t, ok)
			assert.Equal(t, want, handle)
		}
	}

	notOne := func(t *testing.T, handle string, ok bool) {
		t.Helper()

		assert.False(t, ok)
		assert.Empty(t, handle)
	}

	cases := []testCase{
		{name: "the login URL carrying the handle", next: "https://id.example/login?req=h1", assert: recognised("h1")},
		{name: "scheme case is not significant", next: "HTTPS://id.example/login?req=h1", assert: recognised("h1")},
		{name: "the scheme's default port written out", next: "https://id.example:443/login?req=h1", assert: notOne},
		{name: "another port", next: "https://id.example:8443/login?req=h1", assert: notOne},
		{name: "another host", next: "https://evil.example/login?req=h1", assert: notOne},
		{name: "a host that only ends like it", next: "https://id.example.evil.example/login?req=h1", assert: notOne},
		{name: "userinfo", next: "https://id.example@evil.example/login?req=h1", assert: notOne},
		{name: "userinfo on the login host", next: "https://user@id.example/login?req=h1", assert: notOne},
		{name: "empty userinfo", next: "https://@id.example/login?req=h1", assert: notOne},
		{name: "plain http", next: "http://id.example/login?req=h1", assert: notOne},
		{name: "a trailing slash", next: "https://id.example/login/?req=h1", assert: notOne},
		{name: "path case", next: "https://id.example/LOGIN?req=h1", assert: notOne},
		{name: "a percent-encoded path", next: "https://id.example/%6Cogin?req=h1", assert: notOne},
		{name: "a dot segment", next: "https://id.example/x/../login?req=h1", assert: notOne},
		{name: "an extra parameter", next: "https://id.example/login?req=h1&x=1", assert: notOne},
		{name: "an extra parameter first", next: "https://id.example/login?x=1&req=h1", assert: notOne},
		{name: "a repeated req", next: "https://id.example/login?req=h1&req=h2", assert: notOne},
		{name: "an empty req", next: "https://id.example/login?req=", assert: notOne},
		{name: "req with no value", next: "https://id.example/login?req", assert: notOne},
		{name: "a percent-encoded parameter name", next: "https://id.example/login?%72eq=h1", assert: notOne},
		{name: "a semicolon separator", next: "https://id.example/login?req=h1;x=1", assert: notOne},
		{name: "a fragment", next: "https://id.example/login?req=h1#x", assert: notOne},
		{name: "no query", next: "https://id.example/login", assert: notOne},
		{name: "a relative URL", next: "/login?req=h1", assert: notOne},
		{name: "a scheme-relative URL", next: "//id.example/login?req=h1", assert: notOne},
		{name: "empty", next: "", assert: notOne},
		{name: "an empty login path is the root path", login: "https://id.example", next: "https://id.example/?req=h1", assert: recognised("h1")},
		{name: "an empty login path, and a deeper path", login: "https://id.example", next: "https://id.example/x?req=h1", assert: notOne},
		{name: "an empty login path, and an empty path written", login: "https://id.example", next: "https://id.example?req=h1", assert: recognised("h1")},
		{name: "unparseable", next: "https://id.example/login?req=h1%zz", assert: notOne},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			login := loginURL
			if tc.login != "" {
				var err error

				login, err = url.Parse(tc.login)
				require.NoError(t, err)
			}

			handle, ok := parkedHandle(tc.next, login)
			tc.assert(t, handle, ok)
		})
	}
}

// CancelHeldAtLoginForTest hands cancel to every first factor registered before it,
// as EnableAccountRecovery does when its recovery may hold one, so a test can count
// the cancellations a login asks for without wiring a recovery core.
func CancelHeldAtLoginForTest(cancel func(ctx context.Context, user identity.UserID) error) Option {
	return func(c *config) error {
		c.cancelHeldAtLogin(cancel)

		return nil
	}
}

// ErrProviderSignInUnfinishedForTest is what completion answers once the policy owes
// nothing, until the session, resume and answer steps exist.
var ErrProviderSignInUnfinishedForTest = errProviderSignInUnfinished
