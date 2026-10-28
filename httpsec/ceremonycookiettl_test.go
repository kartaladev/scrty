package httpsec_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/onetime"
)

// TestCeremonyCookieTTL_RefusesSubSecond pins that the cookies binding a
// magic link, or a passkey ceremony, to the browser that began it carry the
// lifetime of what they bind, in whole seconds: a fractional lifetime would be
// truncated, and the cookie would expire before the credential does or, for
// less than a second, never be set to live at all.
func TestCeremonyCookieTTL_RefusesSubSecond(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) error
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Contains(t, err.Error(), "whole number of seconds")
	}
	accepted := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}

	magicLink := func(ttl time.Duration) func(t *testing.T) error {
		return func(t *testing.T) error {
			t.Helper()

			h := newMagicLinkHarness(t)

			onetimes, err := onetime.NewManager("magic-link", onetime.WithTTL(ttl))
			require.NoError(t, err)

			h.manager, err = magiclink.NewManager(onetimes, h.users, h.sender, "https://app.example.com")
			require.NoError(t, err)

			_, err = h.build()

			return err
		}
	}

	passwordless := func(ttl time.Duration) func(t *testing.T) error {
		return func(t *testing.T) error {
			t.Helper()

			d := newPwlDeployment(t)
			d.pkOpts = append(d.pkOpts, passkey.WithChallengeTTL(ttl))

			_, err := httpsec.New(d.options(t)...)

			return err
		}
	}

	cases := []testCase{
		{name: "magic link, whole seconds", build: magicLink(90 * time.Second), assert: accepted},
		{name: "magic link, fractional seconds", build: magicLink(1500 * time.Millisecond), assert: refused},
		{name: "magic link, under a second", build: magicLink(500 * time.Millisecond), assert: refused},
		{name: "passkey ceremony, whole seconds", build: passwordless(90 * time.Second), assert: accepted},
		{name: "passkey ceremony, fractional seconds", build: passwordless(1500 * time.Millisecond), assert: refused},
		{name: "passkey ceremony, under a second", build: passwordless(500 * time.Millisecond), assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.build(t))
		})
	}
}
