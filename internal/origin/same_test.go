package origin_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/origin"
)

func TestOriginSame(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		a, b   string
		assert func(t *testing.T, same bool)
	}

	// The table is as much about what must not match as what must: every
	// normalisation step makes more strings equal, which weakens a redirect
	// allowlist.
	sameOrigin := func(t *testing.T, same bool) {
		t.Helper()
		assert.True(t, same, "the two values must have the same origin")
	}
	differentOrigin := func(t *testing.T, same bool) {
		t.Helper()
		assert.False(t, same, "the two values must have different origins")
	}

	cases := []testCase{
		{
			name:   "identical",
			a:      "https://idp.example.com/a",
			b:      "https://idp.example.com/b",
			assert: sameOrigin,
		},
		{
			name:   "ASCII case folding of scheme and host",
			a:      "HTTPS://IdP.Example.com/a",
			b:      "https://idp.example.com/b",
			assert: sameOrigin,
		},
		{
			name:   "a default port is removed",
			a:      "https://idp.example.com:443/a",
			b:      "https://idp.example.com/b",
			assert: sameOrigin,
		},
		{
			name:   "http's default port is removed too",
			a:      "http://idp.example.com:80/a",
			b:      "http://idp.example.com/b",
			assert: sameOrigin,
		},
		{ //nolint:gosec // G101: a fixture proving userinfo is dropped, not a credential
			name:   "userinfo is ignored",
			a:      "https://user:pw@idp.example.com/a",
			b:      "https://idp.example.com/b",
			assert: sameOrigin,
		},

		{
			name:   "different hosts",
			a:      "https://idp.example.com",
			b:      "https://cdn.example.net",
			assert: differentOrigin,
		},
		{
			name:   "a scheme downgrade",
			a:      "https://idp.example.com",
			b:      "http://idp.example.com",
			assert: differentOrigin,
		},
		{
			name:   "a non-default port",
			a:      "https://idp.example.com:8443",
			b:      "https://idp.example.com",
			assert: differentOrigin,
		},
		{
			name:   "ports are compared as written, not numerically",
			a:      "https://idp.example.com:0443",
			b:      "https://idp.example.com:443",
			assert: differentOrigin,
		},
		{
			name:   "a trailing root label is significant",
			a:      "https://idp.example.com./a",
			b:      "https://idp.example.com/a",
			assert: differentOrigin,
		},

		// The look-alikes. Unicode case mapping folds U+0130 to "i" and U+212A
		// to "k"; applying it here would make an attacker's host equal to the
		// one an allowlist declared.
		{
			name:   "U+0130 is not ASCII i",
			a:      "https://İdp.example.com", // LATIN CAPITAL LETTER I WITH DOT ABOVE
			b:      "https://idp.example.com",
			assert: differentOrigin,
		},
		{
			name:   "U+212A is not ASCII k",
			a:      "https://Keys.example.com", // KELVIN SIGN
			b:      "https://keys.example.com",
			assert: differentOrigin,
		},
		{
			name:   "IDNA is not applied",
			a:      "https://xn--idp-9na.example.com",
			b:      "https://ïdp.example.com", // LATIN SMALL LETTER I WITH DIAERESIS
			assert: differentOrigin,
		},

		{
			name:   "another scheme matches nothing",
			a:      "mailto:a@b",
			b:      "mailto:a@b",
			assert: differentOrigin,
		},
		{
			name:   "two unparsable values match nothing",
			a:      "mailto:a@b",
			b:      "mailto:c@d",
			assert: differentOrigin,
		},
		{
			name:   "no host matches nothing",
			a:      "https:///path",
			b:      "https:///path",
			assert: differentOrigin,
		},
		{
			name:   "a value that cannot be parsed at all matches nothing",
			a:      "https://idp.example.com/%zz",
			b:      "https://idp.example.com/%zz",
			assert: differentOrigin,
		},
		{
			name:   "empty matches nothing",
			a:      "",
			b:      "",
			assert: differentOrigin,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			forward := origin.Same(tc.a, tc.b)
			reverse := origin.Same(tc.b, tc.a)
			require.Equal(t, forward, reverse,
				"the comparison must be symmetric: Same(%q, %q) = %v but Same(%q, %q) = %v",
				tc.a, tc.b, forward, tc.b, tc.a, reverse)

			tc.assert(t, forward)
		})
	}
}
