package magiclink_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/magiclink"
)

func TestMagicLinkOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []magiclink.Option
		assert func(t *testing.T, m *magiclink.Links, err error)
	}

	configError := func(t *testing.T, m *magiclink.Links, err error) {
		require.Error(t, err)
		assert.ErrorIs(t, err, magiclink.ErrConfig)
		assert.Nil(t, m)
	}

	cases := []testCase{
		{
			name: "defaults",
			assert: func(t *testing.T, m *magiclink.Links, err error) {
				require.NoError(t, err)
				assert.True(t, m.BindingEnabled(), "same-device binding is on by default")
				assert.Equal(t, 15*time.Minute, m.TTL(), "the link's lifetime is the token manager's")
			},
		},
		{name: "issuance limit of zero", opts: []magiclink.Option{magiclink.WithIssuanceLimit(0)}, assert: configError},
		{name: "negative issuance limit", opts: []magiclink.Option{magiclink.WithIssuanceLimit(-1)}, assert: configError},
		{name: "absolute confirm path", opts: []magiclink.Option{magiclink.WithConfirmPath("https://evil.example/confirm")}, assert: configError},
		{name: "empty confirm path", opts: []magiclink.Option{magiclink.WithConfirmPath("")}, assert: configError},
		{name: "protocol-relative confirm path", opts: []magiclink.Option{magiclink.WithConfirmPath("//evil.example/confirm")}, assert: configError},
		{name: "backslash confirm path", opts: []magiclink.Option{magiclink.WithConfirmPath("/\\evil.example/confirm")}, assert: configError},
		{name: "nil renderer", opts: []magiclink.Option{magiclink.WithRenderer(nil)}, assert: configError},
		{name: "nil random source", opts: []magiclink.Option{magiclink.WithRandom(nil)}, assert: configError},
		{
			// (*bytes.Buffer)(nil) implements io.Reader through a pointer
			// receiver, so the interface WithRandom stores is non-nil even
			// though the pointer is: a plain `== nil` check would accept it
			// and only panic once a request tries to read from it.
			name:   "typed nil random source is refused the same as no random source",
			opts:   []magiclink.Option{magiclink.WithRandom((*bytes.Buffer)(nil))},
			assert: configError,
		},
		{
			name: "a consumer confirm path is accepted",
			opts: []magiclink.Option{magiclink.WithConfirmPath("/auth/link")},
			assert: func(t *testing.T, m *magiclink.Links, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name: "binding disabled",
			opts: []magiclink.Option{magiclink.WithSameDeviceBinding(false)},
			assert: func(t *testing.T, m *magiclink.Links, err error) {
				require.NoError(t, err)
				assert.False(t, m.BindingEnabled())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := newManager(t, "https://app.example.com", tc.opts...)
			tc.assert(t, m, err)
		})
	}
}
