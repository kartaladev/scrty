package magiclink_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/notify"
)

func TestNewMagicLinkManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		baseURL string
		assert  func(t *testing.T, m *magiclink.Manager, err error)
	}

	configError := func(t *testing.T, m *magiclink.Manager, err error) {
		require.Error(t, err)
		assert.ErrorIs(t, err, magiclink.ErrConfig)
		assert.Nil(t, m)
	}

	ok := func(t *testing.T, m *magiclink.Manager, err error) {
		require.NoError(t, err)
		assert.NotNil(t, m)
	}

	cases := []testCase{
		{name: "missing", baseURL: "", assert: configError},
		{name: "host-relative", baseURL: "/login", assert: configError},
		{name: "cleartext on a public host", baseURL: "http://app.example.com", assert: configError},
		{name: "scheme only", baseURL: "https://", assert: configError},
		{name: "not a URL", baseURL: "://nonsense", assert: configError},
		{name: "carries a path", baseURL: "https://app.example.com/app", assert: configError},
		{name: "https", baseURL: "https://app.example.com", assert: ok},
		{name: "https with a port", baseURL: "https://app.example.com:8443", assert: ok},
		{name: "loopback over http", baseURL: "http://localhost:3000", assert: ok},
		{name: "loopback by address", baseURL: "http://127.0.0.1:3000", assert: ok},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := newManager(t, tc.baseURL)
			tc.assert(t, m, err)
		})
	}
}

func TestManagerRefusesSynchronousSender(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		sender func(t *testing.T) notify.Sender
		opts   []magiclink.Option
		assert func(t *testing.T, m *magiclink.Manager, err error)
	}

	smtp := func(t *testing.T) notify.Sender {
		t.Helper()

		s, err := notify.NewSMTPSender("smtp.example.com")
		require.NoError(t, err)

		return s
	}

	cases := []testCase{
		{
			name:   "the SMTP sender is refused",
			sender: smtp,
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, magiclink.ErrConfig)
				assert.Nil(t, m)
				assert.Contains(t, strings.ToLower(err.Error()), "synchronous")
			},
		},
		{
			name:   "a sender reporting NonBlocking false is refused",
			sender: func(_ *testing.T) notify.Sender { return liarSender{nonBlocking: false} },
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, magiclink.ErrConfig)
				assert.Nil(t, m)
			},
		},
		{
			name: "the queued sender is accepted",
			sender: func(t *testing.T) notify.Sender {
				t.Helper()

				q, err := notify.NewQueuedSender(smtp(t))
				require.NoError(t, err)
				t.Cleanup(func() { _ = q.Close(context.WithoutCancel(t.Context())) })

				return q
			},
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name:   "the consumer may accept synchronous delivery explicitly",
			sender: smtp,
			opts:   []magiclink.Option{magiclink.WithSynchronousDelivery()},
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name:   "a nil sender is refused",
			sender: func(_ *testing.T) notify.Sender { return nil },
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, magiclink.ErrConfig)
				assert.Nil(t, m)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := magiclink.NewManager(
				testTokens(t), stubLoader{}, tc.sender(t), "https://app.example.com", tc.opts...)

			tc.assert(t, m, err)
		})
	}
}

func TestMagicLinkOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []magiclink.Option
		assert func(t *testing.T, m *magiclink.Manager, err error)
	}

	configError := func(t *testing.T, m *magiclink.Manager, err error) {
		require.Error(t, err)
		assert.ErrorIs(t, err, magiclink.ErrConfig)
		assert.Nil(t, m)
	}

	cases := []testCase{
		{
			name: "defaults",
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
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
			name: "a consumer confirm path is accepted",
			opts: []magiclink.Option{magiclink.WithConfirmPath("/auth/link")},
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name: "binding disabled",
			opts: []magiclink.Option{magiclink.WithSameDeviceBinding(false)},
			assert: func(t *testing.T, m *magiclink.Manager, err error) {
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

func TestMagicLinkManagerRequiresItsPorts(t *testing.T) {
	t.Parallel()

	t.Run("no token manager", func(t *testing.T) {
		t.Parallel()

		m, err := magiclink.NewManager(nil, stubLoader{}, &recordingSender{}, "https://app.example.com")
		require.ErrorIs(t, err, magiclink.ErrConfig)
		assert.Nil(t, m)
	})

	t.Run("no user loader", func(t *testing.T) {
		t.Parallel()

		m, err := magiclink.NewManager(testTokens(t), nil, &recordingSender{}, "https://app.example.com")
		require.ErrorIs(t, err, magiclink.ErrConfig)
		assert.Nil(t, m)
	})
}
