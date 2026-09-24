package notify_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/notify"
)

// newTestSMTPSenderRaw points a sender at srv with the real encryption
// default — required STARTTLS — so these cases exercise it rather than the
// opportunistic setting the other tasks' helper turns on. It trusts the
// certificate srv's script serves, as a consumer with a private authority
// would.
func newTestSMTPSenderRaw(t *testing.T, srv *scriptedServer, opts ...notify.SMTPOption) *notify.SMTPSender {
	t.Helper()

	base := []notify.SMTPOption{
		notify.WithSMTPPort(srv.Port()),
		notify.WithSMTPFrom("no-reply@example.com"),
		notify.WithSMTPDialer(srv.Dial),
		notify.WithSMTPTLSConfig(trustFor(t, srv.scr)),
	}

	s, err := notify.NewSMTPSender(srv.Host(), append(base, opts...)...)
	require.NoError(t, err)

	return s
}

func TestSMTPSenderRequiresSTARTTLS(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		script script
		opts   []notify.SMTPOption
		assert func(t *testing.T, srv *scriptedServer, err error)
	}

	refusedBeforeData := func(t *testing.T, srv *scriptedServer, err error) {
		require.Error(t, err)
		assert.NotContains(t, srv.Lines(), "DATA", "no message data may be sent")
		assert.Empty(t, srv.Data())
	}

	cases := []testCase{
		{
			name:   "a server without STARTTLS is refused",
			script: scriptNoSTARTTLS(),
			assert: refusedBeforeData,
		},
		{
			name:   "a server that offers STARTTLS but cannot speak it is refused",
			script: scriptBrokenTLS(),
			assert: refusedBeforeData,
		},
		{
			name:   "a server that offers STARTTLS is upgraded and delivers",
			script: scriptSTARTTLS(t),
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.NoError(t, err)
				assert.Contains(t, srv.Lines(), "STARTTLS")
				assert.Contains(t, srv.Data(), "here is your link")
			},
		},
		{
			name:   "opportunistic delivers to a local relay without STARTTLS",
			script: scriptNoSTARTTLS(),
			opts:   []notify.SMTPOption{notify.WithSMTPOpportunisticTLS()},
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.NoError(t, err)
				assert.Contains(t, srv.Data(), "here is your link")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := startScriptedServer(t, tc.script)
			s := newTestSMTPSenderRaw(t, srv, tc.opts...)

			tc.assert(t, srv, s.Send(t.Context(), testMessage()))
		})
	}
}

func TestSMTPSenderOpportunisticTLS(t *testing.T) {
	t.Parallel()

	t.Run("credentials are not sent over an unencrypted non-loopback connection", func(t *testing.T) {
		t.Parallel()

		srv := startScriptedServer(t, scriptNoSTARTTLS())

		// PlainAuth is constructed for a non-loopback host name, so net/smtp's
		// own rule applies even though the connection goes to the test server.
		s, err := notify.NewSMTPSender("smtp.example.com",
			notify.WithSMTPPort(srv.Port()),
			notify.WithSMTPFrom("no-reply@example.com"),
			notify.WithSMTPOpportunisticTLS(),
			notify.WithSMTPAuth("ada", "hunter2"),
			notify.WithSMTPDialer(srv.Dial),
		)
		require.NoError(t, err)

		err = s.Send(t.Context(), testMessage())
		require.Error(t, err, "net/smtp refuses PLAIN over an unencrypted connection")
		assert.NotContains(t, strings.Join(srv.Lines(), "\n"), "hunter2")
		assert.NotContains(t, srv.Lines(), "DATA")
	})
}
