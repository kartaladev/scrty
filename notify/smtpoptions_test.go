package notify_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/notify"
)

func TestNewSMTPSender(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		host   string
		opts   []notify.SMTPOption
		assert func(t *testing.T, s *notify.SMTPSender, err error)
	}

	configError := func(t *testing.T, s *notify.SMTPSender, err error) {
		require.Error(t, err)
		assert.ErrorIs(t, err, notify.ErrConfig)
		assert.Nil(t, s)
	}

	cases := []testCase{
		{
			name: "defaults",
			host: "smtp.example.com",
			assert: func(t *testing.T, s *notify.SMTPSender, err error) {
				require.NoError(t, err)
				assert.Equal(t, 587, s.Port())
				assert.Equal(t, 30*time.Second, s.Timeout())
			},
		},
		{name: "missing host", host: "", assert: configError},
		{
			name:   "port zero",
			host:   "smtp.example.com",
			opts:   []notify.SMTPOption{notify.WithSMTPPort(0)},
			assert: configError,
		},
		{
			name:   "port too high",
			host:   "smtp.example.com",
			opts:   []notify.SMTPOption{notify.WithSMTPPort(65536)},
			assert: configError,
		},
		{
			name:   "negative port",
			host:   "smtp.example.com",
			opts:   []notify.SMTPOption{notify.WithSMTPPort(-1)},
			assert: configError,
		},
		{
			name:   "zero timeout",
			host:   "smtp.example.com",
			opts:   []notify.SMTPOption{notify.WithSMTPTimeout(0)},
			assert: configError,
		},
		{
			name:   "negative timeout",
			host:   "smtp.example.com",
			opts:   []notify.SMTPOption{notify.WithSMTPTimeout(-time.Second)},
			assert: configError,
		},
		{
			name:   "nil dialler",
			host:   "smtp.example.com",
			opts:   []notify.SMTPOption{notify.WithSMTPDialer(nil)},
			assert: configError,
		},
		{
			name: "consumer port and timeout",
			host: "smtp.example.com",
			opts: []notify.SMTPOption{notify.WithSMTPPort(2525), notify.WithSMTPTimeout(5 * time.Second)},
			assert: func(t *testing.T, s *notify.SMTPSender, err error) {
				require.NoError(t, err)
				assert.Equal(t, 2525, s.Port())
				assert.Equal(t, 5*time.Second, s.Timeout())
			},
		},
		{
			name: "does not declare itself non-blocking",
			host: "smtp.example.com",
			assert: func(t *testing.T, s *notify.SMTPSender, err error) {
				require.NoError(t, err)

				_, ok := any(s).(notify.NonBlocking)
				assert.False(t, ok, "SMTP waits for delivery and must not claim otherwise")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := notify.NewSMTPSender(tc.host, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestSMTPSenderFrom(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []notify.SMTPOption
		msgFrom string
		assert  func(t *testing.T, srv *scriptedServer, err error)
	}

	cases := []testCase{
		{
			name:    "the configured default is used when the message names none",
			opts:    []notify.SMTPOption{notify.WithSMTPFrom("no-reply@example.com")},
			msgFrom: "",
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.NoError(t, err)
				assert.Contains(t, srv.MailFrom(), "no-reply@example.com")
			},
		},
		{
			name:    "the message overrides the default",
			opts:    []notify.SMTPOption{notify.WithSMTPFrom("no-reply@example.com")},
			msgFrom: "support@example.com",
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.NoError(t, err)
				assert.Contains(t, srv.MailFrom(), "support@example.com")
				assert.NotContains(t, srv.MailFrom(), "no-reply@example.com")
			},
		},
		{
			name:    "neither is an error before any network activity",
			msgFrom: "",
			assert: func(t *testing.T, srv *scriptedServer, err error) {
				require.Error(t, err)
				assert.False(t, srv.Dialled(), "nothing may be dialled")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := startScriptedServer(t, scriptOK())

			s, err := notify.NewSMTPSender(srv.Host(), append(tc.opts,
				notify.WithSMTPPort(srv.Port()),
				notify.WithSMTPOpportunisticTLS(),
				notify.WithSMTPDialer(srv.Dial),
			)...)
			require.NoError(t, err)

			tc.assert(t, srv, s.Send(t.Context(), notify.Message{
				To:       "ada@example.com",
				From:     tc.msgFrom,
				Subject:  "Sign in",
				TextBody: "link",
			}))
		})
	}
}
