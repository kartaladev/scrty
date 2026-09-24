package test

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/notify"
)

// TestSMTPSenderIntegration drives one message through a real SMTP server.
//
// The scripted server in notify's own tests proves the rules — the deadline,
// the STARTTLS refusal, the bytes written. This proves the wire format is
// acceptable to a server nobody in this repository wrote: the non-ASCII
// subject survives the round trip, the body arrives with CRLF line endings,
// AUTH is negotiated, and no header the server recorded names this library.
func TestSMTPSenderIntegration(t *testing.T) {
	t.Parallel()

	conn := RunTestSMTP(t)

	s, err := notify.NewSMTPSender(conn.Host,
		notify.WithSMTPPort(conn.Port),
		notify.WithSMTPFrom("no-reply@example.com"),
		notify.WithSMTPAuth(conn.Username, conn.Password),
		// The sender keeps its required-STARTTLS default; the only thing
		// replaced is which certificate authority it trusts, so the upgrade
		// and the certificate check both really happen.
		notify.WithSMTPTLSConfig(&tls.Config{
			RootCAs:    conn.RootCAs,
			ServerName: conn.Host,
			MinVersion: tls.VersionTLS12,
		}),
	)
	require.NoError(t, err)

	require.NoError(t, s.Send(t.Context(), notify.Message{
		To:       "ada@example.com",
		Subject:  "Masuk ke akun Anda — tautan",
		TextBody: "line one\nline two",
	}))

	msgs := conn.Messages(t)
	require.Len(t, msgs, 1)

	got := msgs[0]
	assert.Equal(t, "Masuk ke akun Anda — tautan", got.DecodedSubject)
	assert.Contains(t, got.Body, "line one\r\nline two")

	// Without this the loop below would pass on a helper that read no headers
	// at all, which is the one way this check could go quiet.
	require.NotEmpty(t, got.Headers)

	for name, value := range got.Headers {
		assert.NotContains(t, strings.ToLower(name), "scrty")
		assert.NotContains(t, strings.ToLower(value), "scrty")
	}
}
