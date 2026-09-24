package notify_test

import (
	"bytes"
	"io"
	"log/slog"
	"mime"
	"net/mail"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/notify"
)

// parseData reads the payload the scripted server recorded at DATA as the RFC
// 5322 message it is meant to be.
func parseData(t *testing.T, data string) *mail.Message {
	t.Helper()

	m, err := mail.ReadMessage(strings.NewReader(data))
	require.NoError(t, err, "the DATA payload must parse as a message")

	return m
}

// headerValue returns one header exactly as it was written, without decoding.
func headerValue(t *testing.T, data, name string) string {
	t.Helper()

	return parseData(t, data).Header.Get(name)
}

// headersOf returns every header, each value joined, for assertions that look
// across all of them.
func headersOf(t *testing.T, data string) map[string]string {
	t.Helper()

	out := map[string]string{}
	for name, values := range parseData(t, data).Header {
		out[name] = strings.Join(values, " ")
	}

	return out
}

// bodyOf returns the message body with its line endings untouched.
func bodyOf(t *testing.T, data string) string {
	t.Helper()

	body, err := io.ReadAll(parseData(t, data).Body)
	require.NoError(t, err)

	return string(body)
}

func TestSMTPSenderEncoding(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		msg    notify.Message
		assert func(t *testing.T, data string)
	}

	cases := []testCase{
		{
			name: "a non-ASCII subject is Q-encoded and decodes back exactly",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Masuk ke akun Anda — tautan",
				TextBody: "link",
			},
			assert: func(t *testing.T, data string) {
				raw := headerValue(t, data, "Subject")
				assert.True(t, strings.HasPrefix(raw, "=?UTF-8?"), "got %q", raw)

				decoded, err := new(mime.WordDecoder).DecodeHeader(raw)
				require.NoError(t, err)
				assert.Equal(t, "Masuk ke akun Anda — tautan", decoded)
			},
		},
		{
			name: "an ASCII subject is written as-is",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Sign in",
				TextBody: "link",
			},
			assert: func(t *testing.T, data string) {
				assert.Equal(t, "Sign in", headerValue(t, data, "Subject"))
			},
		},
		{
			name: "bare line feeds in the body are normalised to CRLF",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Sign in",
				TextBody: "line one\nline two",
			},
			assert: func(t *testing.T, data string) {
				body := bodyOf(t, data)
				assert.Contains(t, body, "line one\r\nline two")
				assert.NotRegexp(t, regexp.MustCompile(`[^\r]\n`), body)
			},
		},
		{
			name: "the content type names UTF-8 plain text",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Sign in",
				TextBody: "link",
			},
			assert: func(t *testing.T, data string) {
				assert.Equal(t, "text/plain; charset=UTF-8", headerValue(t, data, "Content-Type"))
			},
		},
		{
			name: "no header names scrty or any product",
			msg: notify.Message{
				To:       "ada@example.com",
				Subject:  "Sign in",
				TextBody: "link",
			},
			assert: func(t *testing.T, data string) {
				for name, value := range headersOf(t, data) {
					assert.NotContains(t, strings.ToLower(name), "scrty")
					assert.NotContains(t, strings.ToLower(value), "scrty")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := startScriptedServer(t, scriptOK())
			s := newTestSMTPSender(t, srv)

			require.NoError(t, s.Send(t.Context(), tc.msg))
			tc.assert(t, srv.Data())
		})
	}
}

func TestSMTPSenderLogsCarryNoBody(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	srv := startScriptedServer(t, scriptRejectAt("DATA"))
	s := newTestSMTPSender(t, srv, notify.WithSMTPLogger(logger))

	link := "https://app.example.com/login/magic/confirm?token=abc123secret"
	require.Error(t, s.Send(t.Context(), notify.Message{
		To:       "ada@example.com",
		Subject:  "Sign in",
		TextBody: "Follow " + link + " to sign in.",
	}))

	assert.NotContains(t, buf.String(), link)
	assert.NotContains(t, buf.String(), "abc123secret")
	assert.NotContains(t, buf.String(), "Follow ")
}
