package notify_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/notify"
)

// leakedFixtures are the values a dependency's error text may quote that must
// never reach a written record: the fixture address and the fixture user
// reference every site in this change is proven against.
var leakedFixtures = []string{"alice@example.com", "u-123"}

// failureRecords decodes every JSON line buf holds, so a case can assert on
// fields rather than on message text.
func failureRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()

	var out []map[string]any

	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}

		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec), "log line %q", line)
		out = append(out, rec)
	}

	return out
}

// TestSenderFailureRecords pins the email-notification requirement: a written
// record never carries a mail server's own wording, an inner sender's error
// text or a recovered panic's value — only a fixed reason and a Go type.
//
// Each case's own setup differs in kind — a scripted SMTP server, a queued
// sender whose inner sender errors, one whose inner sender panics — so each is
// a run closure rather than a shared call shape.
func TestSenderFailureRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T) *bytes.Buffer
		assert func(t *testing.T, recs []map[string]any)
	}

	cases := []testCase{
		{
			name: "an SMTP server rejecting the recipient logs the rcpt stage, not the reply",
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				srv := startScriptedServer(t, scriptRejectAtWith("RCPT",
					"550 5.1.1 <alice@example.com>: Recipient address rejected, user u-123"))

				s, err := notify.NewSMTPSender(srv.Host(),
					notify.WithSMTPPort(srv.Port()),
					notify.WithSMTPFrom("no-reply@example.com"),
					notify.WithSMTPOpportunisticTLS(),
					notify.WithSMTPDialer(srv.Dial),
					notify.WithSMTPLogger(logger))
				require.NoError(t, err)

				err = s.Send(t.Context(), notify.Message{
					To:       "alice@example.com",
					Subject:  "Sign in",
					TextBody: "here is your link",
				})
				require.Error(t, err)

				return &buf
			},
			assert: func(t *testing.T, recs []map[string]any) {
				t.Helper()

				require.Len(t, recs, 1)
				assert.Equal(t, "rcpt", recs[0]["reason"])
				assert.NotEmpty(t, recs[0]["error_type"])
			},
		},
		{
			name: "a queued sender whose inner sender fails logs the send stage, not the body",
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				inner := senderFunc(func(context.Context, notify.Message) error {
					return errors.New("api: 422 recipient alice@example.com (user u-123) rejected")
				})

				s, err := notify.NewQueuedSender(inner,
					notify.WithQueueWorkers(1),
					notify.WithQueueLogger(logger))
				require.NoError(t, err)

				require.NoError(t, s.Send(t.Context(), testMessage()))
				require.NoError(t, s.Close(context.WithoutCancel(t.Context())))

				return &buf
			},
			assert: func(t *testing.T, recs []map[string]any) {
				t.Helper()

				require.Len(t, recs, 1)
				assert.Equal(t, "send", recs[0]["reason"])
				assert.NotEmpty(t, recs[0]["error_type"])
			},
		},
		{
			name: "a queued sender whose inner sender panics logs the panic stage and value type, not the value",
			run: func(t *testing.T) *bytes.Buffer {
				t.Helper()

				var buf bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&buf, nil))

				inner := senderFunc(func(context.Context, notify.Message) error {
					panic("rejected alice@example.com for user u-123")
				})

				s, err := notify.NewQueuedSender(inner,
					notify.WithQueueWorkers(1),
					notify.WithQueueLogger(logger))
				require.NoError(t, err)

				require.NoError(t, s.Send(t.Context(), testMessage()))
				require.NoError(t, s.Close(context.WithoutCancel(t.Context())))

				return &buf
			},
			assert: func(t *testing.T, recs []map[string]any) {
				t.Helper()

				require.Len(t, recs, 1)
				assert.Equal(t, "panic", recs[0]["reason"])
				assert.Equal(t, "string", recs[0]["value_type"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			buf := tc.run(t)

			rendered := buf.String()
			for _, v := range leakedFixtures {
				assert.NotContains(t, rendered, v, "a written record leaked the fixture")
			}

			tc.assert(t, failureRecords(t, buf))
		})
	}
}
