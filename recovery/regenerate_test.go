package recovery_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/recovery"
)

// regeneratedMessages is a consumer's message builder: it replaces only the
// regeneration notice, and writes the instant it was given into the body.
type regeneratedMessages struct {
	recovery.Messages
}

func (regeneratedMessages) Regenerated(at time.Time) (string, string) {
	return "Codes renewed", "Your codes were renewed at " + at.UTC().Format(time.RFC3339) + "."
}

// assertNoCode checks that no message carries a code of codes.
func assertNoCode(t *testing.T, msgs []notify.Message, codes []string) {
	t.Helper()

	for _, m := range msgs {
		for _, code := range codes {
			assert.NotContains(t, m.Subject, code, "the notice carries no code")
			assert.NotContains(t, m.TextBody, code, "the notice carries no code")
		}
	}
}

func TestRecoverer_Regenerate(t *testing.T) {
	t.Parallel()

	errStore := errors.New("code store unreachable")

	type testCase struct {
		name   string
		opts   func(e *completeEnv) []recovery.Option
		setup  func(e *completeEnv)
		assert func(t *testing.T, e *completeEnv, codes []string, err error)
	}

	cases := []testCase{
		{
			name: "a new set, the old set void, and one notice to the address with no code",
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.NoError(t, err)
				require.Len(t, codes, 10)

				// Confirm charges a refusal to the saved-code limiter, so the
				// new set is checked first and the old set by one code.
				assert.True(t, e.savedUsable(t.Context(), t, codes[0]), "the new set is usable")
				assert.False(t, e.savedUsable(t.Context(), t, e.saved[0]), "the previous set is void")

				msgs := e.out.messages()
				require.Len(t, msgs, 1, "one notice")
				subject, body := recovery.DefaultMessages().Regenerated(monday1000)
				assert.Equal(t, notify.Message{To: anaUsername, Subject: subject, TextBody: body}, msgs[0])
				assertNoCode(t, msgs, append(codes, e.saved...))

				for _, code := range append(codes, e.saved...) {
					assert.NotContains(t, e.logs.String(), code, "no log record carries a code")
				}
			},
		},
		{
			name: "the consumer's messages and contact resolver are used",
			opts: func(*completeEnv) []recovery.Option {
				return []recovery.Option{
					recovery.WithMessages(regeneratedMessages{Messages: recovery.DefaultMessages()}),
					recovery.WithContactResolver(func(_ context.Context, d *identity.Details) (string, error) {
						return "security+" + string(d.ID) + "@example.net", nil
					}),
				}
			},
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.NoError(t, err)
				require.Len(t, codes, 10)

				msgs := e.out.messages()
				require.Len(t, msgs, 1)
				assert.Equal(t, "security+u-1@example.net", msgs[0].To, "the consumer's resolver addresses it")
				assert.Equal(t, "Codes renewed", msgs[0].Subject, "the consumer's builder writes it")
				assert.Equal(t, "Your codes were renewed at 2026-09-28T10:00:00Z.", msgs[0].TextBody, "the notice names the time")
				assertNoCode(t, msgs, codes)
			},
		},
		{
			name:  "a refused queue is logged and the codes are still returned",
			setup: func(e *completeEnv) { e.out.sendErr = errors.New("queue full") },
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.NoError(t, err)
				require.Len(t, codes, 10)
				assert.True(t, e.savedUsable(t.Context(), t, codes[0]), "the regeneration stands")
				assert.False(t, e.savedUsable(t.Context(), t, e.saved[0]))
				assert.Contains(t, e.logs.String(), "the recovery notice could not be sent")
			},
		},
		{
			name: "an address that cannot be resolved is logged and the codes are still returned",
			opts: func(*completeEnv) []recovery.Option {
				return []recovery.Option{recovery.WithContactResolver(func(context.Context, *identity.Details) (string, error) {
					return "", errors.New("directory down")
				})}
			},
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.NoError(t, err)
				require.Len(t, codes, 10)
				assert.Empty(t, e.out.messages(), "no notice")
				assert.Contains(t, e.logs.String(), "the notice's contact address could not be resolved")
			},
		},
		{
			name:  "a user who cannot be loaded is logged and the codes are still returned",
			setup: func(e *completeEnv) { e.failLookup(errors.New("user store down")) },
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.NoError(t, err)
				require.Len(t, codes, 10)
				assert.Empty(t, e.out.messages(), "no notice")
				assert.Contains(t, e.logs.String(), "the user could not be loaded for the notice")
			},
		},
		{
			name:  "a set that cannot be written is returned as an error and nothing is sent",
			setup: func(e *completeEnv) { e.faults.arm(faultCodesReplaceSet, errStore) },
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.ErrorIs(t, err, errStore)
				assert.Nil(t, codes)
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[0]), "the previous set stands")
				assert.Empty(t, e.out.messages(), "no notice")
			},
		},
		{
			name: "saved codes not enabled is a configuration error",
			opts: func(*completeEnv) []recovery.Option {
				return []recovery.Option{recovery.WithProofs(recovery.ProofIssued, recovery.ProofPassword)}
			},
			assert: func(t *testing.T, e *completeEnv, codes []string, err error) {
				require.ErrorIs(t, err, recovery.ErrConfig)
				assert.Nil(t, codes)
				assert.True(t, e.savedUsable(t.Context(), t, e.saved[0]), "the set is unchanged")
				assert.Empty(t, e.out.messages(), "no notice")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)

			var extra []recovery.Option
			if tc.opts != nil {
				extra = tc.opts(e)
			}
			if tc.setup != nil {
				tc.setup(e)
			}

			r := e.recoverer(t, extra...)

			codes, err := r.Regenerate(t.Context(), anaID)
			tc.assert(t, e, codes, err)

			if err != nil {
				assert.False(t, strings.Contains(err.Error(), anaUsername), "no username in the error")
			}
		})
	}
}
