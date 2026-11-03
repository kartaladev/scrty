package password_test

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
)

// secretQuotingError is a dependency error whose text quotes whatever it is
// given, as a careless store or client might.
type secretQuotingError struct{ quote string }

func (e *secretQuotingError) Error() string { return "boom " + e.quote }

// TestPolicy_NoSecrets is not parallel: it replaces the process-wide default
// logger and standard log output to capture anything the policy writes.
//
//nolint:paralleltest // see above
func TestPolicy_NoSecrets(t *testing.T) {
	var logged bytes.Buffer

	prevSlog := slog.Default()
	prevLog := log.Writer()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.SetOutput(&logged)
	t.Cleanup(func() {
		slog.SetDefault(prevSlog)
		log.SetOutput(prevLog)
	})

	fast := fastArgon2id(t)

	const (
		userID      = "u-secret-4711"
		username    = "ada.lovelace"
		contextWord = "analyticalengine"
	)

	current := mustEncode(t, fast, p0)
	retired := mustEncode(t, fast, p1)

	type testCase struct {
		name      string
		opts      func(ctrl *gomock.Controller) []password.PolicyOption
		candidate string
		assert    func(t *testing.T, err error)
	}

	words := password.ContextWords(func(context.Context, *identity.Details) ([]string, error) {
		return []string{contextWord}, nil
	})

	history := func(ctrl *gomock.Controller, hashes [][]byte, err error) password.History {
		m := NewMockHistory(ctrl)
		m.EXPECT().RecentPasswords(gomock.Any(), identity.UserID(userID), 2).Return(hashes, err).AnyTimes()

		return m
	}

	source := func(ctrl *gomock.Controller, entries map[string]int, err error) password.BreachSource {
		m := NewMockBreachSource(ctrl)
		m.EXPECT().Range(gomock.Any(), gomock.Any()).Return(entries, err).AnyTimes()

		return m
	}

	_, breachedSuffix := sha1Hex(p9)

	cases := []testCase{
		{
			name:      "too short",
			opts:      func(*gomock.Controller) []password.PolicyOption { return nil },
			candidate: "ada-short",
			assert:    rejectedBy(password.RuleTooShort),
		},
		{
			name:      "too long",
			opts:      func(*gomock.Controller) []password.PolicyOption { return nil },
			candidate: strings.Repeat("ada.lovelace-", 10),
			assert:    rejectedBy(password.RuleTooLong),
		},
		{
			name:      "common",
			opts:      func(*gomock.Controller) []password.PolicyOption { return nil },
			candidate: longCommon,
			assert:    rejectedBy(password.RuleCommon),
		},
		{
			name:      "context word",
			opts:      func(*gomock.Controller) []password.PolicyOption { return []password.PolicyOption{words} },
			candidate: "my-" + contextWord + "-pass",
			assert:    rejectedBy(password.RuleContextWord),
		},
		{
			name: "breached",
			opts: func(ctrl *gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{password.Breached(source(ctrl, map[string]int{breachedSuffix: 3}, nil), password.Refuse)}
			},
			candidate: p9,
			assert:    rejectedBy(password.RuleBreached),
		},
		{
			name: "a breach lookup failure quoting the candidate",
			opts: func(ctrl *gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{password.Breached(source(ctrl, nil, &secretQuotingError{quote: p9}), password.Refuse)}
			},
			candidate: p9,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, password.ErrLookupUnavailable)
			},
		},
		{
			name: "reused",
			opts: func(ctrl *gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{password.WithEncoder(fast), password.NoReuse(history(ctrl, [][]byte{retired}, nil), 3)}
			},
			candidate: p1,
			assert:    rejectedBy(password.RuleReused),
		},
		{
			name: "a history failure quoting a stored hash",
			opts: func(ctrl *gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{
					password.WithEncoder(fast),
					password.NoReuse(history(ctrl, nil, &secretQuotingError{quote: string(retired)}), 3),
				}
			},
			candidate: p9,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, password.ErrHistoryUnavailable)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logged.Reset()

			p, err := password.NewPolicy(tc.opts(gomock.NewController(t))...)
			require.NoError(t, err)

			for _, call := range []struct {
				name string
				run  func(user *identity.Details) error
			}{
				{"check", func(u *identity.Details) error { return p.Check(t.Context(), u, tc.candidate) }},
				{"change", func(u *identity.Details) error {
					return p.Change(t.Context(), u, tc.candidate, (&recordingWrite{}).write)
				}},
			} {
				user := &identity.Details{ID: userID, Username: username, Password: current}
				err := call.run(user)
				require.Error(t, err, call.name)
				tc.assert(t, err)

				secrets := []string{tc.candidate, contextWord, userID, username}
				assertNoCredential(t, err.Error(), secrets, current, retired)
				assertNoCredential(t, logged.String(), secrets, current, retired)
				assert.Empty(t, logged.String(), "the policy writes no log record")
			}
		})
	}
}
