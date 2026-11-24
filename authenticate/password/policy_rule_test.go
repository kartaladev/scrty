package password_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
)

// lettersAndDigits is a consumer rule: the candidate holds a letter and a digit.
func lettersAndDigits(_ context.Context, candidate string, _ *identity.Details) (bool, error) {
	var letter, digit bool

	for _, r := range candidate {
		letter = letter || unicode.IsLetter(r)
		digit = digit || unicode.IsDigit(r)
	}

	return letter && digit, nil
}

const lettersAndDigitsRule password.Rule = "letters-and-digits"

func TestPolicy_WithRule_Check(t *testing.T) {
	t.Parallel()

	enc := fastArgon2id(t)
	current := "abcdefghij12"
	currentHash := mustEncode(t, enc, current)

	errRule := errors.New("rule backend down")

	type testCase struct {
		name      string
		opts      func(ctrl *gomock.Controller) []password.PolicyOption
		candidate string
		ctx       func(ctx context.Context) context.Context
		assert    func(t *testing.T, err error)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	with := func(opts ...password.PolicyOption) func(*gomock.Controller) []password.PolicyOption {
		return func(*gomock.Controller) []password.PolicyOption { return opts }
	}

	failing := func(context.Context, string, *identity.Details) (bool, error) { return false, errRule }

	cases := []testCase{
		{
			name:      "no rule: letters only are accepted",
			opts:      with(),
			candidate: "abcdefghijklmnop",
			assert:    accepted,
		},
		{
			name:      "letters and digits: letters only are refused by the consumer rule",
			opts:      with(password.MinLength(10), password.WithRule(lettersAndDigitsRule, lettersAndDigits)),
			candidate: "abcdefghijkl",
			assert:    rejectedBy(lettersAndDigitsRule),
		},
		{
			name:      "letters and digits: a letter and a digit are accepted",
			opts:      with(password.MinLength(10), password.WithRule(lettersAndDigitsRule, lettersAndDigits)),
			candidate: "abcdefghij12",
			assert:    accepted,
		},
		{
			name: "weak and reused stay distinct: the current password is reused, not weak",
			opts: with(
				password.WithEncoder(enc), password.MinLength(10),
				password.WithRule(lettersAndDigitsRule, lettersAndDigits),
				password.NoReuse(newMemHistory(), 1),
			),
			candidate: current,
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, password.ErrReused)
				rejectedBy(password.RuleReused)(t, err)
			},
		},
		{
			name: "weak and reused stay distinct: a candidate the rule refuses is not reused",
			opts: with(
				password.WithEncoder(enc), password.MinLength(10),
				password.WithRule(lettersAndDigitsRule, lettersAndDigits),
				password.NoReuse(newMemHistory(), 1),
			),
			candidate: "abcdefghijkl",
			assert: func(t *testing.T, err error) {
				t.Helper()
				rejectedBy(lettersAndDigitsRule)(t, err)
				assert.NotErrorIs(t, err, password.ErrReused)
			},
		},
		{
			name:      "rule failure: the error is reachable, fixed text, and not a rejection",
			opts:      with(password.WithRule("flaky", failing)),
			candidate: "abcdefghijklmnop",
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, password.ErrRuleFailed)
				require.ErrorIs(t, err, errRule)
				assert.NotErrorIs(t, err, password.ErrPasswordRejected)

				var rejected password.RejectedError

				assert.False(t, errors.As(err, &rejected), "not a RejectedError")
				assert.Contains(t, err.Error(), "flaky", "the text names the rule")
				assert.NotContains(t, err.Error(), errRule.Error(), "fixed text")
				assert.NotContains(t, err.Error(), "abcdefghijklmnop")
			},
		},
		{
			name: "rule failure with an accepting verdict still fails closed",
			opts: with(password.WithRule("flaky", func(context.Context, string, *identity.Details) (bool, error) {
				return true, errRule
			})),
			candidate: "abcdefghijklmnop",
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, password.ErrRuleFailed)
				require.ErrorIs(t, err, errRule)
			},
		},
		{
			name: "a cancelled context reaches the rule and its error is reachable",
			opts: with(password.WithRule("ctx-aware", func(ctx context.Context, _ string, _ *identity.Details) (bool, error) {
				return true, ctx.Err()
			})),
			candidate: "abcdefghijklmnop",
			ctx:       cancelled,
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, password.ErrPasswordRejected)
			},
		},
		{
			name: "the rule is given the user record and the candidate",
			opts: with(password.WithRule("sees-input", func(_ context.Context, candidate string, u *identity.Details) (bool, error) {
				return candidate == "abcdefghijklmnop" && u != nil && u.ID == "u-1", nil
			})),
			candidate: "abcdefghijklmnop",
			assert:    accepted,
		},
		{
			name: "rules run in the order given, and the first refusal ends the check",
			opts: with(
				password.WithRule("first", func(context.Context, string, *identity.Details) (bool, error) { return false, nil }),
				password.WithRule("second", func(context.Context, string, *identity.Details) (bool, error) {
					return false, errors.New("the second rule ran after the first refused")
				}),
			),
			candidate: "abcdefghijklmnop",
			assert:    rejectedBy("first"),
		},
		{
			name: "a cheap refusal skips the consumer rule",
			opts: with(password.WithRule("never", func(context.Context, string, *identity.Details) (bool, error) {
				return false, errors.New("the rule ran for a too-short candidate")
			})),
			candidate: "short",
			assert:    rejectedBy(password.RuleTooShort),
		},
		{
			name: "the consumer rule runs before the breach lookup: a refusal makes no lookup",
			opts: func(ctrl *gomock.Controller) []password.PolicyOption {
				// No EXPECT: any Range call fails the test.
				return []password.PolicyOption{
					password.Breached(NewMockBreachSource(ctrl), password.Refuse),
					password.WithRule(lettersAndDigitsRule, lettersAndDigits),
				}
			},
			candidate: strings.Repeat("a", 16),
			assert:    rejectedBy(lettersAndDigitsRule),
		},
		{
			name: "a rule that fails also makes no breach lookup",
			opts: func(ctrl *gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{
					password.Breached(NewMockBreachSource(ctrl), password.Refuse),
					password.WithRule("flaky", failing),
				}
			},
			candidate: strings.Repeat("a", 16),
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, errRule)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			p, err := password.NewPolicy(tc.opts(ctrl)...)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			user := &identity.Details{ID: "u-1", Username: "ada", Password: currentHash}

			tc.assert(t, p.Check(ctx, user, tc.candidate))
		})
	}
}

// TestPortErrors_ConsumerRule pins that a consumer rule's error is read
// through the boundary sanitizer: a hostile error becomes
// porterr.ErrUnwalkable beneath ErrRuleFailed, never a refusal, and its text
// never reaches the caller.
func TestPortErrors_ConsumerRule(t *testing.T) {
	eachPortErrRow(t, func(t *testing.T, row portErrRow) {
		def := swapDefaultLogger(t)
		pol := &recordingHandler{}

		p, err := password.NewPolicy(
			password.WithRule("flaky", func(context.Context, string, *identity.Details) (bool, error) {
				return false, row.err()
			}),
			password.WithPolicyLogger(slog.New(pol)),
		)
		require.NoError(t, err)

		got := within(t, func() error {
			return p.Check(t.Context(), &identity.Details{ID: "u1"}, "abcdefghijklmnop")
		})

		require.Error(t, got)
		assert.True(t, isWithin(t, got, password.ErrRuleFailed), "errors.Is password.ErrRuleFailed")
		assert.False(t, isWithin(t, got, password.ErrPasswordRejected), "errors.Is password.ErrPasswordRejected")
		assert.NotContains(t, got.Error(), "secret-hash")
		assert.NotContains(t, got.Error(), "port: down")
		wantRecords(t, row, pol)
		assert.Zero(t, abortRecords(def), "the record goes to the policy's logger, not the default")

		if row.hostile {
			assert.True(t, isWithin(t, got, porterr.ErrUnwalkable), "errors.Is porterr.ErrUnwalkable")
		}
	})
}

func TestPolicy_WithRule_ChangeFailureDoesNotWrite(t *testing.T) {
	t.Parallel()

	errRule := errors.New("rule backend down")

	p, err := password.NewPolicy(
		password.WithEncoder(fastArgon2id(t)),
		password.WithRule("flaky", func(context.Context, string, *identity.Details) (bool, error) {
			return false, errRule
		}),
	)
	require.NoError(t, err)

	wrote := false
	err = p.Change(t.Context(), checkUser(), "abcdefghijklmnop", func(context.Context, *identity.Details, []byte, time.Time) error {
		wrote = true

		return nil
	})

	require.ErrorIs(t, err, password.ErrRuleFailed)
	require.ErrorIs(t, err, errRule)
	assert.NotErrorIs(t, err, password.ErrPasswordRejected)
	assert.False(t, wrote, "the write must not be called")
}

func TestPolicy_WithRule_Construction(t *testing.T) {
	t.Parallel()

	ok := func(context.Context, string, *identity.Details) (bool, error) { return true, nil }

	type testCase struct {
		name   string
		opts   []password.PolicyOption
		assert func(t *testing.T, p *password.Policy, err error)
	}

	refused := func(word string) func(t *testing.T, p *password.Policy, err error) {
		return func(t *testing.T, p *password.Policy, err error) {
			t.Helper()

			require.ErrorIs(t, err, password.ErrConfig)
			assert.Contains(t, err.Error(), word)
			assert.Nil(t, p)
		}
	}

	built := func(t *testing.T, p *password.Policy, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.NotNil(t, p)
	}

	var typedNil password.RuleFunc

	rule := func(name password.Rule) []password.PolicyOption {
		return []password.PolicyOption{password.WithRule(name, ok)}
	}

	cases := []testCase{
		{name: "a nil check", opts: []password.PolicyOption{password.WithRule("r", nil)}, assert: refused("rule")},
		{name: "a typed-nil check", opts: []password.PolicyOption{password.WithRule("r", typedNil)}, assert: refused("rule")},
		{name: "an empty name", opts: rule(""), assert: refused("name")},
		{name: "a name of 65 characters", opts: rule(password.Rule(strings.Repeat("a", 65))), assert: refused("name")},
		{name: "a name of 64 characters", opts: rule(password.Rule(strings.Repeat("a", 64))), assert: built},
		{name: "a name with a space", opts: rule("has space"), assert: refused("name")},
		{name: "a name with a dot", opts: rule("a.b"), assert: refused("name")},
		{name: "a name with a non-ASCII letter", opts: rule("café"), assert: refused("name")},
		{name: "a name with a quote", opts: rule(`a"b`), assert: refused("name")},
		{name: "a name with letters, digits, dash and underscore", opts: rule("A-z_09"), assert: built},
		{name: "the built-in name reused", opts: rule("reused"), assert: refused("built-in")},
		{name: "the built-in name common", opts: rule(password.RuleCommon), assert: refused("built-in")},
		{name: "the built-in name breached", opts: rule(password.RuleBreached), assert: refused("built-in")},
		{name: "the built-in name too short", opts: rule(password.RuleTooShort), assert: refused("built-in")},
		{name: "the built-in name too long", opts: rule(password.RuleTooLong), assert: refused("built-in")},
		{name: "the built-in name context word", opts: rule(password.RuleContextWord), assert: refused("built-in")},
		{
			name:   "a duplicate name",
			opts:   []password.PolicyOption{password.WithRule("dup", ok), password.WithRule("dup", ok)},
			assert: refused("dup"),
		},
		{
			name:   "two different names",
			opts:   []password.PolicyOption{password.WithRule("one", ok), password.WithRule("two", ok)},
			assert: built,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := password.NewPolicy(tc.opts...)
			tc.assert(t, p, err)
		})
	}
}
