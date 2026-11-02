package password_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
)

// longCommon is an entry of the bundled common-password list that is long
// enough to pass the default minimum, so only the list can refuse it.
const longCommon = "PolniyPizdec0211"

// rejectedBy asserts err is a password refusal by rule.
func rejectedBy(rule password.Rule) func(t *testing.T, err error) {
	return func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, password.ErrPasswordRejected)

		var rej password.RejectedError
		require.ErrorAs(t, err, &rej)
		assert.Equal(t, rule, rej.Rule)
	}
}

func accepted(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, err)
}

// checkUser is the record a check is made for when the rule under test does
// not read it.
func checkUser() *identity.Details {
	return &identity.Details{ID: "u-1", Username: "ada"}
}

func TestPolicy_Defaults(t *testing.T) {
	t.Parallel()

	p, err := password.NewPolicy()
	require.NoError(t, err)

	type testCase struct {
		name      string
		candidate string
		assert    func(t *testing.T, err error)
	}

	cases := []testCase{
		{name: "a long passphrase is accepted", candidate: "correcthorsebatterystaple", assert: accepted},
		{name: "a long entry of the common list is refused as common", candidate: longCommon, assert: rejectedBy(password.RuleCommon)},
		{name: "the common list compares case-insensitively", candidate: "pOLNIYpIZDEC0211", assert: rejectedBy(password.RuleCommon)},
		{name: "a short candidate is refused as too short", candidate: "short", assert: rejectedBy(password.RuleTooShort)},
		{name: "fourteen characters are too short by default", candidate: "fourteen-chars", assert: rejectedBy(password.RuleTooShort)},
		{name: "fifteen characters pass the default minimum", candidate: "fifteen-chars!!", assert: accepted},
		{name: "no composition rule: letters only are accepted", candidate: "onlylowercaseletters", assert: accepted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, p.Check(t.Context(), checkUser(), tc.candidate))
		})
	}
}

// TestPolicy_Defaults_Encoder pins that a policy built without naming an
// encoder hashes a change with the built-in Argon2id encoder at its defaults.
func TestPolicy_Defaults_Encoder(t *testing.T) {
	t.Parallel()

	p, err := password.NewPolicy()
	require.NoError(t, err)

	w := &recordingWrite{}
	require.NoError(t, p.Change(t.Context(), checkUser(), "correcthorsebatterystaple", w.write))

	defaults, err := password.NewArgon2idEncoder()
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(string(w.hash), "argon2id$65536$1$4$"),
		"an Argon2id hash at the default parameters, got %q", w.hash)
	assert.True(t, defaults.Match("correcthorsebatterystaple", w.hash))
}

func TestPolicy_Options(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		opts      func(ctrl *gomock.Controller) []password.PolicyOption
		candidate string
		assert    func(t *testing.T, err error)
	}

	// noLookup is a breach source that fails the case if it is asked anything.
	noLookup := func(ctrl *gomock.Controller) password.BreachSource {
		m := NewMockBreachSource(ctrl)
		m.EXPECT().Range(gomock.Any(), gomock.Any()).Times(0)

		return m
	}

	cases := []testCase{
		{
			name: "a lower minimum keeps the common list",
			opts: func(*gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{password.MinLength(8)}
			},
			candidate: "password1",
			assert:    rejectedBy(password.RuleCommon),
		},
		{
			name: "a lower minimum accepts a short candidate that is not common",
			opts: func(*gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{password.MinLength(8)}
			},
			candidate: "plumriver",
			assert:    accepted,
		},
		{
			name: "removing the common list explicitly accepts a list entry",
			opts: func(*gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{password.WithoutCommonPasswords()}
			},
			candidate: longCommon,
			assert:    accepted,
		},
		{
			name: "removing the common list keeps the minimum",
			opts: func(*gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{password.WithoutCommonPasswords()}
			},
			candidate: "short",
			assert:    rejectedBy(password.RuleTooShort),
		},
		{
			name: "a replacement list refuses its own entries case-insensitively",
			opts: func(*gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{password.CommonPasswords([]string{"Plum-Orchard-River-Stone"})}
			},
			candidate: "plum-orchard-river-STONE",
			assert:    rejectedBy(password.RuleCommon),
		},
		{
			name: "a replacement list replaces the bundled one",
			opts: func(*gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{password.CommonPasswords([]string{"Plum-Orchard-River-Stone"})}
			},
			candidate: longCommon,
			assert:    accepted,
		},
		{
			name: "a too-short candidate makes no breach lookup",
			opts: func(ctrl *gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{password.Breached(noLookup(ctrl), password.Refuse)}
			},
			candidate: "short",
			assert:    rejectedBy(password.RuleTooShort),
		},
		{
			name: "a common candidate makes no breach lookup",
			opts: func(ctrl *gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{password.Breached(noLookup(ctrl), password.Refuse)}
			},
			candidate: longCommon,
			assert:    rejectedBy(password.RuleCommon),
		},
		{
			name: "a context-word refusal makes no breach lookup",
			opts: func(ctrl *gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{
					password.ContextWords(func(context.Context, *identity.Details) ([]string, error) {
						return []string{"plumriver"}, nil
					}),
					password.Breached(noLookup(ctrl), password.Refuse),
				}
			},
			candidate: "my-plumriver-is-here-1",
			assert:    rejectedBy(password.RuleContextWord),
		},
		{
			name: "a breach refusal reads no history",
			opts: func(ctrl *gomock.Controller) []password.PolicyOption {
				_, suffix := sha1Hex(breachCandidate)

				source := NewMockBreachSource(ctrl)
				source.EXPECT().Range(gomock.Any(), gomock.Any()).Return(map[string]int{suffix: 3}, nil)

				// No expectation: any read of the history fails the case.
				history := NewMockHistory(ctrl)

				return []password.PolicyOption{
					password.Breached(source, password.Refuse),
					password.NoReuse(history, 3),
				}
			},
			candidate: breachCandidate,
			assert:    rejectedBy(password.RuleBreached),
		},
		{
			name: "a lookup outage accepted by the breach rule lets the next rule run",
			opts: func(ctrl *gomock.Controller) []password.PolicyOption {
				enc := fastArgon2id(t)

				source := NewMockBreachSource(ctrl)
				source.EXPECT().Range(gomock.Any(), gomock.Any()).Return(nil, errors.New("outage"))

				// checkUser's earlier password is the candidate, so reuse refuses it.
				history := newMemHistory().seed(checkUser().ID, mustEncode(t, enc, p1))

				return []password.PolicyOption{
					password.WithEncoder(enc),
					password.Breached(source, password.Accept),
					password.NoReuse(history, 3),
				}
			},
			candidate: p1,
			assert:    rejectedBy(password.RuleReused),
		},
		{
			name: "a nil option is ignored",
			opts: func(*gomock.Controller) []password.PolicyOption {
				return []password.PolicyOption{nil}
			},
			candidate: "short",
			assert:    rejectedBy(password.RuleTooShort),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := password.NewPolicy(tc.opts(gomock.NewController(t))...)
			require.NoError(t, err)

			tc.assert(t, p.Check(t.Context(), checkUser(), tc.candidate))
		})
	}
}
