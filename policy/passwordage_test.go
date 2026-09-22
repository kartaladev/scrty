package policy_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
)

func TestPasswordAgePolicyEvaluate(t *testing.T) {
	t.Parallel()

	// The instant every login in this table happens at, and the unit the
	// maximum password age is written in. Ages are measured back from the
	// login, so no case reads the wall clock.
	loginAt := time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)
	const day = 24 * time.Hour

	type testCase struct {
		name      string
		opts      []policy.PasswordAgeOption
		changedAt time.Time
		assert    func(t *testing.T, d policy.Decision)
	}

	allows := func(t *testing.T, d policy.Decision) {
		t.Helper()

		assert.Equal(t, policy.Allow, d.Outcome, "a password that is not overdue was challenged")
		assert.Equal(t, policy.ChallengeNone, d.Challenge, "an allow challenges for nothing")
	}

	challengesForANewPassword := func(t *testing.T, d policy.Decision) {
		t.Helper()

		require.Equal(t, policy.Challenge, d.Outcome, "an overdue password was let through")
		assert.Equal(t, policy.ChallengePasswordChange, d.Challenge,
			"the caller was asked for something other than a new password")
		assert.NoError(t, d.Reason, "a challenge refuses nothing, so it carries no reason")
	}

	cases := []testCase{
		{
			name:      "a password changed inside the maximum age allows",
			changedAt: loginAt.Add(-30 * day),
			assert:    allows,
		},
		{
			// "Expired password": last changed 91 days ago.
			name:      "a password older than ninety days is challenged",
			changedAt: loginAt.Add(-91 * day),
			assert:    challengesForANewPassword,
		},
		{
			// The rule is that the age exceeds the maximum, so a password
			// exactly at the maximum still has today.
			name:      "a password exactly at the maximum age allows",
			changedAt: loginAt.Add(-90 * day),
			assert:    allows,
		},
		{
			// "Unknown change time by default".
			name:      "an unknown change time allows by default",
			changedAt: time.Time{},
			assert:    allows,
		},
		{
			// "Consumer challenges unknown change times".
			name:      "a consumer can challenge unknown change times instead",
			opts:      []policy.PasswordAgeOption{policy.WithUnknownPasswordAge(policy.ChallengeUnknown)},
			changedAt: time.Time{},
			assert:    challengesForANewPassword,
		},
		{
			name:      "the default mode can be asked for by name",
			opts:      []policy.PasswordAgeOption{policy.WithUnknownPasswordAge(policy.AllowUnknown)},
			changedAt: time.Time{},
			assert:    allows,
		},
		{
			name:      "a consumer's shorter maximum age challenges where the default would allow",
			opts:      []policy.PasswordAgeOption{policy.WithMaxPasswordAge(30 * day)},
			changedAt: loginAt.Add(-31 * day),
			assert:    challengesForANewPassword,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := policy.NewPasswordAgePolicy(tc.opts...)
			require.NoError(t, err)

			in := &policy.Input{PasswordChangedAt: tc.changedAt, Now: loginAt}
			tc.assert(t, p.Evaluate(t.Context(), in))
		})
	}
}

func TestPasswordAgePolicyPhases(t *testing.T) {
	t.Parallel()

	p, err := policy.NewPasswordAgePolicy()
	require.NoError(t, err)

	assert.Equal(t, []policy.Phase{policy.PostAuthentication}, p.Phases(),
		"a login is the only moment at which a password change can still be demanded")
	assert.NotEmpty(t, p.Name(), "a policy with no name cannot be told apart in a log")
}

// TestPasswordAgePolicyDocumentation pins the statements the capability
// requires the policy to make about what it cannot see. They are a guarantee to
// the consumer, not a courtesy: a deployment whose change time is never written
// has a policy that never fires, and only the documentation can say so.
func TestPasswordAgePolicyDocumentation(t *testing.T) {
	t.Parallel()

	docs := passwordAgeDocs(t)

	type testCase struct {
		name   string
		phrase string
	}

	cases := []testCase{
		{
			name:   "it enforces nothing where no change time is written",
			phrase: "enforces nothing for a user whose change time is never written",
		},
		{
			name:   "it says who owns the change time",
			phrase: "the consumer, or the default identity store",
		},
		{
			name:   "it warns against refreshing the value from federated logins",
			phrase: "do not refresh it from every federated login",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Contains(t, docs, tc.phrase)
		})
	}
}

// passwordAgeDocs returns the doc comments of every exported declaration in
// passwordage.go — the godoc a consumer reads — lowercased and with runs of
// whitespace collapsed, so an assertion on a phrase is not defeated by where
// the comment happened to wrap a line. An unexported declaration's comment is
// left out: it documents the implementation, not the contract.
func passwordAgeDocs(t *testing.T) string {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), "passwordage.go", nil, parser.ParseComments)
	require.NoError(t, err)

	declaresExported := func(d *ast.GenDecl) bool {
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				if s.Name.IsExported() {
					return true
				}
			case *ast.ValueSpec:
				for _, name := range s.Names {
					if name.IsExported() {
						return true
					}
				}
			}
		}

		return false
	}

	var docs strings.Builder
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Doc != nil && d.Name.IsExported() {
				docs.WriteString(d.Doc.Text())
			}
		case *ast.GenDecl:
			if d.Doc != nil && declaresExported(d) {
				docs.WriteString(d.Doc.Text())
			}
		}
	}

	return strings.ToLower(strings.Join(strings.Fields(docs.String()), " "))
}
