package prblmsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kartaladev/prblm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// allowedMembers are the only extension members a problem may carry.
var allowedMembers = map[string]bool{
	"challenge": true, "methods": true, "max_age": true, "rule": true, "scope": true, "access_token": true,
	"token_type": true,
}

// standardMembers are RFC 9457's own members.
var standardMembers = map[string]bool{"type": true, "title": true, "status": true, "detail": true, "instance": true}

// document returns prob encoded as JSON and decoded back into a map, numbers
// kept as json.Number.
func document(t *testing.T, prob *prblm.Problem) (raw string, doc map[string]any) {
	t.Helper()
	require.NotNil(t, prob)
	b, err := json.Marshal(prob)
	require.NoError(t, err)
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	require.NoError(t, dec.Decode(&doc))
	return string(b), doc
}

// extensions returns the extension members of doc.
func extensions(doc map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range doc {
		if !standardMembers[k] {
			out[k] = v
		}
	}
	return out
}

// twoMethods is u-1's enrolment of the spec scenario: TOTP, then a challenge
// method named passkey.
var twoMethods = []httpsec.MFAMethod{
	{Name: "totp", Channel: factor.AuthenticatorApp, Begins: false},
	{Name: "passkey", Channel: factor.PublicKey, Begins: true},
}

const twoMethodsJSON = `[{"name":"totp","channel":"authenticator-app","begins":false},` +
	`{"name":"passkey","channel":"public-key","begins":true}]`

func TestMapper_Members(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, err error, prob *prblm.Problem)
	}

	const consumerKind = policy.ChallengeKind(100)

	ofType := func(t *testing.T, err error, prob *prblm.Problem, sub string) map[string]any {
		t.Helper()
		require.NotNil(t, prob)
		assert.Equal(t, "security/"+sub, prob.Type)
		assert.Equal(t, httpsec.StatusForError(err), prob.Status)
		_, doc := document(t, prob)
		return extensions(doc)
	}
	noMembers := func(sub string) func(t *testing.T, err error, prob *prblm.Problem) {
		return func(t *testing.T, err error, prob *prblm.Problem) {
			t.Helper()
			assert.Empty(t, ofType(t, err, prob, sub))
		}
	}
	onlyChallenge := func(sub, value string) func(t *testing.T, err error, prob *prblm.Problem) {
		return func(t *testing.T, err error, prob *prblm.Problem) {
			t.Helper()
			assert.Equal(t, map[string]any{"challenge": value}, ofType(t, err, prob, sub))
		}
	}

	cases := []testCase{
		{
			name: "methods in order",
			err:  &httpsec.ChallengeError{Kind: policy.ChallengeMFA, Methods: twoMethods},
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				ofType(t, err, prob, "mfa-required")
				raw, _ := document(t, prob)
				assert.Contains(t, raw, `"methods":`+twoMethodsJSON)
			},
		},
		{
			name: "empty methods",
			err:  &httpsec.ChallengeError{Kind: policy.ChallengeMFA, Methods: []httpsec.MFAMethod{}},
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				ofType(t, err, prob, "mfa-required")
				raw, _ := document(t, prob)
				assert.Contains(t, raw, `"methods":[]`)
			},
		},
		{name: "nil methods", err: &httpsec.ChallengeError{Kind: policy.ChallengeMFA}, assert: onlyChallenge("mfa-required", "mfa")},
		{
			name:   "password change challenge",
			err:    &httpsec.ChallengeError{Kind: policy.ChallengePasswordChange, Methods: twoMethods},
			assert: onlyChallenge("password-change-required", "password-change"),
		},
		{
			name:   "enrolment challenge",
			err:    &httpsec.ChallengeError{Kind: policy.ChallengeMFAEnrolment},
			assert: onlyChallenge("mfa-enrolment-required", "mfa-enrolment"),
		},
		{
			name:   "recovery challenge",
			err:    &httpsec.ChallengeError{Kind: policy.ChallengeAccountRecovery},
			assert: onlyChallenge("account-recovery-required", "account-recovery"),
		},
		{
			// A consumer-built challenge: a token with no session, no methods
			// and a kind of the consumer's own.
			name: "consumer kind",
			err:  &httpsec.ChallengeError{Kind: consumerKind, Token: "tok-consumer", Session: nil, Methods: nil},
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				assert.Equal(t, map[string]any{
					"access_token": "tok-consumer",
				}, ofType(t, err, prob, "challenge-required"), "a kind outside the vocabulary names no challenge")
			},
		},
		{
			name: "max_age of a five-minute window",
			err:  fmt.Errorf("guard: %w", &httpsec.ReauthenticationRequiredError{Window: 5 * time.Minute}),
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				assert.Equal(t, map[string]any{"max_age": json.Number("300")}, ofType(t, err, prob, "reauthentication-required"))
			},
		},
		{
			name: "max_age rounds down",
			err:  &httpsec.ReauthenticationRequiredError{Window: 1999 * time.Millisecond},
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				assert.Equal(t, map[string]any{"max_age": json.Number("1")}, ofType(t, err, prob, "reauthentication-required"))
			},
		},
		{
			name: "max_age of a stale access token",
			err:  fmt.Errorf("guard: %w", &httpsec.InsufficientUserAuthenticationError{Window: 5 * time.Minute}),
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				assert.Equal(t, map[string]any{"max_age": json.Number("300")}, ofType(t, err, prob, "insufficient-user-authentication"))
			},
		},
		{name: "insufficient user authentication with no window", err: httpsec.ErrInsufficientUserAuthentication, assert: noMembers("insufficient-user-authentication")},
		{
			name: "scope of an access-token caller missing scopes",
			err: errors.Join(httpsec.ErrInsufficientScope,
				fmt.Errorf("rule: %w", &authorize.MissingScopesError{Scopes: []string{"orders:read", "orders:export"}, All: true})),
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				assert.Equal(t, map[string]any{"scope": "orders:read orders:export"}, ofType(t, err, prob, "insufficient-scope"))
			},
		},
		{name: "insufficient scope naming no scope", err: httpsec.ErrInsufficientScope, assert: noMembers("insufficient-scope")},
		{name: "zero window", err: &httpsec.ReauthenticationRequiredError{}, assert: noMembers("reauthentication-required")},
		{name: "negative window", err: &httpsec.ReauthenticationRequiredError{Window: -time.Second}, assert: noMembers("reauthentication-required")},
		{name: "reauthentication sentinel", err: httpsec.ErrReauthenticationRequired, assert: noMembers("reauthentication-required")},
		{
			name: "rule",
			err:  fmt.Errorf("change password: %w", password.RejectedError{Rule: password.RuleBreached}),
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				assert.Equal(t, map[string]any{"rule": string(password.RuleBreached)}, ofType(t, err, prob, "password-rejected"))
			},
		},
		{
			name: "rule from a pointer",
			err:  &password.RejectedError{Rule: password.RuleTooShort},
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				assert.Equal(t, map[string]any{"rule": string(password.RuleTooShort)}, ofType(t, err, prob, "password-rejected"))
			},
		},
		{name: "rejection without a rule", err: password.ErrPasswordRejected, assert: noMembers("password-rejected")},
		{
			name:   "typed-nil challenge joined with access denied",
			err:    errors.Join((*httpsec.ChallengeError)(nil), authorize.ErrAccessDenied),
			assert: noMembers("access-denied"),
		},
		{
			name:   "typed-nil challenge joined with a wrong password",
			err:    errors.Join(fmt.Errorf("x: %w", (*httpsec.ChallengeError)(nil)), authenticate.ErrAuthenticationFailed),
			assert: noMembers("authentication-failed"),
		},
		{
			name: "typed-nil challenge alone",
			err:  fmt.Errorf("x: %w", (*httpsec.ChallengeError)(nil)),
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				_, recognised := httpsec.LookupStatus(err)
				require.False(t, recognised)
				assert.Nil(t, prob)
			},
		},
		{
			// A typed-nil challenge ahead of a real one does not hide it.
			name: "typed-nil challenge ahead of a real one",
			err: errors.Join(
				(*httpsec.ChallengeError)(nil),
				&httpsec.ChallengeError{Kind: policy.ChallengeMFA, Methods: twoMethods, Token: "tok-real", TokenType: httpsec.TokenTypeBearer},
			),
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				ext := ofType(t, err, prob, "mfa-required")
				assert.Equal(t, "mfa", ext["challenge"])
				assert.Equal(t, "tok-real", ext["access_token"])
				assert.Equal(t, "Bearer", ext["token_type"])
				raw, _ := document(t, prob)
				assert.Contains(t, raw, `"methods":`+twoMethodsJSON)
			},
		},
		{
			name: "no dependency text",
			err: errors.Join(
				authenticate.ErrAuthenticationFailed,
				fmt.Errorf("attempt store: %w", errConn),
			),
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				ofType(t, err, prob, "authentication-failed")
				raw, _ := document(t, prob)
				assert.NotContains(t, raw, "alice@example.com")
			},
		},
		{
			name: "no dependency text in a challenge",
			err: fmt.Errorf("%w: %w",
				&httpsec.ChallengeError{
					Kind: policy.ChallengeMFA, Methods: twoMethods,
					Session: &session.Session{UserID: "alice@example.com"},
				},
				errConn),
			assert: func(t *testing.T, err error, prob *prblm.Problem) {
				t.Helper()
				ofType(t, err, prob, "mfa-required")
				raw, _ := document(t, prob)
				assert.NotContains(t, raw, "alice@example.com")
			},
		},
	}

	p := newProblems(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var prob *prblm.Problem
			require.NotPanics(t, func() { prob = p.Mapper().MapError(t.Context(), tc.err) })
			tc.assert(t, tc.err, prob)
			if prob != nil {
				_, doc := document(t, prob)
				for name := range extensions(doc) {
					assert.True(t, allowedMembers[name], "member %q is not allowed", name)
				}
				assert.NotContains(t, prob.Header, "Www-Authenticate")
			}
		})
	}
}

// TestMapper_MembersInXML renders through a full handler, since the XML
// encoding of the members is prblm's: it would replace a problem it cannot
// encode with its minimal 500 and report ErrEncoding.
func TestMapper_MembersInXML(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, status int, body string, notes []error)
	}

	cases := []testCase{
		{
			name: "methods and token",
			err: &httpsec.ChallengeError{
				Kind: policy.ChallengeMFA, Methods: twoMethods, Token: "tok-xml", TokenType: httpsec.TokenTypeDPoP,
			},
			assert: func(t *testing.T, status int, body string, notes []error) {
				t.Helper()
				assert.Equal(t, http.StatusUnauthorized, status)
				for _, n := range notes {
					assert.NotErrorIs(t, n, prblm.ErrEncoding)
				}
				assert.Contains(t, body, "<access_token>tok-xml</access_token>")
				assert.Contains(t, body, "<token_type>DPoP</token_type>")
				assert.Contains(t, body, "<methods><i><begins>false</begins><channel>authenticator-app</channel><name>totp</name></i>")
				assert.Contains(t, body, "<challenge>mfa</challenge>")
			},
		},
		{
			name: "empty methods",
			err: errors.Join(
				&httpsec.ChallengeError{Kind: policy.ChallengeMFA, Methods: []httpsec.MFAMethod{}},
			),
			assert: func(t *testing.T, status int, body string, notes []error) {
				t.Helper()
				assert.Equal(t, http.StatusUnauthorized, status)
				for _, n := range notes {
					assert.NotErrorIs(t, n, prblm.ErrEncoding)
				}
				assert.Contains(t, body, "<methods>")
			},
		},
		{
			name: "max_age",
			err:  &httpsec.ReauthenticationRequiredError{Window: 5 * time.Minute},
			assert: func(t *testing.T, status int, body string, notes []error) {
				t.Helper()
				assert.Equal(t, http.StatusForbidden, status)
				for _, n := range notes {
					assert.NotErrorIs(t, n, prblm.ErrEncoding)
				}
				assert.Contains(t, body, "<max_age>300</max_age>")
			},
		},
		{
			name: "rule",
			err:  password.RejectedError{Rule: password.RuleBreached},
			assert: func(t *testing.T, status int, body string, notes []error) {
				t.Helper()
				assert.Equal(t, http.StatusUnprocessableEntity, status)
				for _, n := range notes {
					assert.NotErrorIs(t, n, prblm.ErrEncoding)
				}
				assert.Contains(t, body, "<rule>breached</rule>")
			},
		},
	}

	p := newProblems(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var notes []error
			hook := prblm.AddErrorHook(func(_ context.Context, err error, _ *prblm.Problem) { notes = append(notes, err) })
			w := render(t, tc.err, "application/problem+xml", p.Option(), hook)
			assert.Equal(t, "application/problem+xml", w.Header().Get("Content-Type"))
			tc.assert(t, w.Code, w.Body.String(), notes)
		})
	}
}
