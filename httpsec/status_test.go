package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

func TestStatusForError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		err  error
		want int
	}

	cases := []testCase{
		{name: "authentication required", err: httpsec.ErrAuthenticationRequired, want: 401},
		{name: "authorize's authentication required", err: authorize.ErrAuthenticationRequired, want: 401},
		{
			name: "the stage's wrap matches both identities",
			err:  fmt.Errorf("%w: %w", httpsec.ErrAuthenticationRequired, authorize.ErrAuthenticationRequired),
			want: 401,
		},
		{name: "authentication failed", err: authenticate.ErrAuthenticationFailed, want: 401},
		{name: "session idle", err: policy.ErrSessionIdle, want: 401},
		{name: "throttled source", err: ratelimit.ErrThrottled, want: 401},
		{name: "access denied", err: authorize.ErrAccessDenied, want: 403},
		{name: "reasonless policy deny", err: policy.ErrPolicyDenied, want: 403},
		{name: "second factor required", err: policy.ErrMFARequired, want: 403},
		{name: "second factor unsatisfiable", err: policy.ErrMFARequirementUnsatisfiable, want: 403},
		{name: "second factor enrolment required", err: policy.ErrMFAEnrollmentRequired, want: 403},
		{name: "second factor on the first factor's channel", err: policy.ErrSecondFactorSameChannel, want: 403},
		{name: "malformed login", err: httpsec.ErrCredentialsMissing, want: 400},
		{name: "request too large", err: httpsec.ErrRequestTooLarge, want: 413},
		{name: "account locked", err: policy.ErrAccountLocked, want: 423},
		{name: "too many sessions", err: policy.ErrTooManySessions, want: 429},
		{name: "unknown identity provider", err: oidc.ErrUnknownProvider, want: 404},
		{name: "invalid logout token", err: oidc.ErrInvalidLogoutToken, want: 400},
		{name: "invalid handoff is an authentication failure with no row", err: oidc.ErrInvalidHandoff, want: 401},
		{name: "wrapped invalid ID token", err: fmt.Errorf("x: %w", oidc.ErrInvalidIDToken), want: 401},

		{
			name: "wrapped sentinel keeps its status",
			err:  fmt.Errorf("evaluating the rule set: %w", authorize.ErrAccessDenied),
			want: 403,
		},
		{
			name: "joined verification failure keeps its status",
			err:  errors.Join(authenticate.ErrAuthenticationFailed, errors.New("token: signature invalid")),
			want: 401,
		},
		{
			name: "second-factor challenge",
			err:  &httpsec.ChallengeError{Kind: policy.ChallengeMFA},
			want: 401,
		},
		{
			name: "password-change challenge",
			err:  &httpsec.ChallengeError{Kind: policy.ChallengePasswordChange},
			want: 403,
		},
		{
			name: "a challenge reached through a wrap is still a challenge",
			err: fmt.Errorf("completing the login: %w",
				&httpsec.ChallengeError{Kind: policy.ChallengePasswordChange}),
			want: 403,
		},
		{
			name: "a challenge outranks a sentinel it wraps",
			err: fmt.Errorf("%w: %w",
				&httpsec.ChallengeError{Kind: policy.ChallengeMFA}, authorize.ErrAccessDenied),
			want: 401,
		},
		{
			name: "an unrecognised error is a server fault",
			err:  errors.New("connection refused to db-primary:5432"),
			want: 500,
		},
		{name: "nil is a server fault", err: nil, want: 500},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, httpsec.StatusForError(tc.err))
		})
	}
}

// denyPolicy denies with no reason at all, which is what a consumer policy
// that refuses without explaining itself looks like to the engine.
type denyPolicy struct{ phase policy.Phase }

func (denyPolicy) Name() string             { return "test: reasonless deny" }
func (p denyPolicy) Phases() []policy.Phase { return []policy.Phase{p.phase} }
func (denyPolicy) Evaluate(context.Context, *policy.Input) policy.Decision {
	return policy.Decision{Outcome: policy.Deny}
}

func TestPolicyDenyReason(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		phase  policy.Phase
		assert func(t *testing.T, reason error)
	}

	cases := []testCase{
		{
			name:  "a reasonless deny at login refuses with the engine's substituted sentinel",
			phase: policy.PostAuthentication,
			assert: func(t *testing.T, reason error) {
				require.ErrorIs(t, reason, policy.ErrPolicyDenied)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(reason))
				assert.NotEqual(t, http.StatusOK, httpsec.StatusForError(reason))
				assert.False(t, errors.Is(reason, authenticate.ErrAuthenticationFailed),
					"a policy deny must never read as a failed credential")
			},
		},
		{
			name:  "a reasonless deny per request refuses the same way",
			phase: policy.PerRequest,
			assert: func(t *testing.T, reason error) {
				require.ErrorIs(t, reason, policy.ErrPolicyDenied)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(reason))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			engine, err := policy.NewEngine(denyPolicy{phase: tc.phase})
			require.NoError(t, err)

			d := engine.EvaluatePhase(t.Context(), tc.phase, &policy.Input{Now: time.Now()})
			require.Equal(t, policy.Deny, d.Outcome)

			reason := httpsec.PolicyDenyReason(d)
			require.Error(t, reason, "a deny the engine reduced always carries a reason")
			tc.assert(t, reason)
		})
	}
}

// sentinelRegistry lists every exported refusal sentinel of the packages whose
// refusals reach a client through this chain. It is written out because
// reflection cannot enumerate package-level variables; declaredErrVars keeps it
// honest by failing when a package exports one that is not listed here.
var sentinelRegistry = map[string]map[string]error{
	"github.com/kartaladev/scrty/authenticate": {
		"authenticate.ErrAuthenticationFailed":    authenticate.ErrAuthenticationFailed,
		"authenticate.ErrConfig":                  authenticate.ErrConfig,
		"authenticate.ErrNoEligibleAuthenticator": authenticate.ErrNoEligibleAuthenticator,
		"authenticate.ErrUnsupportedCredentials":  authenticate.ErrUnsupportedCredentials,
	},
	"github.com/kartaladev/scrty/authorize": {
		"authorize.ErrAccessDenied":           authorize.ErrAccessDenied,
		"authorize.ErrAuthenticationRequired": authorize.ErrAuthenticationRequired,
		"authorize.ErrConfig":                 authorize.ErrConfig,
		"authorize.ErrInvalidAttributes":      authorize.ErrInvalidAttributes,
		"authorize.ErrUnsupportedAttributes":  authorize.ErrUnsupportedAttributes,
	},
	"github.com/kartaladev/scrty/oidc": {
		"oidc.ErrConfig":              oidc.ErrConfig,
		"oidc.ErrDiscoveryFailed":     oidc.ErrDiscoveryFailed,
		"oidc.ErrExchangeFailed":      oidc.ErrExchangeFailed,
		"oidc.ErrFlowStoreFull":       oidc.ErrFlowStoreFull,
		"oidc.ErrFlowUnspent":         oidc.ErrFlowUnspent,
		"oidc.ErrHandoffNotFound":     oidc.ErrHandoffNotFound,
		"oidc.ErrInvalidHandoff":      oidc.ErrInvalidHandoff,
		"oidc.ErrInvalidIDToken":      oidc.ErrInvalidIDToken,
		"oidc.ErrInvalidLogoutToken":  oidc.ErrInvalidLogoutToken,
		"oidc.ErrInvalidState":        oidc.ErrInvalidState,
		"oidc.ErrLinkExists":          oidc.ErrLinkExists,
		"oidc.ErrLinkNotFound":        oidc.ErrLinkNotFound,
		"oidc.ErrNoLinkedAccount":     oidc.ErrNoLinkedAccount,
		"oidc.ErrProvisioningRefused": oidc.ErrProvisioningRefused,
		"oidc.ErrRetainSinceRequired": oidc.ErrRetainSinceRequired,
		"oidc.ErrUnknownProvider":     oidc.ErrUnknownProvider,
	},
	"github.com/kartaladev/scrty/policy": {
		"policy.ErrAccountLocked":               policy.ErrAccountLocked,
		"policy.ErrConfig":                      policy.ErrConfig,
		"policy.ErrMFAEnrollmentRequired":       policy.ErrMFAEnrollmentRequired,
		"policy.ErrMFARequired":                 policy.ErrMFARequired,
		"policy.ErrMFARequirementLookupMissing": policy.ErrMFARequirementLookupMissing,
		"policy.ErrMFARequirementUnsatisfiable": policy.ErrMFARequirementUnsatisfiable,
		"policy.ErrPolicyDenied":                policy.ErrPolicyDenied,
		"policy.ErrReapUnsupported":             policy.ErrReapUnsupported,
		"policy.ErrRetainSinceRequired":         policy.ErrRetainSinceRequired,
		"policy.ErrSecondFactorSameChannel":     policy.ErrSecondFactorSameChannel,
		"policy.ErrSessionIdle":                 policy.ErrSessionIdle,
		"policy.ErrTooManySessions":             policy.ErrTooManySessions,
	},
	"github.com/kartaladev/scrty/ratelimit": {
		"ratelimit.ErrConfig":               ratelimit.ErrConfig,
		"ratelimit.ErrSourceEmpty":          ratelimit.ErrSourceEmpty,
		"ratelimit.ErrSourceNotAnIP":        ratelimit.ErrSourceNotAnIP,
		"ratelimit.ErrSourceUnattributable": ratelimit.ErrSourceUnattributable,
		"ratelimit.ErrSourceUnspecified":    ratelimit.ErrSourceUnspecified,
		"ratelimit.ErrThrottled":            ratelimit.ErrThrottled,
	},
	"github.com/kartaladev/scrty/session": {
		"session.ErrConfig":            session.ErrConfig,
		"session.ErrSessionExpired":    session.ErrSessionExpired,
		"session.ErrSessionNotFound":   session.ErrSessionNotFound,
		"session.ErrSessionUnreadable": session.ErrSessionUnreadable,
	},
}

// TestStatusForErrorCoversEverySentinel fails when a mapped package exports a
// refusal sentinel StatusForError does not recognise. A new sentinel is then a
// deliberate decision about its status, not an accidental 500.
func TestStatusForErrorCoversEverySentinel(t *testing.T) {
	t.Parallel()

	// Sentinels that are deliberately unmapped, each with the reason. A
	// configuration error is a wiring fault the consumer sees at construction,
	// never a refusal a client is answered with.
	unmapped := map[string]string{
		"authenticate.ErrConfig":                  "a wiring fault, refused at construction",
		"authenticate.ErrNoEligibleAuthenticator": "a wiring fault: nothing was configured to judge the credentials",
		"authenticate.ErrUnsupportedCredentials":  "internal dispatch between providers, never returned to a client",
		"authorize.ErrConfig":                     "a wiring fault, refused at construction",
		"authorize.ErrUnsupportedAttributes":      "a misbuilt guard, deliberately 500 per design Decision 7",
		"authorize.ErrInvalidAttributes":          "a misbuilt guard, deliberately 500 per design Decision 7",
		"session.ErrConfig":                       "a wiring fault, refused at construction",
		"session.ErrSessionNotFound":              "converted to ErrAuthenticationRequired before it leaves the chain",
		"session.ErrSessionExpired":               "converted to ErrAuthenticationRequired before it leaves the chain",
		"session.ErrSessionUnreadable":            "converted to ErrAuthenticationRequired before it leaves the chain",
		"ratelimit.ErrConfig":                     "a wiring fault, refused at construction",
		"ratelimit.ErrSourceUnattributable":       "converted to authenticate.ErrAuthenticationFailed before it leaves the chain",
		"ratelimit.ErrSourceEmpty":                "converted to authenticate.ErrAuthenticationFailed before it leaves the chain",
		"ratelimit.ErrSourceNotAnIP":              "converted to authenticate.ErrAuthenticationFailed before it leaves the chain",
		"ratelimit.ErrSourceUnspecified":          "converted to authenticate.ErrAuthenticationFailed before it leaves the chain",
		"policy.ErrConfig":                        "a wiring fault, refused at construction",
		"policy.ErrReapUnsupported":               "a maintenance-path fault, not a request refusal",
		"policy.ErrRetainSinceRequired":           "a maintenance-path fault, not a request refusal",
		"policy.ErrMFARequirementLookupMissing":   "a wiring fault, refused at construction",
		"oidc.ErrConfig":                          "a wiring fault, refused at construction",
		"oidc.ErrExchangeFailed":                  "a provider failure, deliberately 500",
		"oidc.ErrDiscoveryFailed":                 "a provider failure, deliberately 500",
		"oidc.ErrLinkNotFound":                    "a store outcome the library converts before it leaves oidc",
		"oidc.ErrLinkExists":                      "a store outcome the library converts before it leaves oidc",
		"oidc.ErrHandoffNotFound":                 "a store outcome the library converts before it leaves oidc",
		"oidc.ErrRetainSinceRequired":             "a purge misuse, never a request outcome",
		"oidc.ErrFlowStoreFull":                   "capacity exhaustion, deliberately 500",
		"oidc.ErrFlowUnspent":                     "a marker joined onto another refusal, never returned alone",
	}

	for _, pkg := range []string{
		"github.com/kartaladev/scrty/authenticate",
		"github.com/kartaladev/scrty/authorize",
		"github.com/kartaladev/scrty/oidc",
		"github.com/kartaladev/scrty/policy",
		"github.com/kartaladev/scrty/ratelimit",
		"github.com/kartaladev/scrty/session",
	} {
		for name, err := range exportedSentinels(t, pkg) {
			if _, ok := unmapped[name]; ok {
				continue
			}
			t.Run(name, func(t *testing.T) {
				assert.NotEqual(t, http.StatusInternalServerError, httpsec.StatusForError(err),
					"%s is exported as a refusal but StatusForError does not recognise it; "+
						"add it to statusTable, or to this test's unmapped map with the reason", name)
			})
		}
	}
}

// exportedSentinels returns every exported Err* variable of pkg, keyed
// "<pkg>.<Name>". It cross-checks the registry against the package's source,
// so a sentinel added without being registered fails the test rather than
// being skipped.
func exportedSentinels(t *testing.T, pkg string) map[string]error {
	t.Helper()

	registered := sentinelRegistry[pkg]
	require.NotEmpty(t, registered, "no sentinels registered for %s", pkg)

	for _, name := range declaredErrVars(t, pkg) {
		_, ok := registered[path.Base(pkg)+"."+name]
		assert.True(t, ok, "%s.%s is exported but not registered in sentinelRegistry", pkg, name)
	}

	return registered
}

// declaredErrVars names the exported Err* package-level variables pkg declares,
// read from its source. It parses rather than reflecting because reflection
// cannot enumerate package-level variables, and it reads the files directly so
// this package gains no tooling dependency to do it.
func declaredErrVars(t *testing.T, pkg string) []string {
	t.Helper()

	const modulePrefix = "github.com/kartaladev/scrty/"
	require.True(t, strings.HasPrefix(pkg, modulePrefix), "%s is outside this module", pkg)
	dir := filepath.Join("..", filepath.FromSlash(strings.TrimPrefix(pkg, modulePrefix)))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "reading %s", dir)

	fset := token.NewFileSet()

	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		require.NoError(t, err, "parsing %s", name)

		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, ident := range vs.Names {
					if strings.HasPrefix(ident.Name, "Err") && ident.IsExported() {
						names = append(names, ident.Name)
					}
				}
			}
		}
	}

	require.NotEmpty(t, names, "no exported Err* variables found in %s", dir)
	return names
}
