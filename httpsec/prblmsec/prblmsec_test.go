package prblmsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kartaladev/prblm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/prblmsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

func TestNew(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []prblmsec.Option
		assert func(t *testing.T, p *prblmsec.Problems, err error)
	}

	refused := func(t *testing.T, p *prblmsec.Problems, err error) {
		t.Helper()
		require.ErrorIs(t, err, prblmsec.ErrConfig)
		assert.Nil(t, p)
	}
	accepted := func(t *testing.T, p *prblmsec.Problems, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, p)
	}

	cases := []testCase{
		{name: "default", assert: accepted},
		{name: "custom prefix", opts: []prblmsec.Option{prblmsec.WithTypePrefix("auth")}, assert: accepted},
		{name: "nested prefix", opts: []prblmsec.Option{prblmsec.WithTypePrefix("auth/v1")}, assert: accepted},
		{name: "without challenge token", opts: []prblmsec.Option{prblmsec.WithoutChallengeToken()}, assert: accepted},
		{
			name: "uppercase and dot-dot",
			opts: []prblmsec.Option{prblmsec.WithTypePrefix("Auth/../x")},
			assert: func(t *testing.T, p *prblmsec.Problems, err error) {
				t.Helper()
				refused(t, p, err)
				assert.Contains(t, err.Error(), `type prefix "Auth/../x" is not a valid prblm sub-type`)
			},
		},
		{name: "empty", opts: []prblmsec.Option{prblmsec.WithTypePrefix("")}, assert: refused},
		{name: "double slash", opts: []prblmsec.Option{prblmsec.WithTypePrefix("a//b")}, assert: refused},
		{name: "nil option", opts: []prblmsec.Option{nil}, assert: refused},
		{
			name:   "prefix given twice",
			opts:   []prblmsec.Option{prblmsec.WithTypePrefix("a"), prblmsec.WithTypePrefix("b")},
			assert: refused,
		},
		{
			name:   "without challenge token given twice",
			opts:   []prblmsec.Option{prblmsec.WithoutChallengeToken(), prblmsec.WithoutChallengeToken()},
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := prblmsec.New(tc.opts...)
			tc.assert(t, p, err)
		})
	}
}

// specTypes is the spec's type table: sub-type and status.
var specTypes = []struct {
	sub    string
	status int
}{
	{"authentication-required", 401},
	{"authentication-failed", 401},
	{"second-factor-failed", 401},
	{"invalid-token", 401},
	{"insufficient-user-authentication", 401},
	{"proof-of-possession-failed", 401},
	{"mfa-required", 401},
	{"challenge-required", 401},
	{"password-change-required", 403},
	{"mfa-enrolment-required", 403},
	{"account-recovery-required", 403},
	{"reauthentication-required", 403},
	{"insufficient-scope", 403},
	{"cross-site-request", 403},
	{"automation-challenge-required", 403},
	{"account-inactive", 403},
	{"access-denied", 403},
	{"invalid-request", 400},
	{"not-found", 404},
	{"conflict", 409},
	{"request-too-large", 413},
	{"password-rejected", 422},
	{"account-locked", 429},
	{"limit-reached", 429},
}

type notes struct {
	t     *testing.T
	calls []error
}

func (n *notes) hook(_ context.Context, err error, _ *prblm.Problem) {
	n.calls = append(n.calls, err)
}

// typeNotes returns the notes prblm sent about a problem's type: one with no
// registered definition, or one that is not a valid sub-type.
func (n *notes) typeNotes() []error {
	var out []error
	for _, err := range n.calls {
		if errors.Is(err, prblm.ErrUndocumentedType) || errors.Is(err, prblm.ErrInvalidType) {
			out = append(out, err)
		}
	}
	return out
}

func (n *notes) assertNoTypeNotes() {
	n.t.Helper()
	assert.Empty(n.t, n.typeNotes())
}

// representative is, for each sub-type, a refusal the real mapper answers
// with it.
var representative = map[string]error{
	"authentication-required":          httpsec.ErrAuthenticationRequired,
	"authentication-failed":            authenticate.ErrAuthenticationFailed,
	"second-factor-failed":             mfa.ErrInvalidCode,
	"proof-of-possession-failed":       httpsec.ErrInvalidDPoPProof,
	"invalid-token":                    httpsec.ErrInvalidToken,
	"insufficient-user-authentication": httpsec.ErrInsufficientUserAuthentication,
	"mfa-required":                     &httpsec.ChallengeError{Kind: policy.ChallengeMFA},
	"challenge-required":               &httpsec.ChallengeError{Kind: policy.ChallengeKind(100)},
	"password-change-required":         &httpsec.ChallengeError{Kind: policy.ChallengePasswordChange},
	"mfa-enrolment-required":           &httpsec.ChallengeError{Kind: policy.ChallengeMFAEnrolment},
	"account-recovery-required":        &httpsec.ChallengeError{Kind: policy.ChallengeAccountRecovery},
	"reauthentication-required":        httpsec.ErrReauthenticationRequired,
	"insufficient-scope":               errors.Join(httpsec.ErrInsufficientScope, &authorize.MissingScopesError{Scopes: []string{"orders:write"}}),
	"cross-site-request":               httpsec.ErrCrossSiteRequest,
	"automation-challenge-required":    httpsec.ErrChallengeRequired,
	"account-inactive":                 authenticate.ErrAccountInactive,
	"access-denied":                    authorize.ErrAccessDenied,
	"invalid-request":                  httpsec.ErrMalformedRequest,
	"not-found":                        httpsec.ErrUnknownMFAMethod,
	"conflict":                         session.ErrRenewalConflict,
	"request-too-large":                httpsec.ErrRequestTooLarge,
	"password-rejected":                password.ErrReused,
	"account-locked":                   lockout.ErrAccountLocked,
	"limit-reached":                    policy.ErrTooManySessions,
}

func TestTypes_DocumentEveryType(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []prblmsec.Option
		prefix string
	}

	cases := []testCase{
		{name: "default prefix", prefix: "security"},
		{name: "nested prefix", opts: []prblmsec.Option{prblmsec.WithTypePrefix("auth/v1")}, prefix: "auth/v1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := prblmsec.New(tc.opts...)
			require.NoError(t, err)

			rec := &notes{t: t}
			h := prblm.NewHandler(prblm.WithNamespace("/probs"), p.Option(), prblm.AddErrorHook(rec.hook))

			require.Len(t, p.Types(), len(specTypes))

			for _, st := range specTypes {
				t.Run(st.sub, func(t *testing.T) {
					// Documentation page answers 200 with the type's status.
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/probs/"+tc.prefix+"/"+st.sub, nil)
					req.Header.Set("Accept", "application/json")
					w := httptest.NewRecorder()
					h.Discovery().ServeHTTP(w, req)

					require.Equal(t, http.StatusOK, w.Code)
					var doc struct {
						Status int `json:"status"`
					}
					require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
					assert.Equal(t, st.status, doc.Status)

					// A problem built from the type is answered without a type note.
					var found *prblm.Type
					for _, ty := range p.Types() {
						if ty.Subtype() == tc.prefix+"/"+st.sub {
							found = ty
						}
					}
					require.NotNil(t, found)
					assert.Equal(t, st.status, found.Status())
					assert.NotEmpty(t, found.Title())

					rw := httptest.NewRecorder()
					h.Write(rw, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil), found.New())
					assert.Equal(t, st.status, rw.Code)

					// So is the real mapper's problem for a refusal of the type.
					refusal, ok := representative[st.sub]
					require.True(t, ok, "no representative refusal for %s", st.sub)
					mw := httptest.NewRecorder()
					h.Write(mw, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil), refusal)
					assert.Equal(t, st.status, mw.Code)
					var mdoc struct {
						Type string `json:"type"`
					}
					require.NoError(t, json.Unmarshal(mw.Body.Bytes(), &mdoc))
					assert.Equal(t, "/probs/"+tc.prefix+"/"+st.sub, mdoc.Type)
				})
			}

			// Negative control: the same check reports a problem whose type
			// the handler does not document.
			t.Run("unregistered type is noted", func(t *testing.T) {
				ctl := &notes{t: t}
				ch := prblm.NewHandler(prblm.WithNamespace("/probs"), p.Option(), prblm.AddErrorHook(ctl.hook))
				stray := prblm.DefineType(tc.prefix+"/unregistered", http.StatusBadRequest, "Stray", "")
				ch.Write(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil), stray.New())
				assert.NotEmpty(t, ctl.typeNotes())
			})

			rec.assertNoTypeNotes()
		})
	}
}

func TestTypes_FreshSlice(t *testing.T) {
	t.Parallel()

	p, err := prblmsec.New()
	require.NoError(t, err)

	first := p.Types()
	require.NotEmpty(t, first)
	want := first[0]
	first[0] = nil

	second := p.Types()
	assert.Same(t, want, second[0])
}

// TestProblems_NotBuiltByNew pins that a *Problems which did not come from New
// fails where it is wired (nil) or maps nothing (zero value), never answering
// a refusal with a problem the integration did not define.
func TestProblems_NotBuiltByNew(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(ctx context.Context) any
		assert func(t *testing.T, panicked bool, result any)
	}

	panics := func(t *testing.T, panicked bool, _ any) {
		t.Helper()
		assert.True(t, panicked, "a nil *Problems must panic when wired, not at the first refusal")
	}

	cases := []testCase{
		{name: "nil Mapper", act: func(context.Context) any { return (*prblmsec.Problems)(nil).Mapper() }, assert: panics},
		{name: "nil Types", act: func(context.Context) any { return (*prblmsec.Problems)(nil).Types() }, assert: panics},
		{name: "nil Option", act: func(context.Context) any { return (*prblmsec.Problems)(nil).Option() }, assert: panics},
		{
			name: "zero value maps nothing",
			act: func(ctx context.Context) any {
				m := (&prblmsec.Problems{}).Mapper()
				return []*prblm.Problem{
					m.MapError(ctx, authorize.ErrAccessDenied),
					m.MapError(ctx, authenticate.ErrAuthenticationFailed),
					m.MapError(ctx, httpsec.ErrChallengeUnavailable),
				}
			},
			assert: func(t *testing.T, panicked bool, result any) {
				t.Helper()
				require.False(t, panicked)
				for _, prob := range result.([]*prblm.Problem) {
					assert.Nil(t, prob)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var (
				result   any
				panicked bool
			)
			func() {
				defer func() { panicked = recover() != nil }()
				result = tc.act(t.Context())
			}()
			tc.assert(t, panicked, result)
		})
	}
}
