package prblmsec_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kartaladev/prblm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec/prblmsec"
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
		{name: "uppercase and dot-dot", opts: []prblmsec.Option{prblmsec.WithTypePrefix("Auth/../x")}, assert: refused},
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
	{"proof-of-possession-failed", 401},
	{"mfa-required", 401},
	{"challenge-required", 401},
	{"password-change-required", 403},
	{"mfa-enrolment-required", 403},
	{"account-recovery-required", 403},
	{"reauthentication-required", 403},
	{"cross-site-request", 403},
	{"automation-challenge-required", 403},
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

func (n *notes) assertNoTypeNotes() {
	n.t.Helper()
	for _, err := range n.calls {
		assert.NotErrorIs(n.t, err, prblm.ErrUndocumentedType)
		assert.NotErrorIs(n.t, err, prblm.ErrInvalidType)
	}
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
				})
			}

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
