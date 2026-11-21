package prblmsec_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kartaladev/prblm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/prblmsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

var (
	errApp  = errors.New("app: vessel not found")
	errFake = errors.New("driver: too many connections")
)

type rendered struct {
	Type   string `json:"type"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

func decode(t *testing.T, w *httptest.ResponseRecorder) rendered {
	t.Helper()
	var doc rendered
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	return doc
}

func TestMapper_DefersUnrecognised(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// handler gives the prblm options, in order, around the integration's.
		handler func(p *prblmsec.Problems) []prblm.Option
		err     error
		assert  func(t *testing.T, w *httptest.ResponseRecorder)
	}

	integrationThen := func(mappers ...prblm.Mapper) func(p *prblmsec.Problems) []prblm.Option {
		return func(p *prblmsec.Problems) []prblm.Option {
			return []prblm.Option{p.Option(), prblm.WithMappers(mappers...)}
		}
	}
	lockPage := prblm.Is(lockout.ErrAccountLocked, func(error) *prblm.Problem {
		return prblm.New(http.StatusTooManyRequests,
			prblm.WithType("app/locked"), prblm.WithTitle("Locked"),
			prblm.WithHeader("Retry-After", "900"))
	})
	consumerFirst := func(p *prblmsec.Problems) []prblm.Option {
		return []prblm.Option{prblm.WithMappers(lockPage), p.Option()}
	}

	cases := []testCase{
		{
			name:    "app error after integration",
			handler: integrationThen(prblm.Status(errApp, http.StatusNotFound)),
			err:     fmt.Errorf("handler: %w", errApp),
			assert: func(t *testing.T, w *httptest.ResponseRecorder) {
				t.Helper()
				assert.Equal(t, http.StatusNotFound, w.Code)
				doc := decode(t, w)
				assert.Equal(t, http.StatusNotFound, doc.Status)
				assert.Empty(t, doc.Type, "the consumer mapper's about:blank, not a scrty type")
			},
		},
		{
			name:    "unknown",
			handler: integrationThen(),
			err:     errConn,
			assert: func(t *testing.T, w *httptest.ResponseRecorder) {
				t.Helper()
				assert.Equal(t, http.StatusInternalServerError, w.Code)
				doc := decode(t, w)
				assert.Empty(t, doc.Type)
				assert.Empty(t, doc.Detail)
				assert.NotContains(t, w.Body.String(), "alice@example.com")
			},
		},
		{
			name:    "recognised failure not remapped",
			handler: integrationThen(prblm.Status(errFake, http.StatusServiceUnavailable)),
			err:     fmt.Errorf("%w: %w", password.ErrHistoryUnavailable, errFake),
			assert: func(t *testing.T, w *httptest.ResponseRecorder) {
				t.Helper()
				assert.Equal(t, http.StatusInternalServerError, w.Code)
				doc := decode(t, w)
				assert.Empty(t, doc.Type)
				assert.Empty(t, doc.Detail)
			},
		},
		{
			name:    "consumer override first: locked",
			handler: consumerFirst,
			err:     lockout.ErrAccountLocked,
			assert: func(t *testing.T, w *httptest.ResponseRecorder) {
				t.Helper()
				assert.Equal(t, http.StatusTooManyRequests, w.Code)
				assert.Equal(t, "900", w.Header().Get("Retry-After"))
				assert.Equal(t, "/probs/app/locked", decode(t, w).Type)
			},
		},
		{
			name:    "consumer override first: wrong password",
			handler: consumerFirst,
			err:     authenticate.ErrAuthenticationFailed,
			assert: func(t *testing.T, w *httptest.ResponseRecorder) {
				t.Helper()
				assert.Equal(t, http.StatusUnauthorized, w.Code)
				assert.Equal(t, "/probs/security/authentication-failed", decode(t, w).Type)
			},
		},
	}

	p := newProblems(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, render(t, tc.err, "", tc.handler(p)...))
		})
	}

	// One *Problems and one handler answer many requests at once; run with
	// -race.
	t.Run("parallel", func(t *testing.T) {
		t.Parallel()
		h := prblm.NewHandler(prblm.WithNamespace("/probs"), p.Option())
		errs := []error{
			authenticate.ErrAuthenticationFailed,
			authorize.ErrAccessDenied,
			&httpsec.ChallengeError{Kind: policy.ChallengeMFA, Methods: twoMethods, Token: "tok", TokenType: httpsec.TokenTypeBearer},
			&httpsec.ReauthenticationRequiredError{Window: 300e9},
			password.RejectedError{Rule: password.RuleBreached},
			errConn,
		}
		for i := range 100 {
			err := errs[i%len(errs)]
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				t.Parallel()
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", nil)
				w := httptest.NewRecorder()
				h.Write(w, req, err)
				assert.Equal(t, httpsec.StatusForError(err), w.Code)
			})
		}
	})
}
