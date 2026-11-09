package ginsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
	"github.com/kartaladev/scrty/identity"
)

// countingAttempts counts what Basic authentication records and clears, and
// otherwise answers as an empty store.
type countingAttempts struct{ fails, resets atomic.Int32 }

func (c *countingAttempts) RecordFailure(context.Context, string, time.Time) error {
	c.fails.Add(1)
	return nil
}

func (c *countingAttempts) Reset(context.Context, string) error {
	c.resets.Add(1)
	return nil
}

func (*countingAttempts) FailureCount(context.Context, string, time.Time) (int, error) {
	return 0, nil
}

// countingAuthenticator counts its calls, and answers with err or, when err is
// nil, with one principal.
type countingAuthenticator struct {
	calls atomic.Int32
	err   error
}

func (a *countingAuthenticator) Authenticate(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
	a.calls.Add(1)

	if a.err != nil {
		return nil, a.err
	}

	return &authenticate.Authentication{Principal: &identity.Principal{ID: "u-1", Username: "ada"}}, nil
}

// TestRepro_DoubleMount pins that one chain used by a gin engine and by one of
// its route groups runs once on a request to that group: the credentials are
// verified once and the attempt counters are touched once.
func TestRepro_DoubleMount(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		authErr error
		assert  func(t *testing.T, a *countingAuthenticator, at *countingAttempts, rec *httptest.ResponseRecorder)
	}

	cases := []testCase{
		{
			name:    "a refused Basic login is charged once",
			authErr: authenticate.ErrAuthenticationFailed,
			assert: func(t *testing.T, a *countingAuthenticator, at *countingAttempts, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
				assert.EqualValues(t, 1, a.calls.Load(), "authenticator calls")
				assert.EqualValues(t, 1, at.fails.Load(), "failures recorded")
			},
		},
		{
			name: "a successful Basic login authenticates once",
			assert: func(t *testing.T, a *countingAuthenticator, at *countingAttempts, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.EqualValues(t, 1, a.calls.Load(), "authenticator calls")
				assert.EqualValues(t, 1, at.resets.Load(), "resets")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a := &countingAuthenticator{err: tc.authErr}
			at := &countingAttempts{}
			chain := newChain(t, httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: a, Attempts: at}))

			eng := gin.New()
			eng.Use(ginsec.Middleware(chain))
			g := eng.Group("/api")
			g.Use(ginsec.Middleware(chain))
			g.GET("/x", func(gc *gin.Context) { gc.Status(http.StatusOK) })

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/x", nil)
			req.SetBasicAuth("ada", "pw")

			rec := httptest.NewRecorder()
			eng.ServeHTTP(rec, req)

			tc.assert(t, a, at, rec)
		})
	}
}
