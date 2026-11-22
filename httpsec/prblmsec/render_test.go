package prblmsec_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kartaladev/prblm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

// render writes err through a prblm handler with the namespace /probs and
// opts, for a POST to /login that accepts accept, and returns the response.
func render(t *testing.T, err error, accept string, opts ...prblm.Option) *httptest.ResponseRecorder {
	t.Helper()
	h := prblm.NewHandler(append([]prblm.Option{prblm.WithNamespace("/probs")}, opts...)...)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	h.Write(w, req, err)
	return w
}

// heldRefusal returns the error a lockout policy gives for an identifier held
// by its failure-streak limit, built the way the policy builds it.
func heldRefusal(t *testing.T) error {
	t.Helper()
	p, err := lockout.New(lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit))
	require.NoError(t, err)
	for range lockout.NISTFailureStreakLimit {
		require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", time.Now()))
	}
	d := p.Evaluate(t.Context(), &policy.Input{Username: "ada"})
	require.Equal(t, policy.Deny, d.Outcome)
	require.ErrorIs(t, d.Reason, lockout.ErrAccountHeld, "the fixture is not a hold")
	return d.Reason
}

func TestMapper_ConcealsWhatStatusConceals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, w *httptest.ResponseRecorder)
	}

	p := newProblems(t)
	wrongPassword := render(t, authenticate.ErrAuthenticationFailed, "", p.Option())
	require.Equal(t, http.StatusUnauthorized, wrongPassword.Code)

	sameAsWrongPassword := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		assert.Equal(t, wrongPassword.Code, w.Code)
		assert.Equal(t, wrongPassword.Body.String(), w.Body.String())
		assert.Equal(t, wrongPassword.Header(), w.Header())
	}

	cases := []testCase{
		{name: "wrong password", err: authenticate.ErrAuthenticationFailed, assert: sameAsWrongPassword},
		{
			name:   "concealed lock",
			err:    errors.Join(authenticate.ErrAuthenticationFailed, lockout.ErrAccountLocked),
			assert: sameAsWrongPassword,
		},
		{
			name:   "concealed held lock",
			err:    errors.Join(authenticate.ErrAuthenticationFailed, heldRefusal(t)),
			assert: sameAsWrongPassword,
		},
		{
			name:   "user store outage",
			err:    fmt.Errorf("%w: %w", authenticate.ErrUnavailable, errConn),
			assert: sameAsWrongPassword,
		},
		{
			name: "disclosed lock",
			err:  lockout.ErrAccountLocked,
			assert: func(t *testing.T, w *httptest.ResponseRecorder) {
				t.Helper()
				assert.Equal(t, http.StatusTooManyRequests, w.Code)
				var doc struct {
					Type string `json:"type"`
				}
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
				assert.Equal(t, "/probs/security/account-locked", doc.Type)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, render(t, tc.err, "", p.Option()))
		})
	}
}
