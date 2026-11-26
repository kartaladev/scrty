package httpsec

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// TestPrefersHTML pins how a cookie chain's sign-in tells a browser's
// navigation or form post from a script: a form body, or an Accept header
// ranking text/html above application/json by its q-values and the most
// specific range matching each, answers HTML; everything else, a malformed
// Accept included, answers JSON.
func TestPrefersHTML(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		contentType string
		accept      []string
		assert      func(t *testing.T, html bool)
	}

	html := func(t *testing.T, got bool) {
		t.Helper()
		assert.True(t, got, "the request prefers HTML")
	}
	json := func(t *testing.T, got bool) {
		t.Helper()
		assert.False(t, got, "the request is answered JSON")
	}

	cases := []testCase{
		{name: "URL-encoded form", contentType: "application/x-www-form-urlencoded", assert: html},
		{name: "form with a charset", contentType: "application/x-www-form-urlencoded; charset=utf-8", assert: html},
		{name: "multipart form", contentType: "multipart/form-data; boundary=x", assert: html},
		{
			name: "form wins over an Accept preferring JSON", contentType: "application/x-www-form-urlencoded",
			accept: []string{"application/json"}, assert: html,
		},
		{name: "no Accept, no body", assert: json},
		{name: "JSON body, no Accept", contentType: "application/json", assert: json},
		{name: "Accept text/html", contentType: "application/json", accept: []string{"text/html"}, assert: html},
		{
			name:   "a browser navigation's Accept",
			accept: []string{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}, assert: html,
		},
		{name: "Accept application/json", accept: []string{"application/json"}, assert: json},
		{name: "Accept */* ranks both alike", accept: []string{"*/*"}, assert: json},
		{name: "Accept text/* ranks HTML above JSON", accept: []string{"text/*"}, assert: html},
		{name: "equal q-values answer JSON", accept: []string{"text/html, application/json"}, assert: json},
		{name: "q-values ranking JSON first", accept: []string{"text/html;q=0.5, application/json;q=0.9"}, assert: json},
		{name: "q-values ranking HTML first", accept: []string{"application/json;q=0.4, text/html;q=0.6"}, assert: html},
		{name: "q=0 refuses HTML", accept: []string{"text/html;q=0, */*"}, assert: json},
		{name: "the specific range beats the wildcard", accept: []string{"*/*;q=0.1, text/html"}, assert: html},
		{name: "the specific range's q=0 beats the wildcard", accept: []string{"text/html;q=0, text/*"}, assert: json},
		{name: "case-insensitive media types", accept: []string{"TEXT/HTML"}, assert: html},
		{name: "ranges over two header lines", accept: []string{"application/json;q=0.2", "text/html"}, assert: html},
		{name: "malformed range", accept: []string{"text/html, ;;"}, assert: json},
		{name: "range without a subtype", accept: []string{"text"}, assert: json},
		{name: "q not a number", accept: []string{"text/html;q=high"}, assert: json},
		{name: "q above 1", accept: []string{"text/html;q=2"}, assert: json},
		{name: "negative q", accept: []string{"text/html;q=-1, application/json;q=0.1"}, assert: json},
		{name: "q is NaN", accept: []string{"text/html;q=NaN"}, assert: json},
		{name: "q in hexadecimal float form", accept: []string{"text/html;q=0x1p-1"}, assert: json},
		{name: "q in exponent form", accept: []string{"text/html;q=1e0"}, assert: json},
		{name: "q with more than three digits", accept: []string{"text/html;q=0.5000"}, assert: json},
		{name: "q with no leading digit", accept: []string{"text/html;q=.5"}, assert: json},
		{name: "q with an explicit plus", accept: []string{"text/html;q=+0.5"}, assert: json},
		{name: "q of 1 with a non-zero fraction", accept: []string{"text/html;q=1.001"}, assert: json},
		{name: "q with a trailing dot", accept: []string{"text/html;q=1."}, assert: json},
		{name: "q of 0.5 is valid", accept: []string{"text/html;q=0.5"}, assert: html},
		{name: "q of 1.000 is valid", accept: []string{"text/html;q=1.000, application/json;q=0.999"}, assert: html},
		{name: "q of 0.001 is valid and ranks above 0", accept: []string{"text/html;q=0.001"}, assert: html},
		{name: "q of 0.000 refuses HTML", accept: []string{"text/html;q=0.000, */*"}, assert: json},
		{name: "duplicated parameter", accept: []string{"text/html;q=1;q=0.5"}, assert: json},
		{name: "too many ranges", accept: []string{strings.Repeat("a/b,", 200) + "text/html"}, assert: json},
		{name: "unparsable content type falls to Accept", contentType: ";;", accept: []string{"text/html"}, assert: html},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/sign-in", nil)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}

			for _, a := range tc.accept {
				req.Header.Add("Accept", a)
			}

			tc.assert(t, prefersHTML(NewHTTPRequest(req)))
		})
	}
}

// TestSessionCookie_AnswerRecovery pins the document a cookie chain's default
// answer to a completed recovery writes when the request does not prefer HTML
// (a form post always does, so this is reached by a request that names its
// body some other way): the saved codes are a member only when the recovery
// reissued them, and are absent, not null, otherwise.
func TestSessionCookie_AnswerRecovery(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		codes  []string
		assert func(t *testing.T, rec *httptest.ResponseRecorder)
	}

	cases := []testCase{
		{
			name: "no reissued codes omits the member",
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusOK, rec.Code)
				assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
				assert.NotContains(t, rec.Body.String(), "recovery_codes", "not even as null")
				assert.JSONEq(t, `{"idle_expires_at":"2030-01-02T03:04:05Z","remaining":3,"low":true}`, rec.Body.String())
			},
		},
		{
			name:  "empty reissued codes omit the member",
			codes: []string{},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.NotContains(t, rec.Body.String(), "recovery_codes")
			},
		},
		{
			name:  "reissued codes are shown",
			codes: []string{"aaaa-bbbb", "cccc-dddd"},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.JSONEq(t,
					`{"idle_expires_at":"2030-01-02T03:04:05Z","recovery_codes":["aaaa-bbbb","cccc-dddd"],"remaining":3,"low":true}`,
					rec.Body.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/recover", nil)
			rec := httptest.NewRecorder()
			ex := &Exchange{Request: NewHTTPRequest(req), Writer: NewHTTPResponseWriter(rec)}

			c := &sessionCookie{nextParam: DefaultSessionCookieNextParam}
			err := c.answerRecovery(ex, RecoveryResult{Recovery: &recovery.Result{
				Session:   &session.Session{IdleExpiresAt: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)},
				Codes:     tc.codes,
				Remaining: recovery.RemainingCodes{N: 3, Low: true},
			}})
			require.NoError(t, err)

			tc.assert(t, rec)
		})
	}
}
