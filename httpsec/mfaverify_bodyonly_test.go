package httpsec_test

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/session"
)

// testMFAWrongCode is a code the method double refuses, posted beside a valid
// one elsewhere in the request.
const testMFAWrongCode = "000000"

// verifyRequest is a POST to the default verify path with the given query,
// content type and body.
func verifyRequest(ctx context.Context, query, contentType, body string) *http.Request {
	target := httpsec.DefaultMFAVerifyPath
	if query != "" {
		target += "?" + query
	}

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return req
}

// multipartVerifyRequest is a POST to the default verify path carrying the
// code as a multipart/form-data field.
func multipartVerifyRequest(ctx context.Context, t *testing.T) *http.Request {
	t.Helper()

	var buf bytes.Buffer

	w := multipart.NewWriter(&buf)
	require.NoError(t, w.WriteField("code", testMFACode))
	require.NoError(t, w.Close())

	return verifyRequest(ctx, "", w.FormDataContentType(), buf.String())
}

// TestVerifyReadsBodyOnly pins where the verify endpoint reads the code from:
// the "code" field of a URL-encoded POST body, and nowhere else. A code in the
// URL has already reached access logs, proxy logs and the Referer header, so it
// is never read; a body the endpoint cannot read is a code that was not
// presented, so it is refused before it is judged and is not counted against
// the user.
func TestVerifyReadsBodyOnly(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		request func(ctx context.Context, t *testing.T) *http.Request
		wire    func(h *mfaHarness)
		assert  func(t *testing.T, h *mfaHarness, s *session.Session, out served)
	}

	// missing and missingUncounted are the wiring and the answer for every
	// request whose code the endpoint cannot read: the throttle is still
	// checked first, nothing is verified, nothing is counted, and the refusal
	// is missing credentials with the challenge still pending.
	missing := func(h *mfaHarness) { h.allows().neverVerifies().recordsNoFailure() }
	missingUncounted := func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
		assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
		assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
	}

	cases := []testCase{
		{
			name: "a valid code in the query only",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "code="+testMFACode,
					"application/x-www-form-urlencoded", "")
			},
			wire:   missing,
			assert: missingUncounted,
		},
		{
			name: "a wrong code in the body and a valid one in the query",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "code="+testMFACode,
					"application/x-www-form-urlencoded", "code="+testMFAWrongCode)
			},
			wire: func(h *mfaHarness) {
				h.allows().recordsFailure()
				h.method.EXPECT().Verify(gomock.Any(), testMFAUser, testMFAWrongCode).
					Return(mfa.ErrInvalidCode)
			},
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
			},
		},
		{
			name:    "a valid code in a multipart body",
			request: multipartVerifyRequest,
			wire:    missing,
			assert:  missingUncounted,
		},
		{
			name: "a valid code in a JSON body",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/json", `{"code":"`+testMFACode+`"}`)
			},
			wire:   missing,
			assert: missingUncounted,
		},
		{
			name: "an empty body",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/x-www-form-urlencoded", "")
			},
			wire:   missing,
			assert: missingUncounted,
		},
		{
			name: "a body without the code field",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/x-www-form-urlencoded", "otp="+testMFACode)
			},
			wire:   missing,
			assert: missingUncounted,
		},
		{
			// It parses only in part: the code before the broken escape is not
			// read out of a body the client did not send whole.
			name: "a body that does not parse",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/x-www-form-urlencoded",
					"code="+testMFACode+"&junk=%zz")
			},
			wire:   missing,
			assert: missingUncounted,
		},
		{
			name: "a body over the limit",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/x-www-form-urlencoded",
					"code="+testMFACode+"&pad="+strings.Repeat("a", 8<<10))
			},
			wire: missing,
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, http.StatusRequestEntityTooLarge, httpsec.StatusForError(out.err))
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
			},
		},
		{
			// The throttle's check runs before the code is read, so a user
			// already locked out learns nothing new from an unreadable body.
			name: "a throttled user posting an empty body",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/x-www-form-urlencoded", "")
			},
			wire: func(h *mfaHarness) { h.throttles().neverVerifies().recordsNoFailure() },
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				require.ErrorIs(t, out.err, mfa.ErrVerifyThrottled)
				assert.NotErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
			},
		},
		{
			name: "a valid URL-encoded code",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return postCode(ctx, httpsec.DefaultMFAVerifyPath)
			},
			wire: func(h *mfaHarness) { h.allows().accepts().recordsNoFailure() },
			assert: func(t *testing.T, h *mfaHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, session.MFASatisfied, h.stored(t, h.resolved.ID).MFA)
			},
		},
		{
			// A guard against a regression to a plain string comparison of the
			// content type: a real client that names its charset must not be
			// refused as if it declared no form at all.
			name: "a valid code with a charset parameter on the content type",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "",
					"application/x-www-form-urlencoded; charset=utf-8", "code="+testMFACode)
			},
			wire: func(h *mfaHarness) { h.allows().accepts().recordsNoFailure() },
			assert: func(t *testing.T, h *mfaHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, session.MFASatisfied, h.stored(t, h.resolved.ID).MFA)
			},
		},
		{
			name: "a valid code with an upper-case media type",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "",
					"APPLICATION/X-WWW-FORM-URLENCODED", "code="+testMFACode)
			},
			wire: func(h *mfaHarness) { h.allows().accepts().recordsNoFailure() },
			assert: func(t *testing.T, h *mfaHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, session.MFASatisfied, h.stored(t, h.resolved.ID).MFA)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)

			s := h.pendingSession(t, factor.Password)
			tc.wire(h)

			out := serve(t, h.chain(t, s), tc.request(t.Context(), t))
			tc.assert(t, h, s, out)
		})
	}
}
