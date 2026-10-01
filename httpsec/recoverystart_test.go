package httpsec_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/recovery"
)

var (
	errRecoveryLookup = errors.New("recovery test: the user store is down")
	errRecoveryTokens = errors.New("recovery test: the token store is down")
	errRecoverySend   = errors.New("recovery test: the sender refused")
)

// TestRecoveryStart pins spec account-recovery "Starting a recovery reveals
// nothing about the account": every cause the start can meet is answered with
// the first row's status, headers and empty body, and never a cookie. Each row
// also shows its cause was the one met, so a row cannot pass by never reaching
// it.
//
// The rows run in order, not in parallel: every row compares its response to
// the first row's.
func TestRecoveryStart(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// arrange changes the harness before the chain is built.
		arrange func(t *testing.T, h *recoveryHarness)

		// request is the start request, made once the chain is built.
		request func(t *testing.T, h *recoveryHarness) *http.Request

		// assert checks the cause was met, given how many messages the
		// sender held before the request.
		assert func(t *testing.T, h *recoveryHarness, sentBefore int)
	}

	form := func(username string) func(t *testing.T, h *recoveryHarness) *http.Request {
		return func(t *testing.T, _ *recoveryHarness) *http.Request {
			return postValues(t.Context(), httpsec.DefaultRecoveryStartPath, e2eSource,
				url.Values{httpsec.RecoveryUsernameParam: {username}})
		}
	}

	nothingSent := func(t *testing.T, h *recoveryHarness, before int) {
		assert.Equal(t, before, h.sender.count(), "a message was sent")
	}

	// usersAnswering replaces the user store with one answering every
	// lookup with d and err.
	usersAnswering := func(t *testing.T, h *recoveryHarness, d *identity.Details, err error) {
		users := NewMockUserLoader(gomock.NewController(t))
		users.EXPECT().LoadByUsername(gomock.Any(), e2eAddress).Return(d, err).Times(1)
		h.users = users
	}

	cases := []testCase{
		{
			name: "a code is sent, and the start is counted",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryStartLimiter(countingLimiter(t, 1))}
			},
			request: form(e2eAddress),
			assert: func(t *testing.T, h *recoveryHarness, before int) {
				assert.Equal(t, before+1, h.sender.count(), "no code was sent")
			},
		},
		{
			name: "a code is sent, asked for as JSON",
			request: func(t *testing.T, _ *recoveryHarness) *http.Request {
				req := postBody(t.Context(), httpsec.DefaultRecoveryStartPath, "application/json",
					strings.NewReader(`{"username":"`+e2eAddress+`"}`))
				req.RemoteAddr = e2eSource + ":51000"

				return req
			},
			assert: func(t *testing.T, h *recoveryHarness, before int) {
				assert.Equal(t, before+1, h.sender.count(), "no code was sent")
			},
		},
		{
			name:    "an unknown username",
			request: form("nobody@example.com"),
			assert:  nothingSent,
		},
		{
			name: "a disabled user",
			arrange: func(t *testing.T, h *recoveryHarness) {
				usersAnswering(t, h, &identity.Details{ID: e2eUser, Username: e2eAddress, Active: false}, nil)
			},
			request: form(e2eAddress),
			assert:  nothingSent,
		},
		{
			name: "the lookup fails",
			arrange: func(t *testing.T, h *recoveryHarness) {
				usersAnswering(t, h, nil, errRecoveryLookup)
			},
			request: form(e2eAddress),
			assert:  nothingSent,
		},
		{
			name: "the issuance limit is reached",
			arrange: func(_ *testing.T, h *recoveryHarness) {
				h.coreOpts = append(h.coreOpts, recovery.WithIssuedCodeLimit(1))
			},
			request: func(t *testing.T, h *recoveryHarness) *http.Request {
				h.issued(t)

				return form(e2eAddress)(t, h)
			},
			assert: nothingSent,
		},
		{
			name: "the source is throttled, and the start never runs",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryStartLimiter(exceededLimiter(t))}
				// A strict double: a start that ran would resolve the user.
				h.users = NewMockUserLoader(gomock.NewController(t))
			},
			request: form(e2eAddress),
			assert:  nothingSent,
		},
		{
			name: "the source cannot be attributed, and the start never runs",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.users = NewMockUserLoader(gomock.NewController(t))
			},
			request: func(t *testing.T, _ *recoveryHarness) *http.Request {
				return postValues(t.Context(), httpsec.DefaultRecoveryStartPath, "0.0.0.0",
					url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}})
			},
			assert: nothingSent,
		},
		{
			name: "the token store fails",
			arrange: func(t *testing.T, h *recoveryHarness) {
				store := NewMockOnetimeStore(gomock.NewController(t))
				store.EXPECT().CountRecentBySubject(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(0, errRecoveryTokens).AnyTimes()
				store.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(errRecoveryTokens).AnyTimes()
				h.coreOpts = append(h.coreOpts, recovery.WithIssuedCodeStore(store))
			},
			request: form(e2eAddress),
			assert:  nothingSent,
		},
		{
			name: "the sender refuses the message",
			arrange: func(t *testing.T, h *recoveryHarness) {
				sender := NewMockSender(gomock.NewController(t))
				sender.EXPECT().Send(gomock.Any(), gomock.Any()).Return(errRecoverySend).Times(1)
				h.send = queuedSender{sender}
			},
			request: form(e2eAddress),
			assert:  func(*testing.T, *recoveryHarness, int) {},
		},
		{
			name: "the body is missing",
			request: func(t *testing.T, _ *recoveryHarness) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultRecoveryStartPath, nil)
				req.RemoteAddr = e2eSource + ":51000"

				return req
			},
			assert: nothingSent,
		},
		{
			name: "the JSON is malformed, and the start is still counted",
			arrange: func(t *testing.T, h *recoveryHarness) {
				h.recOpts = []httpsec.RecoveryOption{httpsec.WithRecoveryStartLimiter(countingLimiter(t, 1))}
			},
			request: func(t *testing.T, _ *recoveryHarness) *http.Request {
				req := postBody(t.Context(), httpsec.DefaultRecoveryStartPath, "application/json",
					strings.NewReader(`{"username":`))
				req.RemoteAddr = e2eSource + ":51000"

				return req
			},
			assert: nothingSent,
		},
	}

	var first *httptest.ResponseRecorder

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRecoveryHarness(t)
			if tc.arrange != nil {
				tc.arrange(t, h)
			}

			h.build(t)

			req := tc.request(t, h)
			before := h.sender.count()

			rec := h.through(req)
			tc.assert(t, h, before)

			assert.Equal(t, http.StatusAccepted, rec.Code)
			assert.Empty(t, rec.Body.Bytes())
			assert.Empty(t, rec.Header().Values("Set-Cookie"))

			if first == nil {
				first = rec
				return
			}

			assert.Equal(t, first.Code, rec.Code)
			assert.Equal(t, first.Header(), rec.Header())
			assert.Equal(t, first.Body.Bytes(), rec.Body.Bytes())
		})
	}
}
