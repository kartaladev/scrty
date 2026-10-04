package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// expectCancelThenFail wires the harness so the client hangs up after sending
// its guess: the authenticator cancels the request context and refuses, and
// the attempt store honours cancellation the way a SQL driver does. It returns
// the context the store was handed, valid once the request has been served.
func expectCancelThenFail(h *authHarness, cancel context.CancelFunc) *context.Context {
	var recorded context.Context

	h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
			cancel()

			return nil, authenticate.ErrAuthenticationFailed
		})
	h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).
		DoAndReturn(func(ctx context.Context, _ string, _ time.Time) error {
			recorded = ctx

			return ctx.Err()
		})

	return &recorded
}

// serveOn runs req through chain on an exchange built from ctx, because the
// exchange's context, not the request's, is what the interceptors act on.
func serveOn(ctx context.Context, chain *httpsec.Chain, req *http.Request) {
	run := chain.Assemble(func(*httpsec.Exchange) error { return nil })
	ex := httpsec.NewExchange(ctx,
		httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))
	_ = run(ex)
}

// TestLogin_RecordsFailureOnUncancellableContext pins that a client which
// disconnects right after sending a wrong password is still charged for it,
// on form login and on Basic authentication alike.
func TestLogin_RecordsFailureOnUncancellableContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		option func(h *authHarness) httpsec.Option
		// request builds the wrong-password request the client hangs up after.
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, recorded context.Context)
	}

	failureReachedStore := func(t *testing.T, recorded context.Context) {
		require.NotNil(t, recorded, "the failure must reach the attempt store")
		assert.NoError(t, recorded.Err(),
			"the failure must be recorded on a context the client cannot cancel")
	}

	cases := []testCase{
		{
			name:   "form login",
			option: func(h *authHarness) httpsec.Option { return httpsec.EnableFormLogin(h.formLoginDeps()) },
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "username=ada&password=wrong")
			},
			assert: failureReachedStore,
		},
		{
			name:   "basic",
			option: func(h *authHarness) httpsec.Option { return httpsec.EnableBasicAuth(h.basicAuthDeps()) },
			request: func(ctx context.Context) *http.Request {
				return basicRequest(ctx, "ada", "wrong")
			},
			assert: failureReachedStore,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			recorded := expectCancelThenFail(h, cancel)

			chain, err := httpsec.New(httpsec.WithLogger(h.logger()), tc.option(h))
			require.NoError(t, err)

			serveOn(ctx, chain, tc.request(ctx))

			tc.assert(t, *recorded)
		})
	}
}
