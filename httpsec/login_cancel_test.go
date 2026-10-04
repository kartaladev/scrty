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

// TestFormLogin_RecordsFailureOnUncancellableContext pins that a client which
// disconnects right after sending a wrong password is still charged for it.
func TestFormLogin_RecordsFailureOnUncancellableContext(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	recorded := expectCancelThenFail(h, cancel)

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableFormLogin(h.formLoginDeps()),
	)
	require.NoError(t, err)

	serveOn(ctx, chain, formRequest(ctx, "/login", "username=ada&password=wrong"))

	require.NotNil(t, *recorded, "the failure must reach the attempt store")
	assert.NoError(t, (*recorded).Err(),
		"the failure must be recorded on a context the client cannot cancel")
}

// TestBasicAuth_RecordsFailureOnUncancellableContext is the same guarantee for
// Basic authentication.
func TestBasicAuth_RecordsFailureOnUncancellableContext(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	recorded := expectCancelThenFail(h, cancel)

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableBasicAuth(h.basicAuthDeps()),
	)
	require.NoError(t, err)

	serveOn(ctx, chain, basicRequest(ctx, "ada", "wrong"))

	require.NotNil(t, *recorded, "the failure must reach the attempt store")
	assert.NoError(t, (*recorded).Err(),
		"the failure must be recorded on a context the client cannot cancel")
}
