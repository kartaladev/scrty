package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// csrfPortErrRowEnv names the row a child process of
// TestPortErrors_CSRFTokensVerify runs. It is empty in the parent.
const csrfPortErrRowEnv = "SCRTY_HTTPSEC_CSRF_PORTERR_ROW"

// csrfPortErrRan is what a child prints, as a line of its own followed by the
// row's name, once it has run its row to the end.
const csrfPortErrRan = "csrf-porterr-row-ran:"

// csrfSourceFailing is a CSRFTokens source whose Verify fails with err,
// calling onCall first.
type csrfSourceFailing struct {
	err    error
	onCall func()
}

func (s csrfSourceFailing) Token(context.Context, *session.Session) (string, error) {
	return "", s.err
}

func (s csrfSourceFailing) Verify(context.Context, *session.Session, string) error {
	s.onCall()

	return s.err
}

// csrfVerifyThrough serves an unsafe cookie-authenticated request whose token
// source's Verify fails with portErr.
func csrfVerifyThrough(t *testing.T, portErr error, run stepUpRun) stepUpOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, run.cancelDuring)
	f := newCSRFFixture(t)

	logs := &capturingHandler{}
	returned := &stepUpReturned{}

	chain, err := httpsec.New(
		stepUpObserver(returned, run.swallow),
		httpsec.WithLogger(slog.New(logs)),
		httpsec.EnableCSRFProtection(httpsec.WithCSRFTokens(csrfSourceFailing{err: portErr, onCall: onCall})),
		httpsec.RegisterInterceptor(consumerCookieAuthenticator{sessions: f.sessions}, httpsec.OrderBearerToken),
	)
	require.NoError(t, err)

	rec, panicked := stepUpServeWithin(t, chain,
		cookieRequest(ctx, http.MethodPost, f.signIn.ID, map[string]string{"X-CSRF-Token": "presented"}, ""))

	return stepUpOutcomeOf(rec, panicked, nil, "", logs, returned)
}

// TestPortErrors_CSRFTokensVerify pins that a hostile error from the
// consumer's CSRFTokens.Verify is answered exactly as a plain outage of the
// source is: the same 500, never a cross-site refusal and never a pass. It is
// reported once, to the chain's logger, and not to slog.Default(), and the
// error CheckCSRFToken returns to the cookie authenticator is the fixed one,
// so nothing hostile travels on past it.
//
// Verify has no unavailable sentinel, and the site tests none, so the fixed
// error is porterr.ErrUnwalkable.
func TestPortErrors_CSRFTokensVerify(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runStepUpPortErrors(t, csrfPortErrRowEnv, csrfPortErrRan, []stepUpPortSite{
		{name: "the token source's Verify", through: csrfVerifyThrough},
	}, errors.New("dependency: connection refused"))
}

// csrfClaimPortErrRowEnv names the row a child process of
// TestPortErrors_CSRFTokensVerify_ClaimedRefusal runs. It is empty in the
// parent.
const csrfClaimPortErrRowEnv = "SCRTY_HTTPSEC_CSRF_CLAIM_PORTERR_ROW"

// csrfClaimPortErrRan is what a child prints, as a line of its own followed by
// the row's name, once it has run its row to the end.
const csrfClaimPortErrRan = "csrf-claim-porterr-row-ran:"

// TestPortErrors_CSRFTokensVerify_ClaimedRefusal pins that an error of the
// source that claims to be a cross-site refusal, through a chain that cannot be
// walked, is not taken for one: the request is answered as a plain outage of the
// source is (a 500), never as the 403 the claimed refusal would be, and the
// abort is reported once.
//
// It is not a site of TestPortErrors_CSRFTokensVerify: that runner's accepted
// row, an Is that panics only for the site's sentinel, does not panic past this
// chain, because the chain's own bounded lookup recovers it.
func TestPortErrors_CSRFTokensVerify_ClaimedRefusal(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const row = "a cycle wrapping ErrCrossSiteRequest"

	childRow := os.Getenv(csrfClaimPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	if childRow != "" && childRow != row {
		return
	}

	if childRow == "" {
		// Unsanitized, the cycle's stdlib check overflows the stack fatally.
		t.Run(row, func(t *testing.T) {
			limiterPortErrInChild(t, csrfClaimPortErrRowEnv, csrfClaimPortErrRan, row)
		})

		return
	}

	t.Run(row, func(t *testing.T) {
		defaults := swapDefaultLogger(t)

		plain := csrfVerifyThrough(t, errors.New("dependency: connection refused"), stepUpRun{})
		got := csrfVerifyThrough(t, &throttleCycleWrapping{sentinel: httpsec.ErrCrossSiteRequest}, stepUpRun{})
		alone := csrfVerifyThrough(t, &throttleCycleWrapping{sentinel: httpsec.ErrCrossSiteRequest}, stepUpRun{swallow: true})

		assert.Equal(t, http.StatusInternalServerError, plain.status)
		assert.Equal(t, plain.status, got.status, "a claimed refusal is answered as an outage")
		assert.Equal(t, plain.body, got.body)
		assert.NotContains(t, got.body, hostileSecret)
		assert.False(t, got.escaped, "an unwalkable error travelled on past the site")
		assert.True(t, got.unwalkable, "the flow returned the sanitizer's fault")

		require.Len(t, abortRecords(alone.logs), 1, "the site's own sanitizer writes the one abort record")
		assertAbortRecord(t, abortRecords(alone.logs)[0], "budget")
		assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

		_, _ = fmt.Fprintln(os.Stdout, csrfClaimPortErrRan+row)
	})
}
