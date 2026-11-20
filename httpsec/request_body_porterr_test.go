package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// bodyPortErrRowEnv names the row a child process of TestPortErrors_RequestBody
// runs. It is empty in the parent.
const bodyPortErrRowEnv = "SCRTY_HTTPSEC_BODY_PORTERR_ROW"

// bodyPortErrRan is what a child prints, as a line of its own followed by the
// row's name, once it has run its row to the end.
const bodyPortErrRan = "body-porterr-row-ran:"

// bodyFailing is a consumer's own Request integration over the library's
// adapter: everything is the adapter's, except that Body fails with err from
// its (pass+1)th call on, calling onCall first.
type bodyFailing struct {
	httpsec.Request

	err    error
	pass   int32
	calls  atomic.Int32
	onCall func()
}

func (r *bodyFailing) Body(limit int64) ([]byte, error) {
	if r.calls.Add(1) <= r.pass {
		return r.Request.Body(limit)
	}

	r.onCall()

	return nil, r.err
}

// bodyTooLargeClaim is a cycle through Unwrap() error whose own Is claims to
// be ErrRequestTooLarge: the stdlib asks Is first and answers 413 without
// ever reaching the cycle.
type bodyTooLargeClaim struct{}

func (*bodyTooLargeClaim) Error() string { return hostileSecret }

func (c *bodyTooLargeClaim) Unwrap() error { return c }

func (*bodyTooLargeClaim) Is(target error) bool { return target == httpsec.ErrRequestTooLarge } //nolint:errorlint // identity of a sentinel

// bodySite is one read of a request body by a library flow.
type bodySite struct {
	name string

	// direct marks a site that reads the body's error itself with errors.Is
	// for ErrRequestTooLarge, where the accepted Is-panicking row panics.
	direct bool

	// pass is how many Body calls the adapter answers before the failing one.
	pass int32

	// world builds the flow's chain with extra on it, and the request that
	// reaches the site, served under ctx. logs is the chain's logger.
	world func(t *testing.T, ctx context.Context, extra ...httpsec.Option) (*httpsec.Chain, *http.Request, *capturingHandler)
}

// bodyIntegration is a consumer's own net/http integration of chain, in
// Middleware's shape: the request is adapted by bodyFailing, and a refusal is
// answered with StatusForError.
func bodyIntegration(chain *httpsec.Chain, failing *bodyFailing) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failing.Request = httpsec.NewHTTPRequest(r)

		ex := httpsec.NewExchange(r.Context(), failing, httpsec.NewHTTPResponseWriter(w))
		run := chain.Assemble(func(*httpsec.Exchange) error {
			w.WriteHeader(http.StatusTeapot)

			return nil
		})

		if err := run(ex); err != nil {
			ex.Writer.WriteHeader(httpsec.StatusForError(err))
		}
	})
}

// bodyThrough serves site's request through the consumer's integration with
// its Body failing with portErr, and fails the test if it does not return
// within five seconds. A panic past the chain is reported, not recovered into
// a failure: the accepted row expects one.
func bodyThrough(t *testing.T, site bodySite, portErr error, run stepUpRun) stepUpOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, run.cancelDuring)
	returned := &stepUpReturned{}
	chain, req, logs := site.world(t, ctx, stepUpObserver(returned, false))

	handler := bodyIntegration(chain, &bodyFailing{err: portErr, pass: site.pass, onCall: onCall})

	type result struct {
		rec      *httptest.ResponseRecorder
		panicked bool
	}

	done := make(chan result, 1)

	go func() {
		r := result{rec: httptest.NewRecorder()}
		served := false

		defer func() {
			if !served {
				_ = recover()
				r.panicked = true
			}

			done <- r
		}()

		handler.ServeHTTP(r.rec, req)

		served = true
	}()

	select {
	case r := <-done:
		return stepUpOutcomeOf(r.rec, r.panicked, nil, "", logs, returned)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile request body error hung the request")

		return stepUpOutcome{}
	}
}

// bodyPortErrKinds are the hostile errors a consumer's Body may fail with. The
// accepted row, an Is that panics only for ErrRequestTooLarge, is a direct
// site's alone: elsewhere no stdlib check asks the error about it.
func bodyPortErrKinds(direct bool) []stepUpPortErrKind {
	kinds := append(stepUpPortErrKinds(nil),
		stepUpPortErrKind{name: "cycle claiming ErrRequestTooLarge through Is", err: &bodyTooLargeClaim{}, reason: "budget"},
		stepUpPortErrKind{
			name: "cycle wrapping ErrRequestTooLarge",
			err:  &throttleCycleWrapping{sentinel: httpsec.ErrRequestTooLarge}, reason: "budget", child: true,
		},
	)

	if direct {
		kinds = append(kinds, stepUpPortErrKind{
			name: "Is panicking only for ErrRequestTooLarge (accepted)",
			err:  stepUpIsPanicsFor{target: httpsec.ErrRequestTooLarge}, panics: true,
		})
	}

	return kinds
}

// withLogs is a fresh capturing handler and the option that makes it the
// chain's logger.
func withLogs() (*capturingHandler, httpsec.Option) {
	logs := &capturingHandler{}

	return logs, httpsec.WithLogger(slog.New(logs))
}

// bodyOIDCWorld is a provider's chain, session management included, and a
// fresh sign-in for a request that needs one.
func bodyOIDCWorld(
	t *testing.T, extra ...httpsec.Option,
) (*httpsec.Chain, *session.Session, *capturingHandler) {
	t.Helper()

	w := newGrantWorld(t)
	s := w.signIn(t)
	logs, logger := withLogs()

	return w.chainWith(t, append([]httpsec.Option{logger, httpsec.EnableSessionManagement()}, extra...)...), s, logs
}

// bodyPOST is a POST of body to target, declared as contentType.
func bodyPOST(ctx context.Context, target, contentType, body string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)

	return req
}

const formType = "application/x-www-form-urlencoded"

// comparableHeader is h without its per-response CSP nonce, and nil for a
// request that produced no response.
func comparableHeader(h http.Header) http.Header {
	if h == nil {
		return nil
	}

	return withoutNonce(h)
}

func bodySites() []bodySite {
	return []bodySite{
		{
			name: "second-factor verify, postedFieldLimited", direct: true,
			world: func(t *testing.T, ctx context.Context, extra ...httpsec.Option) (*httpsec.Chain, *http.Request, *capturingHandler) {
				h := newMFAHarness(t)
				h.channel(factor.AuthenticatorApp)
				s := h.pendingSession(t, factor.Password)
				h.limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
				h.limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				logs, logger := withLogs()

				return h.chain(t, s, append([]httpsec.Option{logger}, extra...)...),
					post(ctx, testMFAVerifyPath, "code="+testMFACode), logs
			},
		},
		{
			name: "passwordless finish, postedJSON", direct: true,
			world: func(t *testing.T, ctx context.Context, extra ...httpsec.Option) (*httpsec.Chain, *http.Request, *capturingHandler) {
				d := newPwlDeployment(t)
				logs, logger := withLogs()
				d.extra = append(append(d.extra, logger), extra...)
				d.build(t)

				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				cookie, challenge := d.begun(t)

				req := jsonPost(ctx, passwordlessFinishPath, handleAssertionBody(challenge, "cred-1", handle))
				req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: cookie}) //nolint:gosec // G124: a request cookie

				return d.chain, req, logs
			},
		},
		{
			name: "form login, the login's body", direct: false,
			world: func(t *testing.T, ctx context.Context, extra ...httpsec.Option) (*httpsec.Chain, *http.Request, *capturingHandler) {
				h := newAuthHarness(t)
				passwordWork(h, false)
				logs, logger := withLogs()

				chain, err := httpsec.New(append([]httpsec.Option{logger, httpsec.EnableFormLogin(h.formLoginDeps())}, extra...)...)
				require.NoError(t, err)

				return chain, formRequest(ctx, httpsec.DefaultLoginPath, "username=ada&password=wrong"), logs
			},
		},
		{
			name: "password re-proof, readPassword", direct: false,
			world: func(t *testing.T, ctx context.Context, extra ...httpsec.Option) (*httpsec.Chain, *http.Request, *capturingHandler) {
				f := newPwFixture(t)
				s := f.newSession(t, factor.Password, session.MFANone)
				f.chainOpts = append(f.chainOpts, extra...)

				chain, err := f.build(nil)
				require.NoError(t, err)

				return chain, passwordPost(ctx, mfaTokenFor(s.ID),
					url.Values{httpsec.DefaultLoginPasswordParam: {reauthAdaPassword}}), f.logs
			},
		},
		{
			name: "recovery complete, readRecoveryForm", direct: true,
			world: func(t *testing.T, ctx context.Context, extra ...httpsec.Option) (*httpsec.Chain, *http.Request, *capturingHandler) {
				h := newRecoveryHarness(t)
				logs, logger := withLogs()
				h.chainOpts = append(append(h.chainOpts, logger), extra...)
				h.build(t)

				return h.chain, postValues(ctx, httpsec.DefaultRecoveryCompletePath, e2eSource,
					url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}}), logs
			},
		},
		{
			name: "passkey rename, postedPasskeyID's second read", direct: false, pass: 1,
			world: func(t *testing.T, ctx context.Context, extra ...httpsec.Option) (*httpsec.Chain, *http.Request, *capturingHandler) {
				h := newPasskeyHarness(t)
				own := seedPasskey(t, h, testMFAUser, "cred-own", passkey.StateActive)
				s := h.sessionIn(t, factor.Password, session.MFANone)
				logs, logger := withLogs()
				h.extra = append(append(h.extra, logger), extra...)

				return h.build(t, s), post(ctx, passkeyRenamePath,
					url.Values{"id": {own.ID.String()}, "name": {"renamed"}}.Encode()), logs
			},
		},
		{
			name: "session management, revokeAccessChosen", direct: true,
			world: func(t *testing.T, ctx context.Context, extra ...httpsec.Option) (*httpsec.Chain, *http.Request, *capturingHandler) {
				chain, s, logs := bodyOIDCWorld(t, extra...)

				req := httptest.NewRequestWithContext(ctx, http.MethodDelete, httpsec.DefaultSessionManagementPrefix,
					strings.NewReader(`{"revoke_application_access":true}`))
				req.Header.Set("Authorization", "Bearer "+s.ID)

				return chain, req, logs
			},
		},
		{
			name: "OIDC token, readOIDCClientRequest", direct: true,
			world: func(t *testing.T, ctx context.Context, extra ...httpsec.Option) (*httpsec.Chain, *http.Request, *capturingHandler) {
				chain, _, logs := bodyOIDCWorld(t, extra...)

				req := bodyPOST(ctx, tokenURL, formType, exchangeOf("code").Encode())
				req.RemoteAddr = tokenAddr
				asClient(tokenWeb)(req)

				return chain, req, logs
			},
		},
		{
			name: "OIDC userinfo, the form's token", direct: true,
			world: func(t *testing.T, ctx context.Context, extra ...httpsec.Option) (*httpsec.Chain, *http.Request, *capturingHandler) {
				chain, _, logs := bodyOIDCWorld(t, extra...)

				return chain, bodyPOST(ctx, userInfoURL, formType, "access_token=presented"), logs
			},
		},
		{
			name: "OIDC authorize, readOIDCAuthorizeParams", direct: false,
			world: func(t *testing.T, ctx context.Context, extra ...httpsec.Option) (*httpsec.Chain, *http.Request, *capturingHandler) {
				chain, _, logs := bodyOIDCWorld(t, extra...)

				return chain, bodyPOST(ctx, opIssuer+flowAuthorizePath, formType, flowParams(flowWeb).Encode()), logs
			},
		},
		{
			name: "OIDC logout confirm, readOIDCLogoutConfirm", direct: false,
			world: func(t *testing.T, ctx context.Context, extra ...httpsec.Option) (*httpsec.Chain, *http.Request, *capturingHandler) {
				chain, _, logs := bodyOIDCWorld(t, extra...)

				return chain, bodyPOST(ctx, opIssuer+logoutConfirmPath, "application/json", `{"handle":"h"}`), logs
			},
		},
		{
			name: "OIDC resume, readOIDCResumeRequest", direct: false,
			world: func(t *testing.T, ctx context.Context, extra ...httpsec.Option) (*httpsec.Chain, *http.Request, *capturingHandler) {
				chain, s, logs := bodyOIDCWorld(t, extra...)

				req := bodyPOST(ctx, opIssuer+flowResumePath, "application/json", flowLoginBody("h"))
				req.Header.Set("Authorization", "Bearer "+s.ID)

				return chain, req, logs
			},
		},
	}
}

// TestPortErrors_RequestBody pins that a hostile error from a consumer's own
// Request integration's Body, at every library read of a request body, is
// answered exactly as a plain failure of that read is: the same response, byte
// for byte, the same records besides one abort record on the chain's logger,
// and none on slog.Default(). A cycle that claims ErrRequestTooLarge is never
// answered 413: a genuine ErrRequestTooLarge, from a walkable error, still is
// (the sites' own tests pin that).
//
// The request is served through a consumer's integration built on NewExchange
// and Chain.Assemble, which answers a refusal with StatusForError.
//
// One row is accepted, not sanitized: an error whose Is panics only for
// ErrRequestTooLarge passes the walk and panics at a direct site's stdlib
// check, for net/http's per-request recovery.
func TestPortErrors_RequestBody(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(bodyPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	plainOutage := errors.New("transport: connection reset by peer")

	contexts := []struct {
		name         string
		cancelDuring bool
	}{
		{name: "live"},
		{name: "cancelled", cancelDuring: true},
	}

	for _, site := range bodySites() {
		for _, c := range contexts {
			for _, kind := range bodyPortErrKinds(site.direct) {
				row := site.name + "/" + c.name + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				if kind.ctx != "" && kind.ctx != c.name {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if kind.child && childRow == "" {
						limiterPortErrInChild(t, bodyPortErrRowEnv, bodyPortErrRan, row)

						return
					}

					defaults := swapDefaultLogger(t)
					run := stepUpRun{cancelDuring: c.cancelDuring}

					plain := bodyThrough(t, site, plainOutage, run)
					require.False(t, plain.panicked, "the plain failure does not panic")
					require.Empty(t, abortRecords(plain.logs), "the plain failure writes no abort record")
					require.GreaterOrEqual(t, plain.status, http.StatusBadRequest, "a plain failure refuses")
					require.NotEqual(t, http.StatusRequestEntityTooLarge, plain.status, "a plain failure is not too large")
					require.False(t, plain.unwalkable, "the plain failure is no fault")

					got := bodyThrough(t, site, kind.err, run)

					if kind.panics {
						assert.True(t, got.panicked, "the accepted case panics past the chain")
					} else {
						assert.False(t, got.panicked, "a hostile body error escaped as a panic")
						assert.Equal(t, plain.status, got.status, "status")
						assert.Equal(t, comparableHeader(plain.header), comparableHeader(got.header), "headers")
						assert.Equal(t, plain.body, got.body, "body")
						assert.NotContains(t, got.body, hostileSecret, "the response quotes the error")
						assert.Equal(t, nonAbortMessages(plain.logs), nonAbortMessages(got.logs), "the chain's records")
						assert.False(t, got.escaped, "an unwalkable error travelled on past the site")

						aborts := abortRecords(got.logs)
						if kind.reason == "" {
							assert.Empty(t, aborts, "a walk that completes writes no abort record")
						} else {
							require.Len(t, aborts, 1, "one abort record, on the chain's logger")
							assertAbortRecord(t, aborts[0], kind.reason)
						}
					}

					assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

					if childRow != "" && !t.Failed() {
						fmt.Fprintln(os.Stdout, bodyPortErrRan+row)
					}
				})
			}
		}
	}
}
