package httpsec_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
)

// parkedState is the state a client parks its request with in these tests.
const parkedState = "s-1"

// withParkedState parks the request with parkedState.
func withParkedState(v url.Values) { v.Set("state", parkedState) }

// parkedPath is one of the sites a failed parked login is met at: run drives it for
// handle, carrying the provider flow cookie flow, and kept is the error the site
// answers when the failure keeps its answer.
type parkedPath struct {
	setup completionSetup
	run   func(t *testing.T, f *completionFlow, handle, flow string) flowAnswer
	kept  error
}

// parkedPaths are the callback (a hook refusal), the start (discovery down) and
// completion (a login that succeeded) paths.
func parkedPaths() map[string]parkedPath {
	callback := func(t *testing.T, f *completionFlow, handle, flow string) flowAnswer {
		t.Helper()

		return f.signIn(t, parkedAt(handle), flowCookieOf(flowCookie, flow))
	}

	return map[string]parkedPath{
		"callback": {
			setup: completionSetup{broker: hookBroker(refusingHook)},
			run:   callback,
			kept:  oidc.ErrProvisioningRefused,
		},
		"start": {
			setup: completionSetup{rp: undiscoverableRP},
			run: func(t *testing.T, f *completionFlow, handle, flow string) flowAnswer {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					f.issuer+httpsec.DefaultOIDCAuthorizePath+testOIDCProvider+"?"+
						url.Values{httpsec.DefaultOIDCNextParam: {parkedAt(handle)}}.Encode(), nil)

				return f.serve(t, r, []flowChange{flowCookieOf(flowCookie, flow)})
			},
			kept: oidc.ErrDiscoveryFailed,
		},
		"completion": {run: callback, kept: httpsec.ErrOIDCUnknownHandle},
	}
}

// assertAnsweredAtClient asserts a sends the browser to the client's redirect URI
// with error code, the parked state and the issuer, and nothing else (D10).
func assertAnsweredAtClient(t *testing.T, f *completionFlow, a flowAnswer, code string) {
	t.Helper()

	require.NoError(t, a.err, "nothing reached the error handling")
	require.Equal(t, http.StatusSeeOther, a.status, a.body)

	loc := a.location(t)
	assert.Equal(t, rpCallback, loc.Scheme+"://"+loc.Host+loc.Path, "the client's redirect URI")
	assert.Equal(t, url.Values{"error": {code}, "state": {parkedState}, "iss": {f.issuer}}, loc.Query(),
		"error, state and iss, and no error_description")
	assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
	assert.Equal(t, "no-referrer", a.header.Get("Referrer-Policy"))
}

// assertSpent asserts the request for handle was answered: it can be ended no more.
func assertSpent(t *testing.T, f *completionFlow, handle, flow string) {
	t.Helper()

	_, err := f.p.EndPending(t.Context(), oidcprovider.EndPendingInput{
		Handle: handle, FlowSecret: flow, Code: oidcprovider.CodeAccessDenied,
	})
	require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle, "the request is spent")
}

// TestParkedFailure_ExpiredWithinGraceAnswersClient pins that on the callback, start
// and completion paths a parked request that expired within its grace window is
// answered access_denied at the client and spent, uncharged (D6, D7, F13), and that
// one past the window keeps the failure's answer, charged once.
func TestParkedFailure_ExpiredWithinGraceAnswersClient(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		path string
		// expiredFor is how long before the failure the request expired.
		expiredFor time.Duration
		assert     func(t *testing.T, f *completionFlow, p parkedPath, a flowAnswer, handle, flow string)
	}

	within := func(t *testing.T, f *completionFlow, _ parkedPath, a flowAnswer, handle, flow string) {
		t.Helper()

		assertAnsweredAtClient(t, f, a, oidcprovider.CodeAccessDenied)
		assertSpent(t, f, handle, flow)
		assert.Zero(t, f.charged.Load(), "a genuine handle is not charged")
		assert.Zero(t, f.storedSessions(t), "no session")
	}

	past := func(t *testing.T, f *completionFlow, p parkedPath, a flowAnswer, _, _ string) {
		t.Helper()

		require.ErrorIs(t, a.err, p.kept, "the failure's own answer")
		assert.Empty(t, a.header.Get("Location"), "no redirect")
		assert.Equal(t, int64(1), f.charged.Load(), "charged once")
		assert.Zero(t, f.storedSessions(t), "no session")
	}

	// The default lifetime and grace window are both 10 minutes.
	const pastGrace = 10*time.Minute + time.Second

	cases := []testCase{
		{name: "callback, within the window", path: "callback", expiredFor: 2 * time.Minute, assert: within},
		{name: "callback, past the window", path: "callback", expiredFor: pastGrace, assert: past},
		{name: "start, within the window", path: "start", expiredFor: 2 * time.Minute, assert: within},
		{name: "start, past the window", path: "start", expiredFor: pastGrace, assert: past},
		{name: "completion, within the window", path: "completion", expiredFor: 2 * time.Minute, assert: within},
		{name: "completion, past the window", path: "completion", expiredFor: pastGrace, assert: past},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := parkedPaths()[tc.path]
			f := newCompletionFlow(t, p.setup)
			handle, flow := f.park(t, flowFirstParty, withParkedState)
			f.clk.Advance(10*time.Minute + tc.expiredFor)

			tc.assert(t, f, p, p.run(t, f, handle, flow), handle, flow)
		})
	}
}

// TestParkedFailureToClient pins WithOIDCFailToClient (D3): a failed parked login
// ends the request with the code the login page would have been given and answers
// the client, spending the handle; an end that fails answers the login's original
// error, with exactly one ERROR record naming the error's type and no text (F7).
func TestParkedFailureToClient(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		setup completionSetup
		// park replaces how the request is parked: an authorization request by default.
		park func(t *testing.T, f *completionFlow) (handle, flow string)
		// arm sets a fault once the request is parked.
		arm    func(t *testing.T, f *completionFlow)
		assert func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string, logs []slog.Record)
	}

	answered := func(code string) func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string, _ []slog.Record) {
		return func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string, _ []slog.Record) {
			t.Helper()

			assertAnsweredAtClient(t, f, a, code)
			assertSpent(t, f, handle, flow)
			assert.Zero(t, f.storedSessions(t), "no session")
		}
	}

	failingEnd := func(t *testing.T, f *completionFlow) {
		t.Helper()

		// The end is the request's one conditional write; the pre-check only reads.
		f.setup.pending.onAdvance = func(context.Context, *oidcprovider.SignIn) error { return errPendingDown }
	}

	cases := []testCase{
		{
			name:   "a hook refusal",
			setup:  completionSetup{broker: hookBroker(refusingHook)},
			assert: answered(oidcprovider.CodeAccessDenied),
		},
		{
			name:   "the sign-in hook's Apply fails",
			setup:  completionSetup{broker: hookBroker(applyDownHook)},
			assert: answered(oidcprovider.CodeServerError),
		},
		{
			// A device request has no client redirect URI to answer at: it returns to the
			// login page, stays parked, and records no failed end.
			name: "a device request returns to the login page",
			setup: completionSetup{
				broker:  hookBroker(refusingHook),
				clients: deviceClients(),
				provider: []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(opIssuer+deviceEntryPage,
					oidcprovider.WithUserCodeKey(deviceKey))},
			},
			park: func(t *testing.T, f *completionFlow) (string, string) {
				t.Helper()

				a := f.enter(t, f.issueDevice(t, deviceTV).UserCode)
				require.Equal(t, http.StatusSeeOther, a.status, a.body)

				flow := a.cookie(flowCookie)
				require.NotNil(t, flow, "the flow cookie is set")

				return a.location(t).Query().Get(oidcprovider.HandleParam), flow.Value
			},
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string, logs []slog.Record) {
				t.Helper()

				require.NoError(t, a.err)
				require.Equal(t, http.StatusSeeOther, a.status, a.body)

				loc := a.location(t)
				assert.Equal(t, completionLoginURL, loc.Scheme+"://"+loc.Host+loc.Path, "the login page")
				assert.Equal(t, handle, loc.Query().Get(oidcprovider.HandleParam))
				assert.Equal(t, oidcprovider.CodeAccessDenied, loc.Query().Get("error"))
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle, flow), "the request stays parked")

				for _, r := range logs {
					assert.Less(t, r.Level, slog.LevelError, "no ERROR record: %s", r.Message)
				}
			},
		},
		{
			name: "an upstream outage",
			arm: func(_ *testing.T, f *completionFlow) {
				f.idp.tokenDown.Store(true)
			},
			assert: answered(oidcprovider.CodeTemporarilyUnavailable),
		},
		{
			name:   "completion's user loader fails",
			setup:  completionSetup{users: loaderAnswering(t, nil, errCompletionLoaderDown)},
			assert: answered(oidcprovider.CodeServerError),
		},
		{
			// The request is live when the return checks it and expires within its
			// grace window before the end: the end answers access_denied, whatever
			// code was asked for, and the record names what the client received.
			name:  "the request expires between the check and the end",
			setup: completionSetup{users: loaderAnswering(t, nil, errCompletionLoaderDown)},
			arm: func(_ *testing.T, f *completionFlow) {
				var reads atomic.Int64

				f.setup.pending.onLoad = func(context.Context) error {
					// Reads: completion's check, the return's check, then the end.
					if reads.Add(1) == 3 {
						f.clk.Advance(12 * time.Minute)
					}

					return nil
				}
			},
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string, logs []slog.Record) {
				t.Helper()

				answered(oidcprovider.CodeAccessDenied)(t, f, a, handle, flow, logs)

				var coded []slog.Record

				for _, r := range logs {
					if _, ok := attrValue(r, "code"); ok {
						coded = append(coded, r)
					}
				}

				require.Len(t, coded, 1, "one record carrying the code")
				code, _ := attrValue(coded[0], "code")
				assert.Equal(t, oidcprovider.CodeAccessDenied, code.String(), "the code the client received")
			},
		},
		{
			name:  "ending the request fails",
			setup: completionSetup{broker: hookBroker(refusingHook)},
			arm:   failingEnd,
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string, logs []slog.Record) {
				t.Helper()

				require.ErrorIs(t, a.err, oidc.ErrProvisioningRefused, "the login's own refusal")
				assert.NotErrorIs(t, a.err, errPendingDown, "the end's failure does not replace it")
				assert.Empty(t, a.header.Get("Location"), "no redirect")
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle, flow), "the request stays parked")

				var errs []slog.Record
				for _, r := range logs {
					if r.Level >= slog.LevelError {
						errs = append(errs, r)
					}
				}

				require.Len(t, errs, 1, "exactly one ERROR record")
				reason, _ := attrValue(errs[0], "reason")
				assert.Equal(t, "parked-not-ended", reason.String())
				typ, ok := attrValue(errs[0], "error_type")
				require.True(t, ok, "the error's type is named")
				assert.NotEmpty(t, typ.String())

				for _, r := range errs {
					r.Attrs(func(a slog.Attr) bool {
						assert.NotContains(t, a.Value.String(), errPendingDown.Error(), "never the error's text")

						return true
					})
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logs := &capturingHandler{}
			setup := tc.setup
			setup.oidc = append(setup.oidc, httpsec.WithOIDCFailToClient())
			setup.pending = &downablePendingStore{
				PendingRequestStore: must.Must(oidcprovider.NewMemoryPendingRequestStore()),
			}
			setup.chain = func(*testing.T, *completionFlow) []httpsec.Option {
				return []httpsec.Option{httpsec.WithLogger(slog.New(logs))}
			}

			f := newCompletionFlow(t, setup)
			f.setup = setup
			park := func(t *testing.T, f *completionFlow) (string, string) {
				t.Helper()

				return f.park(t, flowFirstParty, withParkedState)
			}
			if tc.park != nil {
				park = tc.park
			}

			handle, flow := park(t, f)
			if tc.arm != nil {
				tc.arm(t, f)
			}

			a := f.signIn(t, parkedAt(handle), flowCookieOf(flowCookie, flow))
			tc.assert(t, f, a, handle, flow, logs.records())
		})
	}
}

// TestParkedFailure_EventsAndLogs pins what a redirected parked login reports (F20):
// exactly one AuthnLoginFail for a refusal and none for an outage, one sampled record
// per redirect carrying the code under the site's own flow, and no record holding the
// handle, a state, a flow cookie's value, the upstream's code or the Location.
func TestParkedFailure_EventsAndLogs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		path  string
		setup func(p parkedPath) completionSetup
		// arm sets a fault once the request is parked.
		arm func(f *completionFlow)
		// fails is the number of AuthnLoginFail events, code the code recorded, and
		// flow the flow its record names.
		fails      int
		code, flow string
		// serverError is set when the answer is server_error: exactly one ERROR record
		// then names the reason and the cause's type. Otherwise there is none.
		serverError bool
	}

	cases := []testCase{
		{
			name: "a refusal returned to the login page", path: "callback",
			fails: 1, code: oidcprovider.CodeAccessDenied, flow: "oidc.callback",
		},
		{
			name: "an outage returned to the login page", path: "callback",
			setup: func(parkedPath) completionSetup { return completionSetup{} },
			arm:   func(f *completionFlow) { f.idp.tokenDown.Store(true) },
			fails: 0, code: oidcprovider.CodeTemporarilyUnavailable, flow: "oidc.callback",
		},
		{
			name: "an Apply failure returned to the login page", path: "callback",
			setup: func(parkedPath) completionSetup {
				return completionSetup{broker: hookBroker(applyDownHook)}
			},
			fails: 0, code: oidcprovider.CodeServerError, flow: "oidc.callback", serverError: true,
		},
		{
			name: "a refusal answered at the client", path: "callback",
			setup: func(p parkedPath) completionSetup {
				s := p.setup
				s.oidc = []httpsec.OIDCOption{httpsec.WithOIDCFailToClient()}

				return s
			},
			fails: 1, code: oidcprovider.CodeAccessDenied, flow: "oidc.callback",
		},
		{
			name: "a completion refusal returned to the login page", path: "callback",
			setup: func(parkedPath) completionSetup {
				return completionSetup{users: loaderAnswering(t, nil, identity.ErrUserNotFound)}
			},
			fails: 0, code: oidcprovider.CodeAccessDenied, flow: "oidc.callback",
		},
		{
			name: "a request expired within its grace window", path: "callback",
			arm:   func(f *completionFlow) { f.clk.Advance(12 * time.Minute) },
			fails: 1, code: oidcprovider.CodeAccessDenied, flow: "oidc.callback",
		},
		{
			name: "discovery down at the start", path: "start",
			fails: 0, code: oidcprovider.CodeTemporarilyUnavailable, flow: "oidc.authorize",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := parkedPaths()[tc.path]
			setup := p.setup
			if tc.setup != nil {
				setup = tc.setup(p)
			}

			var out syncBuffer

			logs := &capturingHandler{}
			setup.chain = func(*testing.T, *completionFlow) []httpsec.Option {
				return []httpsec.Option{httpsec.WithLogger(slog.New(slogFanout{
					logs, slog.NewJSONHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}),
				}))}
			}

			f := newCompletionFlow(t, setup)
			handle, flow := f.park(t, flowFirstParty, withParkedState)
			if tc.arm != nil {
				tc.arm(f)
			}

			secrets := []string{handle, flow, parkedState}
			before := len(f.events.named(event.AuthnLoginFail))

			var a flowAnswer
			if tc.path == "start" {
				a = p.run(t, f, handle, flow)
			} else {
				login := f.startSSO(t, parkedAt(handle))
				secrets = append(secrets, login.rpFlow, login.state, login.nonce)
				a = f.callBack(t, login, flowCookieOf(flowCookie, flow))
			}

			require.NoError(t, a.err)
			require.Equal(t, http.StatusSeeOther, a.status, a.body)
			secrets = append(secrets, a.header.Get("Location"))

			assert.Len(t, f.events.named(event.AuthnLoginFail), before+tc.fails, "login-failure events")

			var coded []slog.Record
			for _, r := range logs.records() {
				if _, ok := attrValue(r, "code"); ok {
					coded = append(coded, r)
				}
			}

			require.Len(t, coded, 1, "one record per redirect carrying the code")
			code, _ := attrValue(coded[0], "code")
			assert.Equal(t, tc.code, code.String())
			flowAttr, _ := attrValue(coded[0], "flow")
			assert.Equal(t, tc.flow, flowAttr.String(), "the site's own flow")
			if tc.path == "start" {
				assert.NotContains(t, coded[0].Message, "callback", "the start's own message")
			}

			var errs []slog.Record

			for _, r := range logs.records() {
				if r.Level >= slog.LevelError {
					errs = append(errs, r)
				}
			}

			if tc.serverError {
				require.Len(t, errs, 1, "exactly one ERROR record")
				reason, _ := attrValue(errs[0], "reason")
				assert.Equal(t, "server-error", reason.String())
				typ, ok := attrValue(errs[0], "error_type")
				require.True(t, ok, "the error's type is named")
				assert.NotEmpty(t, typ.String())
			} else {
				assert.Empty(t, errs, "no ERROR record")
			}

			written := out.String()
			assert.NotContains(t, written, "apply down", "never the error's text")
			for _, s := range secrets {
				require.NotEmpty(t, s)
				assert.NotContains(t, written, s, "no record holds a secret or the target")
			}
		})
	}
}

// slogFanout hands every record to each of its handlers.
type slogFanout []slog.Handler

func (h slogFanout) Enabled(context.Context, slog.Level) bool { return true }

func (h slogFanout) Handle(ctx context.Context, r slog.Record) error {
	for _, each := range h {
		if err := each.Handle(ctx, r.Clone()); err != nil {
			return err
		}
	}

	return nil
}

func (h slogFanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(slogFanout, 0, len(h))
	for _, each := range h {
		out = append(out, each.WithAttrs(attrs))
	}

	return out
}

func (h slogFanout) WithGroup(name string) slog.Handler {
	out := make(slogFanout, 0, len(h))
	for _, each := range h {
		out = append(out, each.WithGroup(name))
	}

	return out
}
