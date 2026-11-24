package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/session"
)

// brokeredRP is completionRP with broker resolving identities.
func brokeredRP(t *testing.T, idp *oidcTestProvider, origin string, broker oidc.IdentityBroker) *oidc.RelyingParty {
	t.Helper()

	reg := idp.provider()
	reg.RedirectURL = origin + httpsec.DefaultOIDCCallbackPath + testOIDCProvider

	out := []outbound.Option{outbound.WithHTTPClient(idp.srv.Client())}
	if strings.HasPrefix(origin, "http://") {
		out = append(out, outbound.WithAllowedSchemes("https", "http"))
	}

	return must.Must(oidc.NewRelyingParty(must.Must(oidc.NewRegistry(reg)), broker,
		oidc.WithOutboundClient(must.Must(outbound.New(out...))),
		oidc.WithFlowStore(must.Must(oidc.NewMemoryFlowStore()))))
}

// parkedUsers loads oidcTestUserID as active, and no one else.
func parkedUsers(t *testing.T) identity.UserLoader {
	t.Helper()

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id identity.UserID) (*identity.Details, error) {
			if id != oidcTestUserID {
				return nil, identity.ErrUserNotFound
			}

			return &identity.Details{ID: oidcTestUserID, Username: "ada@example.com", Active: true}, nil
		})

	return users
}

// hookBroker is the library's broker with a sign-in hook for testOIDCProvider, over a
// link store holding links.
func hookBroker(hook oidc.SignInHook, links ...oidc.Link) func(t *testing.T, idp *oidcTestProvider) oidc.IdentityBroker {
	return func(t *testing.T, _ *oidcTestProvider) oidc.IdentityBroker {
		t.Helper()

		store := oidc.NewMemoryLinkStore()
		for _, l := range links {
			require.NoError(t, store.Insert(t.Context(), l))
		}

		return must.Must(oidc.NewBroker(store, parkedUsers(t), oidc.WithBrokerSignInHook(testOIDCProvider, hook)))
	}
}

// refusingHook refuses every identity.
func refusingHook(context.Context, oidc.ExternalIdentity, oidc.Upstream, identity.UserID) (oidc.SignInDecision, error) {
	return oidc.SignInDecision{}, oidc.ErrProvisioningRefused
}

// adoptingHook decides every identity is oidcTestUserID's.
func adoptingHook(context.Context, oidc.ExternalIdentity, oidc.Upstream, identity.UserID) (oidc.SignInDecision, error) {
	return oidc.SignInDecision{User: oidcTestUserID}, nil
}

// userInfoBroker is a consumer broker that fetches UserInfo on every login and
// returns its failure as it is.
type userInfoBroker struct{}

func (userInfoBroker) Broker(context.Context, oidc.ExternalIdentity) (*identity.Principal, error) {
	return nil, oidc.ErrNoLinkedAccount
}

func (userInfoBroker) AcceptsUpstream(string) bool { return true }

func (userInfoBroker) BrokerUpstream(ctx context.Context, _ oidc.ExternalIdentity, up oidc.Upstream) (*identity.Principal, error) {
	if _, err := up.UserInfo(ctx); err != nil {
		return nil, err
	}

	return &identity.Principal{ID: oidcTestUserID}, nil
}

// userInfoHook is a sign-in hook that reads the upstream's UserInfo, returning its
// failure as it is.
func userInfoHook(ctx context.Context, _ oidc.ExternalIdentity, up oidc.Upstream, _ identity.UserID) (oidc.SignInDecision, error) {
	if _, err := up.UserInfo(ctx); err != nil {
		return oidc.SignInDecision{}, err
	}

	return oidc.SignInDecision{User: oidcTestUserID}, nil
}

// userInfoDownRP is a relying party whose library broker runs userInfoHook, against a
// UserInfo endpoint that answers 503.
func userInfoDownRP(t *testing.T, idp *oidcTestProvider, origin string) *oidc.RelyingParty {
	t.Helper()

	down := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)

	reg := idp.provider()
	reg.RedirectURL = origin + httpsec.DefaultOIDCCallbackPath + testOIDCProvider
	reg.UserInfoEndpoint = down.URL + "/userinfo"

	return must.Must(oidc.NewRelyingParty(must.Must(oidc.NewRegistry(reg)),
		hookBroker(userInfoHook)(t, idp),
		oidc.WithOutboundClient(must.Must(outbound.New(outbound.WithHTTPClient(idp.srv.Client())))),
		oidc.WithFlowStore(must.Must(oidc.NewMemoryFlowStore()))))
}

// parkedReturn is the login page the failure of a login for handle returns to,
// carrying code under param.
func parkedReturn(handle, param, code string) string {
	return completionLoginURL + "?" + oidcprovider.HandleParam + "=" + url.QueryEscape(handle) + "&" + param + "=" + code
}

// assertReturnedToLogin asserts a, a callback's answer, sends the browser back to the
// login page for handle with code, and leaves the request parked.
func assertReturnedToLogin(t *testing.T, f *completionFlow, a flowAnswer, handle, flow, param, code string) {
	t.Helper()

	require.NoError(t, a.err, "nothing reached the error handling")
	require.Equal(t, http.StatusSeeOther, a.status, a.body)
	assert.Equal(t, parkedReturn(handle, param, code), a.header.Get("Location"))
	assert.Len(t, a.location(t).Query(), 2, "the handle and the code, and nothing else")
	assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
	assert.Equal(t, "no-referrer", a.header.Get("Referrer-Policy"))

	cleared := a.cookie(httpsec.DefaultOIDCFlowCookieName)
	require.NotNil(t, cleared, "the login's flow cookie is cleared")
	assert.Negative(t, cleared.MaxAge)

	assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle, flow), "the request stays parked")
	assert.Zero(t, f.storedSessions(t), "no session")
}

// TestCallback_ParkedFailureReturnsToLogin pins that a failed brokered login for a
// parked request returns to the provider's login page with the failure's code (D3,
// D4), the request still resumable: every refusal is access_denied (F19) and every
// upstream outage temporarily_unavailable.
func TestCallback_ParkedFailureReturnsToLogin(t *testing.T) {
	t.Parallel()

	otherSubject := oidc.Link{
		Provider: testOIDCProvider, Subject: "another-subject", UserID: oidcTestUserID, CreatedAt: time.Now(),
	}

	type testCase struct {
		name  string
		setup completionSetup
		// before runs once the flow is built and the request parked.
		before func(t *testing.T, f *completionFlow)
		// code is the code the upstream is called back with; empty is the nonce,
		// which the fake upstream issues a valid ID token for.
		code   string
		assert func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string)
	}

	returned := func(param, code string) func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string) {
		return func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string) {
			t.Helper()

			assertReturnedToLogin(t, f, a, handle, flow, param, code)
		}
	}

	denied := returned(httpsec.DefaultOIDCLoginErrorParam, oidcprovider.CodeAccessDenied)
	unavailable := returned(httpsec.DefaultOIDCLoginErrorParam, oidcprovider.CodeTemporarilyUnavailable)

	cases := []testCase{
		{name: "the sign-in hook refuses", setup: completionSetup{broker: hookBroker(refusingHook)}, assert: denied},
		{
			name: "the one-link rule refuses the hook's decision",
			setup: completionSetup{broker: func(t *testing.T, idp *oidcTestProvider) oidc.IdentityBroker {
				t.Helper()

				l := otherSubject
				l.Issuer = idp.srv.URL

				return hookBroker(adoptingHook, l)(t, idp)
			}},
			assert: denied,
		},
		{name: "an invalid ID token", code: "not-the-nonce", assert: denied},
		{name: "an identity linked to no account", setup: completionSetup{unlinked: true}, assert: denied},
		{
			name:   "the upstream's token endpoint is down",
			before: func(_ *testing.T, f *completionFlow) { f.idp.tokenDown.Store(true) },
			assert: unavailable,
		},
		{
			name: "the upstream's UserInfo is down",
			setup: completionSetup{broker: func(*testing.T, *oidcTestProvider) oidc.IdentityBroker {
				return userInfoBroker{}
			}},
			assert: unavailable,
		},
		{
			name:   "the library broker's sign-in hook meets a UserInfo outage",
			setup:  completionSetup{rp: userInfoDownRP},
			assert: unavailable,
		},
		{
			// A broker that met a refusal and an outage at once: the refusal is the
			// answer, so the user is told no, not to try again (D4).
			name: "a refusal beside an outage",
			setup: completionSetup{broker: func(t *testing.T, _ *oidcTestProvider) oidc.IdentityBroker {
				t.Helper()

				b := NewMockIdentityBroker(gomock.NewController(t))
				b.EXPECT().Broker(gomock.Any(), gomock.Any()).AnyTimes().
					Return(nil, errors.Join(oidc.ErrNoLinkedAccount, fmt.Errorf("%w: 503", oidc.ErrUserInfoFailed)))

				return b
			}},
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string) {
				t.Helper()

				assertReturnedToLogin(t, f, a, handle, flow, httpsec.DefaultOIDCLoginErrorParam, oidcprovider.CodeAccessDenied)
				assert.Len(t, f.events.named(event.AuthnLoginFail), 1, "one login-failure event, as for a refusal")
			},
		},
		{
			name: "a consumer's renamed parameter",
			setup: completionSetup{
				broker: hookBroker(refusingHook),
				oidc:   []httpsec.OIDCOption{httpsec.WithOIDCLoginErrorParam("sso_error")},
			},
			assert: returned("sso_error", oidcprovider.CodeAccessDenied),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCompletionFlow(t, tc.setup)
			handle, flow := f.park(t, flowWeb)

			login := f.startSSO(t, parkedAt(handle))
			if tc.code != "" {
				login.nonce = tc.code
			}

			if tc.before != nil {
				tc.before(t, f)
			}

			tc.assert(t, f, f.callBack(t, login, flowCookieOf(flowCookie, flow)), handle, flow)
		})
	}
}

// TestCallback_UnparkedDestinationKeepsAnswer pins that a failed login whose
// destination is not the configured login URL carrying one handle keeps its answer,
// with no redirect: an ordinary destination, a login URL the consumer has since moved
// (Review Focus 2), a look-alike carrying another parameter, and completion off.
func TestCallback_UnparkedDestinationKeepsAnswer(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		off  bool
		next func(handle string) string
	}

	cases := []testCase{
		{name: "an ordinary destination", next: func(string) string { return "/welcome" }},
		{
			name: "a login URL the consumer has since moved",
			next: func(handle string) string {
				return opIssuer + "/old-login?" + url.Values{oidcprovider.HandleParam: {handle}}.Encode()
			},
		},
		{
			name: "the login URL carrying another parameter",
			next: func(handle string) string { return parkedAt(handle) + "&error=x" },
		},
		{name: "completion off", off: true, next: parkedAt},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCompletionFlow(t, completionSetup{broker: hookBroker(refusingHook), off: tc.off})
			handle, flow := f.park(t, flowWeb)

			a := f.signIn(t, tc.next(handle), flowCookieOf(flowCookie, flow))

			require.ErrorIs(t, a.err, oidc.ErrProvisioningRefused, "the login's own refusal")
			assert.Equal(t, http.StatusUnauthorized, a.status)
			assert.Empty(t, a.header.Get("Location"), "no redirect")
			assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle, flow))
			assert.Zero(t, f.charged.Load(), "nothing charged")
		})
	}
}

// TestReturnParked_Guards pins that a return to the login page passes completion's
// checks first (D6): over plain HTTP, throttled, with a handle that is unknown or
// bound to another browser (F1), or past its login stage, the login's own refusal is
// answered with no redirect, and the source is charged once at most (F8).
func TestReturnParked_Guards(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		setup func(t *testing.T) completionSetup
		// parked returns the handle the login starts for and the provider flow
		// cookie the callback carries.
		parked func(t *testing.T, f *completionFlow) (handle, flow string)
		change []flowChange
		// stays says the row's request is live, and must still be parked after.
		stays  bool
		assert func(t *testing.T, f *completionFlow, a flowAnswer, lookups int64)
	}

	refusing := func(*testing.T) completionSetup { return completionSetup{broker: hookBroker(refusingHook)} }

	original := func(charged int64) func(t *testing.T, f *completionFlow, a flowAnswer, lookups int64) {
		return func(t *testing.T, f *completionFlow, a flowAnswer, _ int64) {
			t.Helper()

			require.ErrorIs(t, a.err, oidc.ErrProvisioningRefused, "the login's own refusal")
			assert.Equal(t, charged, f.charged.Load(), "charged to the source")
		}
	}

	// The victim's request in the F1 row, by the flow that parked it, read back once
	// its callback is answered.
	type victim struct{ handle, flow string }

	var victims sync.Map

	cases := []testCase{
		{
			name:  "a handle bound to another browser",
			setup: refusing,
			parked: func(t *testing.T, f *completionFlow) (string, string) {
				t.Helper()

				handle, flow := f.park(t, flowWeb)
				victims.Store(f, victim{handle: handle, flow: flow})
				_, other := f.park(t, flowWeb)

				return handle, other
			},
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, lookups int64) {
				t.Helper()

				original(1)(t, f, a, lookups)
				v, _ := victims.Load(f)
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, v.(victim).handle, v.(victim).flow),
					"the victim's request is unchanged (F1)")
			},
		},
		{
			name:  "an unknown handle",
			setup: refusing,
			parked: func(t *testing.T, f *completionFlow) (string, string) {
				t.Helper()

				_, flow := f.park(t, flowWeb)

				return "rh.unknown", flow
			},
			assert: original(1),
		},
		{
			name:  "a handle at its consent stage",
			setup: refusing,
			parked: func(t *testing.T, f *completionFlow) (string, string) {
				t.Helper()

				handle, flow := f.park(t, flowWeb)
				// Another user's session, so the row's own counts stay the linked user's.
				s, err := f.sessions.Create(t.Context(), "someone-else", session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				_, err = f.p.Resume(t.Context(), oidcprovider.ResumeInput{
					Handle: handle, FlowSecret: flow, IdleTimeout: f.sessions.IdleTimeout(),
					SignIn: &oidcprovider.SignIn{
						User: s.UserID, Family: s.FamilyID,
						AuthenticatedAt: s.AuthenticatedAt, AbsoluteExpiresAt: s.AbsoluteExpiresAt,
					},
				})
				require.NoError(t, err)
				require.Equal(t, oidcprovider.StageConsent, f.stage(t, handle, flow))

				return handle, flow
			},
			assert: original(0),
		},
		{
			name:   "over plain HTTP while the provider insists on TLS",
			setup:  refusing,
			change: []flowChange{flowPlainHTTP},
			stays:  true,
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, lookups int64) {
				t.Helper()

				original(0)(t, f, a, lookups)
				assert.Zero(t, lookups, "the request was never looked up")
			},
		},
		{
			name:  "a throttled source",
			stays: true,
			setup: func(t *testing.T) completionSetup {
				t.Helper()

				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

				return completionSetup{broker: hookBroker(refusingHook), limiter: l}
			},
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, lookups int64) {
				t.Helper()

				original(0)(t, f, a, lookups)
				assert.Zero(t, lookups, "the request was never looked up")
			},
		},
		{
			name: "a pending-request store that cannot answer",
			setup: func(*testing.T) completionSetup {
				return completionSetup{
					broker: hookBroker(refusingHook),
					pending: &downablePendingStore{
						PendingRequestStore: must.Must(oidcprovider.NewMemoryPendingRequestStore()),
					},
				}
			},
			parked: func(t *testing.T, f *completionFlow) (string, string) {
				t.Helper()

				handle, flow := f.park(t, flowWeb)
				f.setup.pending.down.Store(true)

				return handle, flow
			},
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, lookups int64) {
				t.Helper()

				original(0)(t, f, a, lookups)
				assert.NotErrorIs(t, a.err, errPendingDown, "the store's failure does not replace the refusal")
			},
		},
		{
			name: "completion's own pre-check refused a login that succeeded",
			setup: func(*testing.T) completionSetup {
				return completionSetup{}
			},
			parked: func(t *testing.T, f *completionFlow) (string, string) {
				t.Helper()

				handle, _ := f.park(t, flowWeb)
				_, other := f.park(t, flowWeb)

				return handle, other
			},
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, _ int64) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
				assert.Equal(t, int64(1), f.charged.Load(), "charged once, not again by a return")
			},
		},
	}

	// Every guard runs first whichever way the failure is answered: under
	// WithOIDCFailToClient a refused return must not end the request either.
	modes := []struct {
		name string
		oidc []httpsec.OIDCOption
	}{
		{name: "to the login page"},
		{name: "to the client", oidc: []httpsec.OIDCOption{httpsec.WithOIDCFailToClient()}},
	}

	for _, mode := range modes {
		for _, tc := range cases {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				setup := tc.setup(t)
				setup.oidc = append(slices.Clone(setup.oidc), mode.oidc...)
				f := newCompletionFlow(t, setup)
				f.setup = setup

				parked := tc.parked
				if parked == nil {
					parked = func(t *testing.T, f *completionFlow) (string, string) {
						t.Helper()

						return f.park(t, flowWeb)
					}
				}

				handle, flow := parked(t, f)
				login := f.startSSO(t, parkedAt(handle))

				before := f.pending.loads.Load()
				a := f.callBack(t, login, append([]flowChange{flowCookieOf(flowCookie, flow)}, tc.change...)...)

				tc.assert(t, f, a, f.pending.loads.Load()-before)
				assert.Empty(t, a.header.Get("Location"), "no redirect")
				assert.Zero(t, f.storedSessions(t), "no session")

				if tc.stays {
					assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle, flow), "the request is never ended")
				}
			})
		}
	}
}

// parkedErrorRecords are the ERROR records of logs.
func parkedErrorRecords(logs []slog.Record) []slog.Record {
	var out []slog.Record

	for _, r := range logs {
		if r.Level >= slog.LevelError {
			out = append(out, r)
		}
	}

	return out
}

// TestReturnParked_CheckStoreFailure pins that a pending-request store failing in the
// return's own check, in the read or in the end that answers an expired request, gives
// the login's original error with no redirect and no charge, and is recorded once at
// ERROR as parked-unchecked (D6, F7); and that a caller who hung up during the check
// gets the same answer with no record, since nothing failed that anyone can fix.
func TestReturnParked_CheckStoreFailure(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// arm sets the fault once the request is parked; cancel hangs the caller up.
		arm func(f *completionFlow, store *downablePendingStore, cancel func())
		// hangsUp says the caller's context is cancelled by the fault.
		hangsUp bool
	}

	cases := []testCase{
		{
			name: "the read fails",
			arm:  func(_ *completionFlow, store *downablePendingStore, _ func()) { store.down.Store(true) },
		},
		{
			name: "the end of an expired request fails",
			arm: func(f *completionFlow, store *downablePendingStore, _ func()) {
				f.clk.Advance(12 * time.Minute)
				store.downAfterNext.Store(true)
			},
		},
		{
			name:    "the caller hangs up during the read",
			hangsUp: true,
			arm: func(_ *completionFlow, store *downablePendingStore, cancel func()) {
				store.onLoad = func(context.Context) error {
					cancel()

					return context.Canceled
				}
			},
		},
		{
			name:    "the caller hangs up during the end of an expired request",
			hangsUp: true,
			arm: func(f *completionFlow, store *downablePendingStore, cancel func()) {
				f.clk.Advance(12 * time.Minute)

				var reads atomic.Int64

				store.onLoad = func(context.Context) error {
					if reads.Add(1) == 1 {
						return nil
					}

					cancel()

					return context.Canceled
				}
			},
		},
	}

	modes := []struct {
		name string
		oidc []httpsec.OIDCOption
	}{
		{name: "to the login page"},
		{name: "to the client", oidc: []httpsec.OIDCOption{httpsec.WithOIDCFailToClient()}},
	}

	for _, mode := range modes {
		for _, tc := range cases {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				logs := &capturingHandler{}
				store := &downablePendingStore{
					PendingRequestStore: must.Must(oidcprovider.NewMemoryPendingRequestStore()),
				}
				setup := completionSetup{broker: hookBroker(refusingHook), pending: store, oidc: mode.oidc}
				setup.chain = func(*testing.T, *completionFlow) []httpsec.Option {
					return []httpsec.Option{httpsec.WithLogger(slog.New(logs))}
				}

				f := newCompletionFlow(t, setup)
				handle, flow := f.park(t, flowWeb)
				login := f.startSSO(t, parkedAt(handle))

				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)

				hangUp := func(r *http.Request) {
					*r = *r.WithContext(ctx)
				}

				tc.arm(f, store, func() { cancel() })

				a := f.callBack(t, login, flowCookieOf(flowCookie, flow), hangUp)

				require.ErrorIs(t, a.err, oidc.ErrProvisioningRefused, "the login's own refusal")
				assert.Empty(t, a.header.Get("Location"), "no redirect")
				assert.Zero(t, f.charged.Load(), "a store failure is not charged")

				errs := parkedErrorRecords(logs.records())
				if tc.hangsUp {
					assert.Empty(t, errs, "a hung-up caller is no failure to report")

					return
				}

				require.Len(t, errs, 1, "exactly one ERROR record")
				reason, _ := attrValue(errs[0], "reason")
				assert.Equal(t, "parked-unchecked", reason.String())
			})
		}
	}
}

// TestProviderError_ParkedReturnsToLogin pins that an upstream error= on a login for a
// parked request returns to the login page with access_denied once the echoed state
// ends the flow (D3, D5), and that one whose state ends nothing changes nothing (F21).
func TestProviderError_ParkedReturnsToLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		next   func(handle string) string
		state  func(login ssoLogin) string
		assert func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string)
	}

	realState := func(login ssoLogin) string { return login.state }

	cases := []testCase{
		{
			name: "the flow's real state", next: parkedAt, state: realState,
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string) {
				t.Helper()

				assertReturnedToLogin(t, f, a, handle, flow,
					httpsec.DefaultOIDCLoginErrorParam, oidcprovider.CodeAccessDenied)
			},
		},
		{
			name: "a forged state", next: parkedAt,
			state: func(ssoLogin) string { return "forged" },
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string) {
				t.Helper()

				require.ErrorIs(t, a.err, oidc.ErrInvalidState)
				assert.Empty(t, a.header.Get("Location"), "no redirect")
				assert.Empty(t, a.header.Values("Set-Cookie"), "no cookie header")
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle, flow))
			},
		},
		{
			name: "the real state of an ordinary login", next: func(string) string { return "/welcome" }, state: realState,
			assert: func(t *testing.T, _ *completionFlow, a flowAnswer, _, _ string) {
				t.Helper()

				require.ErrorIs(t, a.err, oidc.ErrInvalidState)
				assert.Empty(t, a.header.Get("Location"), "no redirect")
				require.NotNil(t, a.cookie(httpsec.DefaultOIDCFlowCookieName), "the ended flow's cookie is cleared")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCompletionFlow(t, completionSetup{})
			handle, flow := f.park(t, flowWeb)
			login := f.startSSO(t, tc.next(handle))

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
				f.issuer+httpsec.DefaultOIDCCallbackPath+testOIDCProvider+"?"+
					url.Values{"error": {"access_denied"}, "state": {tc.state(login)}}.Encode(), nil)

			a := f.serve(t, r, []flowChange{
				flowCookieOf(httpsec.DefaultOIDCFlowCookieName, login.rpFlow),
				flowCookieOf(flowCookie, flow),
			})

			tc.assert(t, f, a, handle, flow)
		})
	}
}
