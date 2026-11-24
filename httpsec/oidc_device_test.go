package httpsec_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
)

const (
	deviceAuthorizationPath = "/oauth2/device-authorization"
	deviceEntryPath         = "/oauth2/device"
	deviceTokenPath         = "/oauth2/token" //nolint:gosec // G101: a path, not a credential

	// deviceTV is a public client registered for the device grant, and deviceCLI a
	// confidential one authenticating with client_secret_basic.
	deviceTV  = "device-tv"
	deviceCLI = "device-cli"

	// deviceEntryPage is the consumer's code-entry page, under the issuer.
	deviceEntryPage = "/enter-code"

	// deviceUnknownCode is a well-formed user code no authorization holds.
	deviceUnknownCode = "BBBB-BBBB"
)

// deviceKey is the user-code key every device provider here digests under.
var deviceKey = bytes.Repeat([]byte{7}, oidcprovider.MinUserCodeKeyBytes)

// deviceClients are the clients registered for the device grant.
func deviceClients() []oidcprovider.Client {
	scopes := []string{"openid", "profile", "offline_access"}
	device := []oidcprovider.GrantType{oidcprovider.GrantDeviceCode}

	return []oidcprovider.Client{
		{
			ID: deviceTV, Name: "Device TV", Type: oidcprovider.Public, ApplicationType: oidcprovider.Native,
			Scopes: scopes, GrantTypes: device,
		},
		{
			ID: deviceCLI, Name: "Device CLI", Type: oidcprovider.Confidential, Secret: []byte(tokenSecret),
			Scopes: scopes, GrantTypes: device,
		},
	}
}

// deviceSetup is a provider at issuer (opIssuer when empty) with the device grant
// enabled, and the clients registered for it.
func deviceSetup(issuer string, device ...oidcprovider.DeviceOption) flowSetup {
	if issuer == "" {
		issuer = opIssuer
	}

	return flowSetup{
		issuer:  issuer,
		clients: deviceClients(),
		provider: []oidcprovider.Option{oidcprovider.WithDeviceAuthorization(issuer+deviceEntryPage,
			append([]oidcprovider.DeviceOption{oidcprovider.WithUserCodeKey(deviceKey)}, device...)...)},
	}
}

// deviceBasic presents id and secret as client_secret_basic.
func deviceBasic(id, secret string) flowChange {
	return func(r *http.Request) { r.SetBasicAuth(id, secret) }
}

// postForm posts form to path, as a client or a browser would.
func (w *opFlow) postForm(t *testing.T, path string, form url.Values, change ...flowChange) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, w.issuer+path,
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return w.serve(t, r, change)
}

// deviceAuthorize posts form to the device authorization endpoint.
func (w *opFlow) deviceAuthorize(t *testing.T, form url.Values, change ...flowChange) flowAnswer {
	t.Helper()

	return w.postForm(t, deviceAuthorizationPath, form, change...)
}

// entryGET sends rawQuery to the code-entry endpoint, as a browser following a link would.
func (w *opFlow) entryGET(t *testing.T, rawQuery string, change ...flowChange) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, w.issuer+deviceEntryPath+"?"+rawQuery, nil)

	return w.serve(t, r, change)
}

// enter is a GET of the code-entry endpoint carrying code.
func (w *opFlow) enter(t *testing.T, code string, change ...flowChange) flowAnswer {
	t.Helper()

	return w.entryGET(t, url.Values{"user_code": {code}}.Encode(), change...)
}

// deviceIssued is what the device authorization endpoint answered.
type deviceIssued struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
}

// issueDevice starts a device authorization for clientID, which must succeed.
func (w *opFlow) issueDevice(t *testing.T, clientID string, change ...flowChange) deviceIssued {
	t.Helper()

	form := url.Values{"scope": {"openid"}}
	if clientID == deviceTV {
		form.Set("client_id", deviceTV)
	} else {
		change = append(change, deviceBasic(clientID, tokenSecret))
	}

	a := w.deviceAuthorize(t, form, change...)
	require.Equal(t, http.StatusOK, a.status, a.body)

	var issued deviceIssued
	require.NoError(t, json.Unmarshal([]byte(a.body), &issued))
	require.NotEmpty(t, issued.DeviceCode)
	require.NotEmpty(t, issued.UserCode)

	return issued
}

// poll asks the token endpoint for the device code's tokens, as deviceTV.
func (w *opFlow) poll(t *testing.T, deviceCode string) flowAnswer {
	t.Helper()

	return w.postForm(t, deviceTokenPath, url.Values{
		"grant_type":  {string(oidcprovider.GrantDeviceCode)},
		"device_code": {deviceCode},
		"client_id":   {deviceTV},
	})
}

// refusalCode is the error code of a token-style refusal body.
func refusalCode(t *testing.T, a flowAnswer) string {
	t.Helper()

	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(a.body), &doc), a.body)

	code, _ := doc["error"].(string)

	return code
}

// deviceCountingStore counts the device authorizations stored.
type deviceCountingStore struct {
	oidcprovider.DeviceAuthorizationStore

	creates atomic.Int64
}

func (s *deviceCountingStore) Create(ctx context.Context, r *oidcprovider.DeviceAuthorization, now time.Time) error {
	s.creates.Add(1)

	return s.DeviceAuthorizationStore.Create(ctx, r, now)
}

func TestDeviceAuthorizationEndpoint(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		issuer   string
		endpoint []httpsec.OIDCProviderOption
		send     func(t *testing.T, w *opFlow) flowAnswer
		assert   func(t *testing.T, a flowAnswer, stored int64)
	}

	publicForm := url.Values{"client_id": {deviceTV}, "scope": {"openid"}}

	refusedAs := func(status int, code string) func(t *testing.T, a flowAnswer, stored int64) {
		return func(t *testing.T, a flowAnswer, stored int64) {
			t.Helper()

			assert.Equal(t, status, a.status, a.body)
			assert.JSONEq(t, `{"error":"`+code+`"}`, a.body)
			assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			assert.Zero(t, stored, "nothing is issued")
		}
	}

	issued := func(t *testing.T, a flowAnswer, stored int64) {
		t.Helper()

		require.Equal(t, http.StatusOK, a.status, a.body)
		assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
		assert.Equal(t, "application/json", a.header.Get("Content-Type"))

		var doc map[string]any
		require.NoError(t, json.Unmarshal([]byte(a.body), &doc), a.body)

		keys := make([]string, 0, len(doc))
		for k := range doc {
			keys = append(keys, k)
		}

		assert.ElementsMatch(t, []string{"device_code", "user_code", "verification_uri", "expires_in", "interval"}, keys)
		assert.Equal(t, opIssuer+deviceEntryPage, doc["verification_uri"])
		assert.InDelta(t, 600, doc["expires_in"], 0)
		assert.InDelta(t, 5, doc["interval"], 0)
		assert.Equal(t, int64(1), stored)
	}

	cases := []testCase{
		{
			name: "a GET is refused with 405 and nothing is issued",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					w.issuer+deviceAuthorizationPath+"?"+publicForm.Encode(), nil)

				return w.serve(t, r, nil)
			},
			assert: func(t *testing.T, a flowAnswer, stored int64) {
				t.Helper()

				assert.Equal(t, http.StatusMethodNotAllowed, a.status)
				assert.Equal(t, http.MethodPost, a.header.Get("Allow"))
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
				assert.Zero(t, stored)
			},
		},
		{
			name: "plain HTTP on an https issuer is refused",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.deviceAuthorize(t, publicForm, flowPlainHTTP)
			},
			assert: refusedAs(http.StatusBadRequest, oidcprovider.CodeInvalidRequest),
		},
		{
			name:   "plain HTTP on the loopback issuer is answered",
			issuer: flowLoopback,
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.deviceAuthorize(t, publicForm, flowPlainHTTP)
			},
			assert: func(t *testing.T, a flowAnswer, stored int64) {
				t.Helper()

				assert.Equal(t, http.StatusOK, a.status, a.body)
				assert.Equal(t, int64(1), stored)
			},
		},
		{
			name: "a valid POST from a public client is answered with the codes",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.deviceAuthorize(t, publicForm)
			},
			assert: issued,
		},
		{
			name: "a confidential client authenticates as at the token endpoint",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.deviceAuthorize(t, url.Values{"scope": {"openid"}}, deviceBasic(deviceCLI, tokenSecret))
			},
			assert: issued,
		},
		{
			name: "a wrong secret is invalid_client, with the token endpoint's challenge",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.deviceAuthorize(t, url.Values{"scope": {"openid"}}, deviceBasic(deviceCLI, "wrong"))
			},
			assert: func(t *testing.T, a flowAnswer, stored int64) {
				t.Helper()

				refusedAs(http.StatusUnauthorized, oidcprovider.CodeInvalidClient)(t, a, stored)
				assert.Equal(t, `Basic realm="oauth2"`, a.header.Get("WWW-Authenticate"))
			},
		},
		{
			name: "a scope the client may not ask for is invalid_scope",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.deviceAuthorize(t, url.Values{"client_id": {deviceTV}, "scope": {"openid email"}})
			},
			assert: refusedAs(http.StatusBadRequest, oidcprovider.CodeInvalidScope),
		},
		{
			name: "a client not registered for the grant is unauthorized_client",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.deviceAuthorize(t, url.Values{"scope": {"openid"}}, deviceBasic(flowWeb, tokenSecret))
			},
			assert: refusedAs(http.StatusBadRequest, oidcprovider.CodeUnauthorizedClient),
		},
		{
			name: "a credential in the query is refused",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
					w.issuer+deviceAuthorizationPath+"?client_secret="+tokenSecret,
					strings.NewReader(url.Values{"client_id": {deviceCLI}, "scope": {"openid"}}.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return w.serve(t, r, nil)
			},
			assert: refusedAs(http.StatusBadRequest, oidcprovider.CodeInvalidRequest),
		},
		{
			name: "a repeated parameter is refused",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.deviceAuthorize(t, url.Values{"client_id": {deviceTV}, "scope": {"openid", "openid"}})
			},
			assert: refusedAs(http.StatusBadRequest, oidcprovider.CodeInvalidRequest),
		},
		{
			name: "a body that is not a form is refused",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, w.issuer+deviceAuthorizationPath,
					strings.NewReader(`{"client_id":"device-tv","scope":"openid"}`))
				r.Header.Set("Content-Type", "application/json")

				return w.serve(t, r, nil)
			},
			assert: refusedAs(http.StatusBadRequest, oidcprovider.CodeInvalidRequest),
		},
		{
			name:     "a body over the limit is refused before it is parsed",
			endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCDeviceAuthorizationBodyLimit(16)},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.deviceAuthorize(t, publicForm)
			},
			assert: func(t *testing.T, a flowAnswer, stored int64) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
				assert.Zero(t, stored)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &deviceCountingStore{DeviceAuthorizationStore: oidcprovider.NewMemoryDeviceAuthorizationStore()}
			setup := deviceSetup(tc.issuer, oidcprovider.WithDeviceAuthorizationStore(store))
			setup.endpoint = tc.endpoint

			w := newOPFlow(t, setup)
			a := tc.send(t, w)
			tc.assert(t, a, store.creates.Load())
			assert.NotContains(t, a.body, tokenSecret, "no secret is repeated")
		})
	}
}

func TestDeviceAuthorizationEndpoint_Throttle(t *testing.T) {
	t.Parallel()

	t.Run("the eleventh request after 10 failures is invalid_client, and the token endpoint keeps its own budget",
		func(t *testing.T) {
			t.Parallel()

			w := newOPFlow(t, deviceSetup(""))
			started := w.issueDevice(t, deviceCLI)

			for i := range 10 {
				a := w.deviceAuthorize(t, url.Values{"scope": {"openid"}}, deviceBasic(deviceCLI, "wrong"))
				require.Equalf(t, http.StatusUnauthorized, a.status, "failure %d: %s", i+1, a.body)
			}

			a := w.deviceAuthorize(t, url.Values{"scope": {"openid"}}, deviceBasic(deviceCLI, tokenSecret))
			assert.Equal(t, http.StatusUnauthorized, a.status, a.body)
			assert.Equal(t, oidcprovider.CodeInvalidClient, refusalCode(t, a))

			other := w.deviceAuthorize(t, url.Values{"scope": {"openid"}}, deviceBasic(deviceCLI, tokenSecret),
				flowFrom(flowOtherAddr))
			assert.Equal(t, http.StatusOK, other.status, "another source keeps its budget: %s", other.body)

			polled := w.postForm(t, deviceTokenPath, url.Values{
				"grant_type":  {string(oidcprovider.GrantDeviceCode)},
				"device_code": {started.DeviceCode},
			}, deviceBasic(deviceCLI, tokenSecret))
			assert.Equal(t, http.StatusBadRequest, polled.status, polled.body)
			assert.Equal(t, oidcprovider.CodeAuthorizationPending, refusalCode(t, polled),
				"the token endpoint authenticated the client on its own budget")
		})

	t.Run("WithOIDCDeviceAuthorizationLimiter is the limiter asked", func(t *testing.T) {
		t.Parallel()

		limiter := NewMockLimiter(gomock.NewController(t))
		limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).MinTimes(1)
		limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		setup := deviceSetup("")
		setup.endpoint = []httpsec.OIDCProviderOption{httpsec.WithOIDCDeviceAuthorizationLimiter(limiter)}
		w := newOPFlow(t, setup)

		a := w.deviceAuthorize(t, url.Values{"client_id": {deviceTV}, "scope": {"openid"}})
		assert.Equal(t, http.StatusUnauthorized, a.status, a.body)
		assert.Equal(t, oidcprovider.CodeInvalidClient, refusalCode(t, a))
	})

	t.Run("a limiter that cannot answer refuses as invalid_client", func(t *testing.T) {
		t.Parallel()

		setup := deviceSetup("")
		setup.endpoint = []httpsec.OIDCProviderOption{httpsec.WithOIDCDeviceAuthorizationLimiter(flowDownLimiter{})}
		w := newOPFlow(t, setup)

		a := w.deviceAuthorize(t, url.Values{"client_id": {deviceTV}, "scope": {"openid"}})
		assert.Equal(t, http.StatusUnauthorized, a.status, a.body)
	})
}

// deviceFailingPending is a pending-request store whose next Create fails once armed.
type deviceFailingPending struct {
	*oidcprovider.MemoryPendingRequestStore

	failNext atomic.Bool
}

func (s *deviceFailingPending) Create(ctx context.Context, r *oidcprovider.PendingRequest) error {
	if s.failNext.CompareAndSwap(true, false) {
		return errors.New("pending store is out")
	}

	return s.MemoryPendingRequestStore.Create(ctx, r)
}

func TestDeviceEntryEndpoint(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		setup func(s *flowSetup)
		run   func(t *testing.T, w *opFlow)
	}

	loginPage := opIssuer + "/login"

	toLogin := func(t *testing.T, a flowAnswer) {
		t.Helper()

		require.Equal(t, http.StatusSeeOther, a.status, a.body)
		loc := a.location(t)
		assert.Equal(t, loginPage, loc.Scheme+"://"+loc.Host+loc.Path)
		assert.NotEmpty(t, loc.Query().Get(oidcprovider.HandleParam))
		assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
	}

	cases := []testCase{
		{
			name: "a GET with the code goes to the login page and sets the flow cookie",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				a := w.enter(t, w.issueDevice(t, deviceTV).UserCode)
				toLogin(t, a)

				c := a.cookie(flowCookie)
				require.NotNil(t, c, "the flow cookie is set")
				assert.NotEmpty(t, c.Value)
				assert.True(t, c.HttpOnly)
				assert.True(t, c.Secure)
				assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
				assert.Equal(t, "/", c.Path)
			},
		},
		{
			name: "a GET answered by a browser session goes to the consent page",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				browser := w.browserSession(t, w.session(t))
				a := w.enter(t, w.issueDevice(t, deviceTV).UserCode, flowCookieOf(flowSession, browser))

				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				loc := a.location(t)
				assert.Equal(t, opIssuer+"/consent", loc.Scheme+"://"+loc.Host+loc.Path)
			},
		},
		{
			name: "a POST with the flow cookie is answered directly, keeping the cookie",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				_, flow := w.park(t, flowWeb)
				a := w.postForm(t, deviceEntryPath, url.Values{"user_code": {w.issueDevice(t, deviceTV).UserCode}},
					flowCookieOf(flowCookie, flow))
				toLogin(t, a)
				assert.Nil(t, a.cookie(flowCookie), "the browser's own cookie is kept")
			},
		},
		{
			name: "a POST without the flow cookie is turned into a GET carrying the code, with nothing set or claimed",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				code := w.issueDevice(t, deviceTV).UserCode
				a := w.postForm(t, deviceEntryPath, url.Values{"user_code": {code}, "other": {"x"}})

				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Empty(t, a.header.Values("Set-Cookie"), "no cookie is set")
				assert.Equal(t, "no-referrer", a.header.Get("Referrer-Policy"))
				assert.Equal(t, opIssuer+deviceEntryPath+"?user_code="+url.QueryEscape(code), a.header.Get("Location"))

				toLogin(t, w.enter(t, code))
			},
		},
		{
			name: "plain HTTP is refused, and nothing is claimed",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				code := w.issueDevice(t, deviceTV).UserCode
				a := w.enter(t, code, flowPlainHTTP)
				assert.Equal(t, http.StatusBadRequest, a.status)
				assert.Nil(t, a.cookie(flowCookie))

				toLogin(t, w.enter(t, code))
			},
		},
		{
			name: "another method is refused with 405",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPut, w.issuer+deviceEntryPath, nil)
				a := w.serve(t, r, nil)
				assert.Equal(t, http.StatusMethodNotAllowed, a.status)
				assert.Equal(t, "GET, POST", a.header.Get("Allow"))
			},
		},
		{
			name: "an unknown code is 400, with no cookie set",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				a := w.enter(t, deviceUnknownCode)
				assert.Equal(t, http.StatusBadRequest, a.status)
				require.ErrorIs(t, a.err, oidcprovider.ErrInvalidUserCode)
				assert.Empty(t, a.body)
				assert.Nil(t, a.cookie(flowCookie))
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			},
		},
		{
			name: "a missing, empty or repeated code is 400",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				code := w.issueDevice(t, deviceTV).UserCode
				for _, raw := range []string{"", "user_code=", "user_code=" + code + "&user_code=" + code, "%zz"} {
					a := w.entryGET(t, raw)
					assert.Equalf(t, http.StatusBadRequest, a.status, "query %q", raw)
					assert.Nilf(t, a.cookie(flowCookie), "query %q", raw)
				}

				toLogin(t, w.enter(t, code))
			},
		},
		{
			name: "a body over the limit is refused",
			setup: func(s *flowSetup) {
				s.endpoint = []httpsec.OIDCProviderOption{httpsec.WithOIDCDeviceEntryBodyLimit(8)}
			},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				a := w.postForm(t, deviceEntryPath, url.Values{"user_code": {deviceUnknownCode}},
					flowCookieOf(flowCookie, "anything"))
				require.ErrorIs(t, a.err, httpsec.ErrRequestTooLarge)
			},
		},
		{
			name: "the sixth failure from one source is throttled with 429, even for a valid code",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				code := w.issueDevice(t, deviceTV).UserCode
				for i := range oidcprovider.DefaultUserCodeEntryLimit {
					a := w.enter(t, deviceUnknownCode)
					require.Equalf(t, http.StatusBadRequest, a.status, "failure %d", i+1)
				}

				a := w.enter(t, code)
				assert.Equal(t, http.StatusTooManyRequests, a.status)
				require.ErrorIs(t, a.err, ratelimit.ErrThrottled)
				require.ErrorIs(t, a.err, oidcprovider.ErrUserCodeThrottled)
				assert.Empty(t, a.body)
				assert.Nil(t, a.cookie(flowCookie))
			},
		},
		{
			name: "behind a trusted proxy each forwarded address has its own budget",
			setup: func(s *flowSetup) {
				s.chain = func(*testing.T, *opFlow) []httpsec.Option {
					return []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
						Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.20/32")},
						Headers:  httpsec.XForwarded(httpsec.ForwardedFor),
					})}
				}
			},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				from := func(addr string) flowChange {
					return func(r *http.Request) { r.Header.Set("X-Forwarded-For", addr) }
				}

				for i := range oidcprovider.DefaultUserCodeEntryLimit {
					a := w.enter(t, deviceUnknownCode, from("198.51.100.7"))
					require.Equalf(t, http.StatusBadRequest, a.status, "failure %d", i+1)
				}

				assert.Equal(t, http.StatusTooManyRequests, w.enter(t, deviceUnknownCode, from("198.51.100.7")).status,
					"address A is over its limit")
				assert.Equal(t, http.StatusBadRequest, w.enter(t, deviceUnknownCode, from("198.51.100.8")).status,
					"address B keeps its own budget")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			setup := deviceSetup("")
			if tc.setup != nil {
				tc.setup(&setup)
			}

			tc.run(t, newOPFlow(t, setup))
		})
	}
}

// A claim written before parking failed is bound to a flow secret the browser must
// receive, or its re-entry cannot recover the claim that no other browser can take.
func TestDeviceEntryEndpoint_FailedParkSetsTheCookie(t *testing.T) {
	t.Parallel()

	pending := &deviceFailingPending{MemoryPendingRequestStore: must.Must(oidcprovider.NewMemoryPendingRequestStore())}
	setup := deviceSetup("")
	setup.provider = append(setup.provider, oidcprovider.WithPendingRequestStore(pending))
	w := newOPFlow(t, setup)

	code := w.issueDevice(t, deviceTV).UserCode
	pending.failNext.Store(true)

	a := w.enter(t, code)
	require.ErrorIs(t, a.err, oidcprovider.ErrDependency)
	assert.Equal(t, http.StatusInternalServerError, a.status)
	assert.Empty(t, a.header.Get("Location"))

	c := a.cookie(flowCookie)
	require.NotNil(t, c, "the flow cookie the claim is bound to is set")
	assert.True(t, c.HttpOnly)
	assert.True(t, c.Secure)

	again := w.enter(t, code, flowCookieOf(flowCookie, c.Value))
	require.Equal(t, http.StatusSeeOther, again.status, again.body)
	assert.Equal(t, "/login", again.location(t).Path, "the same browser reaches its claim")

	assert.Equal(t, http.StatusBadRequest, w.enter(t, code).status, "another browser is refused")
}

// memoryBackedLimiter is a mock limiter that answers as the memory limiter mem does, so it
// throttles for real while the controller checks how it is used. With charged, it must be
// charged at least once; without it, a charge fails the test.
func memoryBackedLimiter(ctrl *gomock.Controller, mem *ratelimit.MemoryLimiter, charged bool) *MockLimiter {
	m := NewMockLimiter(ctrl)

	charge := m.EXPECT().Charge(gomock.Any(), gomock.Any()).DoAndReturn(mem.Charge)
	if charged {
		charge.MinTimes(1)
	} else {
		charge.Times(0)
	}

	m.EXPECT().Exceeded(gomock.Any(), gomock.Any()).DoAndReturn(mem.Exceeded).AnyTimes()
	m.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).DoAndReturn(mem.RecordFailure).AnyTimes()
	m.EXPECT().Refund(gomock.Any(), gomock.Any()).DoAndReturn(mem.Refund).AnyTimes()

	return m
}

// entryMemory is a memory limiter of the entry throttle's default budget.
func entryMemory(t *testing.T) *ratelimit.MemoryLimiter {
	t.Helper()

	return must.Must(ratelimit.NewMemoryLimiter(oidcprovider.DefaultUserCodeEntryLimit, oidcprovider.DefaultUserCodeEntryWindow))
}

// fallbackToMemory makes f answer every namespace no earlier expectation took with a memory
// limiter, so a test states only the namespaces it cares about. Call it last.
func fallbackToMemory(f *MockLimiterFactory) {
	f.EXPECT().NewLimiter(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ string, limit int, window time.Duration) (ratelimit.Limiter, error) {
			return ratelimit.NewMemoryLimiter(limit, window)
		}).AnyTimes()
}

func TestDeviceEntry_FactoryLimiter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// expect declares what the factory is asked for in the entry and device
		// authorization namespaces; every other namespace falls back to memory.
		expect func(t *testing.T, ctrl *gomock.Controller, f *MockLimiterFactory)
		// build is newOPFlowErr over deviceSetup with the factory when nil.
		build  func(t *testing.T, ctrl *gomock.Controller, f *MockLimiterFactory) (*opFlow, error)
		assert func(t *testing.T, w *opFlow, err error)
	}

	withFactory := func(setup flowSetup, f *MockLimiterFactory) flowSetup {
		setup.chain = func(*testing.T, *opFlow) []httpsec.Option {
			return []httpsec.Option{httpsec.WithRateLimiterFactory(f)}
		}

		return setup
	}

	const entry, authorization = "oidc-device-entry", "oidc-device-authorization"

	cases := []testCase{
		{
			name: "the chain asks for oidc-device-entry at (5, 10 min), and that limiter is consulted on entry",
			expect: func(t *testing.T, ctrl *gomock.Controller, f *MockLimiterFactory) {
				t.Helper()

				f.EXPECT().NewLimiter(entry, gomock.Eq(oidcprovider.DefaultUserCodeEntryLimit),
					gomock.Eq(oidcprovider.DefaultUserCodeEntryWindow)).
					Return(memoryBackedLimiter(ctrl, entryMemory(t), true), nil).Times(1)
				f.EXPECT().NewLimiter(authorization, gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ string, limit int, window time.Duration) (ratelimit.Limiter, error) {
						return ratelimit.NewMemoryLimiter(limit, window)
					}).Times(1)
			},
			assert: func(t *testing.T, w *opFlow, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusBadRequest, w.enter(t, deviceUnknownCode).status,
					"the factory's limiter is the one charged (the controller fails a missing charge)")
			},
		},
		{
			name: "a consumer's limiter given to the provider is kept, and the factory is never asked for the entry",
			expect: func(t *testing.T, _ *gomock.Controller, f *MockLimiterFactory) {
				t.Helper()

				f.EXPECT().NewLimiter(entry, gomock.Any(), gomock.Any()).Times(0)
			},
			build: func(t *testing.T, ctrl *gomock.Controller, f *MockLimiterFactory) (*opFlow, error) {
				t.Helper()

				consumer := memoryBackedLimiter(ctrl, entryMemory(t), true)

				return newOPFlowErr(t, withFactory(deviceSetup("", oidcprovider.WithUserCodeEntryLimiter(consumer)), f))
			},
			assert: func(t *testing.T, w *opFlow, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, http.StatusBadRequest, w.enter(t, deviceUnknownCode).status,
					"the consumer's limiter is charged (the controller fails a missing charge)")
			},
		},
		{
			name: "a factory error fails New, naming the option and the namespace",
			expect: func(t *testing.T, _ *gomock.Controller, f *MockLimiterFactory) {
				t.Helper()

				f.EXPECT().NewLimiter(entry, gomock.Any(), gomock.Any()).Return(nil, errors.New("redis is out")).Times(1)
			},
			assert: func(t *testing.T, _ *opFlow, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "EnableOIDCProvider")
				assert.ErrorContains(t, err, "oidc-device-entry")
			},
		},
		{
			name: "without the grant, neither device namespace is asked for",
			expect: func(t *testing.T, _ *gomock.Controller, f *MockLimiterFactory) {
				t.Helper()

				f.EXPECT().NewLimiter(entry, gomock.Any(), gomock.Any()).Times(0)
				f.EXPECT().NewLimiter(authorization, gomock.Any(), gomock.Any()).Times(0)
			},
			build: func(t *testing.T, _ *gomock.Controller, f *MockLimiterFactory) (*opFlow, error) {
				t.Helper()

				return newOPFlowErr(t, withFactory(flowSetup{}, f))
			},
			assert: func(t *testing.T, _ *opFlow, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			name: "a second chain handing the same provider another limiter fails New",
			expect: func(t *testing.T, ctrl *gomock.Controller, f *MockLimiterFactory) {
				t.Helper()

				f.EXPECT().NewLimiter(entry, gomock.Any(), gomock.Any()).
					Return(memoryBackedLimiter(ctrl, entryMemory(t), false), nil).AnyTimes()
			},
			build: func(t *testing.T, ctrl *gomock.Controller, f *MockLimiterFactory) (*opFlow, error) {
				t.Helper()

				w, err := newOPFlowErr(t, withFactory(deviceSetup(""), f))
				require.NoError(t, err)

				other := NewMockLimiterFactory(ctrl)
				other.EXPECT().NewLimiter(entry, gomock.Any(), gomock.Any()).
					Return(memoryBackedLimiter(ctrl, entryMemory(t), false), nil).AnyTimes()
				fallbackToMemory(other)

				_, err = httpsec.New(
					httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users}),
					httpsec.EnableJWKSEndpoint(tokenKeys()),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(w.p),
					httpsec.WithRateLimiterFactory(other),
				)

				return w, err
			},
			assert: func(t *testing.T, _ *opFlow, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "EnableOIDCProvider")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			f := NewMockLimiterFactory(ctrl)

			tc.expect(t, ctrl, f)
			fallbackToMemory(f)

			build := tc.build
			if build == nil {
				build = func(t *testing.T, _ *gomock.Controller, f *MockLimiterFactory) (*opFlow, error) {
					t.Helper()

					return newOPFlowErr(t, withFactory(deviceSetup(""), f))
				}
			}

			w, err := build(t, ctrl, f)
			tc.assert(t, w, err)
		})
	}
}

func TestDeviceEndpoints_WithoutTheGrant(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) (*httpsec.Chain, error)
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	f := newOPFixture(t)

	cases := []testCase{
		{
			name: "both paths pass through",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				t.Helper()

				p := f.provider(t)

				return httpsec.New(append(f.wired(t, p), httpsec.EnableOIDCProvider(p))...)
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				t.Helper()

				require.NoError(t, err)

				for _, path := range []string{deviceAuthorizationPath, deviceEntryPath} {
					r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil)
					assert.Truef(t, serveOP(t, c, r).passedOn, "%s passes through", path)
				}

				ids := operationIDs(c.Endpoints())
				assert.NotContains(t, ids, httpsec.OperationOAuth2DeviceAuthorization)
				assert.NotContains(t, ids, httpsec.OperationOAuth2DeviceEntry)
			},
		},
		{
			name: "a device path given without the grant is refused",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				t.Helper()

				p := f.provider(t)

				return httpsec.New(append(f.wired(t, p), httpsec.EnableOIDCProvider(p,
					httpsec.WithOIDCProviderPath(httpsec.OIDCDeviceEntry, "/activate")))...)
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.ErrorContains(t, err, "WithOIDCProviderPath")
				assert.ErrorContains(t, err, "OIDCDeviceEntry")
				assert.ErrorContains(t, err, "WithDeviceAuthorization")
			},
		},
		{
			name: "a device limiter given without the grant is refused",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				t.Helper()

				p := f.provider(t)

				return httpsec.New(append(f.wired(t, p), httpsec.EnableOIDCProvider(p,
					httpsec.WithOIDCDeviceAuthorizationLimiter(NewMockLimiter(gomock.NewController(t)))))...)
			},
			assert: func(t *testing.T, _ *httpsec.Chain, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "WithOIDCDeviceAuthorizationLimiter")
			},
		},
		{
			name: "code-entry redirects given without the grant are refused",
			build: func(t *testing.T) (*httpsec.Chain, error) {
				t.Helper()

				p := f.provider(t)

				return httpsec.New(append(f.wired(t, p), httpsec.EnableOIDCProvider(p,
					httpsec.WithOIDCEntryRedirects()))...)
			},
			assert: func(t *testing.T, _ *httpsec.Chain, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "WithOIDCEntryRedirects")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := tc.build(t)
			tc.assert(t, c, err)
		})
	}
}

func TestDeviceEndpoint_Options(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opt    httpsec.OIDCProviderOption
		assert func(t *testing.T, err error)
	}

	refusedNaming := func(option string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.ErrorContains(t, err, option)
		}
	}

	cases := []testCase{
		{
			name:   "a nil device authorization limiter",
			opt:    httpsec.WithOIDCDeviceAuthorizationLimiter(nil),
			assert: refusedNaming("WithOIDCDeviceAuthorizationLimiter"),
		},
		{
			name:   "a typed nil device authorization limiter",
			opt:    httpsec.WithOIDCDeviceAuthorizationLimiter((*ratelimit.MemoryLimiter)(nil)),
			assert: refusedNaming("WithOIDCDeviceAuthorizationLimiter"),
		},
		{
			name:   "a zero device authorization body limit",
			opt:    httpsec.WithOIDCDeviceAuthorizationBodyLimit(0),
			assert: refusedNaming("WithOIDCDeviceAuthorizationBodyLimit"),
		},
		{
			name:   "a negative code-entry body limit",
			opt:    httpsec.WithOIDCDeviceEntryBodyLimit(-1),
			assert: refusedNaming("WithOIDCDeviceEntryBodyLimit"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			setup := deviceSetup("")
			setup.endpoint = []httpsec.OIDCProviderOption{tc.opt}

			_, err := newOPFlowErr(t, setup)
			tc.assert(t, err)
		})
	}
}

// deviceAtConsent issues a device authorization, enters its code and resumes the login
// stage by a sign-in of a new session, through the chain, and returns the device code,
// the handle, the flow secret and the session's credential and family.
type deviceConsent struct {
	deviceCode, handle, flow string
	credential               string
}

func (w *opFlow) deviceAtConsent(t *testing.T, scope string) deviceConsent {
	t.Helper()

	a := w.deviceAuthorize(t, url.Values{"client_id": {deviceTV}, "scope": {scope}})
	require.Equal(t, http.StatusOK, a.status, a.body)

	var issued deviceIssued
	require.NoError(t, json.Unmarshal([]byte(a.body), &issued))

	entered := w.enter(t, issued.UserCode)
	require.Equal(t, http.StatusSeeOther, entered.status, entered.body)

	flow := entered.cookie(flowCookie)
	require.NotNil(t, flow)

	handle := entered.location(t).Query().Get(oidcprovider.HandleParam)
	s := w.session(t)

	login := w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow.Value))
	require.Equal(t, http.StatusOK, login.status, login.body)

	return deviceConsent{
		deviceCode: issued.DeviceCode, handle: handle, flow: flow.Value,
		credential: s.ID,
	}
}

// A sign-in passed to a device resume may end between the chain's check and the
// provider's decision, swept before the approval exists. The chain re-reads the sign-in
// after the resume and ends it again, which reaches the approval through the device
// store, so the device's poll is refused.
func TestDeviceResume_SignInEndedMeanwhile(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		during func(w *opFlow) func(*httpsec.Exchange) error
		assert func(t *testing.T, resumed, polled flowAnswer)
	}

	cases := []testCase{
		{
			name: "no end: the approval stands and the device gets its tokens",
			assert: func(t *testing.T, resumed, polled flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusOK, resumed.status, resumed.body)
				assert.Equal(t, "approved", resumed.redirectTo(t).Query().Get(oidcprovider.DeviceResultParam))
				assert.Equal(t, http.StatusOK, polled.status, polled.body)
				assert.Contains(t, polled.body, "access_token")
			},
		},
		{
			name: "the sign-in ends after the chain read it: the approval is revoked and the poll is invalid_grant",
			during: func(w *opFlow) func(*httpsec.Exchange) error {
				return func(ex *httpsec.Exchange) error {
					_, err := w.sessions.RevokeFamily(context.WithoutCancel(ex.Context()), ex.Session.FamilyID)

					return err
				}
			},
			assert: func(t *testing.T, resumed, polled flowAnswer) {
				t.Helper()

				require.ErrorIs(t, resumed.err, httpsec.ErrOIDCReauthenticate)
				assert.NotContains(t, resumed.body, "redirect_to")
				assert.Equal(t, http.StatusBadRequest, polled.status, polled.body)
				assert.Equal(t, oidcprovider.CodeInvalidGrant, refusalCode(t, polled))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hook := &resumeRaceHook{}
			setup := deviceSetup("")
			setup.chain = func(*testing.T, *opFlow) []httpsec.Option { return []httpsec.Option{hook.option()} }

			w := newOPFlow(t, setup)
			c := w.deviceAtConsent(t, "openid")

			if tc.during != nil {
				hook.arm(tc.during(w))
			}

			resumed := w.resume(t, flowGrantBody(c.handle, "openid"), flowBearer(c.credential),
				flowCookieOf(flowCookie, c.flow))
			polled := w.poll(t, c.deviceCode)

			tc.assert(t, resumed, polled)
		})
	}
}

// The token endpoint answers the device grant's own codes as it answers every refusal:
// 400 with the code alone.
func TestDeviceToken_ErrorCodes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T, w *opFlow) flowAnswer
		assert func(t *testing.T, a flowAnswer)
	}

	answered := func(code string) func(t *testing.T, a flowAnswer) {
		return func(t *testing.T, a flowAnswer) {
			t.Helper()

			assert.Equal(t, http.StatusBadRequest, a.status, a.body)
			assert.JSONEq(t, `{"error":"`+code+`"}`, a.body)
			assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
		}
	}

	cases := []testCase{
		{
			name: "authorization_pending",
			run: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.poll(t, w.issueDevice(t, deviceTV).DeviceCode)
			},
			assert: answered(oidcprovider.CodeAuthorizationPending),
		},
		{
			name: "slow_down",
			run: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				code := w.issueDevice(t, deviceTV).DeviceCode
				require.Equal(t, http.StatusBadRequest, w.poll(t, code).status)

				return w.poll(t, code)
			},
			assert: answered(oidcprovider.CodeSlowDown),
		},
		{
			name: "expired_token",
			run: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				code := w.issueDevice(t, deviceTV).DeviceCode
				w.clk.Advance(oidcprovider.DefaultDeviceLifetime)

				return w.poll(t, code)
			},
			assert: answered(oidcprovider.CodeExpiredToken),
		},
		{
			name: "access_denied",
			run: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				c := w.deviceAtConsent(t, "openid")
				denied := w.resume(t, flowDenyBody(c.handle), flowBearer(c.credential), flowCookieOf(flowCookie, c.flow))
				require.Equal(t, http.StatusOK, denied.status, denied.body)

				return w.poll(t, c.deviceCode)
			},
			assert: answered(oidcprovider.CodeAccessDenied),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPFlow(t, deviceSetup(""))
			tc.assert(t, tc.run(t, w))
		})
	}
}

// Neither endpoint writes a code or a secret where an operator reads: not in a log line
// at any level, and not in a refusal's body.
func TestDeviceEndpoints_NothingSecretLogged(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer

	setup := deviceSetup("")
	setup.chain = func(*testing.T, *opFlow) []httpsec.Option {
		return []httpsec.Option{httpsec.WithLogger(slog.New(slog.NewJSONHandler(&logs,
			&slog.HandlerOptions{Level: slog.LevelDebug})))}
	}
	w := newOPFlow(t, setup)

	issued := w.issueDevice(t, deviceTV)
	raw := strings.ReplaceAll(issued.UserCode, "-", "")

	var bodies []string

	for range oidcprovider.DefaultUserCodeEntryLimit + 1 {
		bodies = append(bodies, w.enter(t, raw[:4]+"-BBBB").body)
	}

	bodies = append(bodies,
		w.enter(t, issued.UserCode, flowPlainHTTP).body,
		w.enter(t, issued.UserCode, flowFrom(flowOtherAddr)).body,
		w.poll(t, issued.DeviceCode).body,
		w.deviceAuthorize(t, url.Values{"scope": {"openid"}}, deviceBasic(deviceCLI, "wrong-secret")).body,
	)

	written := logs.String() + strings.Join(bodies, "\n")
	for _, secret := range []string{issued.UserCode, raw, issued.DeviceCode, "wrong-secret", raw[:4] + "-BBBB"} {
		assert.NotContainsf(t, written, secret, "%q is written", secret)
	}
}

// deviceLookupStore counts the user-code lookups that reach the device store.
type deviceLookupStore struct {
	oidcprovider.DeviceAuthorizationStore

	lookups atomic.Int64
}

func (s *deviceLookupStore) LoadByUserCode(
	ctx context.Context, digest []byte, now time.Time,
) (*oidcprovider.DeviceAuthorization, error) {
	s.lookups.Add(1)

	return s.DeviceAuthorizationStore.LoadByUserCode(ctx, digest, now)
}

// TestDeviceEntryRedirects pins WithOIDCEntryRedirects: a refused code entry is sent back
// to the code-entry page with result=invalid or result=throttled and nothing else, and
// without the option it is refused as before.
func TestDeviceEntryRedirects(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		on   bool
		run  func(t *testing.T, w *opFlow, store *deviceLookupStore) flowAnswer
		// assert receives the store, so a case can say whether the code was looked up.
		assert func(t *testing.T, a flowAnswer, store *deviceLookupStore)
	}

	sentBack := func(result string) func(*testing.T, flowAnswer, *deviceLookupStore) {
		return func(t *testing.T, a flowAnswer, _ *deviceLookupStore) {
			t.Helper()

			require.Equal(t, http.StatusSeeOther, a.status, a.body)
			assert.Equal(t, opIssuer+deviceEntryPage+"?result="+result, a.header.Get("Location"))
			assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			assert.Empty(t, a.body)
			assert.NoError(t, a.err)
		}
	}

	unknown := func(t *testing.T, w *opFlow, _ *deviceLookupStore) flowAnswer {
		t.Helper()

		return w.enter(t, deviceUnknownCode)
	}

	cases := []testCase{
		{
			name: "default: an unknown code is refused as before",
			run:  unknown,
			assert: func(t *testing.T, a flowAnswer, _ *deviceLookupStore) {
				t.Helper()

				assert.Equal(t, http.StatusBadRequest, a.status)
				require.ErrorIs(t, a.err, oidcprovider.ErrInvalidUserCode)
				assert.Empty(t, a.header.Get("Location"))
			},
		},
		{name: "an unknown code: result=invalid", on: true, run: unknown, assert: sentBack("invalid")},
		{
			name: "an unknown code posted with a flow cookie: result=invalid",
			on:   true,
			run: func(t *testing.T, w *opFlow, _ *deviceLookupStore) flowAnswer {
				t.Helper()

				return w.postForm(t, deviceEntryPath, url.Values{"user_code": {deviceUnknownCode}},
					flowCookieOf(flowCookie, "anything"))
			},
			assert: sentBack("invalid"),
		},
		{
			name: "an expired code: result=invalid",
			on:   true,
			run: func(t *testing.T, w *opFlow, _ *deviceLookupStore) flowAnswer {
				t.Helper()

				code := w.issueDevice(t, deviceTV).UserCode
				w.clk.Advance(oidcprovider.DefaultDeviceLifetime + time.Second)

				return w.enter(t, code)
			},
			assert: sentBack("invalid"),
		},
		{
			name: "a code another browser claimed: result=invalid",
			on:   true,
			run: func(t *testing.T, w *opFlow, _ *deviceLookupStore) flowAnswer {
				t.Helper()

				code := w.issueDevice(t, deviceTV).UserCode
				require.Equal(t, http.StatusSeeOther, w.enter(t, code).status)

				return w.enter(t, code)
			},
			assert: sentBack("invalid"),
		},
		{
			name: "a repeated code: result=invalid, with neither code in the redirect",
			on:   true,
			run: func(t *testing.T, w *opFlow, _ *deviceLookupStore) flowAnswer {
				t.Helper()

				return w.entryGET(t, "user_code=AAAA-AAAA&user_code=BBBB-BBBB")
			},
			assert: sentBack("invalid"),
		},
		{
			name: "a throttled source: result=throttled, and the code is not looked up",
			on:   true,
			run: func(t *testing.T, w *opFlow, store *deviceLookupStore) flowAnswer {
				t.Helper()

				code := w.issueDevice(t, deviceTV).UserCode
				for i := range oidcprovider.DefaultUserCodeEntryLimit {
					a := w.enter(t, deviceUnknownCode)
					require.Equalf(t, http.StatusSeeOther, a.status, "failure %d", i+1)
				}

				store.lookups.Store(0)

				return w.enter(t, code)
			},
			assert: func(t *testing.T, a flowAnswer, store *deviceLookupStore) {
				t.Helper()

				sentBack("throttled")(t, a, store)
				assert.Zero(t, store.lookups.Load(), "the code was not looked up")
				assert.Nil(t, a.cookie(flowCookie))
			},
		},
		{
			name: "plain HTTP is still refused, not sent back",
			on:   true,
			run: func(t *testing.T, w *opFlow, _ *deviceLookupStore) flowAnswer {
				t.Helper()

				return w.enter(t, deviceUnknownCode, flowPlainHTTP)
			},
			assert: func(t *testing.T, a flowAnswer, _ *deviceLookupStore) {
				t.Helper()

				assert.Equal(t, http.StatusBadRequest, a.status)
				assert.Empty(t, a.header.Get("Location"))
			},
		},
		{
			name: "a cross-site POST is refused, not sent back",
			on:   true,
			run: func(t *testing.T, w *opFlow, _ *deviceLookupStore) flowAnswer {
				t.Helper()

				return w.postForm(t, deviceEntryPath, url.Values{"user_code": {deviceUnknownCode}},
					flowHeader("Sec-Fetch-Site", "cross-site"), flowHeader("Origin", "https://evil.example.com"))
			},
			assert: func(t *testing.T, a flowAnswer, _ *deviceLookupStore) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrCrossSiteRequest)
				assert.Equal(t, http.StatusForbidden, a.status)
				assert.Empty(t, a.header.Get("Location"))
			},
		},
		{
			name: "an oversized POST is refused, not sent back",
			on:   true,
			run: func(t *testing.T, w *opFlow, _ *deviceLookupStore) flowAnswer {
				t.Helper()

				return w.postForm(t, deviceEntryPath, url.Values{
					"user_code": {deviceUnknownCode},
					"pad":       {strings.Repeat("a", int(httpsec.DefaultLoginBodyLimit))},
				})
			},
			assert: func(t *testing.T, a flowAnswer, _ *deviceLookupStore) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, http.StatusRequestEntityTooLarge, a.status)
				assert.Empty(t, a.header.Get("Location"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &deviceLookupStore{DeviceAuthorizationStore: oidcprovider.NewMemoryDeviceAuthorizationStore()}
			setup := deviceSetup("", oidcprovider.WithDeviceAuthorizationStore(store))
			if tc.on {
				setup.endpoint = append(setup.endpoint, httpsec.WithOIDCEntryRedirects())
			}

			w := newOPFlow(t, setup)

			tc.assert(t, tc.run(t, w, store), store)
		})
	}
}
