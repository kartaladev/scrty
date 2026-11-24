package httpsec_test

import (
	"math"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
)

const (
	throttleRevokePath     = "/oauth2/revoke"
	throttleIntrospectPath = "/oauth2/introspect"
)

// policyLimiter is a consumer's limiter that also reports its policy, the window a
// throttled source's Retry-After is read from.
type policyLimiter struct {
	*MockLimiter

	window time.Duration
}

func (l policyLimiter) Policy() (int, time.Duration) { return 10, l.window }

// throttlingLimiter is a mock limiter that holds every source over its limit.
func throttlingLimiter(t *testing.T) *MockLimiter {
	t.Helper()

	m := NewMockLimiter(gomock.NewController(t))
	m.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()
	m.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	return m
}

// throttleEndpoint is one endpoint a client authenticates at: the option that hands
// it its limiter, and the request a client sends it.
type throttleEndpoint struct {
	name    string
	limiter func(ratelimit.Limiter) httpsec.OIDCProviderOption
	path    string
	form    url.Values
}

var throttleEndpoints = []throttleEndpoint{
	{
		name: "token", limiter: httpsec.WithOIDCTokenLimiter, path: deviceTokenPath,
		form: url.Values{"grant_type": {"client_credentials"}},
	},
	{name: "revocation", limiter: httpsec.WithOIDCRevokeLimiter, path: throttleRevokePath, form: url.Values{"token": {"t"}}},
	{name: "introspection", limiter: httpsec.WithOIDCIntrospectLimiter, path: throttleIntrospectPath, form: url.Values{"token": {"t"}}},
	{
		name: "device authorization", limiter: httpsec.WithOIDCDeviceAuthorizationLimiter, path: deviceAuthorizationPath,
		form: url.Values{"scope": {"openid"}},
	},
}

// TestClientThrottle429 pins how a throttled source is answered at the endpoints a client
// authenticates at: invalid_client by default, and with WithOIDCThrottle429 a 429 whose
// Retry-After is the limiter's window in whole seconds, bounded, read before the client's
// credentials are.
func TestClientThrottle429(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		endpoint throttleEndpoint
		// limiter is the endpoint's limiter, nil for the chain's own.
		limiter func(t *testing.T) ratelimit.Limiter
		on      bool
		// before runs ahead of the request asserted on.
		before func(t *testing.T, w *opFlow, e throttleEndpoint)
		// client is the credentials presented, the confidential device client's by default.
		client flowChange
		assert func(t *testing.T, a flowAnswer)
	}

	withWindow := func(window time.Duration) func(t *testing.T) ratelimit.Limiter {
		return func(t *testing.T) ratelimit.Limiter {
			t.Helper()

			return policyLimiter{MockLimiter: throttlingLimiter(t), window: window}
		}
	}

	invalidClient := func(t *testing.T, a flowAnswer) {
		t.Helper()

		assert.Equal(t, http.StatusUnauthorized, a.status, a.body)
		assert.Equal(t, oidcprovider.CodeInvalidClient, refusalCode(t, a))
		assert.Empty(t, a.header.Get("Retry-After"))
	}

	throttled := func(retryAfter string) func(t *testing.T, a flowAnswer) {
		return func(t *testing.T, a flowAnswer) {
			t.Helper()

			assert.Equal(t, http.StatusTooManyRequests, a.status, a.body)
			assert.Equal(t, retryAfter, a.header.Get("Retry-After"))
			assert.JSONEq(t, `{"error":"temporarily_unavailable"}`, a.body)
			assert.Equal(t, "application/json", a.header.Get("Content-Type"))
			assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			assert.Empty(t, a.header.Values("WWW-Authenticate"))
		}
	}

	var cases []testCase

	for _, e := range throttleEndpoints {
		cases = append(cases,
			testCase{
				name: e.name + ", by default: invalid_client", endpoint: e,
				limiter: withWindow(90 * time.Second), assert: invalidClient,
			},
			testCase{
				name: e.name + ", with the option and the client's good credentials: 429, unchecked", endpoint: e,
				limiter: withWindow(90 * time.Second), on: true, assert: throttled("90"),
			},
			testCase{
				name: e.name + ", with the option and an unknown client: the same answer", endpoint: e,
				limiter: withWindow(90 * time.Second), on: true, client: deviceBasic("nobody", "wrong"),
				assert: throttled("90"),
			},
		)
	}

	token := throttleEndpoints[0]
	cases = append(cases,
		testCase{
			name: "a window of a part second is rounded up", endpoint: token,
			limiter: withWindow(1500 * time.Millisecond), on: true, assert: throttled("2"),
		},
		testCase{
			name: "a window of zero gives 1", endpoint: token,
			limiter: withWindow(0), on: true, assert: throttled("1"),
		},
		testCase{
			name: "a negative window gives 1", endpoint: token,
			limiter: withWindow(-5 * time.Second), on: true, assert: throttled("1"),
		},
		testCase{
			name: "the longest window is bounded at a day", endpoint: token,
			limiter: withWindow(time.Duration(math.MaxInt64)), on: true, assert: throttled("86400"),
		},
		testCase{
			name: "a limiter that reports no window gives 1", endpoint: token,
			limiter: func(t *testing.T) ratelimit.Limiter {
				t.Helper()

				return throttlingLimiter(t)
			},
			on: true, assert: throttled("1"),
		},
		testCase{
			name: "the chain's own limiter, after ten failures: its 15-minute window", endpoint: token, on: true,
			before: func(t *testing.T, w *opFlow, e throttleEndpoint) {
				t.Helper()

				for i := range 10 {
					a := w.postForm(t, e.path, e.form, deviceBasic(deviceCLI, "wrong"))
					require.Equalf(t, http.StatusUnauthorized, a.status, "failure %d: %s", i+1, a.body)
				}
			},
			assert: throttled("900"),
		},
		testCase{
			name: "a limiter that cannot answer, with the option: still invalid_client", endpoint: token,
			limiter: func(*testing.T) ratelimit.Limiter { return flowDownLimiter{} }, on: true, assert: invalidClient,
		},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			setup := deviceSetup("")
			setup.chain = func(*testing.T, *opFlow) []httpsec.Option {
				// A consumer's limiter reporting an odd window would size the IPv6 aggregate
				// from it; the aggregate is not what is tested here.
				return []httpsec.Option{httpsec.WithoutIPv6Aggregate()}
			}

			if tc.limiter != nil {
				setup.endpoint = append(setup.endpoint, tc.endpoint.limiter(tc.limiter(t)))
			}

			if tc.on {
				setup.endpoint = append(setup.endpoint, httpsec.WithOIDCThrottle429())
			}

			w := newOPFlow(t, setup)
			if tc.before != nil {
				tc.before(t, w, tc.endpoint)
			}

			client := tc.client
			if client == nil {
				client = deviceBasic(deviceCLI, tokenSecret)
			}

			tc.assert(t, w.postForm(t, tc.endpoint.path, tc.endpoint.form, client))
		})
	}
}
