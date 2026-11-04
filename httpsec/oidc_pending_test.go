package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
)

func TestOIDCPendingRequest(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		issuer string
		read   func(t *testing.T, w *opFlow) (*oidcprovider.PendingView, error)
		assert func(t *testing.T, view *oidcprovider.PendingView, err error)
	}

	requestWith := func(t *testing.T, name, value string) httpsec.Request {
		t.Helper()

		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://id.example.com/login", nil)
		if name != "" {
			r.AddCookie(&http.Cookie{Name: name, Value: value}) //nolint:gosec // G124: a request sends no attributes
		}

		return httpsec.NewHTTPRequest(r)
	}

	unknown := func(t *testing.T, view *oidcprovider.PendingView, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrOIDCUnknownHandle)
		assert.Nil(t, view)
	}

	cases := []testCase{
		{
			name: "the flow cookie is read from the request",
			read: func(t *testing.T, w *opFlow) (*oidcprovider.PendingView, error) {
				t.Helper()

				handle, flow := w.park(t, flowWeb, func(p url.Values) { p.Set("login_hint", "ada@example.com") })

				return httpsec.PendingOIDCRequest(t.Context(), w.p, requestWith(t, flowCookie, flow), handle)
			},
			assert: func(t *testing.T, view *oidcprovider.PendingView, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, flowWeb, view.ClientID)
				assert.Equal(t, "Flow Web", view.ClientName)
				assert.Equal(t, "ada@example.com", view.LoginHint)
				assert.Equal(t, oidcprovider.StageLogin, view.Stage)
			},
		},
		{
			name: "without the flow cookie the handle is unknown",
			read: func(t *testing.T, w *opFlow) (*oidcprovider.PendingView, error) {
				t.Helper()

				handle, _ := w.park(t, flowWeb)

				return httpsec.PendingOIDCRequest(t.Context(), w.p, requestWith(t, "", ""), handle)
			},
			assert: unknown,
		},
		{
			name: "under another browser's flow cookie the handle is unknown",
			read: func(t *testing.T, w *opFlow) (*oidcprovider.PendingView, error) {
				t.Helper()

				handle, _ := w.park(t, flowWeb)
				_, other := w.park(t, flowWeb)

				return httpsec.PendingOIDCRequest(t.Context(), w.p, requestWith(t, flowCookie, other), handle)
			},
			assert: unknown,
		},
		{
			name: "under the unprefixed name a TLS issuer reads no flow cookie",
			read: func(t *testing.T, w *opFlow) (*oidcprovider.PendingView, error) {
				t.Helper()

				handle, flow := w.park(t, flowWeb)

				return httpsec.PendingOIDCRequest(t.Context(), w.p, requestWith(t, flowCookiePlain, flow), handle)
			},
			assert: unknown,
		},
		{
			name:   "the loopback issuer reads its flow cookie under the unprefixed name",
			issuer: flowLoopback,
			read: func(t *testing.T, w *opFlow) (*oidcprovider.PendingView, error) {
				t.Helper()

				handle, flow := w.parkIn(t, flowCookiePlain, flowWeb)

				return httpsec.PendingOIDCRequest(t.Context(), w.p, requestWith(t, flowCookiePlain, flow), handle)
			},
			assert: func(t *testing.T, view *oidcprovider.PendingView, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, flowWeb, view.ClientID)
			},
		},
		{
			name: "a read does not spend the handle",
			read: func(t *testing.T, w *opFlow) (*oidcprovider.PendingView, error) {
				t.Helper()

				handle, flow := w.park(t, flowWeb)
				r := requestWith(t, flowCookie, flow)

				_, err := httpsec.PendingOIDCRequest(t.Context(), w.p, r, handle)
				require.NoError(t, err)

				return httpsec.PendingOIDCRequest(t.Context(), w.p, r, handle)
			},
			assert: func(t *testing.T, view *oidcprovider.PendingView, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, oidcprovider.StageLogin, view.Stage)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPFlow(t, flowSetup{issuer: tc.issuer})
			view, err := tc.read(t, w)
			tc.assert(t, view, err)
		})
	}
}
