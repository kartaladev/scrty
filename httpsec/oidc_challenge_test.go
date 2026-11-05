package httpsec_test

import (
	"crypto/elliptic"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
)

// RFC 9110 section 15.5.2: a server generating a 401 MUST send WWW-Authenticate. Each row answers a
// 401 from an endpoint resting on a sign-in, and states the challenges that answer carries.
func TestOIDCSignInEndpoints_UnauthorizedCarriesAChallenge(t *testing.T) {
	t.Parallel()

	const (
		bearer     = `Bearer realm="oauth2"` //nolint:gosec // G101: a challenge, and no credential
		bareBearer = "Bearer"
		// dpopScheme stands for a DPoP challenge, whichever algorithms it names.
		dpopScheme = "DPoP algs="
	)

	withDPoP := func(d func(*testing.T) *httpsec.DPoP) flowSetup {
		return flowSetup{
			provider: []oidcprovider.Option{oidcprovider.WithDPoP()},
			chain: func(t *testing.T, _ *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.EnableDPoP(*d(t))}
			},
		}
	}

	// staleResume is a resume whose sign-in is too old for the request.
	staleResume := func(t *testing.T, w *opFlow) flowAnswer {
		t.Helper()

		s := w.session(t)
		handle, flow := w.park(t, flowWeb, func(v url.Values) { v.Set("max_age", "1") })
		w.clk.Advance(5 * time.Second)

		return w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
	}
	// provedStaleResume is staleResume by a sign-in bound to a key, with its proof, which is all a chain
	// requiring DPoP lets through.
	provedStaleResume := func(t *testing.T, w *opFlow) flowAnswer {
		t.Helper()

		k := newDPoPKey(t, elliptic.P256())
		s := w.session(t, session.WithKeyBinding(session.KeyBinding{JKT: k.jkt}))
		handle, flow := w.park(t, flowWeb, func(v url.Values) { v.Set("max_age", "1") })
		w.clk.Advance(5 * time.Second)

		proof := k.validProof("stale-1").with(map[string]any{
			"htm": http.MethodPost, "htu": w.issuer + flowResumePath, "iat": w.clk.Now().Unix(), "ath": tokenHash(s.ID),
		}).sign(t)

		return w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow), func(r *http.Request) {
			r.Header.Set("Authorization", "DPoP "+s.ID)
			r.Header.Set("DPoP", proof)
		})
	}
	noCredentialResume := func(t *testing.T, w *opFlow) flowAnswer {
		t.Helper()

		handle, flow := w.park(t, flowWeb)

		return w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow))
	}
	owing := func(t *testing.T, w *opFlow) *session.Session {
		t.Helper()

		s := w.session(t)
		s.MFA = session.MFAPending
		require.NoError(t, w.sessions.Save(t.Context(), s))

		return s
	}

	type testCase struct {
		name  string
		setup flowSetup
		send  func(t *testing.T, w *opFlow) flowAnswer
		// want is the challenges, in order.
		want []string
	}

	cases := []testCase{
		{name: "a resume by a stale sign-in", send: staleResume, want: []string{bearer}},
		{name: "a resume with no credential", send: noCredentialResume, want: []string{bearer}},
		{
			name: "a resume owing a second factor",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				handle, flow := w.park(t, flowWeb)

				return w.resume(t, flowLoginBody(handle), flowBearer(owing(t, w).ID), flowCookieOf(flowCookie, flow))
			},
			want: []string{bearer},
		},
		{
			name: "the consents list with no credential",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath)
			},
			want: []string{bearer},
		},
		{
			name: "the consents list owing a second factor",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath, flowBearer(owing(t, w).ID))
			},
			want: []string{bearer},
		},
		{
			name: "a consent's revocation with no credential",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsDELETE(t, consentsPath+"/"+flowWeb)
			},
			want: []string{bearer},
		},
		{
			name: "with DPoP on, a stale sign-in is challenged under both schemes", setup: withDPoP(plainDPoP), send: staleResume,
			want: []string{dpopScheme, bearer},
		},
		{
			name: "with DPoP on, a refusal the chain's own challenge answers is challenged once", setup: withDPoP(plainDPoP), send: noCredentialResume,
			want: []string{dpopScheme, bareBearer},
		},
		{
			name: "with DPoP required, only that scheme is asked for", setup: withDPoP(requiredDPoP), send: provedStaleResume,
			want: []string{dpopScheme},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPFlow(t, tc.setup)
			a := tc.send(t, w)

			require.Equal(t, http.StatusUnauthorized, a.status, a.body)

			got := a.header.Values("WWW-Authenticate")
			require.Len(t, got, len(tc.want), "%q", got)
			for i, want := range tc.want {
				if want == dpopScheme {
					assert.True(t, strings.HasPrefix(got[i], dpopScheme), "%q", got)

					continue
				}
				assert.Equal(t, want, got[i])
			}
		})
	}
}

// A refusal that is no 401 is challenged by nothing.
func TestOIDCSignInEndpoints_OtherRefusalsCarryNoChallenge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		send   func(t *testing.T, w *opFlow) flowAnswer
		status int
	}

	cases := []testCase{
		{
			name: "a resume that says nothing the provider could judge",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.resume(t, "not a document", flowBearer(w.session(t).ID))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "a consent the caller never gave",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsDELETE(t, consentsPath+"/no-such-client", flowBearer(w.session(t).ID))
			},
			status: http.StatusNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a := tc.send(t, newOPFlow(t, flowSetup{}))
			require.Equal(t, tc.status, a.status, a.body)
			assert.Empty(t, a.header.Values("WWW-Authenticate"))
		})
	}
}
