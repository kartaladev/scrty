package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// rsToken is the provider-format token the challenge and binding cases present.
const rsToken = "at.0123456789"

// rsExpired is a source verification refusing every token, as an expired one is refused.
func rsExpired(context.Context, string) (*identity.Principal, map[string]string, error) {
	return nil, nil, httpsec.ErrInvalidToken
}

// rsBoundTo is a source verification accepting every token as bound by cnf.
func rsBoundTo(cnf map[string]string) func(context.Context, string) (*identity.Principal, map[string]string, error) {
	return func(context.Context, string) (*identity.Principal, map[string]string, error) {
		return &identity.Principal{ID: "u-1", Kind: identity.KindUser}, cnf, nil
	}
}

// rsStub is how a case's provider source answers.
type rsStub struct {
	Unbound bool
	Verify  func(context.Context, string) (*identity.Principal, map[string]string, error)
}

// rsServe serves req through a chain of opts, on a clock at dpopNow, with a credential mode at
// OrderBearerToken that records whether the request reached it.
func rsServe(t *testing.T, req *http.Request, opts ...httpsec.Option) rsRoute {
	t.Helper()

	var later bool

	opts = append([]httpsec.Option{
		httpsec.WithClock(clockwork.NewFakeClockAt(dpopNow)),
		httpsec.WithLogger(slog.New(slog.DiscardHandler)),
	}, opts...)

	c, err := httpsec.New(append(opts, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
		func(ex *httpsec.Exchange, next httpsec.Next) error {
			later = true

			return next(ex)
		}), httpsec.OrderBearerToken))...)
	require.NoError(t, err)

	out := serve(t, c, req)

	return rsRoute{served: out, laterRan: later}
}

// rsRequest is a GET of target carrying each of authorization as one Authorization line.
func rsRequest(t *testing.T, target string, authorization ...string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	for _, a := range authorization {
		req.Header.Add("Authorization", a)
	}

	return req
}

// TestResourceServer_Challenge pins the challenge every refusal of a resource server carries:
// exactly one WWW-Authenticate, error="invalid_token" for an invalid token, under DPoP when the
// token came under DPoP or its source requires DPoP binding and under Bearer otherwise, with DPoP
// off, optional and required alike; the settled DPoP challenges for binding failures; and
// error="invalid_request" for a repeated Authorization header.
func TestResourceServer_Challenge(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name    string
		dpop    *httpsec.DPoP
		cert    bool
		src     rsStub
		request func(t *testing.T) *http.Request
		assert  func(t *testing.T, out rsRoute)
	}

	challenged := func(want string) func(t *testing.T, out rsRoute) {
		return func(t *testing.T, out rsRoute) {
			t.Helper()
			require.ErrorIs(t, out.err, httpsec.ErrInvalidToken)
			assert.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
			assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
			assert.Equal(t, []string{want}, out.rec.Header().Values("WWW-Authenticate"), "exactly one challenge")
			assert.False(t, out.laterRan, "a refused access token is never handed on")
			assert.NotContains(t, out.err.Error(), rsToken, "the refusal names no token")
		}
	}

	bearer := func(t *testing.T) *http.Request {
		return rsRequest(t, "http://example.com/api/orders", "Bearer "+rsToken)
	}

	cases := []testCase{
		{
			name:    "with DPoP off, an invalid token under Bearer gets Bearer invalid_token alone",
			cert:    true,
			src:     rsStub{Verify: rsExpired},
			request: bearer,
			assert:  challenged(`Bearer error="invalid_token"`),
		},
		{
			name:    "with DPoP off, an API-only chain with an unbound source challenges too",
			src:     rsStub{Unbound: true, Verify: rsExpired},
			request: bearer,
			assert:  challenged(`Bearer error="invalid_token"`),
		},
		{
			name:    "with DPoP optional, an invalid token from an unbound source under Bearer gets Bearer alone",
			dpop:    &httpsec.DPoP{PublicURL: dpopPublicURL},
			src:     rsStub{Unbound: true, Verify: rsExpired},
			request: bearer,
			assert:  challenged(`Bearer error="invalid_token"`),
		},
		{
			name:    "with DPoP optional, a source requiring DPoP binding answers under DPoP",
			dpop:    &httpsec.DPoP{PublicURL: dpopPublicURL},
			src:     rsStub{Verify: rsExpired},
			request: bearer,
			assert:  challenged(`DPoP error="invalid_token", algs="ES256"`),
		},
		{
			name: "with DPoP optional, a token under DPoP is answered under DPoP",
			dpop: &httpsec.DPoP{PublicURL: dpopPublicURL},
			src:  rsStub{Unbound: true, Verify: rsExpired},
			request: func(t *testing.T) *http.Request {
				return rsRequest(t, "http://example.com/api/orders", "DPoP "+rsToken)
			},
			assert: challenged(`DPoP error="invalid_token", algs="ES256"`),
		},
		{
			name:    "with DPoP required, an invalid token is answered under DPoP alone",
			dpop:    &httpsec.DPoP{PublicURL: dpopPublicURL, Require: true},
			src:     rsStub{Verify: rsExpired},
			request: bearer,
			assert:  challenged(`DPoP error="invalid_token", algs="ES256"`),
		},
		{
			name:    "a certificate-bound source with DPoP and certificates both on answers under Bearer",
			dpop:    &httpsec.DPoP{PublicURL: dpopPublicURL},
			cert:    true,
			src:     rsStub{Verify: rsExpired},
			request: bearer,
			assert:  challenged(`Bearer error="invalid_token"`),
		},
		{
			name: "a token over the bound is answered with one challenge",
			dpop: &httpsec.DPoP{PublicURL: dpopPublicURL},
			src:  rsStub{Unbound: true},
			request: func(t *testing.T) *http.Request {
				return rsRequest(t, "http://example.com/api/orders", "Bearer at."+strings.Repeat("A", 64<<10))
			},
			assert: challenged(`Bearer error="invalid_token"`),
		},
		{
			name:    "an access token off every prefix is answered with one challenge",
			dpop:    &httpsec.DPoP{PublicURL: dpopPublicURL},
			src:     rsStub{Unbound: true},
			request: func(t *testing.T) *http.Request { return rsRequest(t, "http://example.com/admin", "Bearer "+rsToken) },
			assert:  challenged(`Bearer error="invalid_token"`),
		},
		{
			name: "a repeated Authorization header on a covered path is 400 invalid_request, never handed on",
			dpop: &httpsec.DPoP{PublicURL: dpopPublicURL},
			src:  rsStub{Unbound: true},
			request: func(t *testing.T) *http.Request {
				return rsRequest(t, "http://example.com/api/orders", "Bearer "+rsToken, "Bearer other")
			},
			assert: func(t *testing.T, out rsRoute) {
				require.ErrorIs(t, out.err, httpsec.ErrMalformedRequest)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
				assert.Equal(t, []string{`Bearer error="invalid_request"`}, out.rec.Header().Values("WWW-Authenticate"))
				assert.False(t, out.laterRan)
				assert.NotContains(t, out.err.Error(), rsToken)
			},
		},
		{
			name: "a repeated Authorization header off every prefix passes on",
			src:  rsStub{Unbound: true},
			request: func(t *testing.T) *http.Request {
				return rsRequest(t, "http://example.com/admin", "Bearer "+rsToken, "Bearer other")
			},
			assert: func(t *testing.T, out rsRoute) {
				require.NoError(t, out.err)
				assert.True(t, out.laterRan)
			},
		},
		{
			name:    "a DPoP-bound token under Bearer with no proof is the invalid-proof refusal, one challenge",
			dpop:    &httpsec.DPoP{PublicURL: dpopPublicURL},
			src:     rsStub{Verify: rsBoundTo(map[string]string{"jkt": key.jkt})},
			request: bearer,
			assert: func(t *testing.T, out rsRoute) {
				require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
				assert.Equal(t, []string{`DPoP error="invalid_dpop_proof", algs="ES256"`},
					out.rec.Header().Values("WWW-Authenticate"))
				assert.False(t, out.handlerRan)
				assert.False(t, out.laterRan)
			},
		},
		{
			name: "a DPoP-bound token with a proof from another key is the invalid-proof refusal",
			dpop: &httpsec.DPoP{PublicURL: dpopPublicURL},
			src:  rsStub{Verify: rsBoundTo(map[string]string{"jkt": key.jkt})},
			request: func(t *testing.T) *http.Request {
				other := newDPoPKey(t, elliptic.P256())
				proof := other.validProof("j-other").with(map[string]any{"ath": tokenHash(rsToken)}).sign(t)
				req := dpopRequest(t, http.MethodGet, "http://example.com/api/orders", proof)
				req.Header.Set("Authorization", "DPoP "+rsToken)

				return req
			},
			assert: func(t *testing.T, out rsRoute) {
				require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
				assert.Equal(t, []string{`DPoP error="invalid_dpop_proof", algs="ES256"`},
					out.rec.Header().Values("WWW-Authenticate"))
				assert.False(t, out.handlerRan)
			},
		},
		{
			name: "a DPoP-bound token with its proof is accepted",
			dpop: &httpsec.DPoP{PublicURL: dpopPublicURL},
			src:  rsStub{Verify: rsBoundTo(map[string]string{"jkt": key.jkt})},
			request: func(t *testing.T) *http.Request {
				proof := key.validProof("j-ok").with(map[string]any{"ath": tokenHash(rsToken)}).sign(t)
				req := dpopRequest(t, http.MethodGet, "http://example.com/api/orders", proof)
				req.Header.Set("Authorization", "DPoP "+rsToken)

				return req
			},
			assert: func(t *testing.T, out rsRoute) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
				assert.Empty(t, out.rec.Header().Values("WWW-Authenticate"))
			},
		},
		{
			name: "a missing server nonce is the nonce-required refusal with a fresh nonce",
			dpop: nonceDPoP(t, []byte("0123456789abcdef0123456789abcdef")),
			src:  rsStub{Verify: rsBoundTo(map[string]string{"jkt": key.jkt})},
			request: func(t *testing.T) *http.Request {
				proof := key.validProof("j-nonce").with(map[string]any{"ath": tokenHash(rsToken)}).sign(t)
				req := dpopRequest(t, http.MethodGet, "http://example.com/api/orders", proof)
				req.Header.Set("Authorization", "DPoP "+rsToken)

				return req
			},
			assert: func(t *testing.T, out rsRoute) {
				askedForNonce(t, out.served)
				assert.False(t, out.laterRan)
			},
		},
		{
			name: "an unbound token from a source that accepts one is refused under the DPoP scheme",
			dpop: &httpsec.DPoP{PublicURL: dpopPublicURL},
			src:  rsStub{Unbound: true, Verify: rsBoundTo(nil)},
			request: func(t *testing.T) *http.Request {
				proof := key.validProof("j-unbound").with(map[string]any{"ath": tokenHash(rsToken)}).sign(t)
				req := dpopRequest(t, http.MethodGet, "http://example.com/api/orders", proof)
				req.Header.Set("Authorization", "DPoP "+rsToken)

				return req
			},
			assert: func(t *testing.T, out rsRoute) {
				require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
				assert.Len(t, out.rec.Header().Values("WWW-Authenticate"), 1)
				assert.False(t, out.handlerRan)
			},
		},
		{
			name:    "a certificate-bound token without its certificate is the certificate-binding refusal, one challenge",
			dpop:    &httpsec.DPoP{PublicURL: dpopPublicURL},
			cert:    true,
			src:     rsStub{Verify: rsBoundTo(map[string]string{"x5t#S256": "AAAA"})},
			request: bearer,
			assert: func(t *testing.T, out rsRoute) {
				require.ErrorIs(t, out.err, httpsec.ErrCertificateBinding)
				assert.Equal(t, []string{`Bearer error="invalid_token"`}, out.rec.Header().Values("WWW-Authenticate"))
				assert.False(t, out.handlerRan)
			},
		},
		{
			name:    "a DPoP-bound token on a chain without DPoP gets one Bearer challenge",
			cert:    true,
			src:     rsStub{Verify: rsBoundTo(map[string]string{"jkt": key.jkt})},
			request: bearer,
			assert: func(t *testing.T, out rsRoute) {
				require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
				assert.Equal(t, []string{`Bearer error="invalid_token"`}, out.rec.Header().Values("WWW-Authenticate"))
				assert.False(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := &httpsec.StubSource{Name: "provider", Provider: true, Unbound: tc.src.Unbound, Verify: tc.src.Verify}

			var opts []httpsec.Option
			if tc.dpop != nil {
				opts = append(opts, httpsec.EnableDPoP(*tc.dpop))
			}
			if tc.cert {
				opts = append(opts, httpsec.EnableCertificateBinding())
			}

			opts = append(opts, httpsec.EnableResourceServer("urn:orders",
				httpsec.WithPathPrefix("/api/"), httpsec.WithStubSource(src)))

			tc.assert(t, rsServe(t, tc.request(t), opts...))
		})
	}
}

// TestResourceServer_ChallengeOff pins that a chain whose only credential mode is a resource
// server counts as having a built-in bearer: it may turn the challenge off, and then refuses
// with no challenge.
func TestResourceServer_ChallengeOff(t *testing.T) {
	t.Parallel()

	src := &httpsec.StubSource{Name: "provider", Provider: true, Unbound: true, Verify: rsExpired}

	out := rsServe(t, rsRequest(t, "http://example.com/api/orders", "Bearer "+rsToken),
		httpsec.WithoutBearerChallenge(),
		httpsec.EnableResourceServer("urn:orders", httpsec.WithStubSource(src)))

	require.ErrorIs(t, out.err, httpsec.ErrInvalidToken)
	assert.Empty(t, out.rec.Header().Values("WWW-Authenticate"))
}

// TestResourceServer_SessionTokenRefusalUnchanged pins that a session token the chain's signed
// bearer refuses keeps its refusal: the authentication failure, never the invalid-token refusal,
// beside a resource server.
func TestResourceServer_SessionTokenRefusalUnchanged(t *testing.T) {
	t.Parallel()

	f := newOPFixture(t)
	src := &httpsec.StubSource{Name: "provider", Provider: true, Unbound: true}

	c, err := httpsec.New(
		f.signedBearer(t, must.Must(session.New()), httpsec.DefaultBearerScheme),
		httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"), httpsec.WithStubSource(src)))
	require.NoError(t, err)

	out := serve(t, c, rsRequest(t, "http://example.com/api/orders", "Bearer "+rsJWT("", "https://x.example", "a")))

	require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
	assert.NotErrorIs(t, out.err, httpsec.ErrInvalidToken)
	assert.Zero(t, src.Offered())
}
