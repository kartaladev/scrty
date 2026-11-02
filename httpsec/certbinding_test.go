package httpsec_test

import (
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// certServer is a chain behind a real TLS server that asks every client for a
// certificate and accepts any, or none: the library compares thumbprints, and
// validating the certificate is the TLS server's own business.
type certServer struct {
	srv  *httptest.Server
	base *issuingBase

	mu       sync.Mutex
	refusals []error
}

// newCertServer serves form login and the signed bearer, issuing through a
// generator that binds, with opts beside them, behind a TLS server that
// requests a client certificate.
func newCertServer(t *testing.T, opts ...httpsec.Option) *certServer {
	t.Helper()

	s := &certServer{base: newIssuingBase(t)}

	chain, err := httpsec.New(append(opts,
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: s.base.authn, Sessions: s.base.sessions, Tokens: s.base.gen,
			Attempts: must.Must(lockout.NewMemoryAttemptStore()),
		}),
		s.base.bearer(),
		httpsec.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
			s.mu.Lock()
			s.refusals = append(s.refusals, err)
			s.mu.Unlock()

			w.WriteHeader(httpsec.StatusForError(err))
		}),
	)...)
	require.NoError(t, err)

	s.srv = httptest.NewUnstartedServer(chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	s.srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)

	return s
}

// client dials the server presenting certs, each run on its own connections.
func (s *certServer) client(certs []tls.Certificate) *http.Client {
	tr := s.srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.Certificates = certs

	return &http.Client{Transport: tr}
}

// lastRefusal is the error the chain refused the last refused request with,
// and nil when it refused none.
func (s *certServer) lastRefusal() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.refusals) == 0 {
		return nil
	}

	return s.refusals[len(s.refusals)-1]
}

// certIssued is what a sign-in issued: the token, its cnf.x5t#S256 and the stored
// sign-in's certificate binding.
type certIssued struct {
	token          string
	tokenX5T       string
	sessionBinding session.KeyBinding
}

// login signs in over a connection presenting certs.
func (s *certServer) login(t *testing.T, certs []tls.Certificate) certIssued {
	t.Helper()

	body := url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {e2ePassword},
	}.Encode()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, s.srv.URL+httpsec.DefaultLoginPath,
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := s.client(certs).Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode, "the sign-in succeeds")

	var doc struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	require.NoError(t, json.NewDecoder(res.Body).Decode(&doc))
	assert.Equal(t, string(httpsec.TokenTypeBearer), doc.TokenType,
		"a certificate-bound token is presented as Bearer (RFC 8705)")

	claims, err := s.base.gen.Verify(t.Context(), doc.AccessToken)
	require.NoError(t, err)

	stored, err := s.base.sessions.Load(t.Context(), claims.ID())
	require.NoError(t, err)

	return certIssued{token: doc.AccessToken, tokenX5T: claims.Confirmation().X5TS256, sessionBinding: stored.KeyBinding}
}

// get presents tok as Bearer over a connection presenting certs, and returns
// the status.
func (s *certServer) get(t *testing.T, tok string, certs []tls.Certificate) int {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, s.srv.URL+"/api/orders", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tok)

	res, err := s.client(certs).Do(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	return res.StatusCode
}

func TestCertificateBinding_Direct(t *testing.T) {
	t.Parallel()

	c := newClientCert(t, "service-c")
	d := newClientCert(t, "service-d")

	type testCase struct {
		name    string
		login   []tls.Certificate
		present []tls.Certificate
		assert  func(t *testing.T, got certIssued, status int, refusal error)
	}

	boundToC := func(t *testing.T, got certIssued) {
		t.Helper()

		assert.Equal(t, c.thumb, got.tokenX5T, "the token carries cnf.x5t#S256 of C")
		assert.Equal(t, session.KeyBinding{X5TS256: c.thumb}, got.sessionBinding, "the sign-in is bound to C")
	}
	refused := func(t *testing.T, status int, refusal error) {
		t.Helper()

		assert.Equal(t, http.StatusUnauthorized, status)
		require.ErrorIs(t, refusal, httpsec.ErrCertificateBinding)
	}

	cases := []testCase{
		{
			name:    "a token bound to C is accepted over a connection with C",
			login:   []tls.Certificate{c.tls},
			present: []tls.Certificate{c.tls},
			assert: func(t *testing.T, got certIssued, status int, refusal error) {
				boundToC(t, got)
				assert.Equal(t, http.StatusOK, status)
				assert.NoError(t, refusal)
			},
		},
		{
			name:  "a token bound to C is refused over a connection with no certificate",
			login: []tls.Certificate{c.tls},
			assert: func(t *testing.T, got certIssued, status int, refusal error) {
				boundToC(t, got)
				refused(t, status, refusal)
			},
		},
		{
			name:    "a token bound to C is refused over a connection with D",
			login:   []tls.Certificate{c.tls},
			present: []tls.Certificate{d.tls},
			assert: func(t *testing.T, got certIssued, status int, refusal error) {
				boundToC(t, got)
				refused(t, status, refusal)
			},
		},
		{
			name: "a sign-in without a certificate issues an unbound token, accepted without one",
			assert: func(t *testing.T, got certIssued, status int, refusal error) {
				assert.Empty(t, got.tokenX5T, "no cnf")
				assert.True(t, got.sessionBinding.IsZero(), "the sign-in is unbound")
				assert.Equal(t, http.StatusOK, status)
				assert.NoError(t, refusal)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newCertServer(t, httpsec.EnableCertificateBinding())

			got := s.login(t, tc.login)
			status := s.get(t, got.token, tc.present)

			tc.assert(t, got, status, s.lastRefusal())
		})
	}
}

func TestEnableCertificateBinding_Construction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(t *testing.T, b *issuingBase) []httpsec.Option
		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refused := func(t *testing.T, chain *httpsec.Chain, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Nil(t, chain)
		assert.Contains(t, err.Error(), "EnableCertificateBinding")
	}

	cases := []testCase{
		{
			name: "beside a bearer mode it builds",
			opts: func(_ *testing.T, b *issuingBase) []httpsec.Option {
				return []httpsec.Option{b.bearer(), httpsec.EnableCertificateBinding(nil)}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, chain)
			},
		},
		{
			name: "beside the session-reference bearer it builds",
			opts: func(_ *testing.T, b *issuingBase) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableCertificateBinding(),
					httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: b.sessions, Users: b.users}),
				}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, chain)
			},
		},
		{
			name: "given twice it is refused",
			opts: func(_ *testing.T, b *issuingBase) []httpsec.Option {
				return []httpsec.Option{
					b.bearer(), httpsec.EnableCertificateBinding(), httpsec.EnableCertificateBinding(),
				}
			},
			assert: refused,
		},
		{
			name: "with nothing that verifies a binding it is refused",
			opts: func(*testing.T, *issuingBase) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCertificateBinding()}
			},
			assert: refused,
		},
		{
			name: "an issuing endpoint whose generator cannot bind is refused",
			opts: func(t *testing.T, b *issuingBase) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: b.authn, Sessions: b.sessions,
						Tokens:   NewMockGenerator(gomock.NewController(t)),
						Attempts: must.Must(lockout.NewMemoryAttemptStore()),
					}),
					b.bearer(),
					httpsec.EnableCertificateBinding(),
				}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				refused(t, chain, err)
				assert.Contains(t, err.Error(), "token.ConfirmingGenerator")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.opts(t, newIssuingBase(t))...)
			tc.assert(t, chain, err)
		})
	}
}

// The addresses of the forwarded-certificate cases: the trusted proxy that
// terminates TLS, and a peer that reaches the app directly.
const (
	certProxyPeer  = "10.20.0.2"
	certDirectPeer = "198.51.100.9"
	certHeader     = "X-Client-Cert"
)

// forwardedCertChain is form login, the signed bearer and certificate binding
// behind proxies in 10.20.0.0/16 that forward the client's certificate in
// X-Client-Cert, decoded by decode, or by the default when it is nil. extra
// joins them.
func forwardedCertChain(t *testing.T, b *issuingBase,
	decode func(string) (*x509.Certificate, error), extra ...httpsec.Option) *httpsec.Chain {
	t.Helper()

	chain, err := httpsec.New(append(extra,
		httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
			Headers:  httpsec.XForwarded(httpsec.ForwardedFor),
		}, httpsec.WithClientCertificateHeader(certHeader, decode)),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: b.authn, Sessions: b.sessions, Tokens: b.gen,
			Attempts: must.Must(lockout.NewMemoryAttemptStore()),
		}),
		b.bearer(),
		httpsec.EnableCertificateBinding(),
	)...)
	require.NoError(t, err)

	return chain
}

// fromPeer is req arriving from peer, forwarding e2eSource as the client when
// peer is the proxy, and carrying the certificate header value when it is not
// empty.
func fromPeer(req *http.Request, peer, value string) *http.Request {
	req.RemoteAddr = peer + ":51000"
	if peer == certProxyPeer {
		req.Header.Set("X-Forwarded-For", e2eSource)
	}

	if value != "" {
		req.Header.Set(certHeader, value)
	}

	return req
}

// certLoginRequest is a sign-in of e2eUser's.
func certLoginRequest(t *testing.T) *http.Request {
	t.Helper()

	return postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {e2ePassword},
	})
}

// issuedBy reads the token a successful sign-in issued and its cnf.x5t#S256,
// and the stored sign-in's binding.
func issuedBy(t *testing.T, b *issuingBase, out served) certIssued {
	t.Helper()

	require.NoError(t, out.err)

	var doc struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))

	claims, err := b.gen.Verify(t.Context(), doc.AccessToken)
	require.NoError(t, err)

	stored, err := b.sessions.Load(t.Context(), claims.ID())
	require.NoError(t, err)

	return certIssued{token: doc.AccessToken, tokenX5T: claims.Confirmation().X5TS256, sessionBinding: stored.KeyBinding}
}

// resource is a GET presenting tok as Bearer.
func resource(t *testing.T, tok string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/api/orders", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	return req
}

// withConnectionCert is req arriving on a TLS connection whose client sent
// cert.
func withConnectionCert(req *http.Request, cert clientCert) *http.Request {
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert.cert}}

	return req
}

func TestCertificateBinding_Forwarded(t *testing.T) {
	t.Parallel()

	c := newClientCert(t, "service-c")
	d := newClientCert(t, "service-d")
	proxyOwn := newClientCert(t, "proxy")

	// decodeAsDER is a consumer's decoder: the value is base64 DER.
	decodeAsDER := func(v string) (*x509.Certificate, error) {
		der, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}

		return x509.ParseCertificate(der)
	}

	type testCase struct {
		name   string
		decode func(string) (*x509.Certificate, error)
		// run sends the case's requests through chain, built over b, and
		// returns what the sign-in issued and what the last request served.
		run    func(t *testing.T, b *issuingBase, chain *httpsec.Chain) (certIssued, served)
		assert func(t *testing.T, got certIssued, last served)
	}

	boundTo := func(cert clientCert) func(t *testing.T, got certIssued) {
		return func(t *testing.T, got certIssued) {
			t.Helper()

			assert.Equal(t, cert.thumb, got.tokenX5T, "the token carries cnf.x5t#S256")
			assert.Equal(t, session.KeyBinding{X5TS256: cert.thumb}, got.sessionBinding, "the sign-in is bound")
		}
	}
	unbound := func(t *testing.T, got certIssued) {
		t.Helper()

		assert.Empty(t, got.tokenX5T, "no cnf")
		assert.True(t, got.sessionBinding.IsZero(), "the sign-in is unbound")
	}
	accepted := func(t *testing.T, last served) {
		t.Helper()

		require.NoError(t, last.err)
		assert.True(t, last.handlerRan)
	}
	refused := func(t *testing.T, last served) {
		t.Helper()

		assert.False(t, last.handlerRan)
		require.ErrorIs(t, last.err, httpsec.ErrCertificateBinding)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(last.err))
	}

	// signInVia signs in from peer forwarding value, then presents the token
	// from peer forwarding presented.
	signInVia := func(peer, value, presented string) func(*testing.T, *issuingBase, *httpsec.Chain) (certIssued, served) {
		return func(t *testing.T, b *issuingBase, chain *httpsec.Chain) (certIssued, served) {
			got := issuedBy(t, b, serve(t, chain, fromPeer(certLoginRequest(t), peer, value)))

			return got, serve(t, chain, fromPeer(resource(t, got.token), peer, presented))
		}
	}

	cases := []testCase{
		{
			name: "URL-encoded PEM from a trusted proxy binds C, and C forwarded again is accepted",
			run:  signInVia(certProxyPeer, c.escaped(), c.escaped()),
			assert: func(t *testing.T, got certIssued, last served) {
				boundTo(c)(t, got)
				accepted(t, last)
			},
		},
		{
			name: "a value percent-encoded with a literal +, as nginx may send it, binds C",
			run:  signInVia(certProxyPeer, pathEscaped(c), c.escaped()),
			assert: func(t *testing.T, got certIssued, last served) {
				boundTo(c)(t, got)
				accepted(t, last)
			},
		},
		{
			name: "a token bound to C, presented with D forwarded, is refused",
			run:  signInVia(certProxyPeer, c.escaped(), d.escaped()),
			assert: func(t *testing.T, got certIssued, last served) {
				boundTo(c)(t, got)
				refused(t, last)
			},
		},
		{
			name: "a token bound to C, presented with nothing forwarded, is refused",
			run:  signInVia(certProxyPeer, c.escaped(), ""),
			assert: func(t *testing.T, got certIssued, last served) {
				boundTo(c)(t, got)
				refused(t, last)
			},
		},
		{
			name:   "the consumer's decoder is used when given",
			decode: decodeAsDER,
			run: signInVia(certProxyPeer, base64.StdEncoding.EncodeToString(c.cert.Raw),
				base64.StdEncoding.EncodeToString(c.cert.Raw)),
			assert: func(t *testing.T, got certIssued, last served) {
				boundTo(c)(t, got)
				accepted(t, last)
			},
		},
		{
			name: "an untrusted peer's header is ignored: its connection's certificate is the client's",
			run: func(t *testing.T, b *issuingBase, chain *httpsec.Chain) (certIssued, served) {
				login := withConnectionCert(fromPeer(certLoginRequest(t), certDirectPeer, c.escaped()), d)
				got := issuedBy(t, b, serve(t, chain, login))

				return got, serve(t, chain, fromPeer(resource(t, got.token), certDirectPeer, d.escaped()))
			},
			assert: func(t *testing.T, got certIssued, last served) {
				boundTo(d)(t, got)
				refused(t, last)
			},
		},
		{
			name: "an untrusted peer without a certificate of its own has none, whatever it forwards",
			run:  signInVia(certDirectPeer, c.escaped(), c.escaped()),
			assert: func(t *testing.T, got certIssued, last served) {
				unbound(t, got)
				accepted(t, last)
			},
		},
		{
			name: "a trusted proxy's own connection certificate is never the client's",
			run: func(t *testing.T, b *issuingBase, chain *httpsec.Chain) (certIssued, served) {
				login := withConnectionCert(fromPeer(certLoginRequest(t), certProxyPeer, ""), proxyOwn)
				got := issuedBy(t, b, serve(t, chain, login))

				return got, serve(t, chain, fromPeer(resource(t, got.token), certProxyPeer, ""))
			},
			assert: func(t *testing.T, got certIssued, last served) {
				unbound(t, got)
				accepted(t, last)
			},
		},
		{
			name: "an undecodable value means no certificate, and a bound token on it is refused",
			run: func(t *testing.T, b *issuingBase, chain *httpsec.Chain) (certIssued, served) {
				unboundLogin := issuedBy(t, b, serve(t, chain, fromPeer(certLoginRequest(t), certProxyPeer, "%zz-not-a-cert")))
				unbound(t, unboundLogin)

				got := issuedBy(t, b, serve(t, chain, fromPeer(certLoginRequest(t), certProxyPeer, c.escaped())))

				return got, serve(t, chain, fromPeer(resource(t, got.token), certProxyPeer, "%zz-not-a-cert"))
			},
			assert: func(t *testing.T, got certIssued, last served) {
				boundTo(c)(t, got)
				refused(t, last)
			},
		},
		{
			name: "PEM that holds no certificate means no certificate",
			run: signInVia(certProxyPeer,
				url.QueryEscape("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), ""),
			assert: func(t *testing.T, got certIssued, last served) {
				unbound(t, got)
				accepted(t, last)
			},
		},
		{
			name: "a consumer decoder's error means no certificate",
			decode: func(string) (*x509.Certificate, error) {
				return nil, errors.New("not a certificate")
			},
			run: signInVia(certProxyPeer, c.escaped(), ""),
			assert: func(t *testing.T, got certIssued, last served) {
				unbound(t, got)
				accepted(t, last)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := newIssuingBase(t)
			got, last := tc.run(t, b, forwardedCertChain(t, b, tc.decode))
			tc.assert(t, got, last)
		})
	}
}

// TestCertificateBinding_ForwardedReachesTheSlot pins that a trusted proxy's
// forwarded certificate reaches the OrderMTLS slot although the header it came
// in is removed from the request before the first interceptor runs.
func TestCertificateBinding_ForwardedReachesTheSlot(t *testing.T) {
	t.Parallel()

	c := newClientCert(t, "service-c")

	var (
		got    *x509.Certificate
		header string
	)

	b := newIssuingBase(t)
	chain := forwardedCertChain(t, b, nil, httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			got, header = ex.Request.ClientCertificate(), ex.Request.Header(certHeader)

			return next(ex)
		}), httpsec.OrderMTLS))

	req := fromPeer(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/r", nil),
		certProxyPeer, c.escaped())
	out := serve(t, chain, req)

	require.NoError(t, out.err)
	assert.Empty(t, header, "the header is removed before the slot")
	assert.Empty(t, req.Header.Get(certHeader), "and from the request the handler reads")
	require.NotNil(t, got, "the forwarded certificate reaches the slot")
	assert.Equal(t, c.cert.Raw, got.Raw)
}

// pathEscaped is the certificate's PEM percent-encoded with "+" left as it
// is, as an encoder that escapes a URI path segment writes it.
func pathEscaped(c clientCert) string { return url.PathEscape(c.pem()) }

// certBoundSignIn creates a sign-in of e2eUser's bound to thumb, and returns
// its reference and a token issued for it carrying cnf.x5t#S256.
func certBoundSignIn(t *testing.T, b *issuingBase, thumb string) (string, string) {
	t.Helper()

	s, err := b.sessions.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Password),
		session.WithKeyBinding(session.KeyBinding{X5TS256: thumb}))
	require.NoError(t, err)

	tok, err := b.gen.GenerateWith(t.Context(), s.ID, &identity.Principal{ID: e2eUser, Username: e2eAddress},
		token.WithConfirmation(token.Confirmation{X5TS256: thumb}))
	require.NoError(t, err)

	return s.ID, tok
}

// TestCertificateBinding_Presented pins how a certificate-bound credential is
// judged by each bearer mode, with certificate binding and DPoP each on or off.
func TestCertificateBinding_Presented(t *testing.T) {
	t.Parallel()

	c := newClientCert(t, "service-c")
	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name string
		// opts is the chain beside the bearer mode.
		opts      []httpsec.Option
		reference bool // the session-reference bearer, not the signed one
		// request presents the case's credential.
		request func(t *testing.T, sid, tok string) *http.Request
		assert  func(t *testing.T, out served)
	}

	asBearerWithC := func(t *testing.T, _, tok string) *http.Request {
		return withConnectionCert(resource(t, tok), c)
	}
	referenceWithC := func(t *testing.T, sid, _ string) *http.Request {
		return withConnectionCert(resource(t, sid), c)
	}
	refusedForCertificate := func(t *testing.T, out served) {
		t.Helper()

		assert.False(t, out.handlerRan, "never accepted as a plain bearer credential")
		require.ErrorIs(t, out.err, httpsec.ErrCertificateBinding)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	}
	refusedProof := func(t *testing.T, out served) {
		t.Helper()

		assert.False(t, out.handlerRan)
		require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	}
	accepted := func(t *testing.T, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.True(t, out.handlerRan)
	}

	cases := []testCase{
		{
			name:    "switched off: a certificate-bound token is refused for its binding",
			request: asBearerWithC,
			assert:  refusedForCertificate,
		},
		{
			name:    "switched off with DPoP on: a certificate-bound token is refused for its binding",
			opts:    []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{})},
			request: asBearerWithC,
			assert:  refusedForCertificate,
		},
		{
			name:      "switched off: a certificate-bound session reference is refused for its binding",
			reference: true,
			request:   referenceWithC,
			assert:    refusedForCertificate,
		},
		{
			name:    "switched on: the same token with its certificate is accepted",
			opts:    []httpsec.Option{httpsec.EnableCertificateBinding()},
			request: asBearerWithC,
			assert:  accepted,
		},
		{
			name:      "switched on: the same session reference with its certificate is accepted",
			opts:      []httpsec.Option{httpsec.EnableCertificateBinding()},
			reference: true,
			request:   referenceWithC,
			assert:    accepted,
		},
		{
			name:      "switched on: the session reference without its certificate is refused",
			opts:      []httpsec.Option{httpsec.EnableCertificateBinding()},
			reference: true,
			request: func(t *testing.T, sid, _ string) *http.Request {
				return resource(t, sid)
			},
			assert: func(t *testing.T, out served) {
				refusedForCertificate(t, out)
				assert.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired,
					"a refused reference reads as a missing session in code")
			},
		},
		{
			name: "a certificate-bound token under the DPoP scheme is refused, its certificate notwithstanding",
			opts: []httpsec.Option{httpsec.EnableCertificateBinding(), httpsec.EnableDPoP(httpsec.DPoP{})},
			request: func(t *testing.T, _, tok string) *http.Request {
				req := withConnectionCert(resource(t, tok), c)
				req.Header.Set("Authorization", "DPoP "+tok)
				req.Header.Set("DPoP", key.validProof("j-1").with(map[string]any{
					"htu": "https://example.com/api/orders", "iat": time.Now().Unix(), "ath": tokenHash(tok),
				}).sign(t))

				return req
			},
			assert: refusedProof,
		},
		{
			name: "a certificate-bound token is refused while DPoP is required",
			opts: []httpsec.Option{
				httpsec.EnableCertificateBinding(), httpsec.EnableDPoP(httpsec.DPoP{Require: true}),
			},
			request: asBearerWithC,
			assert:  refusedProof,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := newIssuingBase(t)
			sid, tok := certBoundSignIn(t, b, c.thumb)

			bearer := b.bearer()
			if tc.reference {
				bearer = httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: b.sessions, Users: b.users})
			}

			chain, err := httpsec.New(append(tc.opts, bearer)...)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.request(t, sid, tok)))
		})
	}
}

// TestCertificateBinding_BothOffered pins which binding a sign-in takes with
// DPoP and certificate binding both on: the DPoP key whenever a proof is
// offered, the certificate only without one.
func TestCertificateBinding_BothOffered(t *testing.T) {
	t.Parallel()

	c := newClientCert(t, "service-c")
	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name      string
		withCert  bool
		withProof bool
		assert    func(t *testing.T, cnf token.Confirmation, stored session.KeyBinding, tokenType string)
	}

	cases := []testCase{
		{
			name:     "a certificate and a valid proof bind the DPoP key only",
			withCert: true, withProof: true,
			assert: func(t *testing.T, cnf token.Confirmation, stored session.KeyBinding, tokenType string) {
				assert.Equal(t, token.Confirmation{JKT: key.jkt}, cnf, "cnf.jkt and no cnf.x5t#S256")
				assert.Equal(t, session.KeyBinding{JKT: key.jkt}, stored)
				assert.Equal(t, string(httpsec.TokenTypeDPoP), tokenType)
			},
		},
		{
			name:     "a certificate without a proof binds the certificate",
			withCert: true,
			assert: func(t *testing.T, cnf token.Confirmation, stored session.KeyBinding, tokenType string) {
				assert.Equal(t, token.Confirmation{X5TS256: c.thumb}, cnf)
				assert.Equal(t, session.KeyBinding{X5TS256: c.thumb}, stored)
				assert.Equal(t, string(httpsec.TokenTypeBearer), tokenType)
			},
		},
		{
			name:      "a proof without a certificate binds the DPoP key",
			withProof: true,
			assert: func(t *testing.T, cnf token.Confirmation, stored session.KeyBinding, tokenType string) {
				assert.Equal(t, token.Confirmation{JKT: key.jkt}, cnf)
				assert.Equal(t, session.KeyBinding{JKT: key.jkt}, stored)
				assert.Equal(t, string(httpsec.TokenTypeDPoP), tokenType)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := newIssuingBase(t)
			chain, err := httpsec.New(
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: b.authn, Sessions: b.sessions, Tokens: b.gen,
					Attempts: must.Must(lockout.NewMemoryAttemptStore()),
				}),
				b.bearer(),
				httpsec.EnableDPoP(httpsec.DPoP{}),
				httpsec.EnableCertificateBinding(),
			)
			require.NoError(t, err)

			req := certLoginRequest(t)
			if tc.withCert {
				req = withConnectionCert(req, c)
			}

			if tc.withProof {
				// A request over TLS resolves to https, which its proof names.
				parts := key.issuingProofParts(httpsec.DefaultLoginPath, "j-1", "")
				if tc.withCert {
					parts = parts.with(map[string]any{"htu": "https://example.com" + httpsec.DefaultLoginPath})
				}

				req.Header.Set("DPoP", parts.sign(t))
			}

			out := serve(t, chain, req)
			require.NoError(t, out.err)

			var doc struct {
				AccessToken string `json:"access_token"`
				TokenType   string `json:"token_type"`
			}
			require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))

			claims, err := b.gen.Verify(t.Context(), doc.AccessToken)
			require.NoError(t, err)

			stored, err := b.sessions.Load(t.Context(), claims.ID())
			require.NoError(t, err)

			tc.assert(t, claims.Confirmation(), stored.KeyBinding, doc.TokenType)
		})
	}
}
