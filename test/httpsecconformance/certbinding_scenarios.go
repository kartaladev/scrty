package httpsecconformance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// certHeader is the header the scenarios' trusted proxy forwards the client's
// certificate in.
const certHeader = "X-Client-Cert"

// RunCertificateBinding puts the certificate-binding scenarios through
// adapter. They are kept apart from Scenarios so a framework's run of them can
// be selected on its own (go test -run TestCertificateBinding).
//
// Every adapter is reached over an in-memory transport that is never TLS, so
// the scenarios present the certificate the way a TLS-terminating proxy does:
// URL-encoded PEM in a header the chain reads only from a trusted peer. Each
// adapter's own reading of a TLS connection's certificate is pinned by the
// adapter's own tests.
func RunCertificateBinding(t *testing.T, adapter Adapter) {
	t.Helper()

	run(t, adapter, certificateBindingScenarios())
}

// certificateBindingScenarios is certificate binding end to end on every
// adapter: a sign-in bound to the forwarded certificate, the bound token
// accepted with that certificate and refused with another or none, and a
// forwarded certificate from a peer that is not a trusted proxy ignored.
func certificateBindingScenarios() []Scenario {
	return []Scenario{
		certSignInIsBound(),
		certBoundTokenReachesTheRoute(),
		certBoundTokenWithAnotherCertificateIsRefused(),
		certBoundTokenWithoutACertificateIsRefused(),
		certFromAnUntrustedPeerIsIgnored(),
	}
}

// certClient is a client certificate and its forms the scenarios use.
type certClient struct {
	der   []byte
	thumb string
}

func newCertClient(t *testing.T, cn string) certClient {
	t.Helper()

	key := must.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der := must.Must(x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key))
	sum := sha256.Sum256(der)

	return certClient{der: der, thumb: base64.RawURLEncoding.EncodeToString(sum[:])}
}

// forwarded is the certificate as nginx's $ssl_client_escaped_cert forwards
// it: PEM, URL-encoded.
func (c certClient) forwarded() string {
	return url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})))
}

// certFixture is one run's certificate-binding wiring: a token generator that
// binds, shared by every request of the run since each builds its chain
// afresh, and the client's certificate C and another, D.
type certFixture struct {
	gen  *token.JWTGenerator
	c, d certClient
}

// spec is form login and the signed bearer issuing and verifying through the
// fixture's generator, with certificate binding on, behind proxyAddress, which
// forwards the client's address and its certificate.
func (fx *certFixture) spec(t *testing.T) ChainSpec {
	t.Helper()

	effects := newEffects(t)

	return ChainSpec{
		Options: []httpsec.Option{
			httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: []netip.Prefix{netip.MustParsePrefix(proxyAddress + "/32")},
				Headers:  httpsec.XForwarded(httpsec.ForwardedFor),
			}, httpsec.WithClientCertificateHeader(certHeader, nil)),
			httpsec.EnableFormLogin(httpsec.FormLoginDeps{
				Authenticator: &fixtureAuthenticator{calls: &effects.authCalls},
				Sessions:      effects.Sessions,
				Tokens:        fx.gen,
				Attempts:      effects.Attempts,
			}),
			httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
				Verifier: fx.gen, Sessions: effects.Sessions, Users: fixtureUsers{},
			}),
			httpsec.EnableCertificateBinding(),
		},
		Effects: effects,
		Routes:  plainRoute(),
	}
}

// viaProxy is req arriving from the trusted proxy, forwarding clientAddress
// and, unless it is empty, cert in the certificate header.
func viaProxy(req RequestSpec, cert string) RequestSpec {
	return fromCertPeer(req, proxyAddress, cert)
}

// fromCertPeer is req arriving from peer, with clientAddress forwarded and,
// unless it is empty, cert in the certificate header.
func fromCertPeer(req RequestSpec, peer, cert string) RequestSpec {
	header := map[string]string{"X-Forwarded-For": clientAddress}
	for k, v := range req.Header {
		header[k] = v
	}

	if cert != "" {
		header[certHeader] = cert
	}

	req.Header, req.ClientAddress = header, peer

	return req
}

// certLogin is a sign-in.
func certLogin() RequestSpec {
	return formBody("username=" + Username + "&password=" + Password)
}

// certResource is a GET of the route presenting tok as Bearer.
func certResource(tok string) RequestSpec {
	return RequestSpec{
		Method: http.MethodGet, Path: RoutePath,
		Header: map[string]string{"Authorization": "Bearer " + tok},
	}
}

// signIn signs in through send from peer forwarding cert, and returns the
// token, its cnf.x5t#S256 and the stored sign-in's binding.
func (fx *certFixture) signIn(t *testing.T, send func(RequestSpec) Result, peer, cert string) (string, string, session.KeyBinding) {
	t.Helper()

	res := send(fromCertPeer(certLogin(), peer, cert))
	require.Equal(t, http.StatusOK, res.Status)
	require.NoError(t, res.Refusal)

	var doc issuedDocument
	require.NoError(t, json.Unmarshal([]byte(res.Body), &doc))
	assert.Equal(t, string(httpsec.TokenTypeBearer), doc.TokenType,
		"a certificate-bound token is presented as Bearer (RFC 8705)")

	claims, err := fx.gen.Verify(t.Context(), doc.AccessToken)
	require.NoError(t, err)

	return doc.AccessToken, claims.Confirmation().X5TS256, res.Effects.LoadSession(t, claims.ID()).KeyBinding
}

// signedInBound signs in through the proxy forwarding C, and returns the
// token, asserting it and the sign-in are bound to C.
func (fx *certFixture) signedInBound(t *testing.T, send func(RequestSpec) Result) string {
	t.Helper()

	tok, x5t, binding := fx.signIn(t, send, proxyAddress, fx.c.forwarded())
	assert.Equal(t, fx.c.thumb, x5t, "the token carries cnf.x5t#S256 of C")
	assert.Equal(t, session.KeyBinding{X5TS256: fx.c.thumb}, binding, "the sign-in is bound to C")

	return tok
}

// refusedForCertificate asserts res was refused for its certificate binding,
// before the route.
func refusedForCertificate(t *testing.T, res Result) {
	t.Helper()

	assert.Equal(t, http.StatusUnauthorized, res.Status)
	require.ErrorIs(t, res.Refusal, httpsec.ErrCertificateBinding)
	assert.False(t, res.RouteRan)
}

// certScenario is a certificate-binding scenario's Build and Steps over one
// fixture, made per run of the scenario so no two adapters share one.
func certScenario(name string, steps func(t *testing.T, fx *certFixture, send func(RequestSpec) Result)) Scenario {
	var (
		mu       sync.Mutex
		fixtures = map[*Effects]*certFixture{}
	)

	return Scenario{
		Name: name,
		Build: func(t *testing.T) ChainSpec {
			keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
			fx := &certFixture{
				gen: must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience())),
				c:   newCertClient(t, "service-c"),
				d:   newCertClient(t, "service-d"),
			}
			spec := fx.spec(t)

			mu.Lock()
			fixtures[spec.Effects] = fx
			mu.Unlock()

			return spec
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			mu.Lock()
			fx := fixtures[spec.Effects]
			mu.Unlock()

			steps(t, fx, send)
		},
	}
}

func certSignInIsBound() Scenario {
	return certScenario("certificate binding: a sign-in with a forwarded certificate is bound to it",
		func(t *testing.T, fx *certFixture, send func(RequestSpec) Result) {
			fx.signedInBound(t, send)
		})
}

func certBoundTokenReachesTheRoute() Scenario {
	return certScenario("certificate binding: a bound token with its certificate reaches the route",
		func(t *testing.T, fx *certFixture, send func(RequestSpec) Result) {
			tok := fx.signedInBound(t, send)

			res := send(viaProxy(certResource(tok), fx.c.forwarded()))

			assert.NoError(t, res.Refusal)
			assert.True(t, res.RouteRan)
			require.True(t, res.PrincipalKnown)
			assert.Equal(t, UserID, res.Principal.ID)
			assert.Empty(t, res.RouteHeader.Get(certHeader), "the consumed certificate header is removed before the route")
		})
}

func certBoundTokenWithAnotherCertificateIsRefused() Scenario {
	return certScenario("certificate binding: a bound token with another certificate is refused",
		func(t *testing.T, fx *certFixture, send func(RequestSpec) Result) {
			tok := fx.signedInBound(t, send)

			refusedForCertificate(t, send(viaProxy(certResource(tok), fx.d.forwarded())))
		})
}

func certBoundTokenWithoutACertificateIsRefused() Scenario {
	return certScenario("certificate binding: a bound token without a certificate is refused",
		func(t *testing.T, fx *certFixture, send func(RequestSpec) Result) {
			tok := fx.signedInBound(t, send)

			refusedForCertificate(t, send(viaProxy(certResource(tok), "")))
		})
}

func certFromAnUntrustedPeerIsIgnored() Scenario {
	return certScenario("certificate binding: a forwarded certificate from an untrusted peer is ignored",
		func(t *testing.T, fx *certFixture, send func(RequestSpec) Result) {
			_, x5t, binding := fx.signIn(t, send, directPeer, fx.c.forwarded())

			assert.Empty(t, x5t, "no cnf")
			assert.True(t, binding.IsZero(), "the sign-in is unbound")
		})
}
