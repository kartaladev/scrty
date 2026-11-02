package httpsec

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// ErrCertificateBinding refuses a credential bound to a TLS client
// certificate (RFC 8705) on a request that does not present that same
// certificate, and a certificate-bound credential presented while certificate
// binding is off. StatusForError answers it with 401. Its text names no
// certificate and no thumbprint.
var ErrCertificateBinding = errors.New("httpsec: the credential is bound to a client certificate the request does not present")

// optionCertificateBinding names EnableCertificateBinding in its configuration
// errors.
const optionCertificateBinding = "EnableCertificateBinding"

// CertificateBindingOption tunes EnableCertificateBinding. A nil option is
// skipped. None is defined yet: every behaviour of certificate binding has
// its default, and where the certificate comes from behind a proxy is the
// trusted-proxy configuration's (WithClientCertificateHeader).
type CertificateBindingOption func(*certBinding)

// certBinding is the chain's certificate binding, built by
// EnableCertificateBinding and frozen at construction.
type certBinding struct{}

// EnableCertificateBinding turns on certificate-bound tokens (RFC 8705) for
// the whole chain: a token issued to a client that signed in over mutual TLS
// is bound to that client's certificate, and is accepted afterwards only on a
// request presenting the same certificate, so a copied token is of no use
// without the certificate's private key.
//
// Default: off. No token is bound, and a token carrying cnf.x5t#S256 is
// refused with ErrCertificateBinding by both bearer modes, whatever scheme
// carried it, never accepted as a plain bearer token.
//
// Once it is on:
//
//   - Every issuing endpoint (login, second-factor verification, passkey
//     login, magic link, OIDC handoff, recovery and its held finish,
//     re-authentication of an unbound sign-in) whose request presents a
//     client certificate binds the sign-in it creates
//     (session.KeyBinding.X5TS256) and the token it issues (cnf.x5t#S256) to
//     the certificate's thumbprint: base64url, without padding, of the
//     SHA-256 of its DER encoding. A request without one is issued an unbound
//     token. A second factor and a renewal keep the sign-in's binding.
//   - When the request also carries a valid DPoP proof (EnableDPoP), the
//     token is bound to the DPoP key only: a token carries one confirmation,
//     and a DPoP key survives proxies that do not forward certificates.
//   - A certificate-bound token or session reference is accepted, by
//     EnableBearerToken and EnableSessionBearer alike, only on a request whose
//     certificate has the same thumbprint, compared in constant time.
//     Anything else, no certificate included, is refused with
//     ErrCertificateBinding (401). The request's certificate is read once, at
//     OrderMTLS, for every interceptor inside it.
//   - A certificate-bound token is presented as Bearer: the issuing endpoints
//     report TokenTypeBearer for it. Under the DPoP scheme it is refused.
//
// The certificate is the request's Request.ClientCertificate: the TLS
// connection's leaf certificate, or, behind a trusted proxy that terminates
// TLS, the certificate it forwards in the header WithClientCertificateHeader
// names, read only from a trusted peer and decoded as URL-encoded PEM unless
// the consumer supplies a decoder there. A forwarded value that does not
// decode means the request has no certificate. The default decoder accepts
// exactly one CERTIFICATE PEM block with only whitespace around it, and the
// header sent on two lines is ignored; the proxy must overwrite or strip the
// header on every request (WithClientCertificateHeader).
//
// The library compares thumbprints and nothing else (RFC 8705 section 3). It
// does not validate the certificate's chain, its validity period, its key
// usage or its revocation: that is the TLS server's job, through
// tls.Config.ClientAuth and ClientCAs, or the proxy's that terminates TLS.
// A server that requests a certificate without verifying it
// (tls.RequestClientCert, nginx's ssl_verify_client optional_no_ca) still
// binds tokens soundly, since only the holder of the certificate's private
// key can present it again.
//
// No CertificateBindingOption is defined yet, so every behaviour above is the
// default; the forwarded header and its decoder are set on the trusted-proxy
// configuration, by WithClientCertificateHeader (no header, and URL-encoded
// PEM, by default).
//
// It may be given once; a second call is a configuration error. Enabling it
// on a chain with no feature that verifies bound credentials (today
// EnableBearerToken and EnableSessionBearer) is a configuration error from
// New, whatever the order of the options, as is an issuing endpoint whose
// token generator does not implement token.ConfirmingGenerator, and so is
// enabling it together with EnableDPoP(DPoP{Require: true}): every issuing
// request would then carry a proof and be bound to its key, so no certificate
// binding could be made. That error wraps ErrConfig and names both options.
func EnableCertificateBinding(opts ...CertificateBindingOption) Option {
	return func(c *config) error {
		if c.certBinding != nil {
			return newConfigError("%s was given twice; one chain has one certificate-binding configuration",
				optionCertificateBinding)
		}

		b := &certBinding{}

		for _, o := range opts {
			if o != nil {
				o(b)
			}
		}

		c.certBinding = b

		c.enable(optionCertificateBinding, func() error {
			if len(c.bindingVerifiers) == 0 {
				return newConfigError("%s was enabled on a chain with no feature that verifies bound "+
					"credentials; enable one, such as EnableBearerToken or EnableSessionBearer",
					optionCertificateBinding)
			}

			if c.dpop != nil && c.dpop.cfg.Require {
				return newConfigError("%s was enabled beside %s with Require set: every issuing request "+
					"would carry a proof and be bound to its key, so no certificate binding could be made; "+
					"drop one of the two, or leave Require unset", optionCertificateBinding, optionDPoP)
			}

			return nil
		})

		c.register(certificateSlot{}, OrderMTLS)

		return nil
	}
}

// certificateSlot is certificate binding's interceptor at OrderMTLS. It reads
// the request's client certificate once and fixes its thumbprint on the
// exchange, so the bearer modes and every endpoint inside the slot judge a
// certificate-bound credential against that one answer.
type certificateSlot struct{}

// Intercept implements Interceptor.
func (certificateSlot) Intercept(ex *Exchange, next Next) error {
	ex.presentedThumbprint()

	return next(ex)
}

// certificateThumbprint is cert's RFC 8705 thumbprint, base64url without
// padding of the SHA-256 of its DER encoding, and "" for no certificate.
func certificateThumbprint(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}

	sum := sha256.Sum256(cert.Raw)

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// presentedThumbprint is the thumbprint of the certificate the exchange's
// request presents, read once and kept for the rest of the exchange, and ""
// when it presents none.
func (ex *Exchange) presentedThumbprint() string {
	if !ex.certificateRead {
		ex.certificateThumb = certificateThumbprint(ex.Request.ClientCertificate())
		ex.certificateRead = true
	}

	return ex.certificateThumb
}

// certBinding is the chain's certificate binding the exchange runs under, and
// nil when it is off or the exchange runs through no chain.
func (ex *Exchange) certBinding() *certBinding {
	if ex.perRequest == nil {
		return nil
	}

	return ex.perRequest.certBinding
}

// admitCertificate decides a credential bound to the certificate thumbprint
// x5t. With certificate binding off it is refused with ErrCertificateBinding,
// whatever scheme carried it and whatever else is enabled, never taken for a
// plain bearer credential. With it on, a credential presented under the DPoP
// scheme (proof not nil) is refused as a DPoP refusal: it is not bound to a
// DPoP key. Otherwise it is accepted only when the request's certificate has
// the same thumbprint, compared in constant time. DPoP is never required while
// certificate binding is on: EnableCertificateBinding refuses that at
// construction.
func admitCertificate(ex *Exchange, v *dpopVerifier, proof *dpopProof, x5t string) error {
	if ex.certBinding() == nil {
		return ErrCertificateBinding
	}

	if v != nil && proof != nil {
		return v.refuse(ex.Context(), reasonProofBinding)
	}

	presented := ex.presentedThumbprint()
	if presented == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(x5t)) != 1 {
		return ErrCertificateBinding
	}

	return nil
}
