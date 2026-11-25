package httpsec

import (
	"context"
	"errors"
)

// bindingVerdict is what checkBinding found of a presented token's binding to a key or a
// certificate. Every verdict but bindingHeld and bindingUnbound is a refusal, and each caller maps it
// to its own answer: UserInfo to the challenges its settled spec names, the resource server to the
// sender-constrained-token refusals.
type bindingVerdict int

const (
	// bindingHeld is a bound token whose binding the request proved.
	bindingHeld bindingVerdict = iota

	// bindingUnbound is a token with no confirmation that the chain admitted as unbound: no proof
	// came with it, and DPoP is not required. Whether an unbound token is acceptable is the caller's
	// decision.
	bindingUnbound

	// bindingKeyMismatch is a binding that does not fit what the request presented: a key-bound
	// token with no proof, a proof from another key, a key binding while DPoP is off, a proof beside
	// an unbound token, or a certificate-bound token presented under the DPoP scheme.
	bindingKeyMismatch

	// bindingProofInvalid is a DPoP proof that failed verification, or was replayed.
	bindingProofInvalid

	// bindingNonceRequired is a proof without the current server nonce, when the chain asks for
	// one.
	bindingNonceRequired

	// bindingCertificateMismatch is a certificate-bound token on a request without its certificate,
	// or on a chain that cannot judge certificates.
	bindingCertificateMismatch

	// bindingUnknownMethod is a confirmation the chain cannot check: a member it does not know, or
	// both a key and a certificate. It is never taken for an unbound token.
	bindingUnknownMethod
)

// bindingCheck is what checkBinding found, and the verified proof to record once every other check
// the request faces has passed. proof is nil when the request presented none.
type bindingCheck struct {
	verdict bindingVerdict
	proof   *dpopProof
}

// checkBinding judges a token's binding, its confirmation cnf, against the request: a certificate
// binding against the request's certificate, a key binding against a proof over raw, and an
// unbound token against whether DPoP is required. It writes nothing and records nothing: the
// verdict is the caller's to answer, and the proof is recorded by bindingCheck.record, last, so a
// request refused for any later reason consumes none.
//
// v is the chain's DPoP verifier, nil while DPoP is off, and underDPoP says the token came under
// the DPoP scheme. A returned error is not a verdict on the token: it is a dependency that failed
// (a nonce cipher) or the request's own context ending, and goes to the chain.
func checkBinding(ex *Exchange, v *dpopVerifier, underDPoP bool, raw string, cnf map[string]string) (bindingCheck, error) {
	var known int
	binding := keyBinding{jkt: cnf[oidcConfirmationJKT], x5tS256: cnf[oidcConfirmationX5T]}

	if binding.jkt != "" {
		known++
	}
	if binding.x5tS256 != "" {
		known++
	}

	binding.other = len(cnf) > known

	var proof *dpopProof

	switch {
	case binding.x5tS256 != "" || binding.other:
		// Judged with no proof verified. Under the DPoP scheme a certificate-bound token is refused
		// for that alone, when the chain can judge certificates at all.
		if underDPoP && ex.certBinding() != nil && binding.jkt == "" && !binding.other {
			return bindingCheck{verdict: bindingKeyMismatch}, nil
		}
	default:
		var err error

		proof, err = presentedProof(ex.Context(), v, ex.Request, underDPoP, raw)
		if err != nil {
			verdict, err := proofVerdict(err)

			return bindingCheck{verdict: verdict}, err
		}
	}

	if err := admitBinding(ex, v, proof, binding); err != nil {
		return bindingCheck{verdict: admissionVerdict(err)}, nil
	}

	if len(cnf) == 0 && proof == nil {
		return bindingCheck{verdict: bindingUnbound}, nil
	}

	return bindingCheck{verdict: bindingHeld, proof: proof}, nil
}

// record records the check's proof, the last check a request presenting it faces, and reports a
// replayed proof as bindingProofInvalid. A check with no proof records nothing. A replay store that
// failed is an error, not a verdict.
func (c bindingCheck) record(ctx context.Context, v *dpopVerifier) (bindingVerdict, error) {
	if err := recordProof(ctx, v, c.proof); err != nil {
		return proofVerdict(err)
	}

	return c.verdict, nil
}

// proofVerdict reads the failure of a proof: a missing nonce, or a proof refused. Anything else is
// not a verdict on the proof, and is returned as an error, beside a refusing verdict so a caller
// that read the verdict first would still refuse.
func proofVerdict(err error) (bindingVerdict, error) {
	switch {
	case errors.Is(err, ErrDPoPNonceRequired):
		return bindingNonceRequired, nil
	case errors.Is(err, ErrInvalidDPoPProof):
		return bindingProofInvalid, nil
	default:
		return bindingProofInvalid, err
	}
}

// admissionVerdict reads admitBinding's refusal. Every refusal it returns is one of the three below;
// anything else is read as a key that does not fit, which refuses, and is never read as held.
func admissionVerdict(err error) bindingVerdict {
	switch {
	case errors.Is(err, errConfirmationNotHonoured):
		return bindingUnknownMethod
	case errors.Is(err, ErrCertificateBinding):
		return bindingCertificateMismatch
	default:
		return bindingKeyMismatch
	}
}
