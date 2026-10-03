// Package assurance holds the library's proof that a login met its second
// factor at the first, and the evidence of the assurance a federated provider
// asserted for a login.
//
// The package is internal, so only packages of the core module can mint a
// proof that holds, or evidence that asserts anything. Outside the module the
// types can be named through policy.SecondFactorProof and
// policy.FederatedAssurance and copied, but a holding or asserting value can
// only come from the library itself.
package assurance

import (
	"slices"
	"time"

	"github.com/kartaladev/scrty/factor"
)

// Proof records that a login's second factor was met at its first factor, by
// a factor of the given kind at the given instant.
//
// The zero value proves nothing.
type Proof struct {
	kind factor.Kind
	at   time.Time
}

// New returns a proof that a factor of kind met the second factor at at.
//
// An empty kind or a zero instant returns the zero Proof, which holds nothing:
// a proof that cannot say what met the factor or when is no proof.
func New(kind factor.Kind, at time.Time) Proof {
	if kind == "" || at.IsZero() {
		return Proof{}
	}

	return Proof{kind: kind, at: at}
}

// Holds reports whether p proves anything.
func (p Proof) Holds() bool {
	return p.kind != "" && !p.at.IsZero()
}

// Kind is the first-factor kind that met the second factor, or empty for a
// proof that does not hold.
func (p Proof) Kind() factor.Kind { return p.kind }

// At is when the second factor was met, or the zero time for a proof that
// does not hold.
func (p Proof) At() time.Time { return p.at }

// Federated is evidence of the assurance an OpenID Connect provider asserted
// for a login: the provider's registered name, the verified issuer, and the
// authentication methods (amr) and context class (acr) the provider's verified
// ID token named.
//
// It is evidence, not a verdict. Whether it meets a user's requirement is
// decided by matching it against the provider's current configuration, every
// time it is asked.
//
// The zero value asserts nothing. A value is immutable: its amr is copied in
// and copied out, so neither the minter nor a reader can change it.
type Federated struct {
	provider string
	issuer   string
	amr      []string
	acr      string
}

// NewFederated returns the evidence that provider, whose ID token was issued
// by issuer, asserted amr and acr for a login.
//
// An empty provider returns the zero Federated, which asserts nothing: evidence
// that cannot say where it came from cannot be matched against anything. An
// empty amr or acr is kept as "not asserted", which is still evidence of the
// provider, so it can be matched and found wanting.
func NewFederated(provider, issuer string, amr []string, acr string) Federated {
	if provider == "" {
		return Federated{}
	}

	return Federated{provider: provider, issuer: issuer, amr: slices.Clone(amr), acr: acr}
}

// Asserted reports whether f is evidence of anything: whether a provider minted
// it at all.
func (f Federated) Asserted() bool { return f.provider != "" }

// Provider is the registered name of the provider, or empty for evidence that
// asserts nothing.
func (f Federated) Provider() string { return f.provider }

// Issuer is the issuer of the verified ID token.
func (f Federated) Issuer() string { return f.issuer }

// AMR is a copy of the authentication methods the provider asserted, in the
// order it asserted them; empty when it asserted none.
func (f Federated) AMR() []string { return slices.Clone(f.amr) }

// ACR is the authentication context class the provider asserted, or empty when
// it asserted none.
func (f Federated) ACR() string { return f.acr }
