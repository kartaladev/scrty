// Package assurance holds the library's proof that a login met its second
// factor at the first.
//
// The package is internal, so only packages of the core module can mint a
// proof that holds. Outside the module the type can be named through
// policy.SecondFactorProof and copied, but a holding value can only come from
// the library itself.
package assurance

import (
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
