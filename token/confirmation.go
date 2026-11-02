package token

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/identity"
)

// ConfirmingGenerator is a Generator that can bind the token it issues to a
// key the client holds. It is optional: Generator keeps its one method, so a
// consumer generator that never binds is unaffected. A component that must
// issue bound tokens, such as an HTTP chain with DPoP enabled, refuses at
// construction a generator that does not implement it, rather than issue a
// token unbound.
//
// The generator NewGenerator returns implements it.
type ConfirmingGenerator interface {
	Generator

	// GenerateWith is Generate with per-token options. With no options it
	// issues exactly what Generate issues. An option it cannot honour fails
	// it, and nothing is issued.
	GenerateWith(ctx context.Context, id string, p *identity.Principal, opts ...IssueOption) (string, error)
}

// The built-in generator binds.
var _ ConfirmingGenerator = (*JWTGenerator)(nil)

// Confirmation is the RFC 7800 confirmation claim, cnf, of a sender-constrained
// token: the key the legitimate client holds, named by its thumbprint.
//
// A token carries at most one binding. JKT is an RFC 9449 DPoP binding, the
// base64url RFC 7638 SHA-256 thumbprint of the client's public key. X5TS256 is
// an RFC 8705 certificate binding, the base64url SHA-256 digest of the client
// certificate's DER encoding. Both are 43 characters of unpadded base64url.
//
// The zero value is no binding: a token issued with it carries no cnf claim.
type Confirmation struct {
	// JKT is the cnf "jkt" member.
	JKT string

	// X5TS256 is the cnf "x5t#S256" member.
	X5TS256 string

	// Other names the cnf members a verified token carries besides jkt and
	// x5t#S256, sorted, so a caller can refuse a binding it cannot honour
	// instead of mistaking it for no binding at all. It is only ever set by
	// verification: issuing a token with it set fails with ErrConfig, because
	// this package never mints a member it cannot check.
	Other []string
}

// IssueOption configures one Generate call. It is distinct from Option, which
// configures the Generator itself, because what it carries belongs to one
// token rather than to every token the generator issues.
type IssueOption func(*issue)

// issue is the per-token state IssueOptions set.
type issue struct {
	cnf Confirmation
}

// WithConfirmation binds the issued token to a key the client holds, by
// carrying c as its cnf claim. Default: no binding, and no cnf claim.
//
// Generate fails with ErrConfig, and issues nothing, when c names both a DPoP
// key and a certificate, when either thumbprint is not 43 characters of
// unpadded base64url, and when c carries Other members. The zero value is no
// binding and is accepted.
func WithConfirmation(c Confirmation) IssueOption {
	return func(i *issue) { i.cnf = c }
}

// The cnf claim and the two members this package issues and checks.
const (
	confirmationClaim = "cnf"
	memberJKT         = "jkt"
	memberX5TS256     = "x5t#S256"
)

// thumbprintLength is the length of an unpadded base64url SHA-256 digest.
const thumbprintLength = 43

// IsZero reports whether c is no binding at all.
func (c Confirmation) IsZero() bool {
	return c.JKT == "" && c.X5TS256 == "" && len(c.Other) == 0
}

// claim renders c as the cnf claim this package issues, or reports why it
// cannot: it carries both bindings, a malformed thumbprint, or a member this
// package does not check. It returns nil for no binding.
func (c Confirmation) claim() (map[string]any, error) {
	switch {
	case len(c.Other) > 0:
		return nil, fmt.Errorf("%w: a confirmation carries only jkt or x5t#S256", ErrConfig)
	case c.JKT != "" && c.X5TS256 != "":
		return nil, fmt.Errorf("%w: a token is bound to one key, not to a DPoP key and a certificate", ErrConfig)
	case c.JKT != "":
		if !WellFormedThumbprint(c.JKT) {
			return nil, fmt.Errorf("%w: the jkt confirmation is not a base64url SHA-256 thumbprint", ErrConfig)
		}

		return map[string]any{memberJKT: c.JKT}, nil
	case c.X5TS256 != "":
		if !WellFormedThumbprint(c.X5TS256) {
			return nil, fmt.Errorf("%w: the x5t#S256 confirmation is not a base64url SHA-256 thumbprint", ErrConfig)
		}

		return map[string]any{memberX5TS256: c.X5TS256}, nil
	default:
		return nil, nil
	}
}

// errMalformedConfirmation is the cause every refused cnf claim wraps. The
// claim's value is never rendered: it is the presenter's input.
var errMalformedConfirmation = errors.New("malformed cnf claim")

// readConfirmation reads the cnf claim of a verified token. A token without
// one has no binding. A cnf that is not an object, is empty, or carries a jkt
// or x5t#S256 that is not a well-formed thumbprint is refused. Any other
// member is named in Other rather than dropped, so a caller that cannot honour
// it refuses the token instead of mistaking it for an unbound one.
func readConfirmation(value any, present bool) (Confirmation, error) {
	if !present {
		return Confirmation{}, nil
	}

	members, ok := value.(map[string]any)
	if !ok || len(members) == 0 {
		return Confirmation{}, errMalformedConfirmation
	}

	var cnf Confirmation
	for name, member := range members {
		switch name {
		case memberJKT, memberX5TS256:
			thumb, isString := member.(string)
			if !isString || !WellFormedThumbprint(thumb) {
				return Confirmation{}, errMalformedConfirmation
			}
			if name == memberJKT {
				cnf.JKT = thumb
			} else {
				cnf.X5TS256 = thumb
			}
		default:
			cnf.Other = append(cnf.Other, name)
		}
	}
	slices.Sort(cnf.Other)

	return cnf, nil
}

// WellFormedThumbprint reports whether s is an unpadded base64url SHA-256
// digest, the form both confirmation members take: 43 characters of the
// base64url alphabet, the last of which leaves no stray bits.
func WellFormedThumbprint(s string) bool {
	if len(s) != thumbprintLength || !base64URL(s) {
		return false
	}

	// 43 characters carry 258 bits for a 256-bit digest, so the low two bits
	// of the last character's value are zero in the one canonical encoding.
	return base64URLValue(s[thumbprintLength-1])&0b11 == 0
}

// base64URLValue is the six-bit value of one base64url character, which the
// caller has already checked is one.
func base64URLValue(c byte) byte {
	switch {
	case c >= 'A' && c <= 'Z':
		return c - 'A'
	case c >= 'a' && c <= 'z':
		return c - 'a' + 26
	case c >= '0' && c <= '9':
		return c - '0' + 52
	case c == '-':
		return 62
	default:
		return 63
	}
}

// NewClaimsWithConfirmation is NewClaims for a token that carries a
// confirmation claim, so a consumer's own Verifier can report a binding the
// chain then enforces. A bound token reported through NewClaims instead reads
// as unbound. The caller vouches for the claim as it does for the rest.
func NewClaimsWithConfirmation(subject, id string, cnf Confirmation) *Claims {
	return &Claims{subject: subject, id: id, cnf: cnf}
}

// Confirmation reports the token's confirmation claim. It is the zero value
// when the token carries no cnf claim, and on the zero Claims.
func (c *Claims) Confirmation() Confirmation {
	if c == nil {
		return Confirmation{}
	}

	return Confirmation{JKT: c.cnf.JKT, X5TS256: c.cnf.X5TS256, Other: slices.Clone(c.cnf.Other)}
}
