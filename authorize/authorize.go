package authorize

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// The errors this package returns, which callers identify with errors.Is.
//
// Three of them are decisions and one is a wiring mistake, and keeping them
// apart is what lets a manager run several authorizers over one request:
// ErrUnsupportedAttributes says "not my kind of question" and is skipped, while
// ErrInvalidAttributes and ErrAccessDenied are answers and stop the chain.
var (
	// ErrConfig is wrapped by every error a constructor in this package returns
	// for a wiring mistake, so a consumer recognises "I assembled this wrongly"
	// without naming each check in turn.
	ErrConfig = errors.New("authorize: invalid configuration")

	// ErrUnsupportedAttributes reports that an authorizer was handed a shape of
	// attributes it does not judge. It is a declination rather than a refusal:
	// the manager passes over the authorizer that returns it and asks the next
	// one, so an authorizer that returned a denial here would answer a question
	// it was never meant to answer.
	ErrUnsupportedAttributes = errors.New("authorize: unsupported attributes")

	// ErrInvalidAttributes reports attributes of a recognised shape whose
	// content cannot be used — a privilege check naming no privileges, for
	// instance. It is deliberately not a declination: attributes that are merely
	// malformed would otherwise fall through to an authorizer that was never
	// meant to judge them, and an empty requirement would read as "nothing is
	// required" rather than as the mistake it is.
	ErrInvalidAttributes = errors.New("authorize: invalid attributes")

	// ErrAccessDenied reports that the caller may not do what they asked to do.
	// It is the answer to every question this package cannot answer positively,
	// including the questions nobody was configured to answer.
	ErrAccessDenied = errors.New("authorize: access denied")

	// ErrAuthenticationRequired reports that a requirement needed a principal
	// and the request carried none. It is distinct from ErrAccessDenied because
	// the two call for different responses: an anonymous caller is asked to
	// authenticate and may then succeed, while a known caller who is refused
	// gains nothing by authenticating again.
	ErrAuthenticationRequired = errors.New("authorize: authentication required")
)

// Attributes describe one attempt for an Authorizer to judge.
//
// It is an empty interface because the set of things a consumer may want
// authorized is theirs, not this package's: PrivilegeAttributes and
// OwnershipAttributes ship here, and a consumer adds a kind of their own by
// writing an Authorizer that recognises it and declines everything else. It is
// a named type rather than a plain any so that the contract has somewhere to be
// written down and so that a signature says what it carries.
type Attributes any

// Authorizer judges one kind of attributes.
//
// An implementation handed attributes of a kind it does not judge returns an
// error matching ErrUnsupportedAttributes and does nothing else — no logging
// decision, no partial check — because a FirstOf will offer the same attributes
// to the next authorizer and the answer must come from exactly one of them.
//
// The subject is read from ctx with identity.PrincipalFromContext rather than
// being passed as an argument, so that the one place a request's caller is
// recorded is the place every authorizer reads it from. An implementation that
// finds no principal decides without one; it never panics, because a request
// that reached authorization anonymously is a normal condition and not a
// wiring mistake.
//
//go:generate mockgen -destination=authorizer_mock_test.go -package=authorize_test -typed github.com/kartaladev/scrty/authorize Authorizer
type Authorizer interface {
	Authorize(ctx context.Context, attrs Attributes) error
}

// MatchMode says how many of the required privileges must be granted.
type MatchMode uint8

// The privilege matching modes.
//
// MatchAllOf is the zero value on purpose: attributes built without naming a
// mode then demand every privilege they list, so a forgotten field narrows what
// a caller may do rather than widening it. The two modes are identical when a
// single privilege is required, which is the common case, and differ only where
// forgetting the field would otherwise have handed out more than was meant.
const (
	MatchAllOf MatchMode = iota
	MatchAnyOf
)

// String returns the constant's own name, so a log or an error message names
// the mode rather than printing a number a reader has to look up.
func (m MatchMode) String() string {
	switch m {
	case MatchAllOf:
		return "all-of"
	case MatchAnyOf:
		return "any-of"
	default:
		return "unknown"
	}
}

// PrivilegeAttributes ask whether the subject's active role grants named
// privileges on one resource.
//
// Group and Resource name the resource as the consumer's own role data names
// it; this package compares them and never parses them. Required lists the
// privilege names the attempt needs, and an empty list is refused as invalid
// rather than read as "nothing is required".
type PrivilegeAttributes struct {
	// Group is the resource group, as the consumer's role data spells it.
	Group string

	// Resource is the resource within the group, as the consumer's role data
	// spells it.
	Resource string

	// Required lists the privilege names this attempt needs. It must name at
	// least one; attributes requiring nothing are invalid, because a check that
	// requires nothing allows everything while looking like a check.
	Required []string

	// Mode says whether every required privilege must be granted or only one of
	// them. The zero value demands every one.
	Mode MatchMode
}

// OwnershipAttributes ask whether the subject owns the record being acted on.
//
// Both functions belong to the consumer: only they know how to find the record
// a request names and what owning it means in their data. This package calls
// them in order, passes the identifier between them without interpreting it,
// and reports their errors as outages rather than as decisions about the
// caller.
type OwnershipAttributes struct {
	// Group is the resource group, carried for the consumer's own functions and
	// for error messages. It is required so that an ownership check names what
	// it was checking when it fails.
	Group string

	// Resource is the resource within the group, carried for the same reason.
	Resource string

	// ResolveID finds the identifier of the record the request is about, from
	// whatever the consumer put in ctx. Returning an error means the record
	// could not be identified, which is an outage on the authorization path and
	// never a judgement about the caller.
	ResolveID func(ctx context.Context) (string, error)

	// OwnedBy reports whether subject owns the record with this identifier. The
	// identifier arrives exactly as ResolveID produced it.
	OwnedBy func(ctx context.Context, subject *identity.Principal, id string) (bool, error)
}

// authorizerContextKey is unexported, so nothing outside this package can
// attach or replace the authorizer a context carries. A request that could be
// handed its own authorizer from outside could be handed a permissive one.
type authorizerContextKey struct{}

// WithAuthorizer returns a copy of ctx carrying a.
//
// A consumer's middleware calls it once per request, and HasPrivilege then
// reaches the same decision the rest of the application reaches, rather than
// each guard being wired with an authorizer of its own.
func WithAuthorizer(ctx context.Context, a Authorizer) context.Context {
	return context.WithValue(ctx, authorizerContextKey{}, a)
}

// AuthorizerFromContext returns the authorizer ctx carries, reporting whether
// one was present.
//
// It reports false for a context carrying an absent authorizer, including an
// interface holding a nil pointer, so a caller that checks ok never calls
// through a value that would panic.
func AuthorizerFromContext(ctx context.Context) (Authorizer, bool) {
	a, ok := ctx.Value(authorizerContextKey{}).(Authorizer)

	return a, ok && !nilcheck.IsNil(a)
}

// FirstOf runs authorizers in the order it was given them and lets the first
// one that does not decline decide.
//
// It is itself an Authorizer, so a consumer puts one in the request context
// with WithAuthorizer and every guard downstream reaches the same decision
// rather than being wired with an authorizer of its own.
//
// When every authorizer declines, the manager denies. That is the whole reason
// the declination is a distinct error: an attempt nobody was configured to
// judge is one the consumer never described, and allowing it would turn a gap
// in the wiring into an open door.
type FirstOf struct {
	authorizers []Authorizer
}

var _ Authorizer = (*FirstOf)(nil)

// NewFirstOf returns a manager over authorizers, consulted in the order given.
//
// It refuses a call with no authorizers, and one with any absent authorizer,
// including an interface holding a nil pointer. Neither is filtered out
// quietly: a manager that skipped an absent authorizer would run fewer checks
// than the consumer wrote, and the missing one is exactly the check a wiring
// mistake removes. Failing here costs a constructor error; filtering costs a
// decision nobody made, on every request, for as long as it goes unnoticed.
//
// The manager holds its own copy of the slice, so a caller that reuses the
// slice it passed cannot swap an authorizer out from under a built manager.
func NewFirstOf(authorizers ...Authorizer) (*FirstOf, error) {
	if len(authorizers) == 0 {
		return nil, fmt.Errorf("%w: a manager with no authorizers denies everything", ErrConfig)
	}

	for i, a := range authorizers {
		if nilcheck.IsNil(a) {
			return nil, fmt.Errorf("%w: authorizer %d is absent", ErrConfig, i)
		}
	}

	return &FirstOf{authorizers: slices.Clone(authorizers)}, nil
}

// Authorize offers attrs to each authorizer in turn and returns the first
// answer that is not a declination, unchanged.
//
// An authorizer's error is returned as it came, so an outage inside a
// consumer's own authorizer still matches its cause and is never rewritten as a
// decision about the caller. Only the case where every authorizer declined
// produces an error of this package's own, and that error is a denial.
func (m *FirstOf) Authorize(ctx context.Context, attrs Attributes) error {
	for _, a := range m.authorizers {
		err := a.Authorize(ctx, attrs)
		if errors.Is(err, ErrUnsupportedAttributes) {
			continue
		}

		return err
	}

	return fmt.Errorf("%w: no authorizer judges attributes of type %T", ErrAccessDenied, attrs)
}
