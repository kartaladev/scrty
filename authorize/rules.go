package authorize

import (
	"context"
	"fmt"
	"slices"
)

// Rule pairs a matcher over the consumer's own request type with the
// requirement that decides the requests it matches.
//
// Both halves are the consumer's. Match sees a whole request of type R and
// answers from whatever it carries — a path, a method, a queue name, a command
// verb — and Require decides from the context alone. Nothing in this package
// looks inside R, which is what lets one rule set guard an HTTP API, a message
// consumer or a command-line tool without any of them being named here.
type Rule[R any] struct {
	// Match reports whether this rule is the one that decides request. It is
	// called with each request until one rule answers true.
	Match func(request R) bool

	// Require decides the requests Match accepts.
	Require Requirement
}

// Rules is an ordered set of rules over one request type: the authorization
// decisions a consumer wants made in one place rather than restated at each
// operation.
//
// R is unconstrained on purpose. Constraining it — to something carrying a
// path, say — would put an assumption about the transport into a package that
// decides about callers, and would oblige every consumer's request type to
// grow a method this package named. Everything a rule needs to know about a
// request is asked through the consumer's own Match, which closes over
// whatever matching means to them; a package that instantiates Rules with its
// own request type and its own path matcher gets both without this package
// learning what a path is.
//
// A non-empty set denies what no rule matched. An operation added without a
// rule is then closed rather than open, which is the failure that is noticed
// in a test instead of in an incident. The override is a trailing rule that
// matches everything and requires PermitAll: one line, visible where the rules
// are read, chosen rather than inherited.
//
// An empty set makes no centralized decision at all and every request is left
// to whatever guards the operation it reaches. That is not the same as
// permitting: it is the consumer saying authorization belongs at the
// operations, and it is why an empty set is a configuration rather than a
// mistake.
type Rules[R any] struct {
	rules []Rule[R]
}

// NewRules returns a rule set evaluated in the order given.
//
// A rule missing either half is refused here. A rule with no matcher can never
// fire, and one with no requirement decides nothing when it does, so in both
// cases the consumer wrote a rule that does not do what reading it suggests —
// and the operations it was meant to cover fall through to whatever follows.
// Catching that at construction costs an error at startup; not catching it
// costs a rule that silently is not there.
//
// No rules at all is accepted, and means no centralized decision is made.
//
// The set holds its own copy of the slice, so a caller that reuses the slice it
// passed cannot substitute a rule after it was checked.
func NewRules[R any](rules ...Rule[R]) (*Rules[R], error) {
	for i, r := range rules {
		if r.Match == nil {
			return nil, fmt.Errorf("%w: rule %d has no matcher, so it can never fire", ErrConfig, i)
		}

		if r.Require == nil {
			return nil, fmt.Errorf("%w: rule %d has no requirement, so a match decides nothing",
				ErrConfig, i)
		}
	}

	return &Rules[R]{rules: slices.Clone(rules)}, nil
}

// Evaluate decides request by the first rule that matches it.
//
// The deciding requirement's answer is returned unchanged, so an anonymous
// caller is still told to authenticate and an outage inside a requirement is
// still an outage. Later rules are not consulted once one has matched: a rule
// set is read top to bottom, and a reader who sees the first matching line has
// seen the decision.
func (r *Rules[R]) Evaluate(ctx context.Context, request R) error {
	for _, rule := range r.rules {
		if rule.Match(request) {
			return rule.Require(ctx)
		}
	}

	if len(r.rules) == 0 {
		return nil
	}

	return fmt.Errorf("%w: no rule covers this request", ErrAccessDenied)
}
