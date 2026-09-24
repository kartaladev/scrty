package httpsec

import (
	"errors"
	"fmt"

	"github.com/kartaladev/scrty/authorize"
)

//go:generate mockgen -destination=authorizer_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/authorize Authorizer

// authorization is the chain's authorization stage.
//
// It is registered for every chain, with or without rules, because its first
// job is to publish the authorizer that the per-endpoint guards behind it read.
// Its second job — enforcing the centralized rule set — is the one the consumer
// switches on by giving rules.
type authorization struct {
	// authorizer is what the guards downstream judge by, and nil when the
	// consumer enabled no authorization at all. Nothing is published then, so a
	// guard finds no judge and fails closed rather than judging by nothing.
	authorizer authorize.Authorizer

	// rules is the centralized set, and nil when the consumer gave none. An
	// empty set is not the same as a permitting one: it says authorization
	// belongs at the operations, and the guards there still decide.
	rules *authorize.Rules[Request]
}

// Intercept publishes the authorizer and applies the centralized rules.
//
// The stage always runs, even with no rules: a per-endpoint guard reads the
// authorizer from the request context, and a guard that finds none fails
// closed. Publishing it here means a consumer wires the authorizer once, and
// every guard behind the chain judges by the same one.
func (a *authorization) Intercept(ex *Exchange, next Next) error {
	if a.authorizer != nil {
		ex.SetContext(authorize.WithAuthorizer(ex.Context(), a.authorizer))
	}

	if a.rules == nil {
		return next(ex)
	}

	if err := a.rules.Evaluate(ex.Context(), ex.Request); err != nil {
		if errors.Is(err, authorize.ErrAuthenticationRequired) {
			return authenticationRequired(err)
		}

		// Returned as it came. A rule's requirement answers with a denial, with
		// a demand to authenticate, or with the outage it hit, and rewriting any
		// of those here would turn a store that was unreachable into a decision
		// about the caller.
		return err
	}

	return next(ex)
}

// authenticationRequired refuses a request that has not said who it is.
//
// The refusal matches both this package's sentinel and the authorization
// core's, so a consumer who matches either identity reaches it and does not
// have to know whether the chain's stage or a per-endpoint guard refused. cause
// is the core's own error where one was produced, so the message it carries
// survives; with none, the core sentinel stands in for it.
func authenticationRequired(cause error) error {
	if cause == nil {
		cause = authorize.ErrAuthenticationRequired
	}

	return fmt.Errorf("%w: %w", ErrAuthenticationRequired, cause)
}
