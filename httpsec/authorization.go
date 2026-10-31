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

// EnableAuthorization judges requests through az, applying rules centrally.
//
// Default: without this option the chain still runs its authorization stage,
// but publishes no authorizer and enforces nothing, so every per-endpoint
// guard behind it fails closed. With it and no rules, the authorizer reaches
// the route and the guards there decide alone.
//
// The rules are an ordered set: the first whose matcher accepts the request
// decides, and a request no rule matches is denied, so an endpoint added
// without a rule is closed rather than open. A consumer opts out of that
// default with a trailing rule that matches everything and requires
// authorize.PermitAll — one line, visible where the rules are read.
//
// Calling it more than once appends: the rules of every call form one set in
// the order the calls were made, so wiring split across modules still reads top
// to bottom. The authorizer of the last call is the one the chain judges by,
// because a chain has one authorizer and a second call is the consumer
// replacing their first choice rather than adding a second judge.
//
// A matcher sees the whole Request — path, method, headers — through the same
// abstraction every interceptor reads, so one rule set is written once and
// applies behind whichever framework the chain is mounted on.
func EnableAuthorization(az authorize.Authorizer, rules ...authorize.Rule[Request]) Option {
	const option = "EnableAuthorization"

	return func(c *config) error {
		c.authorizer = az
		c.authzRules = append(c.authzRules, rules...)

		c.enable(option, func() error {
			return requireDep(option, "authorizer", c.authorizer)
		})

		return nil
	}
}
