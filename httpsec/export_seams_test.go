package httpsec

import (
	"time"

	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// This file exposes the seams other capabilities build their redemption flows
// on, so the package's own black-box tests can pin them before an interceptor
// exists to exercise them. It is a test file, so nothing here reaches a
// production build.

// ClassifyAddressForTest exposes the unexported address rule, so a test can pin
// which addresses may key a bucket and which are refused outright.
var ClassifyAddressForTest = classifyAddress

// SourceThrottledForTest exposes the throttle seam's check, so a test can pin
// what each refusal returns before any interceptor is built on it.
var SourceThrottledForTest = sourceThrottled

// RecordSourceFailureForTest exposes the throttle seam's recording, so a test
// can observe the context it hands the guard.
var RecordSourceFailureForTest = recordSourceFailure

// PostAuthenticationInputForTest exposes the input builder, so a test can pin
// which parameter lands in which field before an interceptor calls it.
var PostAuthenticationInputForTest = postAuthenticationInput

// CompleteLoginForTest exposes the login tail, so a test can pin its order
// before any first factor is built on it.
var CompleteLoginForTest = completeLogin

// LoginTailDepsForTest builds what the login tail needs, so a test assembles it
// without this package exporting the struct to consumers.
func LoginTailDepsForTest(
	engine *policy.Engine,
	sessions *session.Manager,
	tokens token.Generator,
) loginTailDeps {
	return loginTailDeps{engine: engine, sessions: sessions, tokens: tokens, enforced: everyBuiltInEnforced()}
}

// EnableGateForTest records the built-in gate for kind as enabled, exactly as
// its Enable option does, without registering the gate itself. A test whose
// policy raises kind uses it to pin what raising the kind does rather than what
// the gate does with it; it is also how the enrolment kind is counted as
// enforced before EnableMFAEnrolment exists.
func EnableGateForTest(kind policy.ChallengeKind) Option {
	return func(c *config) error {
		c.enableGate(kind)
		return nil
	}
}

// everyBuiltInEnforced is the enforcer set of a chain with every built-in
// gate enabled. The login-tail seams use it because the tests reaching the
// tail through them pin its order, not the chain's enforcer check, which
// TestUnenforcedChallengeAtRuntime pins through a whole chain.
func everyBuiltInEnforced() map[policy.ChallengeKind]bool {
	enforced := make(map[policy.ChallengeKind]bool, len(builtInEnforcers))
	for kind := range builtInEnforcers {
		enforced[kind] = true
	}

	return enforced
}

// LoginTailDepsWithEnrolmentForTest is LoginTailDepsForTest with the lifetime
// an enrolment challenge marks the session for, which the chain otherwise
// hands every login tail at assembly.
func LoginTailDepsWithEnrolmentForTest(
	engine *policy.Engine,
	sessions *session.Manager,
	tokens token.Generator,
	enrolmentLifetime time.Duration,
) loginTailDeps {
	return loginTailDeps{
		engine: engine, sessions: sessions, tokens: tokens,
		enrolmentLifetime: enrolmentLifetime, enforced: everyBuiltInEnforced(),
	}
}
