package httpsec

import (
	"github.com/kartaladev/scrty/pkg/logsample"
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

// LogSampledForTest exposes the sampled writer, so a test can pin the window
// without driving a refusal through a whole interceptor.
var LogSampledForTest = logSampled

// SamplerForTest exposes the chain's own sampler, so a test can put records
// through exactly the one FlushRefusalLogs drains.
func SamplerForTest(c *Chain) *logsample.Sampler { return c.sampler }

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
	return loginTailDeps{engine: engine, sessions: sessions, tokens: tokens}
}
