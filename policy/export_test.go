package policy

// This file exposes what the package's tests need and consumers must not have.
// It is a test file, so nothing here reaches a production build.

// ContextWithPhase exposes the unexported phase publisher, so the tests that
// evaluate a phase-sensitive policy directly — with no engine to say the phase
// for them — can put a phase on a context exactly as Engine.EvaluatePhase does.
var ContextWithPhase = contextWithPhase

// DefaultEnrolmentFirstFactors exposes the enrolment path's default allowlist,
// so a test can pin it as an exact set: a kind added to it silently would widen
// who may bind a second factor, and a behavioural test only sees the kinds it
// thinks to ask about.
var DefaultEnrolmentFirstFactors = defaultEnrolmentFirstFactors
