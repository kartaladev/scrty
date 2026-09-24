package policy

// This file exposes what the package's tests need and consumers must not have.
// It is a test file, so nothing here reaches a production build.

// ContextWithPhase exposes the unexported phase publisher, so the tests that
// evaluate a phase-sensitive policy directly — with no engine to say the phase
// for them — can put a phase on a context exactly as Engine.EvaluatePhase does.
var ContextWithPhase = contextWithPhase
