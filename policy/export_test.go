package policy

import "github.com/kartaladev/scrty/internal/assurance"

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

// MintProofForTest mints a second-factor proof, which only library code can do.
// The policy tests need one that holds to show both MFA policies honour it,
// and a test file of the package is the one place outside the passkey
// verification that may.
var MintProofForTest = assurance.New

// MintFederatedForTest mints federated assurance evidence, which only library
// code can do. The policy tests need evidence that asserts something to show
// the MFA policies hand it to the assurance source, and a test file of the
// package is the one place outside the OIDC redemption and the per-request
// evaluation that may.
var MintFederatedForTest = assurance.NewFederated

// FederatedMetForTest exposes the one rule both MFA policies decide federated
// assurance by, so its refusals to ask the source can be pinned directly.
var FederatedMetForTest = federatedMet
