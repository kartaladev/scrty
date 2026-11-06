# Rule: Code defensively — assume everything that can go wrong will

scrty follows **Murphy's Law**: any failure that can happen will happen, in production, at the worst
moment. Planning, implementation and review therefore start from the question "how does this
fail?", not "does this work?". Every relevant failure is named, and each one is either handled,
tested, or explicitly accepted with a reason.

This applies to code, specs, designs, plans and reviews, whoever writes them: the main session,
a subagent, or a person.

## What counts as a failure to consider

Look for failures in every category the change touches. At minimum:

- **Input**: empty, nil, zero, negative, oversized, malformed, duplicated, out of order, wrong
  encoding, hostile.
- **Dependencies**: the store, network, clock, key source or third-party service is slow, down,
  returns an error, returns a partial or stale result, or returns something that violates its own
  contract.
- **Concurrency**: two callers race on the same record; a retry overlaps the original; a context is
  cancelled mid-operation; a goroutine outlives its caller.
- **State**: a crash or error between two writes leaves state half-applied; a one-time value is
  consumed twice or never; a cache disagrees with its source.
- **Time**: clock skew, expiry exactly at the boundary, a timer that never fires, a deadline that
  already passed.
- **Resources**: exhaustion of memory, connections, file descriptors or rate budget; leaks on the
  error path.
- **Configuration and wiring**: a missing, contradictory or default-but-wrong option; a consumer
  replacing a default with something that breaks a documented guarantee.
- **Security**: an attacker who controls any input, replays any message, or times any response
  (`golang-security`).
- **Observability**: the failure happens and nobody can tell — a swallowed error, a log that leaks
  a secret, a metric that hides the cause.

"Relevant" is the limit. A failure belongs on the list when the change's code, data or callers can
actually reach it. Do not pad the list with failures the change cannot cause or observe.

## What each failure needs

Every listed failure ends in exactly one of three states:

1. **Handled** — the code detects it and responds with a defined outcome: a typed or sentinel error,
   a safe refusal, a retry with a bound, a rollback. The safe outcome is the default
   (`library-design.md`): when unsure, refuse rather than proceed. Wiring mistakes fail at
   construction, not at first use.
2. **Tested** — a handled failure that changes an observable outcome has a test that provokes it
   and asserts the outcome. It is written test-first (`golang-tdd.md`): the red step shows the
   failure unhandled, the green step shows it handled.
3. **Accepted** — a failure deliberately left unhandled is stated in `design.md` with the reason
   (cost, impossibility, out of scope) and what the consumer sees when it happens. Silence is not
   acceptance.

## In planning

- `design.md` carries a **failure modes** section for every decision that introduces or changes
  behaviour: each relevant failure, its state (handled, tested, accepted) and the outcome a caller
  sees.
- Specs include scenarios for the failures the library promises to handle, not only the happy path.
- `tasks.md` and `plans.md` give each handled failure its own test task, so it cannot be dropped as
  "edge case, later".
- A failure that needs a choice the design has not made — refuse or degrade, retry or surface — is a
  design decision. Research it and put it to the user (`research-and-references.md`).

## In implementation

- Check every error. Wrap it with context, or handle it; never discard it silently.
- Validate at the boundary: public API parameters, consumer-supplied ports, decoded input. Inside
  the package, trust what was validated.
- Bound everything that can grow or wait: sizes, retries, timeouts, queue lengths.
- Make partial failure impossible or recoverable: transactions, conditional writes, idempotent
  operations, cleanup on every exit path.
- Follow `golang-safety` for nil, aliasing, numeric conversion and resource lifecycle, and
  `golang-concurrency` for anything shared across goroutines.

## In review

- The reviewer's first job is to **enumerate how the change fails**, category by category, and check
  each failure against the three states. A failure with no state is a finding.
- A claimed defect still needs a failing test or the `UNREPRODUCED` label (`defect-claims.md`). An
  anticipated failure that is unhandled is reported as a **gap**, with the scenario that will become
  its first failing test — not as a proven defect.
- Every delegation prompt for implementation or review states this rule as binding
  (`subagent-delegation.md`).

## Never

- Assume a dependency, input or caller behaves because it usually does.
- Swallow an error, or turn one into a zero value, without a stated reason.
- Leave an anticipated failure unhandled and undocumented.
- Write a test that only covers the happy path of code with reachable failure modes.
- Call an anticipated failure a defect without the proof `defect-claims.md` requires.
- Handle a failure by degrading a guarantee silently; refuse, or document the line
  (`library-design.md`).
