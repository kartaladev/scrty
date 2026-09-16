# Rule: A defect claim needs a failing test as proof

**Any claim that code has an error or defect must be reproduced with a failing test case.** This
covers bugs, security flaws, races, leaks and "this input breaks it". An argument, a code reading or
a plausible attack sequence is a hypothesis, not a defect, until a test fails because of it.

This applies to claims about scrty's own code, the legacy reference, and dependencies. It applies
whether the claim is made by a person, by Claude, or by a subagent.

## What counts as proof

A test that:

1. **Fails** on the code as it is, and the failure message shows the defect: the wrong value,
   the unexpected access, the race report, the panic.
2. **Fails for the claimed reason**, not because of a compile error, a missing fixture or a
   misconfigured environment. Read the failure output and confirm it.
3. **Passes** when the defect is removed. A one-line fix, or reverting to the correct behaviour in a
   disposable copy, is enough to show the test targets the defect and nothing else.
4. Is **minimal**. It exercises the defect directly, with the smallest setup, and names the behaviour
   it proves (`TestBearer_RefusesTokenWhenUsernameReassigned`).

Record for each claim: the test name, the command that ran it, and the relevant lines of failing
output. Keep the test with the change that fixes the defect. It becomes the red step of that
change's test-first loop (see `golang-tdd.md`).

## How to reproduce against the legacy reference

The snapshot in `.claude/.legacy/` is read-only and does not compile on its own (see
`legacy-reference.md`). To reproduce a defect in the predecessor:

- Use a **disposable full export** of the predecessor repository, outside the project, for example in
  the session scratchpad:

  ```sh
  git -C <path-to-predecessor-repo> archive 3dc0f80 | tar -x -C <scratch>/repro/golang-lib
  ```

- Add the failing test inside that export and run it there, e.g.
  `go test -run TestX -count=1 ./security/v2/httpsec/`.
- **Never** edit the predecessor's own repository, never edit `.claude/.legacy/`, and never add
  reproduction code to scrty's tree unless it is the red test of a change being implemented.
- Tests that need PostgreSQL use the predecessor's own testcontainers helpers, which need Docker.
  If Docker is unavailable, say so, and classify the claim as unreproduced.

## Claims that cannot be reproduced yet

Some claims concern behaviour that has no code yet, such as a drafted spec or design, or need an
environment that is unavailable. They stay labelled **unreproduced**:

- In reports and reviews, mark each claim `REPRODUCED` (with test name and output) or
  `UNREPRODUCED` (with the reason: no code yet, needs Docker, needs a third-party service).
- A design departure justified by a defect records either the reproducing test, or
  "pending reproduction" plus the scenario that will become the first failing test. An unreproduced
  defect must not be presented as established fact.
- When implementation starts, the first task for that departure is to write the test and watch it
  fail. If it passes instead, the claim was wrong: remove the departure and restore the reference
  behaviour.

## Never

- Call something a bug, vulnerability or defect in an artifact, commit or report without either a
  failing test or an explicit `UNREPRODUCED` label.
- Weaken a test until it fails, or assert an implementation detail, just to "prove" a claim.
- Count a test that has never been seen to fail as proof.
