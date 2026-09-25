# Rule: Delegate code writing to subagents, and run them in parallel

The main session plans, decides and verifies. **It does not write code.** Every task whose output is
a change to a file goes to a subagent, which returns a *report* — not a transcript, not file dumps.
That is the point: the session's context stays free for the decisions only the main session can
make, instead of filling with the contents of files it merely edited.

Wherever two tasks do not contend, they run **at the same time**.

## What is delegated

Every task whose output is a change to:

- `*.go` source and test files;
- `go.mod`, `go.sum`, `go.work`, `.golangci.yml`, `Makefile` targets, `*.proto`, generated stubs.

## What the main session keeps

- **Everything under `openspec/`**: `proposal.md`, `design.md`, `specs/`, `tasks.md`, `plans.md`.
  These are not a record of the work, they are where the decisions are made and stated, and
  deciding is the main session's job. It is also the session that holds the conversation the
  decisions came out of — what the user chose, what was rejected and why, what a measurement
  actually showed. An agent writing them reconstructs that from a prompt, and reconstructs it
  wrong. `/superpowers:writing-plans` is therefore invoked by the main session too, as
  `tasks-plans.md` requires.
- Reading, searching and navigating the codebase to understand it.
- Design decisions, and the questions put to the user.
- Choosing how the work splits, and which agents run against which files.
- Reviewing what comes back; running the verification commands (`go test`, `go vet`, `gofmt -l`,
  benchmarks) and weighing their output. That output is small and is the evidence the main session
  must judge, so it is never delegated.
- Git: staging, committing, branching.

An agent may be asked to *read* the OpenSpec artifacts for the change it is implementing, and to
report where the code and the artifacts disagree. It never edits them — it reports, and the main
session writes.

The only edit the main session may make itself is a correction of a few lines to work a subagent has
already returned, where dispatching another agent would cost more than the fix. Say so when it
happens; it is not a licence to take the task back.

## How to parallelize

1. **Split by file ownership.** Two agents never own the same file. Name in each prompt the files it
   owns and the ones it must not touch.
2. **Ownership follows the call graph, not the file list.** Changing a signature changes every
   caller, so the callers belong to the same agent as the definition. A file left out of every
   agent's list is not neutral ground — it is a file nobody may fix, and the tree stays broken
   until the main session steps in. Before splitting, find the callers (`gopls` references, not
   grep) and give them to whoever owns the definition.
3. **Respect compile order.** Within one Go module, the package that consumes a new API cannot be
   written beside the package that defines it. Sequence those, or hand both agents the exact agreed
   signature and compile only once both have landed — sequencing is the safer default.
4. **Where a clean split is impossible**, give each agent its own git worktree and integrate
   afterwards, rather than letting two agents write one tree.
5. **Launch every independent agent in a single message**, so they actually run concurrently.
6. **Do not invent parallelism that is not there.** Two agents that must serialize are slower than
   one. Say plainly why the work did not split, rather than splitting it into a conflict.

Large multi-agent fan-out through a workflow is a separate thing, and still needs the user to ask
for it explicitly.

## Dispatch size and review

1. **A lane longer than about six tasks is split into sequential dispatches** at natural seams: one
   component, or one group of spec requirements. Each dispatch is a fresh agent. The dispatches of
   one lane run in order and never at the same time, so a later one may extend files an earlier one
   in the same lane created. Dispatches of different lanes still run in parallel.
2. **After each dispatch, verify, then review.** The main session runs the dispatch's verification
   commands and reads the output, including the red-step failures the agent reports. Then a fresh
   reviewer agent, which did not write the code, checks the diff against the spec requirements and
   design decisions the dispatch covers. The reviewer reports and edits nothing. A defect it claims
   needs a failing test or is labelled `UNREPRODUCED` (`defect-claims.md`).
3. **Findings go back to a fresh dispatch of the same lane.** The main session may correct a few
   lines itself instead, and says so, as allowed above. The lane's next dispatch starts only when
   verification is green and the review is clean.
4. **One whole-branch review runs before the final gate and before archive**, against every spec
   requirement the change covers.

## Choosing the implementer's model

The main session chooses the model of every implementer subagent. It sets it explicitly on each
dispatch, and never leaves it to the default. It chooses from the complexity of that dispatch:

- **Sonnet** when the work is well specified and local. The plan gives the signatures and the tests,
  and the dispatch applies a known pattern: a single-file seam change, an in-memory store
  against a stated contract, a conformance case in an existing suite, option plumbing, adapter
  scenarios, test fixtures, or godoc.
- **Opus** when the dispatch needs judgement the plan cannot fully carry. That includes:
  - concurrency, or ordering under races: singleflight, cooldowns, backoff, conditional writes,
    barrier tests;
  - security-critical verification or refusal logic: token and signature checks, check-then-consume,
    policy guards, redaction;
  - a refactor that must keep existing behaviour while extracting shared code;
  - a change that touches several packages or an interface other lanes compile against;
  - any dispatch where a mistake would pass the tests and still be wrong.
- **When the two are close, choose Opus.** A redo costs more than the difference.
- **Escalate on failure.** A dispatch that comes back failing verification or review for a reason
  the stronger model would likely have avoided goes back on Opus, not Sonnet again.

The main session names the chosen model and a one-line reason when it announces each dispatch, so
the user can overrule it. Reviewer agents are outside this rule; the main session picks their model
as it sees fit.

## What every delegation prompt carries

A subagent does not reliably inherit this directory, so each prompt states for itself:

- the rules that bind it — test-first (`golang-tdd.md`), library design, defect claims, the
  read-only reference — and the skills it must read (`table-test`, `use-mockgen`,
  `use-testcontainers`);
- the files it owns, and the ones another agent is holding;
- the test-first order in full: write the failing test, run it, confirm it fails **for the intended
  reason**, then implement. A compile error is not a red step;
- the verification commands to run before reporting;
- what to report: files changed, the names of tests added, the failing output it actually saw at
  each red step, the final suite result, and anything it could not finish.

## Never

- Write or edit code in the main session because it is quicker that way.
- Paste a subagent's file contents into the session. Take its report; read the file only if the
  report has to be checked.
- Run two agents that write the same file.
- Let an agent edit an OpenSpec artifact, including ticking a task it believes it has finished.
- Let an agent run a git command that discards work: `checkout --`, `restore`, `reset --hard`,
  `stash`, `clean`. The tree holds uncommitted work from the main session and from other agents,
  and a path-level revert takes all of it, not just the agent's own edit. An agent that needs to
  undo something undoes it by editing the file back, or says it cannot and stops.
- State a subagent's results before its completion notification arrives, or accept "the tests pass"
  without the output that shows it.
- Let splitting the work break the test-first order, or let an agent skip the red step because
  another agent is waiting on it.
