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
