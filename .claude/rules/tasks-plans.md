# Rule: Every OpenSpec `tasks.md` gets a `plans.md` beside it

**Whenever an OpenSpec command or skill creates or modifies a change's `tasks.md`, invoke
`/superpowers:writing-plans` and write the resulting implementation plan to `plans.md` in the same
directory.**

```
openspec/changes/<change>/
  proposal.md
  design.md
  specs/...
  tasks.md     <- written by OpenSpec (propose, update, instructions, ...)
  plans.md     <- written by /superpowers:writing-plans, right after
```

## When it applies

- A new `tasks.md` is created, by `/opsx:propose`, the `openspec-propose` or
  `openspec-update-change` skill, `openspec instructions tasks`, or any other OpenSpec command or
  skill.
- An existing `tasks.md` changes in content: tasks added, removed, reworded, reordered or regrouped,
  or their verification steps changed. Update `plans.md` in the same pass so the two never disagree.
- Ticking a checkbox during `/opsx:apply` is progress tracking, not a content change, and does not
  trigger a new plan.

## How

1. Finish and validate the `tasks.md` change first.
2. Invoke `/superpowers:writing-plans` with the change's `proposal.md`, `design.md`, `specs/` and
   `tasks.md` as input. Write its output to `plans.md` beside `tasks.md`.
3. The plan follows `tasks.md`: reference task numbers (`1.2`, `3.4`) so every task maps to plan
   steps and no plan step exists without a task. It also follows the project rules: test-first
   (`golang-tdd.md`), library design (`library-design.md`), and defect claims
   (`defect-claims.md`).
4. Report both files as written in the same message.

## Never

- Leave a created or content-modified `tasks.md` without an up-to-date `plans.md`.
- Hand-write `plans.md` in place of the skill. If `/superpowers:writing-plans` is not available in
  the session, stop and ask the user to install or enable it. Do not substitute.
- Let `plans.md` add scope that `tasks.md` does not have. If planning shows a missing task, update
  `tasks.md` through OpenSpec first, then the plan.
