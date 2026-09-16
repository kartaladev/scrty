# Rule: The legacy reference is read-only, consulted on demand, and never copied

scrty is informed by a mature internal predecessor. A local snapshot of its **code and tests** lives
at `.claude/.legacy/security/v2/`. It is git-ignored and must never be committed.

## When to read it

Read it **when a task needs to know** how a behaviour, edge case, failure mode or trade-off was
handled before. Examples: writing a spec or design for a capability the predecessor already has,
choosing a default, or implementing a flow with known pitfalls (one-time credential consumption,
rate limiting, key rotation, OIDC callbacks).

Do not read it by default for unrelated work. Read selectively (`go doc -all <pkg>`, the tests,
then the files you need), not the whole tree.

The code and its tests are the source of truth for what the predecessor did. Tests pin the
behaviour it guaranteed; comments and godoc explain why.

## Precedence

1. **Settled scrty decisions**: `openspec/config.yaml` context, archived specs under
   `openspec/specs/`, and accepted change designs.
2. **The predecessor's behaviour and decisions**, as its code and tests show them. This is the
   default.
3. Anything else: taste, simplification, "a cleaner design".

Depart from (2) only when (1) requires it, or when the predecessor has a demonstrable defect: a
failing case, an unpinned guarantee, or a pitfall its own comments admit. Record every departure as
a decision in the change's `design.md`, naming what scrty does differently and why.

## Never

- Copy code, tests, comments or godoc verbatim into scrty. Write scrty's own, in its own words and
  to its own rules (test-first, library design, table tests, mockgen placement).
- Cite the predecessor anywhere in scrty's code, docs, commits or OpenSpec artifacts: not its
  name, module path, package paths, file paths, commit or "legacy"/"ported"/"v2" wording.
- Edit, build or test the snapshot. It is reference material only, and does not compile on its own:
  its `go.mod` points at sibling modules that are not in the snapshot. To prove a defect in the
  predecessor, follow `defect-claims.md`: reproduce it with a failing test in a disposable full
  export outside the project.
- Let plain-text searches mix it with scrty's code. Exclude it (`rg --glob '!.claude/.legacy'`,
  `grep --exclude-dir=.legacy`). Go tooling already skips dot-directories.

## Recreating the snapshot

The snapshot is pinned to commit `3dc0f80` of the predecessor repository. On a machine with that
repository checked out:

```sh
mkdir -p .claude/.legacy
git -C <path-to-predecessor-repo> archive 3dc0f80 security/v2 | tar -x -C .claude/.legacy
```

Only `security/v2` is included. Documentation directories are deliberately left out; the code and
tests speak for themselves.
