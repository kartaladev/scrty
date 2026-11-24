# Rename the session token type: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `token.TypeFirstParty` with `token.TypeSessionToken` (same value, `scrty+jwt`, no
alias), and remove the token sense of "first-party" from code, godoc, tests, README and CHANGELOG.

**Architecture:** One identifier rename through `gopls rename`, then hand rewording of the exact
lines listed in design decision 3's inventory, applied per construction. No behaviour, wire or storage
change. The one visible text change is the issuer's error message (design F6).

**Tech Stack:** Go workspace (`go.work`: root module plus `authenticate/passkey/webauthn`,
`expiry/sweep`, `httpsec/fibersec`, `httpsec/ginsec`, `httpsec/prblmsec`, `ratelimit/redisstore`,
`store/gormstore`, `store/pgxstore`, `test`), `gopls`.

**Spec:** `openspec/changes/rename-session-token-type/`: `proposal.md`, `design.md`
(decision 3's construction table, its inventory, and F1–F7), `specs/` and `tasks.md`.

## Global Constraints

- New name: `TypeSessionToken`. Value: `"scrty+jwt"`, unchanged. `TypeFirstParty` is removed; no
  `Deprecated` alias.
- Rewording follows design decision 3's construction table, sentence by sentence. Never substitute
  a phrase blindly. Read every changed sentence back: "the the" or "its the" is a defect (F7).
- Touch only the lines of decision 3's inventory, plus what `gopls rename` rewrites. The "not
  touched" list is never edited.
- Literal `"scrty+jwt"` assertions stay literal (F2).
- Never edit anything under `openspec/`, `store/migrate/`, or `httpsec/oidc_login.go`. Never run
  `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`. Do not commit; the main session
  commits.

## Review Focus

1. A client-sense mention renamed by mistake (the "not touched" list). Expected: unchanged.
2. Garbled prose from a blind substitution ("the the sign-in's sessions", "its the sign-in's
   sessions"). Expected: none.
3. README line 898 reworded to "session token", which would be false. Expected: "sign-in
   credential".
4. The wire value changed. Guarded by task 1.1.
5. The issuer's reserved-type refusal weakened. Guarded by task 1.2.

---

## Dispatch layout

One lane: every task follows the `gopls rename` of task 2.1, so nothing runs in parallel. It has ten
tasks (1.1–4.2), split into two sequential dispatches (`subagent-delegation.md`):

| Dispatch | Tasks | Model | Reason |
|---|---|---|---|
| A | 1.1–2.3 | Sonnet | Guard red steps plus a gopls rename and the `token` rewording; the plan gives every line |
| B | 3.1–4.2 | Opus | Rewording that needs judgement about which sense each sentence has and how it reads; a mistake there passes the tests and is still wrong |
| — | 5.1–5.4 | main session | Verification is never delegated |

Dispatch A gets a Sonnet reviewer and dispatch B an Opus reviewer. Each reviews against the four
spec deltas and design decisions 1–5 before the next dispatch starts.

**Scoped test command** (`test-scope.md`), run from each workspace module's directory. It lists the
changed package itself and every package whose tests or code depend on it, under its real import
path:

```sh
go list -test -f '{{if .ForTest}}{{.ForTest}}{{else}}{{.ImportPath}}{{end}}{{range .Deps}} {{.}}{{end}}' ./... \
  | awk -v P="github.com/kartaladev/scrty/token" '{ if ($1==P) {print $1; next} for (i=2;i<=NF;i++) if ($i==P) {print $1; break} }' \
  | grep -v '\.test$' | sort -u | xargs go test -count=1
```

In the root module this selects 14 packages, `token` included (measured 2026-11-25).

---

### Task 1: Guards seen to fail (tasks 1.1, 1.2)

**Files:** modify temporarily, then restore: `token/config.go:32`, `token/issuer.go:208-210`.

**Interfaces:** none produced.

- [ ] **Step 1 (1.1):** change the value of `TypeFirstParty` in `token/config.go:32` to `"guard+jwt"`.
- [ ] **Step 2:** run `go test -run 'TokenType' -count=1 ./token/`. Expected: FAIL in the cases at
  `generator_tokentype_test.go:40` ("the default is the first-party type") and `:43`, and at
  `verifier_tokentype_test.go:91` ("the first-party type is accepted"), because the issued or
  accepted `typ` is not `scrty+jwt`. Record the failing lines.
- [ ] **Step 3:** edit the value back to `"scrty+jwt"`, and rerun the same command. Expected: PASS.
- [ ] **Step 4 (1.2):** in `token/issuer.go`, comment out the `if typ == normalizeTokenType(TypeFirstParty)`
  block (lines 208–210).
- [ ] **Step 5:** run `go test -run 'Issuer' -count=1 ./token/`. Expected: FAIL in exactly
  `TestIssuer_RefusalAsksNoKey/the_first-party_type` and
  `TestIssuer_RefusalAsksNoKey/the_first-party_type,_spelled_with_the_prefix_and_other_case`.
  Record the failing lines.
- [ ] **Step 6:** restore the block exactly, and rerun. Expected: PASS. Then `git diff --stat token/`
  is empty.

### Task 2: Rename in `token` (tasks 2.1–2.3)

**Files:** `token/config.go`, `token/issuer.go`, `token/generator.go`, `token/verifier.go`,
`token/claims.go`, every file `gopls rename` touches, and the `token` test files of the inventory.

**Interfaces:**
- Produces `const TypeSessionToken = "scrty+jwt"` in `token/config.go`, replacing `TypeFirstParty`.
- Produces unexported `func (c *config) validateSessionTokenType() error`, replacing
  `validateFirstPartyType`.

- [ ] **Step 1 (2.1):** run `gopls rename -w token/config.go:#<offset of TypeFirstParty> TypeSessionToken`.
  Expected: every code reference in every module is rewritten. Six comment mentions remain: at
  `issuer.go:20`, `claims.go:70`, `verifier.go:120,147` and `generator.go:186,217`.
- [ ] **Step 2:** run `go build ./...` and `go vet ./...` in each `go.work` module. Expected: success.
- [ ] **Step 3 (2.2):** `gopls rename` `validateFirstPartyType` to `validateSessionTokenType`, then
  run `go vet ./token/`. Expected: success.
- [ ] **Step 4 (2.3):** reword the `token` lines of the inventory by construction, including:
  - the six comments;
  - the error text at `issuer.go:209`, which becomes
    `"%w: an issuer does not issue session tokens: use a Generator"`;
  - the test case names at `generator_tokentype_test.go:40`, `issuer_test.go:533,534,613` and
    `verifier_tokentype_test.go:91,144`;
  - the comment at `verifier_tokentype_test.go:103`.
- [ ] **Step 5:** run `go test -count=1 ./token/...`. Expected: PASS. Then
  `rg -n TypeFirstParty --glob '!.claude' --glob '!openspec'` and
  `go doc -all ./token | grep -i first-party`. Expected: both empty.
- [ ] **Step 6:** run the scoped test command in every `go.work` module. Expected: PASS. Report the
  output.

### Task 3: Wording in dependent packages (tasks 3.1–3.3)

**Files:** exactly the `oidcprovider`, `httpsec` and `test` lines of design decision 3's inventory.

**Interfaces:**
- Consumes `token.TypeSessionToken` from Task 2.
- Produces `func (f *signInEnds) sessionTokenRefused(t *testing.T, s *session.Session)`, replacing
  `firstPartyRefused`.

- [ ] **Step 1 (3.1):** reword the `oidcprovider` lines by construction. Read each sentence back. Run
  `go test -count=1 ./oidcprovider/...`. Expected: PASS.
- [ ] **Step 2 (3.2):** `gopls rename` `firstPartyRefused` to `sessionTokenRefused`, then reword the
  `httpsec` lines by construction. "The first-party store" becomes "the chain's session store". Run
  `go test -count=1 ./httpsec/...`. Expected: PASS.
- [ ] **Step 3 (3.3):** reword `test/storetest/session_settle.go:157` and
  `test/cmd/conformanceop/pages.go:300`. From `test/`, run `go vet` and `go test -count=1` on
  `./storetest/... ./cmd/conformanceop/...`. Expected: PASS. The container suites need Docker;
  report if it is unavailable.
- [ ] **Step 4:** run `rg -n -i 'first-party' oidcprovider httpsec test --glob '*.go'`. Expected: every
  hit is on the "not touched" list. Report the list.

### Task 4: Documentation (tasks 4.1, 4.2)

**Files:** `README.md` lines 898, 944, 949 and 954; `CHANGELOG.md`, in its *Unreleased* section.

- [ ] **Step 1 (4.1):** reword README 898 to "It issues no sign-in credential". Reword 944, 949 and 954
  by the session constructions. Then run `grep -n -i first-party README.md`. Expected: only lines on
  the "not touched" list, if any.
- [ ] **Step 2 (4.2):** under `## [Unreleased]`, add `### Changed` with this entry:

  ```markdown
  - **BREAKING: `token.TypeFirstParty` is renamed `token.TypeSessionToken`.** Its value, `scrty+jwt`,
    is unchanged, so every token already issued still verifies. "First-party" now means only an
    OAuth client the provider trusts (`oidcprovider.Client.FirstParty`). Replace
    `token.TypeFirstParty` with `token.TypeSessionToken`. An `Issuer` asked for that type now says
    it "does not issue session tokens". Three scenario titles in the `token-issuance` spec keep the
    old wording, because the spec tooling cannot retitle a scenario in place; their text says
    "session token".
  ```

### Task 5: Integration checks (tasks 5.1–5.4, main session)

- [ ] **Step 1 (5.1):** run both searches of task 5.1. Expected: every hit is on the "not touched"
  list.
- [ ] **Step 2 (5.2):** run `gofmt -l` on the touched files (empty output), then `go vet` and the scoped
  test command in every `go.work` module. Expected: PASS.
- [ ] **Step 3 (5.3):** run `openspec validate rename-session-token-type --strict`. Expected: valid.
- [ ] **Step 4 (5.4):** run `make check` and `make spec-check` after the last edit, and read the output.
  `make release-check` reports the removed constant (accepted, F1).
- [ ] **Step 5:** the main session commits on `refactor/session-token-type`, with the project's
  attribution and no session link.
