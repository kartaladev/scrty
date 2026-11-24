# Rename the session token type: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `token.TypeFirstParty` with `token.TypeSessionToken` (same value, `scrty+jwt`, no
alias), and remove the token sense of "first-party" from code, godoc, tests, README and CHANGELOG.

**Architecture:** One identifier rename through `gopls rename`, which moves every reference in
every workspace module at once, followed by hand rewording under design decision 3's table. No
behaviour, wire or storage change.

**Tech Stack:** Go workspace (`go.work`: root module plus `authenticate/passkey/webauthn`,
`expiry/sweep`, `httpsec/fibersec`, `httpsec/ginsec`, `httpsec/prblmsec`, `ratelimit/redisstore`,
`store/gormstore`, `store/pgxstore`, `test`), `gopls`.

**Spec:** `openspec/changes/rename-session-token-type/` (`proposal.md`, `design.md`, `specs/`,
`tasks.md`).

## Global Constraints

- New name: `TypeSessionToken`. Value: `"scrty+jwt"`, unchanged.
- `TypeFirstParty` is removed; no `Deprecated` alias.
- Wording table (design decision 3): first-party token → session token; the first-party type →
  the session token type; first-party verifier → session token verifier; first-party `Generator` /
  token generator → session token `Generator` / generator; first-party credential → session token;
  first-party session(s) → the sign-in's session(s).
- Keep the OAuth client sense: `Client.FirstParty`, every "first-party client" or "first-party
  flag", `firstParty`, `firstPartyClient`, `firstPartyRedirect`, `flowFirstParty`, `opFirstParty`,
  and the client IDs `first-party-web`, `first-party-offline`, `conf-first-party`,
  `flow-first-party`.
- Literal `"scrty+jwt"` assertions stay literal; never rewrite them to the constant (design F2).
- Never edit anything under `openspec/`, `store/migrate/`, or `httpsec/oidc_login.go`. Never run
  `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`.

## Review Focus

1. A client-sense mention renamed by mistake: `Client.FirstParty` godoc, consent comments in
   `oidcprovider/consent.go`, `doc.go:208`, `endsignin.go:287`, `client.go:624`. Expected: unchanged.
2. The wire value changed: expected `scrty+jwt` everywhere. Guarded by task 1.1.
3. The issuer's reserved-type refusal weakened: an `Issue.Type` of `scrty+jwt` in any case or with
   `application/` must still fail with `ErrConfig`. Guarded by task 1.2.
4. A test case renamed into a misleading name, e.g. "a first-party client …" in
   `endsignin_test.go` turned into "a session-token client". Expected: client cases untouched.
5. A leftover token-sense mention in prose. Guarded by task 5.1's search.

---

## Dispatch layout

The work is one lane: every task follows the `gopls rename` of task 2.1, so nothing runs in
parallel. It has eleven tasks, so it is split into two sequential dispatches (`subagent-delegation.md`):

| Dispatch | Tasks | Model | Reason |
|---|---|---|---|
| A | 1.1–2.3 | Sonnet | Guard red steps plus a gopls rename: a known pattern the plan decides |
| B | 3.1–4.2 | Sonnet | Wording under a fixed table, with judgement on which sense each mention has |
| — | 5.1–5.4 | main session | Verification is never delegated |

Each dispatch is reviewed by a fresh Sonnet reviewer against the four spec deltas and design
decisions 1–5 before the next starts.

**Scoped test command** (`test-scope.md`), run from each workspace module's directory:

```sh
go list -test -f '{{.ImportPath}}{{range .Deps}} {{.}}{{end}}' ./... \
  | awk '$0 ~ / github.com\/kartaladev\/scrty\/token( |$)/ {print $1}' \
  | grep -v '\.test$' | sort -u | xargs go test -count=1
```

In the root module this selects 24 of its 55 packages (measured 2026-11-25).

---

### Task 1: Guards seen to fail (tasks 1.1, 1.2)

**Files:**
- Modify temporarily, then restore: `token/config.go:32`, `token/issuer.go:208-210`
- Tests (unchanged): `token/generator_tokentype_test.go:40,44`, `token/verifier_tokentype_test.go:91,133,146`, `token/issuer_test.go:533-534,613`

**Interfaces:** none produced.

- [ ] **Step 1 (1.1):** change the value of `TypeFirstParty` in `token/config.go:32` to `"guard+jwt"`.
- [ ] **Step 2:** run `go test -run 'TokenType' -count=1 ./token/`. Expected: FAIL in
  `generator_tokentype_test.go` ("the default is the first-party type") and
  `verifier_tokentype_test.go` ("the first-party type is accepted") because the issued or accepted
  `typ` is not `scrty+jwt`. Record the failing lines.
- [ ] **Step 3:** edit the value back to `"scrty+jwt"`; rerun the same command. Expected: PASS.
- [ ] **Step 4 (1.2):** in `token/issuer.go`, comment out the `if typ == normalizeTokenType(TypeFirstParty)` block (lines 208–210).
- [ ] **Step 5:** run `go test -run 'Issuer' -count=1 ./token/`. Expected: FAIL in the cases
  "the first-party type", "the first-party type, spelled with the prefix and other case" and
  "the first-party type, named again", because no `ErrConfig` is returned. Record the failing lines.
- [ ] **Step 6:** restore the block exactly; rerun. Expected: PASS. `git diff --stat token/` is empty.

### Task 2: Rename in `token` (tasks 2.1–2.3)

**Files:**
- Modify: `token/config.go`, `token/issuer.go`, `token/generator.go`, `token/verifier.go`, `token/claims.go`, and every file `gopls rename` touches in any module
- Tests: `token/generator_tokentype_test.go`, `token/verifier_tokentype_test.go`, `token/issuer_test.go`, `token/helpers_test.go`, `token/verifier_test.go`

**Interfaces:**
- Produces: `const TypeSessionToken = "scrty+jwt"` in `token/config.go`, replacing `TypeFirstParty`;
  unexported `func (c *config) validateSessionTokenType() error`, replacing `validateFirstPartyType`.

- [ ] **Step 1 (2.1):** `gopls rename -w token/config.go:#<offset of TypeFirstParty> TypeSessionToken`
  (find the offset with `gopls` or use the `LSP` rename). Expected: every reference in every module
  is rewritten.
- [ ] **Step 2:** run `grep -rn TypeFirstParty --include='*.go' . | grep -v '^\./\.claude'`. Expected: empty.
  Run `go build ./...` and `go vet ./...` in each `go.work` module. Expected: success.
- [ ] **Step 3 (2.2):** `gopls rename` `validateFirstPartyType` → `validateSessionTokenType`; run `go vet ./token/`. Expected: success.
- [ ] **Step 4 (2.3):** reword by the Global Constraints table:
  - the constant's godoc (`config.go:29-31`);
  - `claims.go:70-76`, `generator.go:186,194,217`, `verifier.go:120,147`, `issuer.go:20-22`;
  - the error text at `issuer.go:209`, which becomes `"%w: an issuer does not issue session tokens: use a Generator"`;
  - the test case names in `generator_tokentype_test.go:40`, `issuer_test.go:533,534,613` and
    `verifier_tokentype_test.go:91,144`, plus the comments in those files and `helpers_test.go`.

  First check that no test asserts the old error text: `grep -rn "issue first-party" --include='*_test.go' .`. Expected: empty.
- [ ] **Step 5:** run `go test -count=1 ./token/...` (PASS), and
  `go doc -all ./token | grep -i first-party` (empty).
- [ ] **Step 6:** run the scoped test command in every `go.work` module. Expected: PASS. Report the output.

### Task 3: Wording in dependent packages (tasks 3.1–3.3)

**Files:**
- Modify:
  - `oidcprovider/accesstoken.go:232`
  - `oidcprovider/doc.go:113` (not 208)
  - `oidcprovider/endsession.go:51,69,110-120`
  - `oidcprovider/endsignin.go:39,87` (not 287)
  - `httpsec/oidc_provider.go:479,491`
  - `httpsec/oidc_endsession.go:186`
  - `test/storetest/session_settle.go:157`
  - `test/httpsecconformance/oidcprovider_scenarios.go` (token-sense comments only)
  - `test/cmd/conformanceop/pages.go:300`
- Tests:
  - `oidcprovider/accesstoken_test.go:933`
  - `oidcprovider/authorize_test.go:840`
  - `oidcprovider/endsignin_test.go` (token-sense comments only)
  - `httpsec/oidc_logout_retry_test.go:42-47,145,226`
  - `httpsec/oidc_logout_read_test.go`
  - `httpsec/bearer_tokentype_test.go:63`
  - `httpsec/oidc_completion_test.go`
  - `httpsec/oidc_authorize_test.go` (comment only; `flowFirstParty` stays)

**Interfaces:**
- Consumes: `token.TypeSessionToken` from Task 2.
- Produces: `func (f *signInEnds) sessionTokenRefused(t *testing.T, s *session.Session)`, replacing `firstPartyRefused`.

- [ ] **Step 1 (3.1):** reword the `oidcprovider` mentions listed above. "first-party sessions" becomes
  "the sign-in's sessions"; "first-party token" becomes "session token". Run
  `go test -count=1 ./oidcprovider/...`. Expected: PASS.
- [ ] **Step 2 (3.2):** `gopls rename` `firstPartyRefused` → `sessionTokenRefused`. Reword the
  `httpsec` mentions; "the first-party store" in the test case names becomes "the session store".
  Run `go test -count=1 ./httpsec/...`. Expected: PASS.
- [ ] **Step 3 (3.3):** reword the `test` module mentions. From `test/`, run `go vet` and
  `go test -count=1` on `./storetest/... ./httpsecconformance/... ./cmd/conformanceop/...`.
  Expected: PASS (`storetest` needs Docker for its container suites; report if it is unavailable).
- [ ] **Step 4:** run `rg -n -i 'first-party' oidcprovider httpsec test --glob '*.go'` and
  confirm every remaining hit is the client sense. Report the list.

### Task 4: Documentation (tasks 4.1, 4.2)

**Files:**
- Modify: `README.md:898,944,949,954`, `CHANGELOG.md` (*Unreleased*)

- [ ] **Step 1 (4.1):** reword the four README mentions by the table ("first-party credential" →
  "session token"; "first-party sessions" / "a first-party session" → "the sign-in's sessions" /
  "a session of the sign-in"). Run `grep -n -i first-party README.md`. Expected: only client-sense
  hits, if any.
- [ ] **Step 2 (4.2):** under `## [Unreleased]`, add `### Changed` with this entry:

  ```markdown
  - **BREAKING: `token.TypeFirstParty` is renamed `token.TypeSessionToken`.** Its value, `scrty+jwt`,
    is unchanged, so every token already issued still verifies. "First-party" now means only an
    OAuth client the provider trusts (`oidcprovider.Client.FirstParty`). Replace
    `token.TypeFirstParty` with `token.TypeSessionToken`. An `Issuer` asked for that type now says
    it "does not issue session tokens".
  ```

  Expected: the entry names both identifiers and `scrty+jwt`.

### Task 5: Integration checks (tasks 5.1–5.4, main session)

- [ ] **Step 1 (5.1):** run
  `rg -i 'TypeFirstParty|first-party (token|type|session|credential|verifier)|first-party .Generator.|firstPartyRefused|validateFirstPartyType' --glob '!.claude' --glob '!openspec'`.
  Expected: empty.
- [ ] **Step 2 (5.2):** run `gofmt -l` on the touched files (empty output), then `go vet` and the
  scoped test command in every `go.work` module. Expected: PASS.
- [ ] **Step 3 (5.3):** run `openspec validate rename-session-token-type --strict`. Expected: `is valid`.
- [ ] **Step 4 (5.4):** run `make check` and `make spec-check` after the last edit. Expected: both
  succeed. Read the output.
- [ ] **Step 5:** commit on `refactor/session-token-type`:

  ```bash
  git add -A token oidcprovider httpsec test README.md CHANGELOG.md openspec/changes/rename-session-token-type
  git commit -m "refactor(token)!: rename TypeFirstParty to TypeSessionToken"
  ```
