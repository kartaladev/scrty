# Tasks

This change is a mechanical rename covered by existing tests, which `golang-tdd.md` exempts from a
new red step. The guards in group 1 still get a red step of their own: each is seen to fail before
the rename relies on it.

## 1. Guards seen to fail

- [ ] 1.1 Confirm the wire-value guard (design F2): temporarily change the constant's value from `scrty+jwt` to another string, run `go test -run 'TokenType' -count=1 ./token/`, and record that the literal `scrty+jwt` cases in `generator_tokentype_test.go` and `verifier_tokentype_test.go` fail for that reason; then edit the value back and verify the same run passes
- [ ] 1.2 Confirm the reserved-type guard (design F3): temporarily remove the issuer's refusal of the session token type in `token/issuer.go`, run `go test -run 'Issuer' -count=1 ./token/`, and record that the cases naming the first-party type in `issuer_test.go` fail for that reason; then edit the refusal back and verify the same run passes

## 2. Rename in `token`

- [ ] 2.1 Rename `token.TypeFirstParty` to `token.TypeSessionToken` with `gopls rename` across every workspace module (design decisions 1, 2, 5), with no alias left behind; verify `grep -rn TypeFirstParty --include='*.go' .` (excluding `.claude/`) is empty and `go build ./...` succeeds in every module listed in `go.work`
- [ ] 2.2 Rename `validateFirstPartyType` to `validateSessionTokenType` with `gopls rename` (decision 4); verify `go vet ./token/` passes
- [ ] 2.3 Reword the token-sense "first-party" mentions in `token`'s godoc and test case names by design decision 3, keeping the literal `scrty+jwt` assertions literal; verify `go test -count=1 ./token/...` passes and `go doc -all ./token | grep -i first-party` is empty

## 3. Wording in dependent packages

- [ ] 3.1 Reword the token-sense mentions in `oidcprovider` (`accesstoken.go`, `doc.go`, `endsession.go`, `endsignin.go`, and their tests) by decision 3, leaving every client-sense mention (`Client.FirstParty`, consent, first-party client fixtures); verify `go test -count=1 ./oidcprovider/...` passes
- [ ] 3.2 Rename `firstPartyRefused` to `sessionTokenRefused` with `gopls rename`, and reword the token-sense mentions in `httpsec` (`oidc_provider.go`, `oidc_endsession.go`, and the tests that mention it) by decision 3, leaving `flowFirstParty`; verify `go test -count=1 ./httpsec/...` passes
- [ ] 3.3 Reword the token-sense mentions in `test/storetest/session_settle.go`, `test/httpsecconformance/oidcprovider_scenarios.go` and `test/cmd/conformanceop/pages.go`, leaving `opFirstParty`; verify `go vet` and `go test -count=1` pass for the touched packages in the `test` module

## 4. Documentation

- [ ] 4.1 Reword the four token-sense mentions in `README.md` (around lines 898, 944, 949 and 954) by decision 3; verify `grep -n -i 'first-party' README.md` shows only client-sense mentions, if any
- [ ] 4.2 Add a **BREAKING** entry under *Changed* in `CHANGELOG.md`'s *Unreleased* section: the rename, the unchanged wire value, and the one-line migration from the design's Migration Plan; verify the entry names both identifiers and `scrty+jwt`

## 5. Integration checks

- [ ] 5.1 Run design F5's search: `rg -i 'TypeFirstParty|first-party (token|type|session|credential|verifier)|first-party .Generator.|firstPartyRefused|validateFirstPartyType' --glob '!.claude' --glob '!openspec'` comes back empty (the specs are covered by this change's deltas)
- [ ] 5.2 Run `gofmt -l` on every touched file (empty output), and run `go vet` and `go test -count=1` on `token` and every package that depends on it, in every workspace module (`test-scope.md`)
- [ ] 5.3 Run `openspec validate rename-session-token-type --strict` and verify it passes
- [ ] 5.4 Run the full gate, `make check` and `make spec-check`, after the last edit, and read its output

## Workflow follow-up

- Run the whole-branch review against the four modified specs before archive.
- Archive the change with `/opsx:archive` once the review is clean.
