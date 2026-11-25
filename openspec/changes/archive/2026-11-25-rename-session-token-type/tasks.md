# Tasks

This change is a mechanical rename and a rewording, covered by existing tests. That is an accepted
deviation from the project's test-first rule for each task (`golang-tdd.md` exempts mechanical
renames already covered by tests): no task adds behaviour. The guards the rename relies on still get
a red step of their own in group 1, each seen to fail before the rename relies on it.

The scoped test command used below, run from each workspace module's directory, is:

```sh
go list -test -f '{{if .ForTest}}{{.ForTest}}{{else}}{{.ImportPath}}{{end}}{{range .Deps}} {{.}}{{end}}' ./... \
  | awk -v P="github.com/kartaladev/scrty/token" '{ if ($1==P) {print $1; next} for (i=2;i<=NF;i++) if ($i==P) {print $1; break} }' \
  | grep -v '\.test$' | sort -u | xargs go test -count=1
```

## 1. Guards seen to fail

- [x] 1.1 Confirm the wire-value guard (design F2): temporarily change the constant's value from `scrty+jwt` to another string, run `go test -run 'TokenType' -count=1 ./token/`, and record that the literal `scrty+jwt` cases at `generator_tokentype_test.go:40,43` and `verifier_tokentype_test.go:91` fail for that reason; then edit the value back and verify the same run passes
- [x] 1.2 Confirm the reserved-type guard (design F3): temporarily remove the issuer's refusal of the session token type in `token/issuer.go:208-210`, run `go test -run 'Issuer' -count=1 ./token/`, and record that exactly `TestIssuer_RefusalAsksNoKey/the_first-party_type` and `…/the_first-party_type,_spelled_with_the_prefix_and_other_case` fail; then edit the refusal back and verify the same run passes

## 2. Rename in `token`

- [x] 2.1 Rename `token.TypeFirstParty` to `token.TypeSessionToken` with `gopls rename` (design decisions 1, 2, 5), with no alias left behind; verify `go build ./...` and `go vet ./...` succeed in every module listed in `go.work` (comment mentions of the old name remain until 2.3)
- [x] 2.2 Rename `validateFirstPartyType` to `validateSessionTokenType` with `gopls rename` (decision 4); verify `go vet ./token/` passes
- [x] 2.3 Reword the `token` lines of design decision 3's inventory (including `config.go:336`, `generator_tokentype_test.go:13` and `helpers_test.go:121`), per construction, including the error text at `issuer.go:209`, keeping the literal `scrty+jwt` assertions literal; verify `go test -count=1 ./token/...` passes, `rg -n 'TypeFirstParty' --glob '!.claude' --glob '!openspec'` is empty, and `go doc -all ./token | grep -i first-party` is empty

## 3. Wording in dependent packages

- [x] 3.1 Reword the `oidcprovider` lines of the inventory per construction, leaving every client-sense mention on the "not touched" list; verify `go test -count=1 ./oidcprovider/...` passes
- [x] 3.2 Rename `firstPartyRefused` to `sessionTokenRefused` with `gopls rename`, and reword the `httpsec` lines of the inventory per construction ("the first-party store" becomes "the chain's session store"), leaving `flowFirstParty`; verify `go test -count=1 ./httpsec/...` passes
- [x] 3.3 Reword `test/storetest/session_settle.go:157` ("the i-th session") and `test/cmd/conformanceop/pages.go:300`, leaving `opFirstParty`; verify `go vet` and `go test -count=1` pass for `./storetest/... ./cmd/conformanceop/...` in the `test` module (the storetest container suites need Docker; report if it is unavailable)

## 4. Documentation

- [x] 4.1 Reword the four `README.md` lines of the inventory (898 becomes "sign-in credential"; 944, 949, 954 per the session constructions); verify `grep -n -i 'first-party' README.md` returns only lines on the "not touched" list, if any
- [x] 4.2 Add a **BREAKING** entry under *Changed* in `CHANGELOG.md`'s *Unreleased* section: the rename, the unchanged wire value, the one-line migration, the issuer's reworded error text, and that three `token-issuance` scenario titles keep their old wording; verify the entry names both identifiers and `scrty+jwt`

## 5. Integration checks

- [x] 5.1 Run design F5's search: `rg -n -i 'first-party|firstparty|first party' --glob '!.claude' --glob '!openspec' --glob '!CHANGELOG.md' .` and `rg -n -i -U 'first-?\s*(//\s*)?\n\s*(//\s*)?-?party' --glob '!.claude' --glob '!openspec' .`; verify every remaining hit is the client sense, and list them in the report
- [x] 5.2 Run `gofmt -l` on every touched file (empty output), and `go vet` plus the scoped test command in every workspace module (`test-scope.md`)
- [x] 5.3 Run `openspec validate rename-session-token-type --strict` and verify it passes
- [x] 5.4 Run the full gate, `make check` and `make spec-check`, after the last edit, and read its output; `make release-check` reports the removed constant, which design F1 accepts

## Workflow follow-up

- Merge this change before `fold-migrations-callback-server-error` and `resource-server`; each later change merges its CHANGELOG entries by hand.
- Run the whole-branch review against the four modified specs before archive.
- Archive the change with `/opsx:archive` once the review is clean.
