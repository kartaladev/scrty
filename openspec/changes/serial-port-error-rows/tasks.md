# Tasks

This change touches test code only, in package `httpsec`. Each task runs red before green: first a run that should fail and the reason it should fail, then the change, then the run that passes. Restore a file you broke on purpose by editing it back, never with a git command that discards work.

Tasks marked **(main session)** record measurements, push or open pull requests. Agents do none of those.

## 1. The copied launchers go through the shared helper (decision 1)

- [ ] 1.1 Red: run `go test -race -count=1 -json -run '^TestPortErrors_SourceThrottle$' ./httpsec`.
  - Verify that no row emits a `pause` action, so its child rows run one at a time today.
  - Record the test's wall time from the first and last event timestamps.
- [ ] 1.2 Check every caller of `throttlePortErrInChild`, `redemptionPortErrInChild` and `backchannelPortErrInChild` against the helper's contract, using gopls references:
  - the helper is called once per subtest;
  - no `t.Setenv` or `t.Chdir` ancestor;
  - no post-loop code, `defer` or parent `t.Cleanup` that depends on the rows.

  Report each caller with its verdict. Stop if any caller breaks the contract.
- [ ] 1.3 Green:
  - Each of the three copies becomes `limiterPortErrInChild(t, <its env var>, <its marker>, row)`, keeping its name, signature and godoc purpose.
  - The helper's excerpt of a failing child's output rises from 8 to 12 lines, and its godoc says so.
  - Verify:
    - the 1.1 command now shows `pause` actions on those rows;
    - `go test -race -count=1 -run '^(TestPortErrors_SourceThrottle|TestPortErrors_Redemption|TestPortErrors_OIDCRedemption|TestPortErrors_BackchannelLinkStore|TestPortErrors_TokenGenerator)$' ./httpsec` passes.
- [ ] 1.4 The guard still fails through a former copy.
  - In a `TestPortErrors_SourceThrottle` child row, in the child path only, induce `t.Fatal("induced")`. Verify that the row fails with "the child failed:" and `induced`, then edit it back.
  - Make the same row print a wrong marker. Verify "the child printed no line", then edit it back.

## 2. One fixture hash per test process (decision 2)

- [ ] 2.1 Red: run `go test -race -count=1 -cpuprofile <scratch>/cpu.out -run '^TestPortErrors_RecoveryCooldown$/^live$/^Unwrap_panicking_with_nil$' ./httpsec`.
  - Verify that `golang.org/x/crypto/argon2` takes most of the profile's CPU.
  - Record the row's elapsed time.
- [ ] 2.2 Check each fixture that encodes `e2ePassword` for setup, starting with `newRecoveryHarness` and `newPwlDeployment`, and including any other `e2eEncoder(t).Encode(e2ePassword)` found with gopls.
  - Verify that no test using the fixture asserts on the hash's salt or bytes, needs distinct hashes, or lets the encoder rewrite the hash.
  - Report each fixture as switched or kept, with the reason.
- [ ] 2.3 Green:
  - Add `e2eHash(t *testing.T) string` beside `e2eEncoder` in `httpsec/integration_test.go`. It returns a hash of `e2ePassword` derived once per process with `sync.OnceValues` at `e2eEncoder`'s parameters, and fails the test on the derivation's error.
  - Switch the fixtures 2.2 cleared.
  - Verify:
    - re-running the 2.1 command shows the row's elapsed time down and argon2's share of the profile reduced;
    - `go test -race -count=1 -run '^(TestPortErrors_RecoveryCooldown|TestPortErrors_PasswordlessUserLoader|TestPortErrors_TokenGenerator|TestRecovery.*|TestPasskeyLogin.*)$' ./httpsec` passes.

## 3. The rehash rig's target drops to 20 MiB (decision 3)

- [ ] 3.1 Red: temporarily set `rehashNewMemory` to `19 * 1024`, equal to the stored cost.
  - Verify that the rehash tests' upgrade cases fail (`go test -race -count=1 -run '^(TestLogin_Rehash.*|TestPortErrors_RehashWrite)$' ./httpsec`). This proves they need new memory strictly above old.
  - Then set it to `20 * 1024`.
- [ ] 3.2 Green: verify that the same command passes, and that no assertion ties the `47104` sentinel to `rehashNewMemory`. Record `TestPortErrors_RehashWrite`'s wall time from its event timestamps, before and after.

## 4. Gates, measurements and review

- [ ] 4.1 Verify `make lint`, `make vet` and `gofmt -l httpsec` report nothing.
- [ ] 4.2 **(main session)** Run `go test -race -count=1 -timeout 300s -json ./httpsec` on an idle machine.
  - Record in a `## Measurements` section of `design.md`:
    - the package `Elapsed`;
    - the count of rows with a `pause` action;
    - the time left in rows that never paused.
  - Verify the package is at most 300 s.
- [ ] 4.3 **(main session)** Run `make check`. Verify it passes, and keep the output.
- [ ] 4.4 **(main session)** Push the branch and open a pull request. Run CI by hand so `test` runs.
  - Verify both `test` legs report `httpsec` at no more than 300 s.
  - Record both figures and the run ID in Measurements.
- [ ] 4.5 A fresh reviewer that wrote none of the change reviews the diff against decisions 1–3 and every row of the failure-modes table. It enumerates how the change fails before judging whether it works, and reports each row as handled, tested or accepted, or as a finding (`REPRODUCED` with a failing run, or `UNREPRODUCED` with the reason).

## Workflow follow-up

- Archive `serial-port-error-rows` after it merges.
