# Tasks

Every task follows the project's test-first rule: write the failing test, run it, confirm it fails
for the intended reason (a compile error is not a red step), then implement. "Verify" in a task
names the focused run that must first fail and then pass. Table tests follow the `table-test`
skill and test doubles the `use-mockgen` skill. Each group ends with a `/simplify` pass on the code
it touched and a re-run of its tests.

Two claims in `design.md` are `UNREPRODUCED` (the verify endpoint accepts a code in the query; fiber
prefers the query over the body). The task that addresses each starts with its reproducing test. If
that test passes on the unchanged code, the claim was wrong: stop, report it, and the main session
removes the decision from `design.md` instead of implementing it.

## 1. The verify endpoint reads its code from the body only

- [ ] 1.1 Write the failing tests for the `UNREPRODUCED` claim first: a pending session posting to the verify path with a valid code only in the query string, and with a wrong code in the body and a valid one in the query, is verified today. Then move `postedField` out of `httpsec/mfaenrol.go` into a file of its own (unchanged behaviour; the enrolment tests stay green), and read `code` through it in `httpsec/mfaverify.go`. Verify a table: code in the query only → `ErrCredentialsMissing` (400), challenge pending, no failure recorded on the throttle; wrong code in the body with a valid one in the query → `mfa.ErrInvalidCode`, one failure recorded; multipart, JSON, empty body, missing field, a body that does not parse → 400, nothing recorded; a body over the limit → 413; a valid URL-encoded code → verified as today (spec `multi-factor-auth`, "The verify endpoint resolves the challenge and rotates the session"): `go test -run 'TestVerifyReadsBodyOnly|TestMFAVerify' -count=1 ./httpsec/ && go test -count=1 ./httpsec/`.
- [ ] 1.2 Add a conformance scenario to `test/httpsecconformance` (a valid code in the query of a POST to the verify path is refused as missing credentials) so net/http, gin and fiber run it; see it fail on fiber and net/http against the unchanged endpoint, then pass: `cd test && go test -run TestConformance -count=1 .`.
- [ ] 1.3 Godoc: `EnableMFA` states that the verify endpoint reads only the `code` field of a URL-encoded POST body, that other bodies get 400 and are not counted, and why. Verify with `go doc ./httpsec EnableMFA` and `go vet ./...`.

## 2. fiber reads a form field with net/http's precedence

- [ ] 2.1 Write the failing conformance scenario first: a consumer interceptor reads field `x` from a POST whose URL-encoded body carries `x=body` and whose query carries `x=query`, and answers with what it read; net/http and gin answer `body`, fiber answers `query` today. Add the rows "only the query carries it" (`query` everywhere) and a multipart body (`body` everywhere). Then change `fibersec`'s `FormValue` to look in the posted form (URL-encoded, then multipart, within the app's `BodyLimit`) before the query, and update its godoc and the `httpsec.Request.FormValue` godoc to state the precedence on every adapter (spec `framework-adapters`, "Every adapter reads a form field with the same precedence"): `cd test && go test -run TestConformance -count=1 . && cd ../fibersec && go test -count=1 ./...`.

## 3. The OIDC components flush their refusal logs

- [ ] 3.1 Add `FlushRefusalLogs() error` to `oidc.HandoffManager` and `oidc.Broker`. Verify a table per type with a counting reporter: records suppressed within a window are reported by the flush with their count; a flush with nothing pending reports nothing; the component still works after a flush (spec `oidc-login`, "OIDC components flush their refusal logs"): `go test -run 'TestHandoffManagerFlushRefusalLogs|TestBrokerFlushRefusalLogs' -count=1 ./oidc/`.
- [ ] 3.2 Add `FlushRefusalLogs() error` to `oidc.Manager`, flushing its own sampler and, when the broker it was given implements the flush, the broker's. Verify: the manager's pending count reported; a broker with a pending count reached through the manager; a consumer broker without a flush is skipped without error (spec `oidc-login`, scenario "Manager flushes its broker"): `go test -run TestManagerFlushRefusalLogs -count=1 ./oidc/`.

## 4. One flush reaches every sampler the chain holds

- [ ] 4.1 Add `(*policy.Engine).FlushRefusalLogs()` flushing every registered policy that implements `policy.RefusalLogFlusher`, including one added after the chain was built. Verify a table with a lockout policy, the MFA requirement policy, and a consumer policy without a flush: `go test -run TestEngineFlushRefusalLogs -count=1 ./policy/`.
- [ ] 4.2 Give the `sourceGuard` seam in `httpsec/throttle.go` a `Flush()`, and have `Chain.FlushRefusalLogs` walk its registrations through an unexported flusher interface implemented by the verify interceptor (its throttle), the interceptors holding a source guard (API key, magic link, OIDC handoff), form login and basic (their authenticator, when it implements `authenticate.RefusalLogFlusher`), and OIDC login (manager and handoff manager); then flush the policy engine. Keep the enrolment interceptor's flush. Verify a table where each component holds suppressed counts under a long interval and one `FlushRefusalLogs` call reaches each reporter: the verification throttle, a chain-built and a consumer-supplied source guard, the password authenticator, a registered policy, the OIDC manager and handoff manager (spec `http-security-chain`, "Chain refusal logs are sampled and summarised", scenarios "One flush reaches the components", "Registered policy flushed"): `go test -run TestFlushRefusalLogsReachesComponents -count=1 ./httpsec/`.
- [ ] 4.3 Rewrite the `Chain.FlushRefusalLogs` godoc to list exactly what it reaches, and to name what it does not: components the consumer holds but never gave the chain, and `signingkey.KeyManager`, which flushes when its loops stop. Verify with `go doc ./httpsec Chain.FlushRefusalLogs` against the list in design decision 3.

## 5. Final gate

- [x] 5.1 Main session: if `mfa-enrolment-path` has archived first, update this change's `multi-factor-auth` delta to carry its text of the verify requirement (and otherwise record in `mfa-enrolment-path` that its delta must carry this change's text), then `openspec validate request-input-and-log-flush --strict`.
- [ ] 5.2 Run across every module in `go.work`: `go test -race -count=1 ./...`, `go vet ./...`, `gofmt -l .` empty, and `golangci-lint run ./...` clean. Then run a whole-branch review against every requirement in this change's delta specs and resolve its findings before archive.
