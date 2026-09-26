# Tasks

Every task follows the project's test-first rule: write the failing test, run it, confirm it fails
for the intended reason (a compile error is not a red step), then implement. "Verify" in a task
names the focused run that must first fail and then pass. Table tests follow the `table-test`
skill and test doubles the `use-mockgen` skill. Each group ends with a `/simplify` pass on the code
it touched and a re-run of its tests.

Every site in this change is a defect claim found by reading (`defect-claims.md`): the task's first
test is its reproduction — a dependency whose error quotes `alice@example.com` and `u-123`, and a
capturing log handler or error handler — run against the unchanged site. A site whose test passes
unchanged is reported and dropped, not rewritten.

## 1. The shared helper

- [ ] 1.1 Add `internal/diag` with `Failure(reason string, err error) []slog.Attr` (a fixed `reason`, `error_type` as `%T`, and `cancelled=true` for a context cancellation or deadline) and `Fault`/`Wrap` (fixed text; `Unwrap() []error` returns the library sentinels given and the cause; `Wrap` returns nil for nil and the error itself when it is exactly one of the given sentinels). Verify a table: text never contains the cause's; `errors.Is` finds each sentinel and the cause; `errors.As` finds a typed cause; a bare sentinel passes through; cancellation is flagged (design decisions 1, 3): `go test -run 'TestFailure|TestFault|TestWrap' -count=1 ./internal/diag/`.
- [ ] 1.2 Move the enrolment path's `enrolmentFault` and `refusedAs` (`httpsec/mfaenrol.go`) onto `internal/diag`, behaviour unchanged. Verify the existing leak tests stay green: `go test -run 'TestEnrolment' -count=1 ./httpsec/`.

## 2. The password authenticator

- [ ] 2.1 Stop writing the submitted username in refusal records by default, and add `WithUsernameInRefusalLogs()` with godoc stating the risk. Verify a table: an unknown username `alice@example.com` is refused and no record contains it; with the option, the record contains it; sampling per reason is unchanged (spec `authentication`, "Authentication refusal logs are bounded and never carry the password"): `go test -run TestPasswordRefusalRecords -count=1 ./authenticate/`.
- [ ] 2.2 Record a user loader failure through `diag.Failure`. Verify: a loader error quoting `alice@example.com` leaves no record containing it, and the record carries `reason` and `error_type` (spec `diagnostic-redaction`, "Log records carry no dependency error text"): `go test -run TestPasswordLoaderFailureRecord -count=1 ./authenticate/`.

## 3. `httpsec` log sites

- [ ] 3.1 Record through `diag.Failure`: form login's attempt store record and reset (`login.go`), basic's attempt store (`basic.go`), the session-touch store failure (`sessiontouch.go`), the OIDC callback's handoff-issue failure (`oidc_callback.go`) and the limiter failures (`throttle.go`, keeping the deliberate `source` attribute). Verify a table, one row per site, with a dependency whose error quotes `alice@example.com` and `u-123` (spec `diagnostic-redaction`, scenario "Attempt store quotes the username"): `go test -run TestHTTPSecFailureRecords -count=1 ./httpsec/`.

## 4. Senders, magic link and the rate limiter

- [ ] 4.1 `notify`: the SMTP sender's and the queued sender's failure records name the stage and the error's type, never the error's text or the recipient. Verify a table: a `RCPT TO` refusal quoting the address; an inner sender failing with an HTTP-API body quoting it; a recovered panic whose value quotes it (spec `email-notification`, "Send logs carry no message body and no recipient"): `go test -run TestSenderFailureRecords -count=1 ./notify/`.
- [ ] 4.2 `magiclink`: the issued-count, issue, send, resolver and user-loader failure records through `diag.Failure`. Verify a table, one row per site (spec `diagnostic-redaction`, scenario "Sender quotes the recipient"): `go test -run TestMagicLinkFailureRecords -count=1 ./magiclink/`.
- [ ] 4.3 `ratelimit`: the source guard's limiter-failure records carry the fixed reason and type, keeping the deliberate `source` on the throttle record. Verify (spec `diagnostic-redaction`, scenarios "Limiter names its key", "Throttled source stays visible"): `go test -run TestGuardFailureRecords -count=1 ./ratelimit/`.

## 5. OIDC, stores and policies

- [ ] 5.1 `oidc`: the callback's flow-store completion failure and the handoff manager's user-loader failure (the case its current value scrubbing misses) through `diag.Failure`; the broker's existing redaction is unchanged. Verify a table: `go test -run 'TestCallbackFailureRecords|TestHandoffFailureRecords' -count=1 ./oidc/`.
- [ ] 5.2 `onetime`, `apikey`, `signingkey`: their store failures through `diag.Failure`, keeping the public token and key identifiers. Verify one table per package: `go test -run 'Test.*StoreFailureRecords' -count=1 ./onetime/ ./apikey/ ./signingkey/`.
- [ ] 5.3 `policy`: the MFA requirement policy's lookup-failure record through `diag.Failure` (keeping the deliberate user reference), and the refusal reasons of the lockout, concurrent-session and MFA policies that wrap a store error built with `diag.Wrap` (text fixed, the policy's sentinel and the cause reachable). Verify a table: no reason's text or record contains the store's text; each reason still matches its sentinel and the cause: `go test -run 'TestPolicyStoreFailureReasons' -count=1 ./policy/`.

## 6. Returned errors on the HTTP paths

- [ ] 6.1 Wrap with `diag.Wrap` every error an `httpsec` interceptor returns that a consumer-supplied dependency caused: login completion (session create and save, token generation), the bearer's per-request save, the verify endpoint's store reads, rotation and token generation, logout's session delete, OIDC authorize (flow begin), the OIDC callback (flow abort, handoff issue) and back-channel logout (link lookups, session and link deletes). Leave the consumer's own refusal checks, guards, authorizers and rule sets unchanged. Verify a table, one row per path, with an error handler recording `err.Error()`: no row's text contains `alice@example.com` or `u-123`; `errors.Is` finds the original error; `StatusForError` is unchanged; and a consumer refusal check's error is returned byte for byte (spec `http-error-propagation`, "Refusal errors are a stable public contract"; spec `diagnostic-redaction`, "Returned errors caused by a dependency carry fixed library text"): `go test -run TestReturnedErrorsCarryFixedText -count=1 ./httpsec/`.
- [ ] 6.2 Add a conformance scenario to `test/httpsecconformance`: a login whose session store fails with an error quoting an address is refused with the same status on net/http, gin and fiber, and gin's error channel carries no address. Verify: `cd test && go test -run TestConformance -count=1 .`.

## 7. Documentation and final gate

- [ ] 7.1 Godoc: every component that logs a dependency failure says the consumer keeps full detail by logging inside their own implementation; each deliberate field (throttled source, user reference in MFA and policy records, email domain, protocol-failure text) is named where it is logged. Verify with `go doc` on each touched package and `go vet ./...`.
- [ ] 7.2 Run across every module in `go.work`: `go test -race -count=1 ./...`, `go vet ./...`, `gofmt -l .` empty, `golangci-lint run ./...` clean, and `rg --glob '!.claude' --glob '!*_test.go' 'err(or)?\.Error\(\)' -n` reviewed so that no remaining site renders a dependency's error into a record or a returned error's text. Then run a whole-branch review against every requirement in this change's delta specs and resolve its findings before archive.
