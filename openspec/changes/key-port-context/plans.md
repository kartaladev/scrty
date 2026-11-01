# key-port-context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the key and cipher ports a per-call context, report a missing signing key apart from an outage, stop an outage or a hang-up from reading as a refusal on the verification, issuing and session-resolution paths, and issue every credential before anything is stored or spent, as the eleven spec deltas and design decisions D1–D8 require.

**Architecture:**
- **Defects first, on today's signatures (tasks 2.x).** Each misclassification is reproduced by a failing test and fixed before any port changes, so every claim is proven or dropped on its own.
- **The ports then change one at a time:** `seal` (3.x), `session.Cipher` and its marker (4.x), `KeySource` and `KeySetProvider` (5.x). Each lane owns its port, its implementations and every caller `gopls` finds.
- **Issue, then commit, last (6.x).** `session` gains a creation and a grace rotation the caller completes before the write, the shape `RotateIssuing` has; each issuing path in `httpsec` and `recovery` then moves onto them.

**Tech Stack:** Go 1.27 workspace, testify, mockgen v0.6 (`--typed`), jwx v4 (signing through `crypto.Signer`), testcontainers suites in `test/` (CI only).

**Spec:** `openspec/changes/key-port-context/`: `proposal.md`, `design.md` (D1–D8), `specs/*/spec.md` and `tasks.md`. Step labels cite `tasks.md`.

## Global Constraints

- **Paths are `main` after `reauthentication` merged.** Locate each symbol with `gopls`, not by the file names below, which are where they are on 2026-11-01.
- **`ctx context.Context` is always the first parameter.** No caller substitutes a context or imposes a deadline of its own (D1). No nil-context check is added (`idiomatic-api-shape` D6). The in-memory implementations ignore their context entirely.
- **New sentinels, exact text:**
  - `signingkey.ErrNoKey = errors.New("signingkey: no key for the algorithm")`;
  - `session.ErrCipherUnavailable = errors.New("session: cipher unavailable")`;
  - `seal.ErrUnavailable = errors.New("seal: keys unavailable")`.

  None of them matches any existing sentinel.
- **A dependency failure returned by `httpsec`, `authenticate` or `recovery` carries fixed library text** through `internal/diag.Wrap(err, text, kinds...)`, and its log record uses `diag.Failure(reason, err)`, never the error's text (`diagnostic-redaction`). It never matches `httpsec.ErrAuthenticationRequired` or `authenticate.ErrAuthenticationFailed`.
- **A hang-up is classified with `ctx.Err() != nil && errors.Is(err, ctx.Err())`**, the request's own context, never a bare `errors.Is(err, context.Canceled)`: a dependency's own timeout is an outage, not a hang-up (D8).
- **An issuing failure is a dependency failure on every path** (D7): never counted against a source or user, never answered as an invalid link, handoff or recovery.
- **Table tests** follow `.claude/skills/table-test`: the `assert` closure, a `ctx` modifier where context matters, and `t.Context()`. Test doubles come from `use-mockgen`, by regenerating the existing directives (`store/seal`'s `cipher_mock_test.go` and `keyring_mock_test.go`, `session`'s `store_encrypted_mock_test.go`, `token`'s `keysource_mock_test.go`, `httpsec`'s `KeySetProvider` mock). The Docker suites use `use-testcontainers` helpers.
- **Defect reproductions named in `tasks.md` are rewritten as the red step**, under a name that states the behaviour (`TestSealingStore_OpenDeadlineIsAStoreFailure`, not `TestRepro_…`). If one passes before the fix, stop and report: the decision it supports is withdrawn (`defect-claims.md`).
- **Never run** `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`.
- **Agents never edit `openspec/`,** and never read, copy or cite `.claude/.legacy`.
- **A defect found in passing** is reported `REPRODUCED` with its failing test, or `UNREPRODUCED`. It is not fixed in passing.

## Review Focus

1. **A context error wrapped by the cipher** (`fmt.Errorf("kms: %w", context.Canceled)`) must still read as an outage, not as unreadable. Matching uses `errors.Is`. Table case in 2.1.
2. **`identity.ErrUserNotFound` wrapped by a consumer loader** (`fmt.Errorf("db: %w", identity.ErrUserNotFound)`) is still a 401 refusal, not a 500, at resolution and at renewal. Table case in 2.3.
3. **A key source whose `Signer` returns a nil error with a nil signer.** Issuing fails as an outage behind fixed text, never panics, never produces a token. Table case in 5.2.
4. **The caller's step succeeds and the write then fails**, by a lost race or a store outage. The issued credential is never handed out, and it authenticates nothing. Table cases in 6.1 and 6.2.
5. **Two redemptions of one magic link both issue.** Only the consume's winner stores a session; the loser's token, presented as a bearer, is refused as authentication-required. Test in 6.5.

---

## Dispatches and models

| Dispatch | Tasks | Owns | Model, reason | Reviewer |
|---|---|---|---|---|
| main session | 1.1 | `openspec/changes/key-port-context/` | done 2026-11-01 | none |
| A | 2.1 | `session/store_encrypted.go` and its test | Sonnet: an `errors.Is` classification the design fixes exactly | Sonnet |
| R1 | 2.2, 2.3, 2.5 | `httpsec/resolve.go`, `httpsec/session_renewal.go` (its user reload only), `httpsec/bearer_test.go`, `httpsec/session_bearer_test.go`, `httpsec/session_renewal_test.go`, a new `httpsec/resolve_test.go` | Opus: refusal logic on a security path, written for the first time | Opus |
| R2 | 2.6, 2.4, 2.7 | `httpsec/session_bearer.go`, `httpsec/session_renewal.go` (its throttle only), `httpsec/bearer.go`, `authenticate/jwt.go`, their tests | Opus: refusal and charging logic on a security path | Opus |
| R3 | 2.8 | `httpsec/bearer.go` (`notVerified`), `authenticate/jwt.go`, `httpsec/bearer_test.go`, `authenticate/jwt_test.go`, `httpsec/session_bearer_test.go` (guard charging rows only) | Opus: refusal and logging classification on a security path | Opus |
| B | 3.1–3.3 | `store/seal` (all files), the passkey credential files in `store/sqlstore`, `store/gormstore`, `store/pgxstore`, `test/internal/storefix`, `test/storetest` sealed-column suite and `broken_sealed_test.go` | Opus: an interface other packages and modules compile against | Opus |
| C | 4.1–4.4 | `session/store_encrypted.go`, `session` errors, `store/seal/cipher.go` (`SessionCipher` only), `store/seal/errors.go`, `session/helpers_test.go`, `test/storetest/memory_test.go`, `NewSessionStore` godoc in the three SQL stores | Opus: an interface two packages compile against, and outage classification | Opus |
| D | 5.1–5.5 | `token/signingkey` (all files), `token/generator.go`, `token/verifier.go`, their tests and doubles, `httpsec/jwks.go` and its test, every other `KeySource` or `KeySetProvider` caller `gopls` finds | Opus: interfaces several packages compile against | Opus |
| S1 | 6.1, 6.2 | `session/sessions.go`, `session/reuse.go`, their tests | Opus: ordering under races, decided by the store | Opus |
| S2 | 6.3, 6.4 | `httpsec/session_renewal.go`, `httpsec/complete.go`, `httpsec/login.go`, `httpsec/passkey_login.go`, their tests | Opus: credential ordering on a security path | Opus |
| S3 | 6.5, 6.6 | `httpsec/magiclink.go`, `httpsec/oidc_redeem.go`, `authenticate/magiclink/links.go` (godoc), `authenticate/oidc/handoff.go` (godoc), their tests | Opus: check-then-consume | Opus |
| S4 | 6.7, 6.8, 6.9 | `recovery/recover.go`, `recovery/recover_complete.go`, `recovery/hold.go`, `httpsec/recovery.go`, their tests, README | Opus: a refactor of an ordered, security-critical flow | Opus |
| main session + Opus reviewer | 7.1–7.2 | whole branch | | Opus |

**Order** (one lane's dispatches never overlap; different lanes run in parallel where their files and compile units allow):
1. **A and R1 in parallel.** `httpsec` imports `session`, but A changes no signature.
2. **R2 and B in parallel.** No shared file; B builds only `store/*` and `test` while R2 builds `httpsec` and `authenticate`.
3. **C (after A and B) and D (after R2) in parallel.** C changes `session` and `store/seal/cipher.go`; D changes `token`, `token/signingkey` and `httpsec/jwks.go`. The `test` module is built only after both have landed.
4. **R3 after D**, since D changes the `KeySource` doubles in `httpsec/bearer_test.go` and `authenticate/jwt_test.go`; R3 runs beside S1, which touches neither package.
5. **S1 after C**, since both are in `session`. **S2 after S1 and D. S3 after S2**, which owns `complete.go`. **S4 after S3.**
6. **7.1 and 7.2 last.**

After each dispatch the main session runs its verification commands, then a fresh reviewer of the stated model checks the diff against the scenarios the dispatch covers.

---

### Task 2.1: A context error on open is a store failure (dispatch A)

**Files:** Modify `session/store_encrypted.go` (`Load`'s open classification). Test `session/store_encrypted_test.go`.

**Interfaces:** Produces the classification C extends in 4.2: an open error matching `context.Canceled` or `context.DeadlineExceeded` is returned wrapped, not as `session.ErrUnreadable`.

- [ ] **Step 1: Write the failing table** `TestSealingStore_OpenFailureClassification` with rows: `context.DeadlineExceeded`; `fmt.Errorf("kms: %w", context.Canceled)`; a plain `errors.New("bad tag")`. Assert the first two match their context error and do not match `session.ErrUnreadable`; the third matches `session.ErrUnreadable`.
- [ ] **Step 2: Run** `go test -run TestSealingStore_OpenFailureClassification -count=1 ./session/`. Expected FAIL: the deadline rows match `session.ErrUnreadable` (`session: session cannot be read … context deadline exceeded`).
- [ ] **Step 3: Implement** the split in `Load`: context errors wrap through unchanged; everything else stays `ErrUnreadable`.
- [ ] **Step 4: Run** `go test -race -count=1 ./session/`. Expected PASS, with "Sealed round trip", "Value moved between sessions" and "No rewrite on read" green.
- [ ] **Step 5: Commit** `fix(session): a cancelled or timed-out open is a store failure, not an unreadable session`.

### Task 2.2, 2.3, 2.5: Resolution answers outages and hang-ups as what they are (dispatch R1)

**Files:** Modify `httpsec/resolve.go` (session load and user reload classification), `httpsec/session_renewal.go` (its user reload). Test `httpsec/resolve_test.go` (new), `httpsec/bearer_test.go`, `httpsec/session_bearer_test.go`, `httpsec/session_renewal_test.go`.

**Interfaces:** Produces one classifier both paths use, for example `func classifyLoad(ctx context.Context, err error) error` and `func classifyReload(ctx context.Context, err error) error` in `httpsec/resolve.go`: refusals keep their errors; a hang-up returns an error matching `ctx.Err()`; anything else returns `diag.Wrap(err, "httpsec: session could not be resolved")` or `"httpsec: user could not be reloaded"`. R2 reads the result to decide charging.

- [ ] **Step 1: Write the failing table** `TestResolve_DependencyFailureIsNotARefusal`, through the signed bearer and the session-reference bearer, rows:
  - session store returns `errors.New("db down")` → error does not match `ErrAuthenticationRequired`, `errors.Is(err, dbDown)`, text is fixed, status 500 through the default mapping, no undecryptable-session record;
  - user loader returns `errors.New("db down")` → same, no record;
  - user loader returns `fmt.Errorf("db: %w", identity.ErrUserNotFound)` → matches `ErrAuthenticationRequired` (Review Focus 2);
  - session store returns `session.ErrUnreadable` → matches `ErrAuthenticationRequired`, ERROR record written.
- [ ] **Step 2: Write the failing renewal rows** `TestSessionRenewal_UserReloadOutageIsNotARefusal` (outage → 500, no rotation; wrapped not-found → 401), the reproduction of `TestRepro_RenewalUserStoreOutageIsNotARefusal`.
- [ ] **Step 3: Write the failing hang-up table** `TestResolve_HangUpIsNotARefusal`: cancel the request context inside the store's `Load` and inside the loader, at the bearer, the session-reference bearer and the renewal endpoint. Assert `errors.Is(err, context.Canceled)`, not `ErrAuthenticationRequired`, no ERROR record.
- [ ] **Step 4: Run** `go test -run 'TestResolve_|TestSessionRenewal_UserReloadOutage' -count=1 ./httpsec/`. Expected FAIL: `found: "httpsec: authentication required"`, `expected: 500, actual: 401`.
- [ ] **Step 5: Implement** the two classifiers and use them in resolution and the renewal reload.
- [ ] **Step 6: Rewrite on purpose** `bearer_test.go` "the user store is down" and `session_bearer_test.go` "a user store that is down" to expect the dependency failure, and make `TestSessionRenewal_UserReloadPrecedesRotation` and `TestSessionRenewalThrottle_RemovedUserIsNotCharged` return `identity.ErrUserNotFound` for a removed user.
- [ ] **Step 7: Run** `go test -race -count=1 ./httpsec/...`. Expected PASS.
- [ ] **Step 8: Commit** `fix(httpsec): an outage or a hang-up at session resolution is not a refusal`.

### Task 2.6, 2.4, 2.7: Charging refusals only, and the verification outage (dispatch R2)

**Files:** Modify `httpsec/session_bearer.go` (guard charging), `httpsec/session_renewal.go` (late-renewal charging), `httpsec/bearer.go` (verify join), `authenticate/jwt.go` (bearer provider). Test their `_test.go` files.

**Interfaces:** Consumes R1's classifiers. Produces: only `errors.Is(err, token.ErrInvalid)` is joined with `authenticate.ErrAuthenticationFailed`; any other `Verify` error is `diag.Wrap(err, "httpsec: verification keys unavailable")`, logged with `diag.Failure`.

- [ ] **Step 1: Write the failing charging table** `TestSessionReferenceGuard_ChargesRefusalsOnly`: 101 presentations from one source while the store fails → none refused by the guard; rows that an unreadable session and a user who is not the session's, or disabled, are charged. And `TestLateRenewal_OutageIsNotCharged`.
- [ ] **Step 2: Write the failing verification table** `TestBearer_KeySourceOutageIsNotARefusal` with the real `signingkey.Keys`, generator and verifier over a key source whose `VerificationKeys` fails with `errors.New("kms: dependency timeout")`: status 500, error matches neither `ErrAuthenticationFailed` nor `ErrAuthenticationRequired`, no record contains `kms: dependency timeout`. Same split in `authenticate`: `TestJWTProvider_KeySourceOutage`.
- [ ] **Step 3: Run** `go test -run 'TestSessionReferenceGuard_ChargesRefusalsOnly|TestLateRenewal_OutageIsNotCharged|TestBearer_KeySourceOutage' -count=1 ./httpsec/` and `go test -run TestJWTProvider_KeySourceOutage -count=1 ./authenticate/`. Expected FAIL: outages charged; `expected: 500, actual: 401`.
- [ ] **Step 4: Implement** charging on refusals only, and the `token.ErrInvalid` split in both places. Rewrite `TestBearerToken`'s tampered-token case to mock `Verify` with an error wrapping `token.ErrInvalid`.
- [ ] **Step 5: Run** `go test -race -count=1 ./httpsec/... ./authenticate/...` and `go test ./...` in `test` (2.7: the refusal scenarios pass unchanged). Expected PASS.
- [ ] **Step 6: Commit** `fix(httpsec): charge refusals only; a key source outage at verification is a dependency failure`.

### Task 2.8: A hang-up during verification is not a key outage (dispatch R3)

**Files:** Modify `httpsec/bearer.go` (`notVerified`), `authenticate/jwt.go` (the bearer provider's verify error). Test `httpsec/bearer_test.go`, `authenticate/jwt_test.go`, `httpsec/session_bearer_test.go`.

**Interfaces:** Consumes `endedByRequest(ctx, err) bool` from `httpsec/resolve.go` (R1) and D's `KeySource` signatures. Produces, in both places, a third outcome beside the `token.ErrInvalid` refusal and the outage: a hang-up returns `diag.Wrap(err, text, ctx.Err())` with fixed text `httpsec: the request ended while its token was verified` and `authenticate: the caller left while the token was verified`, and writes no ERROR record (a debug record at most, carrying no error text). The order is: `token.ErrInvalid` first, then hang-up, then outage.

- [ ] **Step 1: Write the failing table** `TestBearer_HangUpDuringVerificationIsNotAnOutage`, with the real `signingkey.Keys`, generator and verifier, rows:
  - a correctly signed token on an already-cancelled request context → `errors.Is(err, context.Canceled)`; matches neither `authenticate.ErrAuthenticationFailed` nor `ErrAuthenticationRequired`; text is the hang-up text, not `httpsec: verification keys unavailable`; no record with `reason=verification-keys` at ERROR;
  - a key source whose `VerificationKeys` returns `context.DeadlineExceeded` of its own while the request context is live → still the outage: verification-keys text, ERROR record, 500.
- [ ] **Step 2: Write the failing table** `TestJWTProvider_CallerLeavesDuringVerification`, with the same two rows against the provider: the hang-up text, and the outage text `authenticate: verification keys unavailable`.
- [ ] **Step 3: Add pinning rows** to `TestSessionReferenceGuard_ChargesRefusalsOnly`: the store answers `session.ErrExpired`, and `session.ErrReused` → each charged once. These pin today's behaviour, so they pass at once. Show they bite by disabling the guard's charge in a scratch copy.
- [ ] **Step 4: Run** `go test -run 'TestBearer_HangUpDuringVerification|TestSessionReferenceGuard_ChargesRefusalsOnly' -count=1 ./httpsec/` and `go test -run TestJWTProvider_CallerLeaves -count=1 ./authenticate/`. Expected FAIL on the hang-up rows: `expected: "httpsec: the request ended while its token was verified", actual: "httpsec: verification keys unavailable"`, and a `verification-keys` ERROR record.
- [ ] **Step 5: Implement** the hang-up branch in both places, classified on the request's own context, never by a bare `errors.Is(err, context.Canceled)`. Update the godoc of `EnableBearerToken` and the provider.
- [ ] **Step 6: Run** `go test -race -count=1 ./httpsec/... ./authenticate/...` and `golangci-lint run ./httpsec/... ./authenticate/...`. Expected PASS, 0 issues.
- [ ] **Step 7: Commit** `fix(httpsec): a client that leaves during verification is not reported as a key outage`.

### Task 3.1–3.3: Context on `seal.Keyring` and `seal.Cipher` (dispatch B)

**Files:** Modify `store/seal/keyring.go`, `store/seal/cipher.go`, `store/seal/mfa.go`, `store/seal/signingkey.go`, the passkey credential files in `store/sqlstore`, `store/gormstore`, `store/pgxstore`, `test/internal/storefix`, `test/storetest` (sealed-column suite, `broken_sealed_test.go`). Regenerate `store/seal` mocks.

**Interfaces:** Produces the D1 signatures for `Keyring` and `Cipher` exactly as `design.md` gives them. C consumes `Cipher.Open(ctx, …)` in `SessionCipher`.

- [ ] **Step 1: Write the failing tests:** `TestAEADCipher_AnswersUnderCancelledContext` (seal and open under a cancelled context succeed and round-trip); `TestAEADCipher_PassesContextToKeyring` (a recording keyring sees the cipher's context value); `TestEnrolmentStore_CipherCarriesStoreContext` (seal and open carry the store call's context value); `TestEnrolmentStore_ResealOutageDoesNotFailRead` (cipher opens, then fails `ActiveKeyID` with `errors.New("kms: unavailable")`: read returns the secret, stored value unchanged; C adds the `seal.ErrUnavailable` row in 4.3).
- [ ] **Step 2: Run** `go test -run 'TestAEADCipher_|TestEnrolmentStore_' -count=1 ./store/seal/`. A compile error is not the red step: first add the parameters with bodies that ignore `ctx`, then run. Expected FAIL on the context assertions (`context value: <nil>`).
- [ ] **Step 3: Implement** the signatures through every caller in the Files list, including `activeKeyForReseal(ctx)`, the passkey `scan`/`query`/`list`/`fromRow`/`one`/`List` helpers and `ChargeEmailAttempt`; regenerate the mocks; update `storefix` and `broken_sealed_test.go`.
- [ ] **Step 4: Extend the sealed-column suite** with `cipher carries the operation's context`: a recording cipher, every sealed column written and read under a context value, the passkey emailed code included; prove it fails against a store whose helper uses `context.Background()` by temporarily inverting one helper.
- [ ] **Step 5: Run** `go test -race -count=1 ./store/...`, `make check`. Expected PASS; the Docker suites run in CI.
- [ ] **Step 6: Godoc (3.3)** on `Keyring` and `Cipher`: honour the context; cache or use envelope encryption. Check with `go doc ./store/seal Keyring`.
- [ ] **Step 7: Commit** `feat(seal)!: the keyring and the cipher take a per-call context`.

### Task 4.1–4.4: Context on `session.Cipher`, and the outage marker (dispatch C)

**Files:** Modify `session/store_encrypted.go`, `session` errors, `store/seal/cipher.go` (`SessionCipher`), `store/seal/errors.go`, `session/helpers_test.go`, `test/storetest/memory_test.go`, `NewSessionStore` godoc in `store/sqlstore`, `store/pgxstore`, `store/gormstore`. Regenerate the `session` cipher mock.

**Interfaces:** Produces `session.Cipher` with `ctx` first, `session.ErrCipherUnavailable`, `seal.ErrUnavailable`.

- [ ] **Step 1: Write the failing tests:** `TestSealingStore_CipherCarriesContext` (save and load context values reach the cipher); extend `TestSealingStore_OpenFailureClassification` with rows: an error joining `session.ErrCipherUnavailable` → matches it, not `ErrUnreadable`; joining the marker with `errors.New("bad tag")` → outage (the marker wins); `TestSessionCipher_TranslatesUnavailable` (`seal.ErrUnavailable` → `session.ErrCipherUnavailable`; `context.Canceled` passes through; `seal.ErrUnavailable` matches neither `seal.ErrDecryptionFailed` nor `seal.ErrUnknownKeyID`); `TestEnrolmentStore_OutageIsDistinguishable` (an enrolment read through a cipher whose open wraps `seal.ErrUnavailable` → matches it, not `ErrDecryptionFailed` or `ErrUnknownKeyID`); and a `seal.ErrUnavailable` row in `TestEnrolmentStore_ResealOutageDoesNotFailRead`.
- [ ] **Step 2: Run** `go test -run 'TestSealingStore_|TestSessionCipher_' -count=1 ./session/ ./store/seal/`. Expected FAIL on the marker rows (`matches session.ErrUnreadable`).
- [ ] **Step 3: Implement** the signature through the sealing helper reached from `Create`, `Save` and `Supersede`, the marker classification, and the translation.
- [ ] **Step 4: Godoc (4.4):** which errors read as an outage and how a remote cipher marks one, on `session.Cipher`, `seal.Cipher`, `seal.SessionCipher` and each `NewSessionStore`.
- [ ] **Step 5: Run** `go test -race -count=1 ./session/ ./store/...` and `go vet ./...` in `test`. Expected PASS.
- [ ] **Step 6: Commit** `feat(session)!: the session cipher takes a context, and a marked outage is not an unreadable session`.

### Task 5.1–5.5: `KeySource`, `ErrNoKey` and `KeySetProvider` (dispatch D)

**Files:** Modify `token/signingkey/keysource.go`, `token/signingkey/keys.go`, `token/generator.go`, `token/verifier.go`, `httpsec/jwks.go`, the doubles in `token/consumerkeysource_test.go`, `token/generator_test.go`, `token/verifier_test.go`, `token/signingkey/keysource_test.go`, `test/httpsecconformance` if it implements either port. Regenerate the `KeySource` and `KeySetProvider` mocks.

**Interfaces:** Produces `Signer(ctx, alg) (string, crypto.Signer, error)`, `VerificationKeys(ctx) ([]PublicKey, error)`, `KeySetProvider.JWKS(ctx) ([]byte, error)`, `signingkey.ErrNoKey`. The generator's failure text is fixed: `token: no current key for the algorithm` for `ErrNoKey`, `token: signing key unavailable` for anything else.

- [ ] **Step 1: Write the failing tests:** `TestKeys_SignerReportsNoKey` (EdDSA on an RS256-only manager; ES256 published from another replica) → `errors.Is(err, signingkey.ErrNoKey)`; `TestKeys_AnswersUnderCancelledContext`; `TestGenerator_KeySourceOutage` (rows: outage error → wraps it, not `ErrNoKey`, no token; nil error with nil signer → outage, no panic — Review Focus 3); `TestGenerator_AsksForASignerPerToken` (three tokens, three requests, each signer signs once); `TestKeySource_ReceivesCallersContext` (issue and verify under distinct context values); `TestJWKS_RequestContextAndOutage`.
- [ ] **Step 2: Run** `go test -run 'TestKeys_|TestGenerator_|TestKeySource_' -count=1 ./token/...` and `go test -run TestJWKS_ -count=1 ./httpsec/`. Expected FAIL on the assertions after the signatures compile (`ok == false` mapped to plain text; context value `<nil>`).
- [ ] **Step 3: Implement** the signatures and the generator's two failure texts through every caller `gopls` finds; the JWKS endpoint passes the request context and returns `diag.Wrap`.
- [ ] **Step 4: Godoc (5.5)** of `KeySource`, `Signer`, `KeySetProvider`, as `tasks.md` 5.5 lists.
- [ ] **Step 5: Run** `go test -race -count=1 ./token/... ./httpsec/...`, then `go vet ./...` in `test` once C has landed. Expected PASS.
- [ ] **Step 6: Commit** `feat(signingkey)!: the key source takes a context and reports a missing key apart from an outage`.

### Task 6.1, 6.2: Creation and grace rotation the caller completes (dispatch S1)

**Files:** Modify `session/sessions.go`, `session/reuse.go`. Test their `_test.go` files.

**Interfaces:** Produces, beside `RotateIssuing` and in its style (names indicative; record any change in the report):
- `func (m *Sessions) Prepare(user identity.UserID, opts ...CreateOption) (*Prepared, error)`;
- `func (p *Prepared) Session() *Session`;
- `func (p *Prepared) Commit(ctx context.Context) (*Session, error)`;
- `func (m *Sessions) CreateIssuing(ctx context.Context, user identity.UserID, issue func(*Session) (string, error), opts ...CreateOption) (*Session, string, error)`;
- `func (m *Sessions) RotateWithGraceIssuing(ctx context.Context, s *Session, grace time.Duration, issue func(*Session) (string, error), opts ...RotateOption) (*Session, RenewalKind, string, error)`.

`Create` becomes `Prepare` then `Commit`; `RotateWithGrace` becomes `RotateWithGraceIssuing` with no step.

- [ ] **Step 1: Write the failing tables** `TestCreateIssuing` (step fails → nothing stored for the user; a load of the identifier inside the step → not found; success → loads; the store's `Create` fails after the step succeeded → error, credential not returned — Review Focus 4) and `TestRotateWithGraceIssuing` (step fails → nothing superseded, 31 s later the old identifier loads and no reuse is observed; two concurrent rotations with successful steps → one successor stored, the other loads nothing; a 5-second step at 10:00:00 with 30 s grace → old identifier loads until 10:00:30; the supersession fails after the step → credential not returned).
- [ ] **Step 2: Run** `go test -run 'TestCreateIssuing|TestRotateWithGraceIssuing' -count=1 ./session/`. Expected FAIL: undefined is a compile error, so stub the methods returning `errors.New("not implemented")` first; then FAIL on the assertions.
- [ ] **Step 3: Implement**, reading the clock before the step, as `RotateIssuing` does.
- [ ] **Step 3a (6.2, added 2026-11-01): Write the failing row** in `TestRotateWithGraceIssuing`: 30 s grace at 10:00:00, a step that advances the clock 31 s and succeeds → `errors.Is(err, context.DeadlineExceeded)`, empty credential, nothing superseded or revoked, the old identifier loads with no reuse observed, and a second rotation succeeds. Run it; expected FAIL: the supersession is written and the old identifier reads as reuse. Then re-read the clock after the step in `RotateWithGraceIssuing` and, when `grace > 0` and the window has closed, return `diag.Wrap(context.DeadlineExceeded, "session: the credential was issued after the grace window")` before any write.
- [ ] **Step 3b (review follow-ups):** `Prepared.Commit` repeats `Prepare`'s lifetime checks before the write (lifetime in (0, max], idle deadline capped at the absolute one), refusing with `ErrConfig`, test-first; `Prepared.Session` godoc says the identifier, user, family and deadlines must not be changed; a `TestRotateWithGraceIssuing` row for reuse after a successful step (`ErrSuccessorAdvanced` during the step → `ErrReused`, family revoked, empty credential, observer once); a godoc note on `RotateWithGraceIssuing` that a save of the old session during the step is not carried to the successor.
- [ ] **Step 4: Run** `go test -race -count=1 ./session/` and the session store conformance suites (`go test ./...` in `test`, CI). Expected PASS, the existing grace and reuse scenarios unchanged.
- [ ] **Step 5: Commit** `feat(session): creation and grace rotation the caller completes before anything is stored`.

### Task 6.3, 6.4: Renewal and login completion issue first (dispatch S2)

**Files:** Modify `httpsec/session_renewal.go`, `httpsec/complete.go` (`completeLogin`, `credentialIssuer` use), `httpsec/login.go`, `httpsec/passkey_login.go`. Test their `_test.go` files.

**Interfaces:** Consumes S1's methods. Produces, in `httpsec/complete.go`, a completion that accepts an optional spend step run after issuing and before `Commit`, for S3: for example `completeLogin(ctx, ex, in loginInput, spend func(context.Context) error)`. A spend failure discards the credential and stores nothing.

- [ ] **Step 1: Write the failing tests:** `TestSessionRenewal_IssueFailureDoesNotLaterReadAsReuse` (failing generator; clock +31 s; the old credential loads and renews; reuse observer count 0); `TestFormLogin_TokenCannotBeIssued` (key source fails → error matches neither `ErrAuthenticationFailed` nor `ErrAuthenticationRequired`, the store holds no session); `TestCompleteLogin_ChallengeStoredBeforeHandOut` (enrolment challenge: the session is in the store, enrolment-pending, before the response is written, in one write).
- [ ] **Step 2: Run** `go test -run 'TestSessionRenewal_IssueFailure|TestFormLogin_TokenCannotBeIssued|TestCompleteLogin_ChallengeStored' -count=1 ./httpsec/`. Expected FAIL: `session: a superseded session was presented after its window`, reuse observer `1`; a session stored for the failed login.
- [ ] **Step 3: Implement** renewal through `RotateWithGraceIssuing`, and `completeLogin` through `Prepare`, mark, issue, spend, `Commit`, hand out.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/...` and `go test ./...` in `test`. Expected PASS.
- [ ] **Step 5: Commit** `fix(httpsec): renewal and login completion issue the credential before anything is stored`.

### Task 6.5, 6.6: Redemptions issue inside the check (dispatch S3)

**Files:** Modify `httpsec/magiclink.go`, `httpsec/oidc_redeem.go`; godoc of `magiclink.Check` (`authenticate/magiclink/links.go`) and `oidc.RedeemCheck` (`authenticate/oidc/handoff.go`). Test their `_test.go` files.

**Interfaces:** Consumes S2's completion with its spend step. The redeemer's check builds and issues; the redeemer's consume is the spend; `Commit` runs after the redeemer returns.

- [ ] **Step 1: Write the failing tests:** `TestMagicLink_CredentialCannotBeIssuedKeepsLink` (first redemption fails as a dependency failure, not an invalid link, no session, nothing charged; second succeeds); `TestMagicLink_RacingRedemptionsStoreOneSession` (16 concurrent redemptions → one success, one stored session; a loser's token presented as a bearer → `ErrAuthenticationRequired` — Review Focus 5); `TestOIDCHandoff_CredentialCannotBeIssuedKeepsCode`.
- [ ] **Step 2: Run** `go test -run 'TestMagicLink_|TestOIDCHandoff_CredentialCannotBeIssued' -count=1 ./httpsec/`. Expected FAIL: the second redemption is refused, the link or code spent.
- [ ] **Step 3: Implement** the reordering, and the godoc on both check types: the library may issue a credential between the checks and the consume, and discards it on a lost race.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/... ./authenticate/magiclink/... ./authenticate/oidc/...`. Expected PASS.
- [ ] **Step 5: Commit** `fix(httpsec): a link or handoff code is spent only after its credential is issued`.

### Task 6.7, 6.8, 6.9: Recovery issues before it spends (dispatch S4)

**Files:** Modify `recovery/recover.go` (`Request`), `recovery/recover_complete.go`, `recovery/hold.go`, `httpsec/recovery.go`; README. Test their `_test.go` files.

**Interfaces:** Produces `type IssueFunc func(ctx context.Context, s *session.Session) (string, error)` in `recovery`; `Request.Issue IssueFunc`; `Finish(ctx context.Context, completionToken string, issue IssueFunc) (*Result, error)`; `Result.Credential string`. The core builds the recovery-pending session with S1's `Prepare`, calls `issue` after the checks and before any spend, and `Commit`s after reset, revocation and code replacement. `httpsec/recovery.go` passes its `credentialIssuer` and stops issuing after the core returns.

- [ ] **Step 1: Write the failing tests:** `TestRecover_IssueFailureSpendsAndEndsNothing` (saved code + password, failing issue: the error is a dependency failure; the earlier session loads; a second code of the old set confirms; nothing recorded against the user or the source; no notice queued) and `TestFinish_IssueFailureLeavesRecordPending` (a held recovery finished while issue fails: record pending, token usable, authenticators and sessions unchanged; finish again succeeds).
- [ ] **Step 2: Run** `go test -run 'TestRecover_IssueFailure|TestFinish_IssueFailure' -count=1 ./recovery/`. Expected FAIL: `session: session not found` for the earlier session; the old code refused.
- [ ] **Step 3: Implement** the hook and the reordering; one creating write, already recovery-pending.
- [ ] **Step 4: Godoc and README (6.9)** for every seam 6.1–6.8 changed: issue before store or spend; an issuing failure is a dependency failure.
- [ ] **Step 5: Run** `go test -race -count=1 ./recovery/... ./httpsec/...`, `golangci-lint run ./...`. Expected PASS.
- [ ] **Step 6: Commit** `fix(recovery): a recovery spends and replaces nothing for a credential it could not issue`.

### Task 7.1, 7.2: The gate and the whole-branch review (main session)

- [ ] **Step 1 (7.1):** `make check` locally, then CI green on both PostgreSQL and Redis matrix jobs. Record the output.
- [ ] **Step 2 (7.2):** dispatch a fresh Opus reviewer over the whole branch against every requirement of the eleven deltas and D1–D8. A finding needs a failing test or an `UNREPRODUCED` label.
- [ ] **Step 3:** `openspec validate key-port-context --strict`. Expected `Change 'key-port-context' is valid`.

## Group 8: Review findings (added 2026-11-01)

Every defect here was reproduced in a disposable copy (`tasks.md` group 8 names the tests). Each task writes that test again in the tree as its red step and watches it fail for the claimed reason before fixing. Tasks 8.1 to 8.5 own disjoint packages and run in parallel; 8.6 runs in its own worktree, since it compiles `httpsec` beside 8.1.

**Review Focus (group 8):**
1. A context cancelled with a cause, where the dependency returns the cause rather than `context.Canceled`: answered as a hang-up everywhere one is told (8.1).
2. A password login or recovery proof whose load ends with a cause: still charged to its source, as today. The shared predicate must not change the guess paths (8.1).
3. A prepared session that a library path marks before commit (enrolment, recovery-pending, an OIDC provider session): still committed. Only identity changes and later deadlines are refused (8.2).
4. A step that ends exactly at the session's absolute deadline: refused, because the window closes at it (8.4).
5. A key source error that names its key inside a wrapped cause: no record contains the name (8.6).

### Task 8.1: One hang-up predicate, cause included (dispatch R8a, Opus)

Opus, because the refactor spans `httpsec`, `authenticate` and `recovery`, and must keep the guess paths' charging.

**Files:** Create `internal/hangup/hangup.go` and `hangup_test.go`. Modify `httpsec/resolve.go` (`endedByRequest`), `httpsec/login.go` (`loadEndedByCaller`, which keeps its `authenticate.ErrAuthenticationFailed` precondition), `authenticate/jwt.go` (`callerLeft`), `recovery/recover.go` (`loadEndedByCaller`). Test `httpsec/bearer_test.go`, `httpsec/resolve_test.go`, `authenticate/jwt_test.go`.

**Interfaces:** Produces `func hangup.ByCaller(ctx context.Context, err error) bool`: true when `ctx.Err() != nil` and `err` matches `ctx.Err()` or `context.Cause(ctx)`.

- [ ] **Step 1: Write the failing tests:** rows in the existing hang-up tables (`TestBearer_HangUpDuringVerificationIsNotAnOutage`, the resolution hang-up rows, `TestJWTProvider_CallerLeavesDuringVerification`) using `context.WithCancelCause` and a dependency returning `context.Cause(ctx)`. Each asserts the hang-up text, `errors.Is(err, cause)`, and no ERROR record. Add a table test of `hangup.ByCaller`: live context → false; cancelled, err `Canceled` → true; cancelled with cause, err cause → true; cancelled, unrelated err → false.
- [ ] **Step 2: Run** `go test -run 'HangUp|CallerLeaves|ByCaller' -count=1 ./httpsec/ ./authenticate/ ./internal/hangup/`. Expected FAIL: `httpsec: verification keys unavailable`, `httpsec: session could not be resolved`, `authenticate: verification keys unavailable`.
- [ ] **Step 3: Implement** `hangup.ByCaller`, and make all four helpers call it.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/... ./authenticate/... ./recovery/... ./internal/...`. Expected PASS, with the existing password-login and recovery hang-up charging rows unchanged.
- [ ] **Step 5: Commit** `fix(httpsec,authenticate): a request cancelled with a cause is a client that left`.

### Task 8.2: Commit refuses a session changed beyond marking (dispatch R8b, Sonnet)

**Files:** Modify `session/prepared.go` (`Prepared`, `Prepare`, `Commit`, the `Prepared.Session` godoc). Test `session/prepared_test.go`.

**Interfaces:** `Prepared` keeps a snapshot, taken in `Prepare`, of `ID`, `UserID`, `FamilyID`, the family start, `CreatedAt`, `AuthenticatedAt`, `IdleExpiresAt` and `AbsoluteExpiresAt`. `Commit` returns an error matching `ErrConfig`, and stores nothing, when an identity field differs or a deadline is after its snapshot. The field names are the `Session` struct's own.

- [ ] **Step 1: Write the failing tests:** rows in a `TestPrepared_Commit` table: a changed ID; a changed user; an absolute deadline lengthened within the maximum; an idle deadline lengthened; a deadline shortened by `MarkEnrolmentPending` (stored); `MarkRecoveryPending` (stored). The refused rows assert `ErrConfig` and that neither identifier loads.
- [ ] **Step 2: Run** `go test -run TestPrepared_Commit -count=1 ./session/`. Expected FAIL: `got nil` for the changed ID and the lengthened deadlines.
- [ ] **Step 3: Implement** the snapshot and the check.
- [ ] **Step 4: Run** `go test -race -count=1 ./session/... ./httpsec/... ./recovery/...`. Expected PASS. A library caller refused here is reported, not loosened.
- [ ] **Step 5: Commit** `fix(session): a prepared session is committed only as it was built, apart from its marks`.

### Task 8.3: The missing-key error names the algorithm, and the caller's deadline reaches the key source (dispatch R8c, Sonnet)

**Files:** Modify `token/generator.go`. Test `token/generator_test.go`, `token/verifier_test.go`.

- [ ] **Step 1: Write the failing tests:** `TestGenerator_NoKeyNamesTheAlgorithm` (EdDSA over an RS256-only `signingkey.Keys`: the error text contains `"EdDSA"` and matches `signingkey.ErrNoKey`). Rows in the context-passing tests whose context carries a deadline, asserting `Deadline()` is the same inside `Signer` and `VerificationKeys`. Deliberately rewrite the expected text in `TestGenerateRefusesRatherThanIssuingAnUnusableToken` and `TestGenerator_KeySourceOutage`.
- [ ] **Step 2: Run** `go test -run 'NoKey|Deadline|KeySourceOutage|RefusesRather' -count=1 ./token/`. Expected FAIL: `token: no current key for the algorithm` does not contain `EdDSA`. A deadline row that passes at once is shown failing by wrapping the context with `context.WithTimeout` inside the generator, then reverted.
- [ ] **Step 3: Implement** `diag.Wrap(err, fmt.Sprintf("token: no current key for algorithm %q", cfg.alg))`.
- [ ] **Step 4: Run** `go test -race -count=1 ./token/...`. Expected PASS.
- [ ] **Step 5: Commit** `fix(token): the missing-key error names the configured algorithm`.

### Task 8.4: The grace step's absolute-deadline cap, and the mark-carrying limit (dispatch R8b, after 8.2)

This task runs in the same lane as 8.2, after it, because both are in `session`.

**Files:** Modify the `session/reuse.go` godoc of `RotateWithGraceIssuing`. Test `session/reuse_test.go`.

- [ ] **Step 1: Write the test:** a `TestRotateWithGraceIssuing` row whose session's absolute deadline is 10 s away, with a 30 s grace and a step that takes 15 s. It asserts `errors.Is(err, context.DeadlineExceeded)`, nothing stored or superseded, and the old identifier loading.
- [ ] **Step 2: Show it red by mutation:** remove the absolute-deadline cap in `reuse.go`, run `go test -run TestRotateWithGraceIssuing -count=1 ./session/` and see the row fail, then revert by editing back.
- [ ] **Step 3: Godoc:** a mark saved on the old session during the step is not carried to the successor; confinement relies on per-request policies raising their marks again.
- [ ] **Step 4: Run** `go test -race -count=1 ./session/`. Expected PASS.
- [ ] **Step 5: Commit** `test(session): pin the absolute-deadline cap on a grace rotation's step`.

### Task 8.5: `seal` stores tell an outage and a hang-up apart (dispatch R8d, Sonnet)

**Files:** Test `store/seal/signingkey_test.go`, `store/seal/mfa_test.go`.

- [ ] **Step 1: Write the tests:** for the signing-key store's `LoadAll` and the MFA store's `Get`, a cipher failing with `context.DeadlineExceeded` → the error matches it; a cipher failing with `seal.ErrUnavailable` → the error matches it and matches neither `seal.ErrDecryptionFailed` nor `seal.ErrUnknownKeyID`. For the re-seal on read, a re-seal failing with `context.Canceled` → the read still succeeds.
- [ ] **Step 2: Show each red by mutation:** in a store, replace the cipher's error with a fixed one (`errors.New`) and see the rows fail, then revert.
- [ ] **Step 3: Run** `go test -race -count=1 ./store/seal/...`. Expected PASS.
- [ ] **Step 4: Commit** `test(seal): pin that the seal stores keep a hang-up and a marked outage apart`.

### Task 8.6: Remaining coverage gaps (dispatch R8e, Sonnet, own worktree)

**Files:** Test only: `httpsec/session_bearer_test.go`, `httpsec/bearer_test.go` (only the "Key source names its key" check), an issuing-path test file, `httpsec/oidc_redeem_test.go`, `httpsec/magiclink_test.go`, `httpsec/recovery_test.go`, `recovery/hold_test.go`. Because R8a also edits `bearer_test.go`, the "Key source names its key" assertion goes to R8a, and R8e does not touch that file.

- [ ] **Step 1: Write one row per gap in `tasks.md` 8.6,** each with its assertion:
  - a late renewal refused as not found is charged once;
  - an issuing path behind the real generator with a failing key source leaves no record containing the source's text;
  - the provider's verifier receives a context equal to the caller's;
  - a finish whose issue fails leaves the saved codes unreplaced;
  - an HTTP recovery whose issue fails leaves the authenticators unchanged;
  - the losers' tokens in `TestOIDCRedeemRacing` load nothing;
  - the OIDC issuing-failure answer has exactly the fixed text;
  - the source limiter records nothing on an issuing failure (magic link and OIDC).
- [ ] **Step 2: Show each red by a mutation** of the code it pins, then revert by editing back. Record the failing lines.
- [ ] **Step 3: Run** `go test -race -count=1 ./httpsec/... ./authenticate/... ./recovery/...`. Expected PASS.
- [ ] **Step 4: Commit** in the worktree: `test(httpsec,recovery): close the whole-branch review's coverage gaps`.

### After group 8 (main session)

Verify and review each dispatch. Then re-run 7.1 (`make check`, and CI after marking PR #39 ready), and close 7.2 with a review of the group-8 diff against D2, D7 and D8.

## Group 9: Second review findings (added 2026-11-01)

Each defect was reproduced in a disposable copy (`tasks.md` group 9 names the tests). Each task writes that test again in the tree as its red step and watches it fail for the claimed reason before fixing.

**Lanes, by file ownership:**

| Lane | Tasks | Owns | Runs |
|---|---|---|---|
| H, httpsec refusal logic | 9.1, 9.2, 9.5 | `httpsec/session_renewal.go`, `httpsec/errors.go`, `httpsec/complete.go`, `httpsec/recovery.go`, `httpsec/redemption.go`, their tests, and the `recovery/recover_complete.go` godoc | main tree; Opus, because it is refusal versus outage classification |
| O, expiry at the spend | 9.3 | `token/onetime/*.go`, `authenticate/oidc/handoff.go`, their tests, and the magic-link HTTP row in `httpsec/magiclink_test.go`, added only after H lands | own worktree; Sonnet |
| S, family end | 9.4 | `session/reuse.go`, `session/reuse_test.go` | own worktree; Sonnet |
| R, refactor | 9.6 | `authenticate/password.go`, `recovery/codes.go`, `httpsec/apikey.go`, `httpsec/resolve.go`, `httpsec/bearer.go`, `httpsec/basic.go`, `httpsec/login.go`, `recovery/recover.go`, `token/generator.go`, and `httpsec/session_renewal.go`'s calls | after H, O and S have landed, because it edits files H owns; Sonnet, since it is identical code moved, pinned by existing tests |

9.7 is the main session's: a fresh Opus review of the group-9 diff.

**Review Focus (group 9):**
1. A link or code checked at its last valid instant and spent at expiry: refused at the spend, since "at and after its expiry" includes the instant itself (9.3).
2. A consumer generator whose error wraps `authenticate.ErrAuthenticationFailed`, not only `ErrUnavailable`: still 500 (9.2).
3. A recovery whose issuer fails with a wrapped refusal sentinel: still answered as the recovery endpoint's dependency failure, and not charged (9.2).
4. `RotateIssuing` (no grace, MFA and re-proof) with a step crossing the family's end: the same refusal as the grace rotation, or a row proving it is already refused (9.4).
5. A hang-up during the late-renewal load that reached no verdict: still a hang-up, not charged. The existing row must stay green under 9.1's reorder.

### Task 9.1: A verdict wins over a hang-up at renewal (lane H)

**Files:** Modify `httpsec/session_renewal.go` (`renewing`). Test `httpsec/session_bearer_test.go`.

- [ ] **Step 1: Write the failing test.** Add a `TestSessionBearerLateRenewals` row in which the store's load returns `errors.Join(session.ErrReused, ctx.Err())` on a cancelled request. Assert that the error matches `ErrAuthenticationRequired` and `session.ErrReused`, and that exactly one failure is recorded.
- [ ] **Step 2: Run** `go test -run TestSessionBearerLateRenewals -count=1 ./httpsec/`. Expected FAIL: `"httpsec: the request ended while its session loaded"`, `has 0`.
- [ ] **Step 3: Implement.** In `renewing`, classify with `refusedRenewal` (or `renewalRefusal`) first, and ask `endedByRequest` only when no refusal was found.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/...`. Expected PASS, Review Focus 5 included.

### Task 9.2: An issuing failure is never a refusal (lane H)

**Files:** Modify `httpsec/complete.go` (`signedTokens`), `httpsec/errors.go` (`StatusForError`), `httpsec/recovery.go` (the recovery issuer), and the `rotationFailure` godoc. Test an issuing-failure table in `httpsec/issuing_keysource_test.go`, and an internal test for the recovery issuer's own branch (`httpsec/recovery_internal_test.go`, or the existing internal test file gopls finds).

**Interfaces:** Produces an unexported `type issueFailure struct{ err error }` with `Error() string` (fixed library text) and `Unwrap() error`. `signedTokens` and the recovery issuer return `&issueFailure{err}` on failure. `StatusForError` returns 500 when `errors.As(err, new(*issueFailure))`, before it checks the challenge and the table.

- [ ] **Step 1: Write the failing test.** `TestIssuingFailureIsNeverARefusal` is a table over renewal, form login, a magic-link redemption, MFA verification and recovery completion, each with a generator that fails with `fmt.Errorf("kms: %w", authenticate.ErrUnavailable)`, plus one row with `authenticate.ErrAuthenticationFailed` (Review Focus 2 and 3). Assert status 500 through the default mapping, that the cause is reachable with `errors.Is`, and that nothing is charged.
- [ ] **Step 2: Run** `go test -run TestIssuingFailureIsNeverARefusal -count=1 ./httpsec/`. Expected FAIL: `status=401`.
- [ ] **Step 3: Implement** the mark and the mapping. The text stays the issuer's existing fixed text.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/...`. Expected PASS.

**Follow-up after the group-9 review (lane H, dispatch H2).** The recovery issuer's own mark (`httpsec/recovery.go`, `issueRecovered`) is redundant where the shared issuer already marked the error; the branch that needs it, a nil user before the shared issuer runs, is untested.

- [ ] **Step 5: Write the pin.** An internal test (`package httpsec`) `TestIssueRecovered_NilUserIsAnIssuingFailure`: `issueRecovered(ctx, s, nil)` returns an error for which `StatusForError` is 500 and `errors.As(err, new(*issueFailure))` holds.
- [ ] **Step 6: See it fail by mutation.** Replace that branch's `issuingFailure(...)` with an unmarked error; run `go test -run TestIssueRecovered_NilUserIsAnIssuingFailure -count=1 ./httpsec/`. Expected FAIL on the `errors.As` assertion: an unmarked unknown error also maps to 500, so the mark, not the status, is what this pins. Restore by hand.
- [ ] **Step 7: Godoc.** `StatusForError`: an issuing failure is answered 500 even when a refusal is joined beside it, not only when its cause wraps one.

### Task 9.5: A redemption forgets an issuing failure once a later issue succeeds; the recovery limit is stated (lane H)

**Files:** Modify `httpsec/redemption.go` (`redemptionLogin.issue`, `countsAgainstSource`) and the `recovery/recover_complete.go` godoc of `WithCredentialIssuer`. Test `httpsec/magiclink_test.go` (`TestRedeemerGuard`).

- [ ] **Step 1: Write the failing test.** Add a `TestRedeemerGuard` row in which a redeemer's first issue fails, a retried issue succeeds, and it then fails with `errors.Join(firstErr, ErrInvalidLink)`. Assert one failure charged.
- [ ] **Step 2: Run.** Expected FAIL: `expected: 1 actual: 0`.
- [ ] **Step 3: Implement** `r.out.issueErr = nil` once the issue succeeds. Godoc: a recovery slower than its session's lifetime stores an expired session; the response still carries the new saved codes.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/... ./recovery/...`. Expected PASS.

**Follow-up after the group-9 review (lane H, dispatch H2).** `countsAgainstSource` (`httpsec/redemption.go`) recognises only the last issuing failure, by identity; each `signedTokens` failure is a new `*issueFailure`.

- [ ] **Step 5: Write the failing test.** A `TestRedeemerGuard` row, "a redeemer whose every issue failed and that returns its first failure is not charged": the generator always fails with `errKeySourceDown`; the redeemer runs the checks twice and returns the first error; the limiter is `countingLimiter(t, 0)`; the result matches `errKeySourceDown` and `StatusForError` is 500.
- [ ] **Step 6: Run** `go test -run 'TestRedeemerGuard' -count=1 ./httpsec/`. Expected FAIL: `Unexpected call to *httpsec_test.MockLimiter.RecordFailure(... magic-link-redeem:203.0.113.7)`.
- [ ] **Step 7: Implement.** In `countsAgainstSource`, while `out.issueErr != nil`, an error matching `out.issueErr` or carrying any `*issueFailure` (`errors.As`) is not charged. Once a later issue succeeded, `issueErr` is nil and the request is charged as 9.5's first row requires.
- [ ] **Step 8: Pin the accepted 500.** In the retried-then-refused row, also assert `StatusForError(err) == 500` (design, "Review findings accepted without change").
- [ ] **Step 9: Comment nits from the review.** `session_renewal.go` (`renewing` godoc and the inline comment): only an authentication-required refusal is charged, a conflict is not. `redemption.go`: rewrap the long comment line. `recover_complete.go`: "the result still carries the new saved codes" holds when the saved set was replaced.
- [ ] **Step 10: Run** `go test -race -count=1 ./httpsec/... ./recovery/...` and `golangci-lint run ./httpsec/... ./recovery/...`. Expected PASS, 0 issues. Commit lane H as one commit per task.

### Task 9.3: Expiry judged at the spend (lane O)

**Files:** Modify `token/onetime/tokens.go` (`Tokens.Consume`) and `authenticate/oidc/handoff.go` (`Handoff.Redeem`, before `store.Consume`). Test `token/onetime/*_test.go` and `authenticate/oidc/*_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestTokens_ConsumeRefusesExpiredToken`: a 60 s token, checked at +59 s, with the clock at +61 s at consume → `ErrInvalidToken`, and still unspent, so a re-check at +61 s is refused as expired, not as consumed. A row consumed at exactly +60 s is refused too (Review Focus 1).
  - `TestHandoff_RedeemRefusesCodeExpiredDuringChecks`: a check advances the clock past expiry → the invalid-handoff outcome, and the record is not consumed.
  - Magic link: an `authenticate/magiclink` row through `Redeem` with an advancing check.
- [ ] **Step 2: Run** `go test -run 'Expired' -count=1 ./token/onetime/ ./authenticate/oidc/ ./authenticate/magiclink/`. Expected FAIL: `got nil`.
- [ ] **Step 3: Implement.** `Tokens.Consume` compares `!now.Before(c.token.ExpiresAt)` with the clock it reads. `Redeem` re-reads `h.clock.Now()` and refuses as `"expired"` before `store.Consume`. Update the godoc of both.
- [ ] **Step 4: Run** `go test -race -count=1 ./token/... ./authenticate/...`. Expected PASS. Commit.

### Task 9.4: A step that outlives the family stores nothing (lane S)

**Files:** Modify `session/reuse.go` (`RotateWithGraceIssuing`, and `RotateIssuing` if it has the same gap). Test `session/reuse_test.go`.

- [ ] **Step 1: Write the failing tests.** In `TestRotateWithGraceIssuing`, one row with no grace and one with a family maximum lowered by a second manager over the same store: the family ends at 21:00:00, the rotation starts at 20:59:50, and the step ends at 21:00:05. Expect `session.ErrExpired`, nothing stored, and no `Supersede`. Add the same row for `RotateIssuing` (Review Focus 4); if it already passes, keep it as a pin and say so.
- [ ] **Step 2: Run** `go test -run 'TestRotate' -count=1 ./session/`. Expected FAIL: `An error is expected but got nil`.
- [ ] **Step 3: Implement.** After the step, `if !m.clock.Now().Before(familyEnd) { return ..., ErrExpired }`, ahead of the grace-window check.
- [ ] **Step 4: Run** `go test -race -count=1 ./session/... ./httpsec/...`. Expected PASS. Commit.

### Task 9.6: One copy of the hang-up predicate and of the signer text (lane R, after H, O and S)

**Files:** listed in the lane table. No new tests: the existing hang-up and outage suites pin the behaviour.

- [ ] **Step 1:** Replace `authenticate.causedByCaller`, `recovery.causedByCaller` and `httpsec.ownerLoadEndedByCaller` with `hangup.ByCaller`. Replace calls to `httpsec.endedByRequest` and `recovery.loadEndedByCaller` with direct calls. `httpsec.loadEndedByCaller` keeps its precondition. In `token/generator.go`, define `const textSignerUnavailable = "token: signing key unavailable"`, used by `diag.Wrap` and by `errSignerUnavailable`.
- [ ] **Step 2: Run** `go test -race -count=1 ./...`, `golangci-lint run ./...` and `go vet ./...`. Expected PASS with no test edited.
- [ ] **Step 3: Commit** `refactor: one hang-up predicate and one signer-unavailable text`.

### Task 9.7: Review (main session)

- [ ] Run each lane's verification commands. Then a fresh Opus reviewer checks the group-9 diff against D7, D8 and the four deltas. Findings go back to a fresh dispatch of the lane. Then run `openspec validate key-port-context --strict`, re-run 7.1 (`make check`, and CI green on the final head), and tick.
