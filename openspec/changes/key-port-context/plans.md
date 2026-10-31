# key-port-context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the key and cipher ports a per-call context, report a missing signing key apart from an outage, and stop an outage from reading as a refusal on the session path, as the five spec deltas and design decisions D1–D5 require.

**Architecture:**
- **Defect claims come first, on today's signatures (tasks 2.x).** The two misclassifications are reproduced by failing tests and fixed before any port changes, so each claim is proven or dropped on its own.
- **The ports then change one at a time:** `seal` (3.x), `session.Cipher` and its outage marker (4.x), and `KeySource` (5.x). Each lane owns its port, its implementations and every caller `gopls` finds.

**Tech Stack:** Go 1.27 workspace, testify, mockgen v0.6 (`--typed`), jwx v4 (signing through `crypto.Signer`), testcontainers suites in `test/` (CI only).

**Spec:** `openspec/changes/key-port-context/`: `proposal.md`, `design.md` (D1–D5), `specs/*/spec.md` and `tasks.md`. Step labels cite `tasks.md`.

## Global Constraints

- **Lands after `restructure-layout` and `idiomatic-api-shape`.**
  - Paths: `store/seal`, `token/signingkey`, `store/sqlstore`, `store/gormstore`, `store/pgxstore`.
  - Names: `session.ErrUnreadable`, `session.ErrNotFound`, `seal.ErrConfig`, `signingkey.Keys`, `*seal.AEADCipher`, `*seal.StaticKeyring`.
  - File names follow `restructure-layout` D1. Locate each file with `gopls`, not by the pre-restructure names.
- **`ctx context.Context` is always the first parameter.** No caller substitutes a context or imposes a deadline of its own (D1).
- **No nil-context check is added** (`idiomatic-api-shape` D6). The in-memory implementations ignore their context entirely.
- **New sentinels, exact text:**
  - `signingkey.ErrNoKey = errors.New("signingkey: no key for the algorithm")`;
  - `session.ErrCipherUnavailable = errors.New("session: cipher unavailable")`;
  - `seal.ErrUnavailable = errors.New("seal: keys unavailable")`.

  None of them matches any existing sentinel.
- **Table tests** follow `.claude/skills/table-test`: the `assert` closure, a `ctx` modifier where context matters, and `t.Context()`. Test doubles come from `use-mockgen`, by regenerating the existing directives (for example `store/seal`'s `cipher_mock_test.go` and `keyring_mock_test.go`, `session`'s `store_encrypted_mock_test.go`, `token`'s `keysource_mock_test.go`). The Docker suites use `use-testcontainers` helpers.
- **Never run** `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`.
- **Agents never edit `openspec/`,** and never read, copy or cite `.claude/.legacy`.
- **A defect found in passing** is reported `REPRODUCED` with its failing test (`defect-claims.md`). It is not fixed in passing.

## Review Focus

1. **A context error wrapped by the cipher** (`fmt.Errorf("kms: %w", context.Canceled)`) must still read as an outage, not as unreadable. Matching uses `errors.Is`. A table case is added in 2.1.
2. **An error that joins a marker with a context error**, or a marker with `seal.ErrDecryptionFailed`, is an outage. The marker wins, because the cipher said it could not reach its keys. Table cases are added in 4.2 and 4.3.
3. **`identity.ErrUserNotFound` wrapped by a consumer loader** (`fmt.Errorf("db: %w", identity.ErrUserNotFound)`) is still a 401 refusal, not a 500. A table case is added in 2.3.
4. **A key source whose `Signer` returns `nil` error with a nil signer.** Issuing must fail as an outage behind fixed text, never panic, and never produce a token. A table case is added in 5.2.
5. **A session-store outage on the renewal endpoint's own request**, where resolution lets a renewal-required session through. A store failure there must still fail the request, not go on unauthenticated. A table case is added in 2.2.

---

## Dispatches and models

| Dispatch | Tasks | Owns | Model, reason | Reviewer |
|---|---|---|---|---|
| main session | 1.1 | `openspec/changes/key-port-context/` | design decision against the established design | none |
| A1 | 2.1 | `session` sealing store file and its test | Sonnet: an `errors.Is` classification the design fixes exactly | Sonnet |
| A2 | 2.2–2.4 | `httpsec` resolution (`resolve.go`) and its tests | Opus: refusal logic on a security path, written for the first time | Opus |
| B | 3.1–3.3 | `store/seal` (all files), the passkey credential stores in `store/sqlstore`, `store/gormstore` and `store/pgxstore`, `internal/storekit` if it calls the cipher, `test/internal/storefix/ciphers.go` | Opus: an interface other packages and modules compile against | Opus |
| D | 5.1–5.4 | `token/signingkey` (`KeySource`, `Keys`), `token` generator and verifier, every other `KeySource` caller or implementation `gopls` finds (including in `httpsec` and `test/`) | Opus: an interface several packages compile against | Opus |
| C | 4.1–4.4 | `session.Cipher` and the sealing store file, `store/seal/cipher.go`, `store/seal` errors file, `session` and `store/seal` cipher mocks, `test/internal/storefix/ciphers.go` | Opus: an interface two packages compile against, and outage classification | Opus |
| main session + Opus reviewer | 6.1–6.2 | whole branch | | Opus |

**Order:**
1. **1.1 runs first.** If it revises a decision, the affected tasks change before any dispatch starts.
2. **A1 and A2 run in parallel.** `httpsec` imports `session`, but A1 changes no signature.
3. **B and D then run in parallel.**
   - Their files do not overlap.
   - `store/seal` imports `token/signingkey` only for `Record` and `KeyStore`, which D does not change.
   - Each runs only its own packages' tests while the other works. The test module is built only after both have landed.
4. **C runs after B and A1.** It changes `store/seal/cipher.go` (B's file) and the sealing store file (A1's file).

---

### Task 1: Compare with the established design (task 1.1, main session)

- [ ] **Step 1:** Obtain the reference snapshot (`legacy-reference.md`, "Recreating the snapshot"). If it is unavailable, stop and ask the user. Do not start the dispatches on a pending D5.
- [ ] **Step 2:** For each of D1–D4, record in `design.md` whether the established design agrees. Record each departure with its reason, or revise the decision and the deltas.
- [ ] **Step 3:** `openspec validate key-port-context --strict`. Expected: valid. Commit: `docs(openspec): compare key-port-context with the established design`.

### Task 2: A context error on open is not unreadable (task 2.1, dispatch A1)

**Files:**
- Modify: the `session` sealing store (`encryptedStore.Load`)
- Test: its test file

**Interfaces:**
- Produces: `encryptedStore.Load` returns `storeFailed(err, …)` for an open error matching `context.Canceled` or `context.DeadlineExceeded`. Its result does not match `session.ErrUnreadable`.

- [ ] **Step 1: Failing test.** `TestEncryptedStore_LoadClassifiesOpenFailure`, a table over the session `MockCipher`'s `Open` result. Each case loads a session that has an ID token. The cases:
  - `"deadline"`: `context.DeadlineExceeded`. Asserts `errors.Is(err, context.DeadlineExceeded)` and `!errors.Is(err, session.ErrUnreadable)`.
  - `"cancelled, wrapped"`: `fmt.Errorf("kms: %w", context.Canceled)`. Asserts the same with `context.Canceled`.
  - `"own error"`: `errors.New("tag mismatch")`. Asserts `errors.Is(err, session.ErrUnreadable)`.
- [ ] **Step 2:** `go test -run TestEncryptedStore_LoadClassifiesOpenFailure -count=1 ./session/`. Expected: FAIL on `"deadline"` and `"cancelled, wrapped"`, because the error matches `session.ErrUnreadable`. If both pass, the claim was wrong: report that, with the output, and stop (`defect-claims.md`).
- [ ] **Step 3:** In `Load`, test the open error with `errors.Is` against both context errors before the unreadable wrap, and return `storeFailed(err, "session: the provider ID token could not be opened")`.
- [ ] **Step 4:** Rerun, then `go test -count=1 ./session/...`. Expected: PASS, including "Sealed round trip", "Value moved between sessions" and "No rewrite on read". Commit: `fix(session): report a cancelled open as a store failure`.

### Task 3: Resolution answers a dependency failure as one (tasks 2.2–2.4, dispatch A2)

**Files:**
- Modify: `httpsec/resolve.go` (`sessionResolver.resolve`)
- Test: `resolve_test.go`, or the bearer and session-bearer test files the restructure produces

**Interfaces:**
- Consumes: `session.Sessions.Load` errors, and `identity.ErrUserNotFound`.
- Produces: `resolve` returns the load or reload error itself for any error not in the refusal set (D4 table).

- [ ] **Step 1 (2.2): Failing test.** `TestResolve_SessionLoadFailure`, a table over the session store's `Load` result, driving a valid signed bearer request through the chain. A failing store comes from a regenerated `session.Store` mock. The cases:
  - `"store down"`: `errors.New("pg: connection refused")`. Asserts:
    - `!errors.Is(err, httpsec.ErrAuthenticationRequired)`;
    - `httpsec.StatusForError(err) == 500`;
    - no log record with message `"httpsec: a session could not be decrypted"`.
  - `"store down, session-reference bearer"`: the same, with session-reference mode and a well-formed identifier.
  - `"store down on the renewal endpoint"`: the same, on the renewal endpoint's own request (Review Focus 5).
  - `"not found"` and `"expired"`: assert `errors.Is(err, httpsec.ErrAuthenticationRequired)`.
- [ ] **Step 2:** `go test -run TestResolve_SessionLoadFailure -count=1 ./httpsec/`. Expected: FAIL on the three outage cases, because the error matches `ErrAuthenticationRequired`. If they pass, the claim was wrong: report that, with the output, and stop.
- [ ] **Step 3:** In `resolve`, keep every existing refusal branch. The final `return ErrAuthenticationRequired` applies only when the error matches `session.ErrNotFound`, `session.ErrExpired` or `session.ErrUnreadable`. Any other error is returned unchanged.
- [ ] **Step 4 (2.3): Failing test.** `TestResolve_UserReloadFailure`, a table over the `UserLoader` mock:
  - `"loader down"`: `errors.New("db down")`. Asserts it is not `ErrAuthenticationRequired`, and the status is 500.
  - `"not found"`: `identity.ErrUserNotFound`. Asserts `ErrAuthenticationRequired`.
  - `"not found, wrapped"`: `fmt.Errorf("db: %w", identity.ErrUserNotFound)`. Asserts `ErrAuthenticationRequired` (Review Focus 3).

  Run as in step 2. Expected: FAIL on `"loader down"` only.
- [ ] **Step 5:** After `by.load`, return `ErrAuthenticationRequired` only for `errors.Is(err, identity.ErrUserNotFound)`. Otherwise return the error unchanged.
- [ ] **Step 6 (2.4):** `go test -count=1 ./httpsec/... && (cd httpsec/ginsec && go test ./...) && (cd httpsec/fibersec && go test ./...)`. Expected: PASS, with "Expired session", "Superseded identifier presented after its window", "Session sealed under a retired key" and every renewal test unchanged. Commit: `fix(httpsec): fail a session or user store outage instead of asking for a new login`.

### Task 4: Context on `seal.Keyring` and `seal.Cipher` (tasks 3.1–3.3, dispatch B)

**Files:**
- Modify: `store/seal/keyring.go`, `store/seal/cipher.go` (the AEAD cipher, and `SessionCipher`, which calls `seal.Cipher` and keeps its `session.Cipher` signature until Task 6), the `store/seal` enrolment and signing-key store files
- Modify: the passkey credential files in `store/sqlstore`, `store/gormstore` and `store/pgxstore`; `test/internal/storefix/ciphers.go`; every other caller `gopls references` finds
- Regenerate: `store/seal`'s `cipher_mock_test.go` and `keyring_mock_test.go`

**Interfaces:**
- Produces:
  - `Keyring.Active(ctx context.Context) (id string, key []byte, err error)`
  - `Keyring.ByID(ctx context.Context, id string) ([]byte, error)`
  - `Cipher.Seal(ctx context.Context, plaintext, aad []byte) ([]byte, error)`
  - `Cipher.Open(ctx context.Context, sealed, aad []byte) (plaintext []byte, keyID string, err error)`
  - `Cipher.ActiveKeyID(ctx context.Context) (string, error)`

- [ ] **Step 1 (3.1): Failing tests.**
  - `TestAEADCipher_Context`, a table with a `ctx` modifier:
    - `"cancelled"`: seal, then open, under a cancelled context. Asserts the plaintext round-trips with no error.
    - `"passed to keyring"`: a `MockKeyring` expects `Active` and `ByID` with the exact context value carried by `context.WithValue(t.Context(), key{}, "v")`.
  - The same `"cancelled"` case for `*StaticKeyring`.

  Run `go test -run 'TestAEADCipher_Context|TestStaticKeyring_Context' -count=1 ./store/seal/` once the signatures are stubbed. Expected: FAIL on `"passed to keyring"`, because the keyring receives no context.
- [ ] **Step 2:** Change the two ports and both implementations, and regenerate the mocks. Run the step 1 command. Expected: PASS.
- [ ] **Step 3 (3.2): Failing test.** `TestEnrolmentStore_PassesContextToCipher`: store and read an enrolment under a value-carrying context through a `MockCipher` that asserts the value on `Seal` and `Open`. Expected: FAIL until the stores pass their context. Then pass the store method's context at every call site `gopls references` lists, including re-sealing on read and the passkey row helpers, which gain a `ctx` parameter.
- [ ] **Step 4:** `go build ./...` in the core and in `store/gormstore` and `store/pgxstore`. Then `go test -count=1 ./store/...` and, in those two modules, `go test ./...`. Expected: PASS, including every existing `secrets-at-rest` scenario.
- [ ] **Step 5 (3.3):** Add to the `Keyring` and `Cipher` godoc: honour the context; cache or use envelope encryption because of service quotas. `go doc ./store/seal Cipher` shows it. Commit: `feat(seal)!: pass the caller's context to the keyring and cipher`.

### Task 5: Context on `KeySource`, and `ErrNoKey` (tasks 5.1–5.4, dispatch D)

**Files:**
- Modify: the `token/signingkey` key source file and `Keys`' signer method; the `token` generator and verifier files; every `KeySource` implementation and caller `gopls implementation` and `references` find
- Regenerate: `token`'s `keysource_mock_test.go`

**Interfaces:**
- Produces:
  - `KeySource.Signer(ctx context.Context, alg Alg) (kid string, signer crypto.Signer, err error)`
  - `KeySource.VerificationKeys(ctx context.Context) ([]PublicKey, error)`
  - `signingkey.ErrNoKey`

- [ ] **Step 1 (5.1): Failing test.** `TestKeys_Signer`, a table with a `ctx` modifier over a `Keys` configured for RS256 only:
  - `"configured"`: returns a non-nil signer, a kid and a nil error.
  - `"unconfigured"`: asks for EdDSA, and asserts `errors.Is(err, signingkey.ErrNoKey)`.
  - `"cancelled"`: asks for RS256 under a cancelled context, and asserts success.

  Expected: FAIL on `"unconfigured"` once the signature is stubbed to return a nil error.
- [ ] **Step 2:** Implement. Rerun `go test -run TestKeys_Signer -count=1 ./token/signingkey/`. Expected: PASS.
- [ ] **Step 3 (5.2): Failing test.** `TestGenerator_SignerResult`, a table over the `MockKeySource`:
  - `"no key"`: `ErrNoKey`. Asserts an error and no token, as "No key for the algorithm".
  - `"outage"`: `errors.New("kms down")`. Asserts that `errors.Is` matches it and does not match `ErrNoKey`, that the error text does not contain `"kms down"`, and that no token is produced.
  - `"nil signer, nil error"`: asserts an error, no panic, and no token (Review Focus 4).
  - `"context reaches the source"`: `Generate` under a value-carrying context, and the mock asserts it.
  - `"once per token"`: three `Generate` calls. Asserts `Signer` was called three times, and each returned signer's `Sign` was called exactly once.

  Run `go test -run TestGenerator_SignerResult -count=1 ./token/`. Expected: FAIL on `"outage"`, `"context reaches the source"` and `"nil signer, nil error"`.
- [ ] **Step 4:** In `Generate`, pass `ctx` and call `Signer` once. Keep the existing "no current key for algorithm" text for `ErrNoKey`, and wrap any other error with `diag.Wrap(err, "token: obtain signing key")`. Treat a nil signer as an outage. Rerun. Expected: PASS.
- [ ] **Step 5 (5.3): Failing test.** `TestVerifier_PassesContextToKeySource`: verification under a value-carrying context, and the mock asserts it on `VerificationKeys`. Implement, then run `go test -count=1 ./token/... ./httpsec/...`. Expected: PASS, including "Typed-nil RSA key".
- [ ] **Step 6 (5.4):** Godoc for `KeySource` and `Signer`: the meaning of `ErrNoKey`, that any other error is an outage, one issuance per signer (which may be bound to `ctx`), and the caching advice. `go doc ./token/signingkey KeySource` shows it. Commit: `feat(signingkey)!: pass the caller's context to the key source and report a missing key`.

### Task 6: Context on `session.Cipher`, and the outage marker (tasks 4.1–4.4, dispatch C)

**Files:**
- Modify: `session.Cipher` and the sealing store; the `session` errors file; `store/seal/cipher.go`; the `store/seal` errors file; `test/internal/storefix/ciphers.go`
- Regenerate: `session`'s `store_encrypted_mock_test.go`

**Interfaces:**
- Consumes: Task 4's `seal.Cipher`, and Task 2's context classification.
- Produces:
  - `session.Cipher.Seal(ctx context.Context, plaintext, additionalData []byte) ([]byte, error)`
  - `session.Cipher.Open(ctx context.Context, ciphertext, additionalData []byte) ([]byte, error)`
  - `session.ErrCipherUnavailable`, `seal.ErrUnavailable`

- [ ] **Step 1 (4.1): Failing test.** `TestEncryptedStore_PassesContextToCipher`: save and load under a value-carrying context, and the `MockCipher` asserts the value on `Seal` and `Open`. Implement the signature and pass the context through `seal.SessionCipher`. Run `go test -count=1 ./session/... ./store/seal/...`. Expected: PASS, including "Consumer cipher used".
- [ ] **Step 2 (4.2): Failing test.** Extend Task 2's table with these cases:
  - `"marked"`: `errors.Join(session.ErrCipherUnavailable, errors.New("503"))`. Asserts `errors.Is(err, session.ErrCipherUnavailable)` and not `ErrUnreadable`.
  - `"marked with a context error"`: `errors.Join(session.ErrCipherUnavailable, context.Canceled)` (Review Focus 2).

  A separate assertion checks that the sentinel matches neither `ErrUnreadable` nor `ErrNotFound`. Expected: FAIL until the marker is classified with the context errors.
- [ ] **Step 3 (4.3): Failing test.** `TestSessionCipher_TranslatesOutage`, a table over the `seal` `MockCipher`'s `Open` result:
  - `"unavailable"`: `seal.ErrUnavailable`. Asserts `errors.Is(err, session.ErrCipherUnavailable)`.
  - `"unavailable and decryption failed"`: `errors.Join(seal.ErrUnavailable, seal.ErrDecryptionFailed)`. Asserts the same.
  - `"cancelled"`: `context.Canceled`. Asserts it passes through unchanged and matches no marker.
  - `"decryption failed"`: `seal.ErrDecryptionFailed`. Asserts no marker.

  Then implement the translation, wrapping as `errors.Join(session.ErrCipherUnavailable, err)`. Rerun. Expected: PASS.
- [ ] **Step 4:** Update the storefix ciphers. Run `go test -count=1 ./session/... ./store/...`, then build the test module (`cd test && go build ./... && go vet ./...`). Expected: PASS.
- [ ] **Step 5 (4.4):** Godoc for `session.Cipher`, `seal.Cipher` and `seal.SessionCipher`: which errors read as an outage, and how to mark one. Commit: `feat(session)!: pass the caller's context to the session cipher and mark cipher outages`.

### Task 7: Final integration (tasks 6.1–6.2, main session)

- [ ] **Step 1 (6.1):** `make check`. Expected: PASS. Push, and confirm CI is green on both matrix jobs (the Docker store-conformance suites run there).
- [ ] **Step 2 (6.2):** Dispatch one fresh Opus reviewer over the whole branch. Check it against the five deltas' requirements and D1–D5, and against the Review Focus list. Defects come back with a failing test or labelled `UNREPRODUCED`. Fold the findings back to a fresh dispatch of the owning lane. Then run `openspec validate key-port-context --strict`. Expected: valid.
