# Design

## Context

See `proposal.md` (Why) for the motivation, and the deltas under `specs/` for the requirements. This change lands after `restructure-layout`, `idiomatic-api-shape` and `reauthentication`, all archived. Every name below is one they produce: `store/seal`, `token/signingkey`, `signingkey.Keys`, `KeySource.Signer`, `session.ErrUnreadable`, `session.Sessions`, `Sessions.RotateIssuing`, `seal.ErrConfig`, `*seal.AEADCipher`, `*seal.StaticKeyring`, `httpsec.KeySetProvider`.

The change was audited against `main` on 2026-11-01, after `reauthentication` merged. The audit swept every settled spec and every caller of the ports, and reproduced the defects it claims in disposable copies of the tree. Those reproductions are gone; each becomes the red step of its task. The facts that shape the approach:

- **Every caller of the four ports already holds a context, or can be handed one.**
  - `token`'s generator discards the context it is given; its verifier holds one.
  - `seal`'s enrolment store holds one in `Get`, `PutPending`, `ProveDevice` and its re-seal. Its signing-key store holds one in `Store`, `LoadAll` and its re-seal, but `activeKeyForReseal` takes none.
  - The passkey credential stores in `store/sqlstore`, `store/gormstore` and `store/pgxstore` seal in their insert helpers, one call below a method with a context. They open two calls below one: `open` is reached through `scan` and `query`/`list` (sqlstore, pgxstore) or `fromRow` and `one`/`List` (gormstore). `ChargeEmailAttempt` opens directly.
  - `session`'s sealing store seals in a helper reached from `Create`, `Save` and `Supersede`, which hold a context, and opens in `Load`.
  - `*seal.AEADCipher` is the only caller of `Keyring`; its `active` helper takes no context.
  - `httpsec.KeySetProvider.JWKS` takes no context. `signingkey.Keys` implements it, and the JWKS endpoint is its only caller.
- **Every remote key service's Go SDK takes a context first, on every call.** That covers AWS KMS, Google Cloud KMS, Azure Key Vault and HashiCorp Vault. A PKCS#11 HSM is reached in-process, and neither common Go binding takes a context.
- **The standard library's `crypto.Signer` and `crypto.MessageSigner` take no context.** A context-aware signer (golang/go#56508) is accepted but unimplemented. jwx v4 signs through a `crypto.Signer`, and its `WithContext` applies to verification only.
- **An outage is reported as a refusal on four paths today.**
  - The sealing session store maps every open failure to `session.ErrUnreadable`, a context deadline included. `httpsec` logs that error as a retired sealing key and answers "log in again". (D3)
  - `httpsec`'s shared resolution, used by signed and session-reference bearers, answers every session-load and user-reload error with the authentication-required error. (D4)
  - The renewal endpoint does the same for its own user reload. Its session load and rotation already return a store failure unchanged. (D4)
  - The bearer joins every verification error with the authentication failure, so a key source that cannot supply the key set is a refused token, although `token` itself keeps that failure apart from `token.ErrInvalid`. (D6)
- **Every credential is issued through one generator call, and seven of nine issuing paths store or spend something first.** Form login and the login completion step create the session before issuing, and its callers spend first: magic link and OIDC handoff consume their code, passkey login spends its challenge. Renewal stores the rotation, then issues. Recovery spends its proofs, removes authenticators, ends sessions and replaces the saved codes, then issues. MFA verification and re-proof issue through `Sessions.RotateIssuing`, which stores nothing until its caller's step succeeds. (D7)
- **Some outages stay refusals by settled decisions, and this change keeps them:**
  - a user-store outage at a password login or a recovery proof answers as a wrong password (`restructure-layout` D19), and a client that leaves during that load is charged to its source;
  - an API key owner lookup that fails answers as an unavailable credential, 401;
  - a session-reference or renewal limiter that fails refuses;
  - a family revocation that fails during reuse detection still answers the reuse;
  - a handoff store or user loader failure at OIDC redemption answers as an invalid handoff.
- **A remote service's quotas make a call on every session read or every token issue impractical at scale.** AWS KMS, for example, allows 1,000 asymmetric signs per second per account and Region by default.
- **`token.NewGenerator` and `token.NewVerifier` refuse construction without an issuer and an audience,** unless each is explicitly waived (`restructure-layout` D18). Every generator and verifier the tests build therefore configures both claims, or waives the ones the test is not about.
- **Dependency failures carry fixed library text** (`diagnostic-redaction`): an error a library interceptor returns because of a consumer's dependency has fixed text, and keeps the dependency's error reachable by identity and type.

## Goals / Non-Goals

**Goals:**
- **A request's deadline and cancellation reach a remote key service** through every port.
- **On the verification, issuing and session-resolution paths, an outage of a key source, cipher, session store or user store is never reported as a refusal.** The settled exceptions listed under Context stay as they are.
- **A credential that cannot be issued leaves the user as they were.** Nothing is stored, spent, removed or revoked for a credential the user never received.
- **Every behaviour change is test-first.** Each defect is reproduced by a failing test before anything is fixed.

**Non-Goals:**
- **A caching or envelope-encryption decorator** (proposal, Not in this change).
- **Changing how values are sealed.** The envelope format and the AES-256-GCM default are unchanged, and so are stored values.
- **Classifying cipher errors in the `seal` stores.** They already fail closed with the cipher's error, which is what `secrets-at-rest` requires.
- **Revisiting the settled outage exceptions** listed under Context.
- **Refunding a passkey login's challenge.** `passkey-authentication` already accepts that any attempt spends it; D7 still keeps the session from being stored.

## Decisions

### D1. Every key and cipher port takes a per-call context first

```go
type Keyring interface {
    Active(ctx context.Context) (id string, key []byte, err error)
    ByID(ctx context.Context, id string) ([]byte, error)
}

type Cipher interface { // store/seal
    Seal(ctx context.Context, plaintext, aad []byte) ([]byte, error)
    Open(ctx context.Context, sealed, aad []byte) (plaintext []byte, keyID string, err error)
    ActiveKeyID(ctx context.Context) (string, error)
}

type Cipher interface { // session
    Seal(ctx context.Context, plaintext, additionalData []byte) ([]byte, error)
    Open(ctx context.Context, ciphertext, additionalData []byte) ([]byte, error)
}

type KeySource interface { // token/signingkey
    Signer(ctx context.Context, alg Alg) (kid string, signer crypto.Signer, err error) // D2
    VerificationKeys(ctx context.Context) ([]PublicKey, error)
}

type KeySetProvider interface { // httpsec; D6
    JWKS(ctx context.Context) ([]byte, error)
}
```

- **Callers pass the context they hold:**
  - the generator passes the context given to `Generate`, and the verifier the one given to verification;
  - each `seal` store passes the context of the store method it serves, re-sealing on read included. `activeKeyForReseal` takes the read's context;
  - `*seal.AEADCipher` passes its own context on to the keyring, through `active`, and `seal.SessionCipher` passes its context to the cipher it adapts;
  - the passkey row helpers take the context of the method that calls them, two levels down where they sit two levels down, and `ChargeEmailAttempt` passes its own;
  - the sealing session store passes the context of the save or load it serves;
  - the JWKS endpoint passes the request's context.
- **No caller substitutes a context of its own, or imposes a deadline of its own.** This is the rule `signing-keys` already sets for construction over a key store. The conformance suite's sealed-column cases check it for every durable store (`store-conformance` delta).
- **The in-memory implementations ignore the context.** `*seal.StaticKeyring`, `*seal.AEADCipher` and `signingkey.Keys` perform no input or output, so they succeed whatever state the context is in. This follows the `signing-keys` precedent for the in-memory key store.
- **No nil-context check is added.** `idiomatic-api-shape` D6 adds none to functions that merely pass a context along, and the in-memory implementations do not use theirs. A nil context fails at first use, as in the standard library.
- **Godoc of each port:**
  - an implementation over a remote service should honour the context;
  - a remote service's quotas make a call per seal, open or signature impractical at scale, so such an implementation is expected to cache, or to use envelope encryption. `VerificationKeys` already says so.

**Default and override:** the in-memory implementations stay the defaults (`KeySource` and `KeySetProvider` have none: the caller always supplies them). A consumer replaces any port with their own implementation, which now receives the caller's context.

**Alternatives considered:**
- **A context on the ciphers and `KeySource` only, with `Keyring` left as it is.** `*seal.AEADCipher` would then hold a context it cannot pass on. A keyring that fetches its key bytes from a secrets service would be back to inventing one.
- **Parallel interfaces that take a context, probed alongside the current ports (the approach Tink takes).** That gives two contracts per port and a type check on every call. It exists to keep compatibility, which scrty does not yet owe anyone.
- **No change, with remote implementations capturing a context at construction or using a background context with a timeout.** The request's deadline would never reach the service, and the Go guidance argues against storing contexts.

### D2. `Signer` reports a missing key apart from an outage, and its signer serves one issuance

`Signer(ctx, alg) (kid string, signer crypto.Signer, err error)`:

- **A source holding no key for `alg` returns an error matching `signingkey.ErrNoKey`.** `signingkey.Keys` does so for an algorithm it was not configured with, a key it publishes for another replica included (`signing-keys`, "A key for an unconfigured algorithm is published but never signed with"). Issuing over a source that answers `ErrNoKey` fails as "no current key for algorithm" followed by the configured algorithm, as it does today. The algorithm is the consumer's configuration, not a dependency's text, so `diagnostic-redaction` does not ask for it to be dropped; the first implementation dropped it, and the review of 2026-11-01 reproduced the loss (`TestRepro_NoKeyErrorNamesTheAlgorithm`).
- **Any other error is an outage.** Issuing fails with it, behind the generator's fixed text, as the verifier already does with `VerificationKeys`. It is never reported as a missing key.
- **The returned signer serves the one issuance `ctx` belongs to.** The generator asks for a signer once per token, and never keeps or reuses it. A source over a remote service may therefore return a `crypto.Signer` bound to `ctx`, so the service's signing call receives the request's deadline and cancellation. That guarantee is what makes binding the context into the signer safe. It is a contract the spec states and a test pins, because the compiler cannot check it.
- **The signer stays a standard-library `crypto.Signer`.** The `signing-keys` requirement that the contract needs only standard-library types and scrty's own algorithm names is kept.
- **Neither error is a refusal at an endpoint.** Whichever the generator returns, the endpoint that asked fails as a dependency failure, and D7 keeps that failure from costing the user anything.

**Default and override:** `signingkey.Keys` is the default source, and its signers are in-memory. A consumer supplies their own `KeySource`, and decides whether its signer binds the context.

**Alternatives considered:**
- **A signer port of scrty's own whose `Sign` takes a context.** The compiler would enforce the context, but every in-process `crypto.Signer` (an HSM's included) would need an adapter. The contract would also stop being standard-library only, and the port would duplicate `crypto.ContextSigner` if the standard library ships it.
- **The same, plus probing the returned signer for a `SignContext` method shaped like golang/go#56508.** The proposal is unimplemented and its final signature is not settled. A probe can be added once it ships, without breaking anything.
- **Keeping `ok bool`.** An outage would stay indistinguishable from a key that was never configured.

### D3. An outage on open is a store failure, not an unreadable session

The sealing session store classifies a failed open:

| The cipher's error | The load fails with |
|---|---|
| matches `context.Canceled` or `context.DeadlineExceeded` | a store failure wrapping it |
| matches `session.ErrCipherUnavailable` | a store failure wrapping it |
| anything else | `session.ErrUnreadable`, as today |

- **`session.ErrCipherUnavailable` is the marker.** A cipher over a remote service wraps its retryable failures with it, for example with `errors.Join`. The service's own retryable-versus-invalid distinction maps onto it: AWS KMS, for example, separates `InvalidCiphertextException` from its retryable timeout, internal and key-unavailable errors.
- **`seal.ErrUnavailable` is the same marker in `seal`.** `seal.SessionCipher` translates it to `session.ErrCipherUnavailable`, so a remote `seal.Cipher` marks its outages once, and `session` keeps not importing `seal`. Context errors pass through the adapter unchanged. The `seal` stores return it as they return any cipher error, and a failed re-seal on read still never fails the read.
- **Neither sentinel matches `seal.ErrDecryptionFailed`, `seal.ErrUnknownKeyID` or `session.ErrUnreadable`.**
- **What `httpsec` does with the store failure** is D4, and with a cancelled request, D8.

**Default and override:** an error nobody classified stays `session.ErrUnreadable`. That is the safer default. A value that truly does not open still ends the session and lets the user log in again. Treating such a value as an outage would instead fail every request on that session until it expired. A consumer opts their cipher's outages out of that default by wrapping them with the marker. Cancellation and deadlines are classified with no work from the implementer.

**Reproduced.** In a disposable copy of `main`, `TestRepro_SealingStoreOpenDeadlineIsNotUnreadable` (`go test -run TestRepro_ -count=1 ./session/`) loaded a session through a cipher whose `Open` returned `context.DeadlineExceeded`, and failed with `session: session cannot be read … context deadline exceeded`: the load matched `session.ErrUnreadable`. Task 2.1 writes it again as its red step.

**Alternatives considered:**
- **Context errors only.** A remote service's timeout or throttling that is not a context error would still log users out.
- **A sentinel for "does not open", with every other error treated as an outage.** A consumer cipher that reports a corrupt value with an error of its own would leave that session failing every request until it expired. Every consumer cipher would also have to adopt the sentinel to keep today's behaviour.

### D4. Session resolution answers a dependency failure as one

Signed and session-reference bearers share one resolution, and the renewal endpoint reloads the user of the session it renews. Each classifies a failure:

| The failure | The request |
|---|---|
| session not found, expired, or unreadable | refused with the authentication-required error; unreadable also writes its ERROR record |
| reused superseded identifier | refused as both authentication-required and reused, as today |
| renewal required, on the renewal endpoint's own request | goes on unauthenticated, as today |
| user not found; user not the session's, or not active | refused with the authentication-required error, as today |
| the request's own context ended | D8 |
| any other session-load or user-reload failure | fails with fixed library text that keeps the session manager's or the loader's error reachable, which the default mapping answers with 500; no undecryptable-session record, and nothing charged to the source |

- **The `identity-model` spec already requires a loader to report a miss as "user not found" and any other failure as an error that is not,** so resolution relies on a contract that is already settled, and the `identity` ports need no change.
- **The throttle charges only refusals.** The session-reference guard and the late-renewal count record a failure only for a refused reference, so a store outage stops being charged to the source, as it is today through the 401. The guard's list also names, for the first time in the spec, the refusals the code already charges: unreadable, and a user who is not the session's or not active.
- **Fixed text.** The returned error's text is the library's, as `diagnostic-redaction` requires of every dependency failure; the cause stays reachable with `errors.Is` and `errors.As`.
- **Existing tests change on purpose.** `httpsec/bearer_test.go` ("the user store is down"), `httpsec/session_bearer_test.go` ("a user store that is down") and the renewal tests `TestSessionRenewal_UserReloadPrecedesRotation` and `TestSessionRenewalThrottle_RemovedUserIsNotCharged`, which model a removed user as a plain error, pin today's 401 for an outage. They are rewritten to this decision, the last two to report a removed user as "user not found".

**Default and override:** the default status mapping answers the failure with 500, as for any dependency failure. A consumer who wants another answer to an outage, 503 with `Retry-After` for example, replaces the error handler, the override `http-error-propagation` already specifies. No new option is added.

**Reproduced, in part.** In a disposable copy of `main`, `TestRepro_RenewalUserStoreOutageIsNotARefusal` (`go test -run TestRepro_ -count=1 ./httpsec/`) failed with `found: "httpsec: authentication required"` and `expected: 500, actual: 401`, and passed with the reload split on `identity.ErrUserNotFound`. That resolution answers a session-store or user-store outage with the authentication-required error is `UNREPRODUCED`, but two existing tests assert it (above). Task 2.2 writes the failing test first.

**Trade-off recorded.** A cipher outage can only arise after an existing session has loaded, since the store opens the token of a record it found. While a cipher outage lasts, someone holding a session identifier could therefore tell a live session (500) from a missing one (401). Session identifiers are secret credentials, and unknown references are throttled per source, so this design accepts that exposure. The existing reason for answering missing, expired and unreadable alike, which is not to report whether a session ever existed, still holds for every refusal. A future cookie-borne session (the `bff-resource-server` draft) must resolve through this same core, or it brings the old answer back.

**Alternatives considered:**
- **Keep answering every load error with authentication-required.** A key service or database blip would log every active user out, and resolution would stay inconsistent with renewal.
- **A separate change after this one.** D3 would ship only half effective until that change landed.

### D5. The established design, compared

The comparison task 1.1 called for was made on 2026-11-01.

- **D1 departs.** None of the established design's key, keyring or cipher ports takes a context, and its generator and verifier discard the ones they are given. Its documentation names those ports as the seam for a KMS-backed implementation, which would have to impose its own timeout. D1 adds what it lacks.
- **D2 departs.** It reports a missing signing key as a boolean that the generator turns into an unclassified error, and has no notion of a key source failing, because its key manager is in-process. D2 adds `ErrNoKey` and the outage.
- **D3 narrows it.** It maps every failure to open a sealed session field to unreadable, a missing key and a failed key lookup alike, answers 401 and logs at ERROR. That was a deliberate choice to let a session sealed under a retired key heal by logging in again, instead of failing every request until it expired. D3 keeps that default and the ERROR record, and narrows it only for cancellation, deadlines and marked outages.
- **D4 does not depart.** The established design answers a session error that is not a refusal, and a user-loader error other than "not found", with the error itself, which its error mapping answers with 500. scrty's current answer of 401 is the departure; D4 restores the established behaviour.
- **D6, D7 and D8 are new.** It has no remote key fetch, so its bearer answers every verification error with 401 and nothing pins an outage. It issues after creating the session and after spending a one-time link or handoff code, with no restore, and its tests assert only that the error is returned. It has no special handling of a cancelled request at verification, or at session or user load. What it does have, and D7 keeps, is the order in which the pending challenge is recorded before the credential is handed out, and the check-before-spend order of its redemptions.

### D6. A key source outage during verification is a dependency failure

A bearer token whose verification keys cannot be obtained is not a refused token:

- **The bearer joins the authentication failure only to a token the verifier rejects as invalid** (`token.ErrInvalid`). A failure to obtain the key set, which `token-issuance` already keeps apart from "token invalid", fails the request with fixed library text that keeps the key source's error reachable. The default mapping answers it with 500.
- **The `authentication` bearer provider makes the same split,** and passes the caller's context to the verifier.
- **The JWKS endpoint passes the request's context to `KeySetProvider.JWKS`,** which gains a context (D1), and answers a failure as a dependency failure, as it already propagates one.
- **The log records it as a dependency failure,** with a fixed reason and the error's type, not as a token-verification failure whose text a record keeps (`diagnostic-redaction`).

**Default and override:** 500 through the default status mapping. A consumer who prefers 503 with `Retry-After`, or a 401, answers it so in their error handler; the error carries the key source's error for them to match.

**Reproduced.** In a disposable copy of `main`, `TestRepro_BearerKeySourceOutageIsNotARefusal` (`go test -run TestRepro_ -count=1 ./httpsec/`), with the real `signingkey.Keys`, generator and verifier and a key source whose `VerificationKeys` fails, failed with `found: "authenticate: authentication failed" … "kms: dependency timeout"` and `expected: 500, actual: 401`. It passed when only `token.ErrInvalid` was joined. `TestBearerToken`'s tampered-token case mocks `Verify` with a plain error, and is rewritten to return one matching `token.ErrInvalid`.

**Why not the common answer.** Most resource servers checked answer this case with 401 `invalid_token`: Envoy's `jwt_authn`, auth0's `go-jwt-middleware`, and ASP.NET Core's default path. Spring Security tells the two apart internally but answers both with 401, the outage with a bare challenge. scrty departs from that majority:
- RFC 6750 defines `invalid_token` as a token that is "expired, revoked, malformed, or invalid for other reasons", and RFC 9068 lists only properties of the token. Neither covers a server that cannot reach its keys.
- A 401 tells the client its token was refused and that it may obtain a new one. During an outage every client then discards a valid token and returns to the authorisation server, a refresh or login storm on top of the outage.
- OWASP's error-handling guidance answers a request the server cannot fulfil with 5xx and monitors the 5xx rate. A 401 hides the outage among ordinary authentication failures.
- It is the answer scrty gives every other dependency failure (D4, `http-error-propagation`).

Both answers deny access, so neither fails open. The 500 does tell an unauthenticated caller that verification is failing; it does not say which dependency, and the consumer can answer otherwise.

**Alternatives considered:**
- **401 with `invalid_token`, the majority practice.** The reasons above.
- **401 with a bare `Bearer` challenge and no error code, Spring's middle path.** It avoids declaring the token invalid, but still sends the client back to authenticate, and still hides the outage from 5xx monitoring.
- **503 with `Retry-After` by default.** It is the more precise status, but no other dependency failure in scrty answers 503, and the error handler already lets a consumer choose it.

### D7. A credential is issued before anything is stored or spent

Every path that hands out a credential issues it first, then spends and stores, so a credential that cannot be issued costs the user nothing:

```go
// session: the shape RotateIssuing already has, for creation and for grace rotation.
func (m *Sessions) Prepare(user identity.UserID, opts ...CreateOption) (*Prepared, error) // builds; stores nothing
func (p *Prepared) Session() *Session                                                     // for marking, and for the credential
func (p *Prepared) Commit(ctx context.Context) (*Session, error)                          // the one creating write
func (m *Sessions) CreateIssuing(ctx context.Context, user identity.UserID,
    issue func(*Session) (string, error), opts ...CreateOption) (*Session, string, error)  // Prepare, issue, Commit
func (m *Sessions) RotateWithGraceIssuing(ctx context.Context, s *Session, grace time.Duration,
    issue func(*Session) (string, error), opts ...RotateOption) (*Session, RenewalKind, string, error)
```

The names are indicative; the implementer may choose others that read better beside `RotateIssuing`, and records the choice.

| Path | Today | After |
|---|---|---|
| Form login, login completion | create the session, save any challenge mark, issue | build, mark, issue, store in one write, hand out |
| Magic link | consume the link, then complete the login | build and issue inside the pre-spend check, consume, cancel held recoveries, then store |
| OIDC handoff | consume the code, then complete the login | build and issue inside the refusal checks, consume, cancel held recoveries, then store |
| Passkey login | spend the challenge, then complete the login | the challenge is still spent (settled); the session is stored only after issuing |
| Renewal | store the rotation, then issue | issue between building the successor and the conditional supersession |
| Recovery, completing at once | spend proofs, remove authenticators, end sessions, replace codes, create the session, issue | build the session and issue after the checks; then spend, reset, revoke, replace and store |
| Recovery, finish after a hold | complete the record, then as above | issue before the record is completed |
| MFA verification, re-proof | `RotateIssuing` | unchanged |

- **A credential is never handed out for a session that was not stored.** A token signed for a session that is never stored names an identifier that loads nothing, so a racing redemption that loses the atomic consume discards its credential, and its session is never written. This keeps the guarantee the pending-challenge rule was written for: a token never exists for a session whose challenge mark did not persist. The rule's wording moves from "save before issuing" to "store before handing out".
- **Check-then-consume is kept.** Issuing writes no state, so it can run inside the side-effect-free checks of magic link and OIDC handoff; their godoc says the library may issue there, and discards what it issued on a lost race. Only the atomic consume decides single use. A redemption cancels the user's held recoveries after the consume, as it did before, because a check must have no side effects; a credential that cannot be issued therefore cancels nothing.
- **Recovery.** The recovery core cannot import `token`, so it takes the issuing step as a hook, and stores the session it was given after its other effects. The session is created already recovery-pending, one write instead of today's two. The saved codes are replaced only once the credential that answers with them exists, so they are never lost to a failed issue.
  - **The hook is a constructor option, `recovery.WithCredentialIssuer`,** chosen during implementation over a field on the request and a parameter of `Finish`, so `Recover` and `Finish` keep their signatures. It is handed the session and the user's details, because a recovery completing at once learns who the user is only inside the core. With no issuer, the core issues nothing and a caller that issues afterwards does so after the proofs were spent, which the option's godoc states. `httpsec` always installs its own, after a consumer's core options, as it already does with the password check.
  - **A store failure at the final write is the one residue.** The ended sessions must be revoked before the new session is stored, or the revocation would end it too, so a creating write that fails after the spends leaves the proofs spent and the codes replaced, and hands out nothing. It is a dependency failure, and the user recovers again.
  - **An issuing failure is charged to no source** at the recovery endpoints, as at every other issuing path.
- **A prepared session is stored as it was built, apart from its marks.** `Prepared.Commit` refuses with `ErrConfig`, storing nothing, a session whose identifier, user, family, family start, creation or authentication time changed after `Prepare`, or whose idle or absolute deadline moved later than `Prepare` set it. Marking a challenge or recovery shortens deadlines, which stays allowed. The credential the caller issued names those values, so a session stored under others is not the one it was issued for. The first implementation stated this only in godoc and checked the maximum lifetime alone; the review of 2026-11-01 reproduced a commit under a changed identifier and a lengthened deadline (`TestRepro_CommitAcceptsChangedID`, `TestRepro_CommitAcceptsLengthenedDeadline`). Default and override: no option; it guards a guarantee, and a caller that wants other values prepares a session with them.
- **A grace rotation does not carry a mark saved on the old session during the caller's step to the successor.** This predates the change (`RotateWithGrace` reads, then writes, the same way). The review of 2026-11-01 probed whether a confinement escapes through it, and it does not: the only mark saved on an existing session is the per-request enrolment mark, which the per-request policy raises again on the successor's first request. A consumer policy that marks once, rather than on every request, would be exposed; `RotateWithGraceIssuing`'s godoc states that dependency. Accepted, not a defect.
- **Renewal's grace window** is counted from the clock reading taken before the issuing step, as `RotateIssuing` documents for its window. The store still decides racing rotations: a loser's credential names a successor that was never stored. A step that succeeds only after the window has closed stores nothing and fails as a dependency failure (Risks, "A signer slower than the whole grace window").
- **The renewal limiter still counts every renewal attempt**, a failed one included (`http-security-chain`, "Renewals are throttled per family"). An outage longer than ten renewals in ten minutes therefore throttles the family; that is accepted, as the limiter bounds a loop and the outage is answered as one either way.
- **An issuing failure is a dependency failure on every path,** never a refusal: it is not counted against a source or a user, and is not answered as an invalid link, an invalid handoff or a failed recovery.

**Default and override:** this is an ordering, not a policy, and has no option: a consumer cannot ask for a credential to be issued after its session is stored. The consumer's responders, success writers and refusal checks are unchanged, and receive the same values.

**Reproduced, in part.**
- **Renewal.** In a disposable copy of `main`, `TestSessionRenewal_IssueFailureDoesNotLaterReadAsReuse` (`go test -run TestSessionRenewal_IssueFailureDoesNotLaterReadAsReuse -count=1 ./httpsec/`) made the generator fail, moved the clock 31 seconds and loaded the old identifier. It failed with `session: a superseded session was presented after its window: session: session expired`, with the reuse observer called once. It passed once issuing moved before the supersession, with the `session` and `httpsec` suites green.
- **Recovery.** `TestRecoveryComplete_IssueFailureSpendsAndEndsNothing` presented a saved code and the password with a failing generator. The recovery reported "the access token could not be issued"; the user's earlier session then loaded as `session: session not found`, and a second code from the old set was refused. It was not shown passing under a fix, which is this decision's restructure.
- **Magic link, OIDC handoff, form login and passkey login** (a link or code spent, or a session stored, for a credential never issued) are `UNREPRODUCED`; the order is plain in the code, and each path's task writes its failing test first.

**Alternatives considered:**
- **Restore what was spent when issuing fails.** A restored link, code or recovery set races a replay of the same credential, needs an "un-spend" method on three store ports and their conformance suites, and cannot restore removed authenticators, ended sessions or a sent notice.
- **Obtain the signer before spending.** A signer bound to the request's context (D2) can still fail when it signs.
- **Spend first, as Keycloak's authorisation code does, and let the user start again.** Acceptable for a code the user can re-request; not for a recovery that ends every session and replaces the saved codes.
- **Leave it to a later change.** Under a remote key source, renewal turns an outage into a family revocation and a false theft alarm, which breaks D2's promise that an outage is not a missing key, let alone a theft.

### D8. A request whose own context ended is not refused

When the request's own context ends while the bearer verifies the token, or while resolution loads the session or reloads the user, at the bearer, the session-reference bearer or the renewal endpoint:

- the request fails with an error that matches the context's error, not the authentication failure or the authentication-required error, with fixed library text of its own;
- it is not logged at ERROR as a dependency failure, a verification-key failure or an undecryptable session;
- it is not charged to the session-reference or late-renewal throttle.

The `authentication` bearer provider makes the same split for its caller's context. A hang-up is told by the request's own context: it has ended, and the error is that context's error or the cause it was cancelled with (`context.Cause`), as the password login's and recovery's load already tell it. One predicate, shared by every path that tells a hang-up, decides it; the first implementation had four copies, and the two new ones ignored the cause, which the review of 2026-11-01 reproduced at the bearer, at resolution and in the `authentication` provider (`TestRepro_BearerHangUpWithCause` and its siblings). A dependency that times out on a context of its own while the request still waits is an outage.

**Verification was added on 2026-11-01, during implementation.** The first draft covered only the session load and the user reload. The review of task 2.4 reproduced, on the code of that task, that a bearer whose request is cancelled during verification was answered "verification keys unavailable" and logged at ERROR as a key outage: the JOSE library checks the context's state itself, before any key is fetched. That is the case this decision exists to prevent, and a remote key source (D1) makes it routine, so the decision now covers verification too.

Nobody receives the answer: Go's `net/http` cancels a request's context when the client's connection closes. The point is what the library records. A hang-up is neither a refusal (no verdict was reached) nor an outage (nothing failed), which is how nginx's 499 and gRPC's `CANCELLED` treat it. Not charging it opens nothing: a client that leaves before the store answers learns nothing about the reference it presented.

This applies only to verification and resolution. A client that leaves during a password login's or a recovery proof's user load is still charged to its source (`authentication`, `account-recovery`), because those are guesses at a secret, and charging them is what stops a client from hanging up to escape the count.

**Default and override:** no option. A consumer's error handler sees the context's error and may log it as it chooses.

**Alternatives considered:**
- **Answer it as any other outage.** A client that hangs up would look like an outage in logs and alerts.
- **Keep answering authentication-required.** It contradicts D3, and records a refusal for a request nobody refused.

## Risks / Trade-offs

- **A source ignores the context in the signer it returns** → the issuance cannot be cancelled once the signer is called. It still works, it fails no worse than today, and the godoc says what binding gives.
- **A remote cipher does not mark its outages** → its outages log users out, as they do today. The godoc of both ciphers names the marker, and context errors are classified without it.
- **A remote implementation calls its service on every seal, open or signature** → it runs into the service's quotas. The godoc of each port says to cache or use envelope encryption. scrty does not ship a decorator for it.
- **A 500 on a verification outage departs from most resource servers** (D6) → a consumer whose clients expect 401 answers so in their error handler.
- **A slow signer shortens renewal's grace window** (D7) → the same trade-off `RotateIssuing` documents; the window is bounded at 5 minutes, and the default 30 seconds is far above a signing call's latency.
- **A signer slower than the whole grace window** (D7) → a successor written after the window closed would make the holder's requests still in flight under the old identifier read as reuse, revoking the family and raising a theft alarm for an outage. The grace rotation therefore re-reads the clock after the caller's step and, when the window has closed, writes nothing and fails as a dependency failure matching the context deadline error; the old identifier renews on the next attempt. Decided on 2026-11-01, after the review of task 6.2 reproduced the revocation.
- **A losing racer at magic link or OIDC handoff spends a signing call** (D7) → bounded by the source throttles on both endpoints; the signature itself is discarded.
- **A recovery's MFA proof is judged after the credential is issued** (D7), because recording its time step is a spend → every wrong MFA guess costs a signing call, bounded by the user and source limiters that count it; and while the issuer is out, a valid saved or issued code with any MFA code answers 500, uncounted, which reveals the code was valid. The password check's outage path already reveals as much, so the exposure is not new in kind.
- **The change grows from the ports to every issuing path** → the issuing paths are only reachable by a failure the ports introduce, so splitting them would ship D2 with renewal's family-revocation trap open. The tasks keep the two halves in separate groups with their own verification.
- **Every test double of the four ports, and `KeySetProvider`'s, changes** → that is mechanical. Mocks are regenerated with the `use-mockgen` skill, and the test module's cipher fixtures and the six hand-written doubles change with them.
- **`release-readiness` modifies the same `authentication` requirement and the bearer's user reload, and edits the same files** (`token/generator.go`, the signing-key and passkey stores, their suites) → it lands after this change and rebases its deltas, plans and tests onto this change's text and signatures.

## Review findings accepted without change (2026-11-01)

The whole-branch review, `/code-review` and `/security-review` ran on the branch. The security review found nothing. Reproduced findings are folded into D2, D7 and D8 above and into group 8 of `tasks.md`; these were weighed and left as they are:

- **A grace rotation's step that outlives the window fails matching `context.DeadlineExceeded`** although no context deadline fired. That was decided on 2026-11-01 (Risks, "A signer slower than the whole grace window"), and is kept: it is a deadline, the window's, and the endpoints answer it as a dependency failure, never as a client that left.
- **`Sessions.CreateIssuing` has no caller inside the library.** D7 names it as the API for a consumer's own sign-in; the library's paths mark the session, so they use `Prepare` and `Commit`.
- **The renewal endpoint's `rotationFailure` reads like `renewalRefusal`.** Cosmetic; not changed.
- **The test module's sealed passkey view spends an emailed-code attempt per read.** Reproduced from the sixth read of one owner, which its godoc and error already state as its limit; no suite comes near it.

## Migration Plan

None. Nothing is tagged, there are no consumers, and stored values are unchanged.

## References

### D1. A per-call context on every port

**Researched (accessed 2026-10-25):**
- [aws-sdk-go-v2/service/kms](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/kms) v1.61.6: `Sign`, `Encrypt`, `Decrypt`, `GenerateDataKey` and `GetPublicKey` take a context first.
- [cloud.google.com/go/kms/apiv1](https://pkg.go.dev/cloud.google.com/go/kms/apiv1) v1.36.0: `AsymmetricSign`, `Encrypt`, `Decrypt` and `GetPublicKey` take a context first.
- [azkeys](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys) v1.5.0: `Sign`, `Encrypt`, `Decrypt`, `WrapKey` and `UnwrapKey` take a context first.
- [hashicorp/vault/api](https://pkg.go.dev/github.com/hashicorp/vault/api) v1.23.0: Transit is reached through `Logical.WriteWithContext` and `ReadWithContext`.
- [miekg/pkcs11](https://pkg.go.dev/github.com/miekg/pkcs11) v1.1.2 and [ThalesGroup/crypto11](https://pkg.go.dev/github.com/ThalesGroup/crypto11) v1.6.2: in-process PKCS#11, with no `context.Context`.
- [gocloud.dev/secrets](https://pkg.go.dev/gocloud.dev/secrets) v0.47.0: `Keeper.Encrypt` and `Decrypt` take a context per call.
- [tink-go/v2 `AEADWithContext`](https://pkg.go.dev/github.com/tink-crypto/tink-go/v2/tink) v2.9.0: a context-taking AEAD added beside the original, documented as preferred for RPC-backed primitives (the rejected parallel-interface alternative).
- [AWS KMS request quotas](https://docs.aws.amazon.com/kms/latest/developerguide/requests-per-second.html): 10,000 to 100,000 symmetric operations per second by Region; 1,000 asymmetric `Sign` and 2,000 `GetPublicKey` per second. Figures read on 2026-10-25; they drift.
- [AWS Encryption SDK data key caching](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html): caching is optional, to be used cautiously, and helps stay within service limits.
- [Google Cloud KMS envelope encryption](https://docs.cloud.google.com/kms/docs/envelope-encryption): data keys wrapped by a KMS key; a 64 KiB limit on `Encrypt` and `Decrypt`.

**Primary documentation:**
- [context](https://pkg.go.dev/context): pass a context explicitly, as the first parameter, and do not store it in a struct.
- [Contexts and structs](https://go.dev/blog/context-and-structs): a duplicate context-taking API is preferred over a stored context, but only where compatibility rules out changing a signature.

### D2. The signer

**Researched (accessed 2026-10-25):**
- [golang/go#56508](https://github.com/golang/go/issues/56508): a context-aware `crypto.ContextSigner`, accepted, in the Backlog and not implemented.
- [golang/go#63405](https://github.com/golang/go/issues/63405): `crypto.MessageSigner`, shipped in Go 1.25, with no context.
- [sigstore `kms.SignerVerifier.CryptoSigner`](https://pkg.go.dev/github.com/sigstore/sigstore/pkg/signature/kms) v1.11.1: returns a `crypto.Signer` bound to the context it was asked with.
- [go.step.sm/crypto/kms](https://pkg.go.dev/go.step.sm/crypto/kms) v0.91.0: signs over a background context with a fixed 15-second timeout, the pattern D2 avoids.
- [jwx v4 `jws`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jws) v4.5.0: signs through a `crypto.Signer`; `WithContext` applies to verification only.

**Primary documentation:**
- [crypto.Signer](https://pkg.go.dev/crypto#Signer): `Sign(rand, digest, opts)`, with no context.

### D3. Outage and unreadable

**Researched (accessed 2026-10-26):**
- [aws-sdk-go-v2/service/kms/types](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/kms/types) v1.61.6: `InvalidCiphertextException` for corrupt or invalid ciphertext, versus `DependencyTimeoutException`, `KMSInternalException` and `KeyUnavailableException`, each documented as retryable.
- [google.golang.org/grpc/codes](https://pkg.go.dev/google.golang.org/grpc/codes) v1.84.0: `Unavailable` (transient) versus `DataLoss` (unrecoverable corruption).

**Primary documentation:**
- [errors](https://pkg.go.dev/errors): `errors.Is` and `errors.Join`.
- [context](https://pkg.go.dev/context): `Canceled` and `DeadlineExceeded`.

### D4. Dependency failures at session resolution

Reasoned from scrty's own settled specs and the established design: `http-error-propagation` ("One public table maps refusals to a status": any other error is 500, and a dependency failure is not a refusal); `http-security-chain` (the bearer, session-reference and renewal requirements); `identity-model` (a loader reports a miss as "user not found" and any other failure as an error that is not); `diagnostic-redaction` ("Returned errors caused by a dependency carry fixed library text"); and the code of `httpsec`'s resolution and renewal endpoint as of 2026-11-01.

### D5. The established design

Reasoned from scrty's own settled specs and the established design, compared on 2026-11-01.

### D6. A key source outage during verification

**Researched (accessed 2026-11-01):**
- [RFC 6750 §3, §3.1](https://www.rfc-editor.org/rfc/rfc6750.txt): `invalid_token` is a token "expired, revoked, malformed, or invalid for other reasons", answered 401, after which the client may obtain a new token and retry. No code for a server-side failure.
- [RFC 9068 §4](https://www.rfc-editor.org/rfc/rfc9068.txt): validation failures are `invalid_token`; every failure listed is a property of the token, and key retrieval is not addressed.
- [RFC 9110 §15.5.2, §15.6.1, §15.6.4, §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.txt): 401 refuses the credentials presented; 500 is an unexpected condition; 503 is a temporary condition, with an optional `Retry-After`.
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html): 5xx for requests the server cannot fulfil, 4xx for client errors, generic bodies, monitoring of 5xx rates. Read through a summarising fetch; the wording is paraphrased.
- [OWASP ASVS 5.0.0, V16.5.1 to V16.5.3](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md): operate securely when an external resource fails, prevent fail-open, return a generic message.
- [Spring Security 7.1.2 `JwtAuthenticationProvider`](https://github.com/spring-projects/spring-security/blob/7.1.2/oauth2/oauth2-resource-server/src/main/java/org/springframework/security/oauth2/server/resource/authentication/JwtAuthenticationProvider.java) and [`BearerTokenAuthenticationEntryPoint`](https://github.com/spring-projects/spring-security/blob/7.1.2/oauth2/oauth2-resource-server/src/main/java/org/springframework/security/oauth2/server/resource/web/BearerTokenAuthenticationEntryPoint.java): a key-retrieval failure is kept apart from a bad token internally, and both are answered 401, the former with no `error` attribute (the middle path considered).
- [Envoy v1.40.2 `jwt_authn`](https://github.com/envoyproxy/envoy/tree/v1.40.2/source/extensions/filters/http/jwt_authn): a remote JWKS fetch failure is answered 401 `invalid_token`, with its own `jwks_fetch_failed` statistic.
- [auth0/go-jwt-middleware v3.4.0](https://github.com/auth0/go-jwt-middleware/tree/v3.4.0): `jwks_fetch_failed` is answered 401 `invalid_token`.
- [ASP.NET Core v10.0.13 `JwtBearerHandler.cs`](https://github.com/dotnet/aspnetcore/blob/v10.0.13/src/Security/Authentication/JwtBearer/src/JwtBearerHandler.cs): on the default path a failure inside token validation is answered 401 `invalid_token`; a configuration-manager failure is rethrown.
- [go-oidc v3.21.0 `jwks.go`](https://github.com/coreos/go-oidc/blob/v3.21.0/oidc/jwks.go), [keyfunc v3.8.0](https://github.com/MicahParks/keyfunc/blob/v3.8.0/keyfunc.go), [golang-jwt v5.3.1 `parser.go`](https://github.com/golang-jwt/jwt/blob/v5.3.1/parser.go): Go libraries that do not classify a key-retrieval failure, so a caller must.

### D7. Issue, then commit

**Researched (accessed 2026-11-01):**
- [RFC 6749 §4.1.2, §10.5](https://www.rfc-editor.org/rfc/rfc6749.txt) and [RFC 9700 §4.2.4](https://www.rfc-editor.org/rfc/rfc9700.txt): authorisation codes are single-use and invalidated after first use; silent on a token response that fails after the code is spent.
- [Ory fosite v0.49.0 `flow_authorize_code_token.go`](https://github.com/ory/fosite/blob/v0.49.0/handler/oauth2/flow_authorize_code_token.go): tokens are generated before the code is invalidated, and the invalidation commits in a transaction with the token sessions (the order D7 takes).
- [Keycloak 26.8.1 `OAuth2CodeParser.java`](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/protocol/oidc/utils/OAuth2CodeParser.java): the code is removed first, and a later failure leaves it spent (the alternative considered).
- [Ory Kratos v26.2.0 lookup-secret settings](https://github.com/ory/kratos/blob/v26.2.0/selfservice/strategy/lookup/settings.go) and [its documentation](https://www.ory.com/docs/kratos/mfa/lookup-secrets): regenerated recovery codes replace the old set only once the user has received them.
- [NIST SP 800-63B-4 §3.1.2, §4.2.1.1](https://pages.nist.gov/800-63-4/sp800-63b.html): look-up secrets are used once; a used saved recovery code is invalidated and replaced; silent on ordering against delivery.
- [Django 5.2 `PasswordResetTokenGenerator`](https://github.com/django/django/blob/5.2/django/contrib/auth/tokens.py): a stateless token spent only by the successful state change.

Also reasoned from scrty's own `Sessions.RotateIssuing` (`sessions`, "A rotation without grace stores nothing when the caller cannot complete it") and the established design's order of recording a pending challenge before handing out a credential.

### D8. A request whose own context ended

**Primary documentation:**
- [context.Cause and WithCancelCause](https://pkg.go.dev/context#Cause): a context cancelled with a cause reports it through `Cause`, while `Err` stays `Canceled`.

**Researched (accessed 2026-11-01):**
- [Go `net/http` `Request.Context`](https://pkg.go.dev/net/http#Request.Context) (go1.27.3): cancelled when the client's connection closes, the request is cancelled, or the handler returns.
- [nginx release-1.28.0 `ngx_http_request.h`](https://github.com/nginx/nginx/blob/release-1.28.0/src/http/ngx_http_request.h): `NGX_HTTP_CLIENT_CLOSED_REQUEST` 499, a status logged for a request the client abandoned, never sent.
- [gRPC status codes](https://github.com/grpc/grpc/blob/master/doc/statuscodes.md) (commit df3dd4d): `CANCELLED`, typically by the caller, distinct from `UNAVAILABLE` and `UNAUTHENTICATED`.

Also reasoned from scrty's own `authentication` and `account-recovery` requirements on a client that leaves during a password proof's user load.
