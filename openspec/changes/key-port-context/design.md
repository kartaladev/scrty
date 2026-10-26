# Design

## Context

See `proposal.md` (Why) for the motivation, and the four deltas under `specs/` for the requirements. This change lands after `restructure-layout` and `idiomatic-api-shape`. Every name below is one they produce: `store/seal`, `token/signingkey`, `signingkey.Keys`, `KeySource.Signer`, `session.ErrUnreadable`, `seal.ErrConfig`, `*seal.AEADCipher`, `*seal.StaticKeyring`.

Facts that shape the approach:

- **Every caller of the four ports already holds a context, or is one call away from one.** The callers are `token`'s generator (which discards its context today) and verifier; `seal`'s enrolment and signing-key stores; the passkey credential stores in `store/sqlstore`, `store/gormstore` and `store/pgxstore` (their row helpers are one call below a method taking a context); and `session`'s sealing store. `*seal.AEADCipher` is the only caller of `Keyring`.
- **Every remote key service's Go SDK takes a context first, on every call.** That covers AWS KMS, Google Cloud KMS, Azure Key Vault and HashiCorp Vault. A PKCS#11 HSM is reached in-process, and neither common Go binding takes a context.
- **The standard library's `crypto.Signer` and `crypto.MessageSigner` take no context.** A context-aware signer (golang/go#56508) is accepted but unimplemented. jwx v4 signs through a `crypto.Signer`, and its `WithContext` applies to verification only.
- **The sealing session store maps every open failure to `session.ErrUnreadable`.** `httpsec` logs that error as a retired sealing key and answers it with "log in again". The `seal` stores for MFA enrolments, signing keys and passkeys already return any cipher error as a store error.
- **A remote service's quotas make a call on every session read or every token issue impractical at scale.** AWS KMS, for example, allows 1,000 asymmetric signs per second per account and Region by default.

## Goals / Non-Goals

**Goals:**
- **A request's deadline and cancellation reach a remote key service** through every port.
- **An outage is never reported as a refusal,** on the signing path or the session path.
- **Every behaviour change is test-first.** The misclassified outage is reproduced by a failing test before anything is fixed (D3).

**Non-Goals:**
- **A caching or envelope-encryption decorator** (proposal, Not in this change).
- **Changing how values are sealed.** The envelope format and the AES-256-GCM default are unchanged, and so are stored values.
- **Classifying cipher errors in the `seal` stores.** They already fail closed with the cipher's error, which is what `secrets-at-rest` requires.

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
```

- **Callers pass the context they hold:**
  - the generator passes the context given to `Generate`, and the verifier the one given to verification;
  - each `seal` store passes the context of the store method it serves, re-sealing on read included;
  - `*seal.AEADCipher` passes its own context on to the keyring, and `seal.SessionCipher` passes its context to the cipher it adapts;
  - the passkey row helpers take the context of the method that calls them.
- **No caller substitutes a context of its own, or imposes a deadline of its own.** This is the rule `signing-keys` already sets for construction over a key store.
- **The in-memory implementations ignore the context.** `*seal.StaticKeyring`, `*seal.AEADCipher` and `signingkey.Keys` perform no input or output, so they succeed whatever state the context is in. This follows the `signing-keys` precedent for the in-memory key store.
- **No nil-context check is added.** `idiomatic-api-shape` D6 adds none to functions that merely pass a context along, and the in-memory implementations do not use theirs. A nil context fails at first use, as in the standard library.
- **Godoc of each port:**
  - an implementation over a remote service should honour the context;
  - a remote service's quotas make a call per seal, open or signature impractical at scale, so such an implementation is expected to cache, or to use envelope encryption. `VerificationKeys` already says so.

**Default and override:** the in-memory implementations stay the defaults (`KeySource` has none: the caller always supplies it). A consumer replaces any port with their own implementation, which now receives the caller's context.

**Alternatives considered:**
- **A context on the ciphers and `KeySource` only, with `Keyring` left as it is.** `*seal.AEADCipher` would then hold a context it cannot pass on. A keyring that fetches its key bytes from a secrets service would be back to inventing one.
- **Parallel interfaces that take a context, probed alongside the current ports (the approach Tink takes).** That gives two contracts per port and a type check on every call. It exists to keep compatibility, which scrty does not yet owe anyone.
- **No change, with remote implementations capturing a context at construction or using a background context with a timeout.** The request's deadline would never reach the service, and the Go guidance argues against storing contexts.

### D2. `Signer` reports a missing key apart from an outage, and its signer serves one issuance

`Signer(ctx, alg) (kid string, signer crypto.Signer, err error)`:

- **A source holding no key for `alg` returns an error matching `signingkey.ErrNoKey`.** `signingkey.Keys` does so for an algorithm it was not configured with. Issuing over a source that answers `ErrNoKey` fails as "no current key for the algorithm", as it does today.
- **Any other error is an outage.** Issuing fails with it, behind the generator's fixed text, as the verifier already does with `VerificationKeys`. It is never reported as a missing key.
- **The returned signer serves the one issuance `ctx` belongs to.** The generator asks for a signer once per token, and never keeps or reuses it. A source over a remote service may therefore return a `crypto.Signer` bound to `ctx`, so the service's signing call receives the request's deadline and cancellation. That guarantee is what makes binding the context into the signer safe. It is a contract the spec states and a test pins, because the compiler cannot check it.
- **The signer stays a standard-library `crypto.Signer`.** The `signing-keys` requirement that the contract needs only standard-library types and scrty's own algorithm names is kept.

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
- **`seal.ErrUnavailable` is the same marker in `seal`.** `seal.SessionCipher` translates it to `session.ErrCipherUnavailable`, so a remote `seal.Cipher` marks its outages once, and `session` keeps not importing `seal`. Context errors pass through the adapter unchanged.
- **Neither sentinel matches `seal.ErrDecryptionFailed`, `seal.ErrUnknownKeyID` or `session.ErrUnreadable`.**
- **What `httpsec` does with the store failure** is D4.

**Default and override:** an error nobody classified stays `session.ErrUnreadable`. That is the safer default. A value that truly does not open still ends the session and lets the user log in again. Treating such a value as an outage would instead fail every request on that session until it expired. A consumer opts their cipher's outages out of that default by wrapping them with the marker. Cancellation and deadlines are classified with no work from the implementer.

**Pending reproduction.** The claim that an outage is reported as an unreadable session is `UNREPRODUCED`. The first task writes the failing test: a sealing session store over a cipher whose `Open` returns `context.DeadlineExceeded`, then one returning an error that wraps `session.ErrCipherUnavailable`, and a load that must not match `session.ErrUnreadable`. If that test passes on the code as it is, the claim was wrong, and this decision is removed.

**Alternatives considered:**
- **Context errors only.** A remote service's timeout or throttling that is not a context error would still log users out.
- **A sentinel for "does not open", with every other error treated as an outage.** A consumer cipher that reports a corrupt value with an error of its own would leave that session failing every request until it expired. Every consumer cipher would also have to adopt the sentinel to keep today's behaviour.

### D4. Session resolution answers a dependency failure as one

Today `httpsec`'s session resolution answers every load error with the authentication-required error, a store failure included (`httpsec/resolve.go`). Signed and session-reference bearers share that resolution. D3 alone would therefore stop the false retired-key record, but a key service or database outage would still answer "log in again". The renewal endpoint, by contrast, already returns a store failure unchanged, and `http-error-propagation` maps any unrecognised error, a dependency failure included, to 500.

Resolution classifies a failed load:

| The session manager's error | The request |
|---|---|
| not found, expired, or unreadable | refused with the authentication-required error; unreadable also writes its ERROR record |
| reused superseded identifier | refused as both authentication-required and reused, as today |
| renewal required, on the renewal endpoint's own request | goes on unauthenticated, as today |
| anything else | fails with the session manager's error, which the default mapping answers with 500; no undecryptable-session record |

(The user reload that follows has the same split; see the end of this decision.)

**Pending reproduction.** That resolution answers a store outage with the authentication-required error is `UNREPRODUCED`, and rests on a code reading. Its failing test comes first: a bearer request whose session store fails with an error that is not a refusal must not match the authentication-required error.

**Default and override:** the default status mapping answers the failure with 500, as for any dependency failure. A consumer who wants another answer to an outage replaces the error handler, the override `http-error-propagation` already specifies. No new option is added.

**Trade-off recorded.** A cipher outage can only arise after an existing session has loaded, since the store opens the token of a record it found. While a cipher outage lasts, someone holding a session identifier could therefore tell a live session (500) from a missing one (401). Session identifiers are secret credentials, and unknown references are throttled per source, so this design accepts that exposure. The existing reason for answering missing, expired and unreadable alike, which is not to report whether a session ever existed, still holds for every refusal.

**Alternatives considered:**
- **Keep answering every load error with authentication-required.** A key service or database blip would log every active user out, and resolution would stay inconsistent with renewal.
- **A separate change after this one.** D3 would ship only half effective until that change landed.

**The user reload follows the same rule.** After the session loads, resolution reloads its user, and today answers every reload error with the authentication-required error as well. Under this decision:
- an error matching `identity.ErrUserNotFound` is refused with the authentication-required error, as today;
- any other reload error fails the request with the loader's error.

The `identity-model` spec already requires a loader to report a miss as "user not found" and any other failure as an error that is not, so resolution relies on a contract that is already settled, and the `identity` ports need no change. The same pending-reproduction rule applies: a bearer request whose user loader fails with an error that is not "user not found" must not match the authentication-required error.

### D5. The established design is not consulted in this change

The read-only reference snapshot was not available when this design was made. Whether the established design gave these ports a context, and how it classified a cipher outage, has not been checked. D1 to D4 rest on the research below and on scrty's own settled specs.

**Pending:** before implementation starts, compare D1 to D4 with the established design. Record any departure as `legacy-reference.md` requires, or revise the decision if the established design is the better default.

## Risks / Trade-offs

- **A source ignores the context in the signer it returns** → the issuance cannot be cancelled once the signer is called. It still works, it fails no worse than today, and the godoc says what binding gives.
- **A remote cipher does not mark its outages** → its outages log users out, as they do today. The godoc of both ciphers names the marker, and context errors are classified without it.
- **A remote implementation calls its service on every seal, open or signature** → it runs into the service's quotas. The godoc of each port says to cache or use envelope encryption. scrty does not ship a decorator for it.
- **Every test double of the four ports changes** → that is mechanical. Mocks are regenerated with the `use-mockgen` skill, and the test module's cipher fixtures change with them.

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

Reasoned from scrty's own settled specs: `http-error-propagation` ("One public table maps refusals to a status": any other error is 500, and a dependency failure is not a refusal) `http-security-chain` (the bearer and session-reference requirements); and `identity-model` (a loader reports a miss as "user not found" and any other failure as an error that is not); and from the code of `httpsec`'s resolution and renewal endpoint.

### D5. The established design

Reasoned from scrty's own settled specs; the comparison with the established design is pending.
