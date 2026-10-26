# Proposal

## Why

The godoc of scrty's key and cipher ports invites implementations over a key management service, an HSM or an external key service, yet none of the ports takes a `context.Context`. Every remote key service's Go SDK takes a context on every call, so today a remote implementation cannot receive the request's deadline or cancellation, and has to invent a context of its own.

Two contracts also cannot tell an outage from a refusal:

- `KeySource` reports "no key" as `ok == false`, so a key service that is down reads as a key that was never configured.
- The sealing session store answers every cipher failure with the unreadable-session error. A timed-out or cancelled open would then log the user out and raise an operator alarm about a retired key. This is pending reproduction: no test exists yet, and the first task of this change writes it.

Nothing is tagged, so this is the last point at which the ports can change without breaking anyone. The change lands after `idiomatic-api-shape` and uses the names `restructure-layout` produces.

## What Changes

**BREAKING** in the signatures of four ports and their implementations.

- **A per-call context on the key and cipher ports.** `ctx` becomes the first parameter of every method:
  - `seal.Keyring`: `Active`, `ByID`;
  - `seal.Cipher`: `Seal`, `Open`, `ActiveKeyID`;
  - `session.Cipher`: `Seal`, `Open`;
  - `signingkey.KeySource`: `Signer`, `VerificationKeys`.
- **Callers pass the context they already hold.** `token`'s generator stops discarding its context. The verifier, the sealing stores in `seal`, the passkey credential stores and the sealing session store pass theirs.
- **`KeySource.Signer` returns an error instead of a boolean.** It becomes `Signer(ctx, alg) (kid string, signer crypto.Signer, err error)`.
  - A source that holds no key for the algorithm returns an error matching the new `signingkey.ErrNoKey`.
  - Any other error is an outage. Issuing then fails with that error, not with "no current key".
  - The returned signer serves the one issuance the context belongs to. scrty asks for a signer once per token and never keeps it, so a remote source may bind the context into the signer it returns.
- **An outage is not an unreadable session.** The sealing session store reports a load whose open failed because of an outage as a store failure, not as the unreadable-session error:
  - an error that matches the context's cancellation or deadline is an outage;
  - so is an error matching the new `session.ErrCipherUnavailable`, which a remote cipher wraps around its retryable failures;
  - `seal` gains `ErrUnavailable`, and `seal.SessionCipher` translates it to `session.ErrCipherUnavailable`;
  - every other open failure stays the unreadable-session error.
- **Session resolution answers an outage as an outage.** When a session store or cipher outage keeps `httpsec` from loading a session, the request fails with the store's error, which the default mapping answers with 500. It is not answered with the authentication-required error, and it is not logged as an undecryptable session. Missing, expired, undecryptable and reused sessions keep their refusals. The user reload that follows has the same split: a user who no longer exists is still refused, and a user store outage fails the request. This matches the renewal endpoint and the dependency-failure rule `http-error-propagation` already states.
- **The in-memory implementations ignore the context.** These are `seal.StaticKeyring`, `seal.AEADCipher` and `signingkey.Keys`. They perform no input or output, so they succeed whatever state the context is in.

### Not in this change

- **A caching or envelope-encryption decorator.** The ports' godoc tells remote implementers to cache or to use envelope encryption, and why. Building such a decorator is the implementer's choice.
- **A context-taking signer port of scrty's own, and a probe for a future `crypto.ContextSigner`.** The standard library has neither today. A probe can be added later without breaking anything.
- **`signingkey.KeyStore`.** It already takes a context.

### Order

`restructure-layout` → `idiomatic-api-shape` → this change → `trusted-proxy-client-ip` → `release-readiness` (v0.1.0).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `signing-keys`: "Signing and verification keys can be supplied without the key manager". The key source receives the caller's context, reports a missing key apart from an outage, and its signer is asked for once per token and never kept.
- `token-issuance`: "Issuing requires a key and a valid lifetime". Issuing passes its context to the key source, and an outage fails issuing with the source's error rather than as a missing key.
- `sessions`: "A sealing store protects the provider ID token at rest". An open that failed because of an outage fails the load as a store failure, not as the unreadable-session error.
- `secrets-at-rest`: "The cipher is replaceable". The consumer's cipher receives the caller's context, and can mark an outage so it is not mistaken for a value that does not open.
- `http-security-chain`: "Bearer tokens authenticate against a live session and a live user". A failure to load the session, or to reload its user, that is not a refusal fails the request as a dependency failure, not with the authentication-required error. Session-reference bearers follow the same rule, because they resolve as signed bearers do.

## Impact

- **Code:**
  - `httpsec`'s session resolution, shared by signed and session-reference bearers;
  - the four ports and their implementations: `seal.StaticKeyring`, `seal.AEADCipher`, `seal.SessionCipher`, `signingkey.Keys`;
  - every caller: `token` (generator and verifier); `seal`'s enrolment and signing-key stores; the passkey credential stores in `store/sqlstore`, `store/gormstore` and `store/pgxstore`; `session`'s sealing store;
  - the test module's cipher fixtures, and every test double of these ports.
- **Tests:** test-first for every behaviour change. The first test reproduces the misclassified outage.
- **Dependencies, migrations, stored data:** unchanged. Sealed values and their envelope format do not change.
- **Consumers:** none yet. Nothing is tagged.

## References

See `design.md`, References, grouped by decision.
