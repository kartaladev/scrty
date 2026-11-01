# Proposal

## Why

The godoc of scrty's key and cipher ports invites implementations over a key management service, an HSM or an external key service, yet none of the ports takes a `context.Context`. Every remote key service's Go SDK takes a context on every call, so today a remote implementation cannot receive the request's deadline or cancellation, and has to invent a context of its own.

Once a key or cipher can live behind a network, it can be unavailable, and scrty does not tell an outage from a refusal:

- `KeySource` reports "no key" as `ok == false`, so a key service that is down reads as a key that was never configured.
- The sealing session store answers every cipher failure with the unreadable-session error, a context deadline included. A timed-out open logs the user out and raises an operator alarm about a retired key. This is reproduced.
- `httpsec` answers a session-store or user-store outage at session resolution, and at the renewal endpoint's user reload, with the authentication-required error, so a database blip logs every active user out. The renewal case is reproduced.
- The bearer answers a key source that cannot supply the verification keys as a refused token, 401. This is reproduced.

And a credential that cannot be issued already costs the user something, because seven of the nine issuing paths store or spend first. Renewal stores its rotation and then signs: an outage longer than the 30-second grace window makes the user's next request read as token reuse, which revokes the whole session family and raises a false theft alarm. Recovery spends its proofs, removes the user's authenticators, ends their sessions and replaces their saved codes, then fails to issue, so the new codes are never shown. Both are reproduced. A magic link, an OIDC handoff code and a session are lost the same way.

Nothing is tagged, so this is the last point at which the ports can change without breaking anyone.

## What Changes

**BREAKING** in the signatures of five ports and their implementations.

- **A per-call context on the key and cipher ports.** `ctx` becomes the first parameter of every method:
  - `seal.Keyring`: `Active`, `ByID`;
  - `seal.Cipher`: `Seal`, `Open`, `ActiveKeyID`;
  - `session.Cipher`: `Seal`, `Open`;
  - `signingkey.KeySource`: `Signer`, `VerificationKeys`;
  - `httpsec.KeySetProvider`: `JWKS`.
- **Callers pass the context they already hold.** `token`'s generator stops discarding its context. The verifier, the JWKS endpoint, the sealing stores in `seal`, the passkey credential stores and the sealing session store pass theirs, down to the row helpers that seal and open.
- **`KeySource.Signer` returns an error instead of a boolean.** It becomes `Signer(ctx, alg) (kid string, signer crypto.Signer, err error)`.
  - A source that holds no key for the algorithm returns an error matching the new `signingkey.ErrNoKey`.
  - Any other error is an outage. Issuing then fails with that error, not with "no current key".
  - The returned signer serves the one issuance the context belongs to. scrty asks for a signer once per token and never keeps it, so a remote source may bind the context into the signer it returns.
- **An outage is not an unreadable session.** The sealing session store reports a load whose open failed because of an outage as a store failure, not as the unreadable-session error:
  - an error that matches the context's cancellation or deadline is an outage;
  - so is an error matching the new `session.ErrCipherUnavailable`, which a remote cipher wraps around its retryable failures;
  - `seal` gains `ErrUnavailable`, and `seal.SessionCipher` translates it to `session.ErrCipherUnavailable`;
  - every other open failure stays the unreadable-session error.
- **Session resolution answers an outage as an outage.** At the bearer, the session-reference bearer and the renewal endpoint, a session-store, cipher or user-store failure that is not a refusal fails the request as a dependency failure, with fixed library text, which the default mapping answers with 500. It is not answered with the authentication-required error, not logged as an undecryptable session, and not charged to the source's throttle. Missing, expired, undecryptable and reused sessions, and a user who is gone, not the session's or not active, keep their refusals.
- **A key source outage during verification is a dependency failure.** Only a token the verifier rejects as invalid is the authentication failure; a key set that cannot be obtained fails the request with 500 by default, at the bearer, the `authentication` bearer provider and the JWKS endpoint.
- **A credential is issued before anything is stored or spent.** `session` gains a creation the caller completes before it is stored, and a grace rotation with the caller's step, the shape `RotateIssuing` already has. Form login and the login completion step, magic link, OIDC handoff, passkey login, renewal, and recovery, at once and after a hold, issue first and then spend and store. A credential that cannot be issued stores, spends, removes and revokes nothing, and is a dependency failure, never a refusal.
- **A request whose own context ended is not refused.** At session resolution, a hang-up fails with the context's error, is not logged as an outage and is not charged.
- **The in-memory implementations ignore the context.** These are `seal.StaticKeyring`, `seal.AEADCipher` and `signingkey.Keys`. They perform no input or output, so they succeed whatever state the context is in.

### Not in this change

- **A caching or envelope-encryption decorator.** The ports' godoc tells remote implementers to cache or to use envelope encryption, and why. Building such a decorator is the implementer's choice.
- **A context-taking signer port of scrty's own, and a probe for a future `crypto.ContextSigner`.** The standard library has neither today. A probe can be added later without breaking anything.
- **`signingkey.KeyStore`.** It already takes a context.
- **The settled outage answers elsewhere:** a password login's or recovery proof's user-store outage, an API key owner lookup, the limiters, a failed family revocation during reuse detection, and a handoff store or loader failure at OIDC redemption keep their answers.
- **A passkey login's challenge** stays spent by any attempt, as `passkey-authentication` settles.

### Order

`restructure-layout` → `idiomatic-api-shape` → `reauthentication` → this change → `trusted-proxy-client-ip` → `release-readiness` (v0.1.0). `release-readiness` modifies the same `authentication` requirement and the bearer's user reload, and edits the same token and store files; it rebases onto this change's text and signatures.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `signing-keys`: the key source receives the caller's context, reports a missing key apart from an outage, and its signer is asked for once per token and never kept; a key for an unconfigured algorithm answers with the no-key error.
- `token-issuance`: issuing passes its context to the key source, and an outage fails issuing with the source's error rather than as a missing key.
- `sessions`: an open that failed because of an outage fails the load as a store failure; a creation and a grace rotation can be completed by the caller before anything is stored.
- `secrets-at-rest`: the consumer's cipher receives the caller's context, can mark an outage, and a re-seal that cannot reach the keys does not fail the read.
- `http-security-chain`: a dependency failure at session resolution, at renewal and at verification is not a refusal and is not charged; a hang-up is not refused; form login, the login completion step and renewal issue before they store; the key set is served with the request's context.
- `authentication`: the bearer provider answers a key source outage as a dependency failure.
- `diagnostic-redaction`: a keyring and a key source are dependencies whose error text stays out of the logs.
- `magic-link` and `oidc-login`: the credential is issued before the link or code is consumed, and a failure to issue it keeps the link or code redeemable.
- `one-time-tokens`: a consume refuses a token whose expiry has passed by then, and leaves it unspent, so issuing between the check and the consume cannot spend an expired token.
- `account-recovery`: the credential is issued before anything is spent, and a failure to issue it spends, removes, ends and replaces nothing, at once and after a hold.
- `store-conformance`: the sealed-column suite checks that every seal and open carries the store operation's context.

## Impact

- **Code:**
  - the five ports and their implementations: `seal.StaticKeyring`, `seal.AEADCipher`, `seal.SessionCipher`, `signingkey.Keys`;
  - every caller: `token` (generator and verifier); `seal`'s enrolment and signing-key stores; the passkey credential stores in `store/sqlstore`, `store/gormstore` and `store/pgxstore`; `session`'s sealing store; `httpsec`'s JWKS endpoint;
  - `session`'s creation and grace rotation;
  - `httpsec`'s session resolution, bearer, renewal endpoint, form login, login completion, magic-link and OIDC handoff redemption, passkey login, and recovery completion and finish; the `recovery` core's completion;
  - the test module's cipher fixtures and store conformance suites, and every test double of these ports.
- **Tests:** test-first for every behaviour change. Each reproduced defect is the red step of its task, and existing tests that pin an outage as a refusal are rewritten on purpose.
- **Dependencies, migrations, stored data:** unchanged. Sealed values and their envelope format do not change, and no store port changes.
- **Consumers:** none yet. Nothing is tagged.

## References

See `design.md`, References, grouped by decision.
