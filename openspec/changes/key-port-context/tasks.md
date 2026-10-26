# Tasks

Every task is test-first: write the failing test, run it, confirm it fails for the intended reason (a compile error is not a red step), make the smallest change that turns it green, then refactor. Paths are the ones `restructure-layout` produces.

## 1. Established design

- [ ] 1.1 Compare D1 to D5 with the established design's handling of context on its key and cipher ports, of a missing signing key, of a cipher outage on a session read, and of a store outage at session resolution. Record every departure in `design.md` as `legacy-reference.md` requires, or revise the decision and the affected deltas. Verified by D5 in `design.md` no longer reading "pending", and `openspec validate key-port-context --strict` passing.

## 2. Outages are not refusals (reproduced on today's signatures)

- [ ] 2.1 Reproduce and fix the sealing session store's classification of a context error (design D3; `sessions` delta, scenario "Open abandoned when the context ends"). The red test loads a session through a cipher whose open fails with `context.DeadlineExceeded`, and fails today because the load matches `session.ErrUnreadable`. If it passes instead, remove the context half of D3 and report it. Verified by the test passing, together with "Sealed round trip", "Value moved between sessions" and "No rewrite on read".
- [ ] 2.2 Reproduce and fix session resolution answering a session-store failure with the authentication-required error (design D4; `http-security-chain` delta, scenarios "Session store outage" and "Session-reference bearer during a store outage"). The red test fails today because the request's error matches `httpsec.ErrAuthenticationRequired`. Verified by both scenarios passing, with the default mapping answering 500 and no undecryptable-session record written.
- [ ] 2.3 Reproduce and fix session resolution answering a user-reload failure that is not `identity.ErrUserNotFound` with the authentication-required error (design D4; scenario "User store outage"). Verified by the scenario passing, and by a reload that returns `identity.ErrUserNotFound` still being refused with the authentication-required error.
- [ ] 2.4 Confirm the refusals resolution keeps (design D4 table). Verified by the existing scenarios "Expired session", "Superseded identifier presented after its window" and "Session sealed under a retired key", and the renewal endpoint's tests, passing unchanged with `go test ./httpsec/...`.

## 3. Context on `seal.Keyring` and `seal.Cipher`

- [ ] 3.1 Add `ctx` as the first parameter of `seal.Keyring.Active` and `ByID`, and of `seal.Cipher.Seal`, `Open` and `ActiveKeyID`, in `*seal.StaticKeyring` and `*seal.AEADCipher` (design D1). `*seal.AEADCipher` passes its context to the keyring. Both answer whatever state the context is in. Verified by the `secrets-at-rest` scenario "The default cipher answers under a cancelled context", and a test that the keyring receives the cipher's context.
- [ ] 3.2 Pass the store operation's context to every `seal.Cipher` call (design D1): `store/seal`'s enrolment and signing-key stores (re-sealing on read included), and the passkey credential stores in `store/sqlstore`, `store/gormstore` and `store/pgxstore`, whose row helpers take the calling method's context. Regenerate the affected mocks with the `use-mockgen` skill, and update the test module's cipher fixtures. Verified by the scenario "The cipher receives the store's context", the existing `secrets-at-rest` scenarios, `make check`, and the store conformance suites in CI.
- [ ] 3.3 Update the godoc of `seal.Keyring` and `seal.Cipher` (design D1): an implementation over a remote service should honour the context, and is expected to cache or use envelope encryption because of the service's quotas. Verified by `go doc ./store/seal Keyring` and `go doc ./store/seal Cipher` showing the text.

## 4. Context on `session.Cipher`, and the outage marker

- [ ] 4.1 Add `ctx` as the first parameter of `session.Cipher.Seal` and `Open`. The sealing session store passes the context of the save or load it serves, and `seal.SessionCipher` passes its context to the cipher it adapts (design D1). Verified by a test that the cipher receives the load's and the save's context, and by the `secrets-at-rest` scenario "Consumer cipher used".
- [ ] 4.2 Add `session.ErrCipherUnavailable`, and classify an open failure that matches it as a store failure (design D3). Verified by the `sessions` scenarios "Consumer cipher marks an outage" and "An unmarked cipher failure stays unreadable", and by a test that the sentinel matches neither `session.ErrUnreadable` nor `session.ErrNotFound`.
- [ ] 4.3 Add `seal.ErrUnavailable`. `seal.SessionCipher` reports it as `session.ErrCipherUnavailable` and passes context errors through unchanged (design D3). Verified by the `secrets-at-rest` scenario "A marked outage reaches sessions as unavailable", a pass-through test for `context.Canceled`, and a test that `seal.ErrUnavailable` matches neither `seal.ErrDecryptionFailed` nor `seal.ErrUnknownKeyID`.
- [ ] 4.4 Update the godoc of `session.Cipher`, `seal.Cipher` and `seal.SessionCipher` (design D3): which errors read as an outage, and how a remote cipher marks one. Verified by `go doc ./session Cipher` and `go doc ./store/seal SessionCipher` showing the text.

## 5. Context on `signingkey.KeySource`, and the missing-key error

- [ ] 5.1 Add `signingkey.ErrNoKey`, and change `KeySource.Signer` to `Signer(ctx, alg) (kid string, signer crypto.Signer, err error)` in `signingkey.Keys`, which returns `ErrNoKey` for an algorithm it was not configured with and answers whatever state the context is in (design D2). Regenerate the `KeySource` mocks. Verified by the `signing-keys` scenarios "The key manager reports a missing key" and "The key manager answers under a cancelled context".
- [ ] 5.2 Make the generator pass the context given to `Generate`, ask for a signer once per token without keeping it, refuse `ErrNoKey` as today, and wrap any other error behind fixed text (design D2). Verified by the `token-issuance` scenarios "No key for the algorithm" and "Key source outage", and the `signing-keys` scenario "A signer is asked for once per token and never reused".
- [ ] 5.3 Add `ctx` to `KeySource.VerificationKeys`, and make the verifier pass the context given to verification (design D1). Verified by the `signing-keys` scenario "The key source receives the caller's context", and by the `token-issuance` scenario "Typed-nil RSA key" passing unchanged.
- [ ] 5.4 Update the godoc of `KeySource` and `Signer` (design D2): what `ErrNoKey` means, what any other error means, that the returned signer serves one issuance and may be bound to the context, and the caching advice. Verified by `go doc ./token/signingkey KeySource` showing the text.

## 6. Integration

- [ ] 6.1 Run the full gate. Verified by `make check` passing locally, and by CI green on both PostgreSQL and Redis matrix jobs.
- [ ] 6.2 Run one whole-branch review against every requirement of the five deltas and decisions D1 to D5. Verified by a review report with no open finding, and by `openspec validate key-port-context --strict` passing.

## Workflow follow-up

- Archive the change after review, and after `restructure-layout` and `idiomatic-api-shape` have been archived.
- Verify that the archived specs carry the five modified requirements.
