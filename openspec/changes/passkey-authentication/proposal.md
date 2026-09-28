## Why

Users increasingly expect to sign in with a passkey: a fingerprint, face or device PIN on their own device, with no password to type, phish or reuse. scrty offers passwords, magic links, OIDC, Basic and API keys, but no WebAuthn. The same credential is also the strongest second factor available, because it resists phishing, so it should serve after a password as well. With a user verification step, one passkey proves both possession and the user. The library can support both uses from one credential store and one verifier.

## What Changes

- **Passkey registration.** A signed-in user can register passkeys: platform authenticators (Touch ID, Windows Hello, Android) and roaming ones (security keys), synced or device-bound. A user may hold several, and can list, name and remove them. Registration is a begin/finish ceremony over a one-time, server-issued challenge. Registering a passkey notifies the user through a channel independent of the registration, as NIST SP 800-63B-4 §4.1.2.1 requires when an authenticator is bound.
- **A first passkey can wait for recovery codes.** `recovery-codes` decides, as the user's decision, that a user with no other way back in holds saved recovery codes before their first passkey counts. Registration enforces it:
  - **Who:** the user has no password, no TOTP, no saved codes, and no linked OIDC identity whose provider login would admit them without the second factor they might lose. The check belongs to `recovery-codes` and is not redefined here.
  - **The pending state:** for such a user the finish step stores the passkey as pending, generates a set of saved codes, and returns them once. The passkey cannot be used to log in or as a second factor while pending.
  - **The confirm step:** the passkey becomes usable only when the user enters one of the codes back at a confirm endpoint, which shows the set was kept. A wrong code leaves the passkey pending. An abandoned registration leaves a pending passkey that never works, and a new registration can replace it.
  - **Other users:** a user who already has another way back in registers without the extra step.
  - **The optional mode:** where the consumer chose `recovery-codes`' optional mode, registration completes at once and reports that recovery is not set up, for the consumer's interface to prompt.
  - **Wiring:** enabling passwordless login while recovery codes are disabled, without choosing the optional mode, is a construction error, because the default cannot be met. Recovery is off by default, so a consumer enabling passwordless login meets this rule at once.
  - **How recovery reaches passkeys:** `recovery-codes` lands first and defines two contracts, an authenticator-reset port and the "no other way back in" check. This change implements the reset port for passkeys, so a recovery removes them, and feeds the check with the user's passkeys.
- **Passwordless login.** A new first factor: a begin/finish ceremony that authenticates by a passkey assertion alone, including discoverable ("usernameless") credentials. A successful assertion establishes a session like any other login.
- **Passkey as a second factor.** Passkeys are a challenge-capable MFA method on the multi-method slot `mfa-multi-method` introduces, so a password login can be completed with a passkey. A pending or suspended passkey does not count as an enrolment, so the slot's usable-methods function never offers the passkey method to a user whose only passkeys are pending or suspended. The slot stays the only place that resolves the MFA challenge.
- **User verification is required by default.** The ceremony asks for user verification, and an assertion without it is refused. A consumer can relax this to "preferred", for plain security keys. An assertion without user verification then never counts as satisfying an MFA requirement.
- **A new first-factor kind and channel.** The identity model names a `passkey` kind and a channel for authenticator-held credentials. The `passkey` kind is not exempt from an MFA requirement, and the exemption list stays `oidc` and `api-key`.
- **A user-verified passkey login satisfies the second factor.** This is the user's decision, and it matches NIST SP 800-63B, which counts such a login as a multi-factor cryptographic authenticator at AAL2, and the behaviour GitHub and Google document.
  - **How it counts:** a passkey whose private key the device releases only after a fingerprint, face or PIN proves two distinct factors in one step. The library records such a login as having satisfied its second factor, and the session keeps the time and that the passkey met it.
  - **Not an exemption:** unlike OIDC, which is exempt because the provider is trusted to have done MFA elsewhere, the passkey proves both factors to scrty directly, through the user-verification flag in the signed assertion.
  - **Only the library can make the claim:** the security policy honours a second factor met at the first factor only when the library's own passkey verification recorded it, never when it is merely asserted.
  - **No second place resolves the challenge:** a login whose second factor was recorded at the first factor never has the MFA challenge raised at all. So the MFA slot's verify step stays the only place that resolves a raised challenge, as `mfa-multi-method` requires.
  - **Without user verification:** where a consumer relaxes user verification, an assertion without it proves possession only. That login is single-factor, and a user required to use MFA must then complete a second factor on a different channel, never a passkey again.
  - **Stricter option:** a consumer can require a separate second factor even after a user-verified passkey login. The same different-channel rule then applies.
- **Recovery of lost passkeys.** A user who has lost every passkey recovers through `recovery-codes`:
  - recovery takes two independent proofs, such as a saved recovery code and an emailed code;
  - it leads to a confined session whose way out is registering a new passkey or another authenticator;
  - by default every passkey and MFA enrolment of the user is removed, except an authenticator proved in that recovery. Removing only what the user reports lost, or a consumer's own policy, are `recovery-codes` opt-ins.

  An emailed link or code alone never recovers a passkey account, so recovery is never weaker than the passkey it replaces. For a passwordless-only user this means holding saved recovery codes, which registration requires by default (see "A first passkey can wait for recovery codes").
- **Prevention before recovery.** The documentation advises at least two passkeys, one of them synced. A user whose only passkey is device-bound is told so at registration.
- **Ceremony challenges are one-time tokens.** Registration, passwordless login and the passkey second factor keep their pending challenge the way `mfa-multi-method` decides. Each is a one-time token under its own purpose, and the token string is the challenge.
  - **Binding:** the token is bound to the session for registration and the second factor. Passwordless login begins before any session exists, so its token is bound to a short-lived ceremony cookie.
  - **Spent on every attempt:** a challenge is spent by any finish attempt, accepted or refused, and is never taken from the client. The rest of the ceremony state is rebuilt at finish from configuration and the credential store.
  - **Passwordless begin writes before anyone is authenticated:** it is therefore throttled per source, and expired tokens are purged.
  - **Challenge strength:** the settled `one-time-tokens` capability fixes a token's secret at 32 random bytes, above the 16 bytes WebAuthn asks of a challenge.
  - **For the design:** define the ceremony cookie: its attributes, its lifetime, and how it is cleared.
- **WebAuthn responses are JSON.** Registration, passwordless login and the passkey second factor all post the WebAuthn response as a JSON body. They read it through the library-owned JSON reader `mfa-multi-method` introduces, with a size cap that fits the largest legal credential. It never reads the URL query, and a body that cannot be read is refused without being charged to a throttle. The passkey method declares the JSON format on the MFA slot and answers at `/mfa/verify/passkey` by default. No passkey code reads the request itself.
- **A suspected clone is refused and its credential suspended.** This is the user's decision.
  - **The signal:** an authenticator adds to a signature counter each time it signs, and the counter travels inside the signed data. The store keeps the last value seen per credential. When a counter that has been counting (nonzero) arrives equal to or lower than the stored value, two copies of that private key are in use.
  - **Default response:** the login is refused with a clone-suspected error. It is a refusal, not counted as a wrong guess. The credential is suspended, so it can no longer log in or serve as a second factor until the user deals with it. The user is notified with repudiation instructions. The library cannot tell which copy is genuine, so it stops trusting the credential rather than guessing.
  - **Why:** NIST SP 800-63B-4 requires a compromised authenticator to be suspended or invalidated promptly once the compromise is detected. The WebAuthn Level 3 specification leaves the response to the relying party, and scrty's rule is that the safe choice is the default.
  - **Scope:** synced passkeys (iCloud Keychain, Google Password Manager and other sync providers) always report 0, which the specification treats as an authenticator that does not count, so they are never affected. The response falls only on authenticators whose keys are meant never to leave the device, such as hardware security keys, where a counter going backwards is a strong signal.
  - **Clearing a suspension:** a suspended credential is never reinstated, because a copied key cannot become trustworthy again. The user removes it from a full session signed in another way, or recovers the account through `recovery-codes`, whose reset removes it. The user then registers a new passkey.
  - **Cost, accepted:** an authenticator with a buggy counter can suspend itself. The user keeps their other passkeys and recovery.
  - **Opt-in alternatives:**
    - **Signal only:** allow the login and record a sampled warning, which is the WebAuthn library's own behaviour;
    - **A consumer function:** given the signal, it chooses to allow, refuse, or refuse and suspend, for example strict for administrators only.
  - **Always:** the signature counter and the backup-eligible and backup-state flags are stored and updated on every successful login, as the WebAuthn library requires of the backup state. The flags are reported, so a consumer can apply its own policy, such as requiring device-bound credentials for some users.
- **Attestation is not requested by default.** This is the user's decision.
  - **What attestation is:** at registration an authenticator can return a statement signed with its manufacturer's key, vouching for the device model that created the passkey. A relying party checks it against the FIDO Metadata Service. It says what kind of device holds a key, never who the user is, and it does not strengthen any login.
  - **Default:** registration asks for no attestation (conveyance `none`) and accepts any authenticator. The authenticator's model identifier (AAGUID) is recorded when the response carries one.
  - **Why:**
    - synced passkeys from Apple and Google carry no attestation, so requiring it would exclude most users' passkeys;
    - the WebAuthn specification warns that attestation can identify the authenticator model, batch or device, and so enable tracking;
    - industry guidance for general audiences, Google's defaults and Yubico's advice, is to leave attestation unset or not to require it.
  - **Opt-in alternatives:**
    - **Record without enforcing:** request full attestation and store what is provided, for audit and a later policy, accepting every authenticator. This is Yubico's "request and store for future reference". It is documented as collecting device-identifying data, and some browsers ask the user's consent.
    - **Require trusted attestation:** refuse registration unless the statement verifies against a trusted, non-revoked metadata entry, optionally limited to an allowlist of models. This is the path to proving hardware-bound keys (NIST SP 800-63B-4 AAL3) and to company-issued authenticators. It is documented as excluding synced passkeys.
  - **Wiring:**
    - requiring attestation without a metadata source is a construction error;
    - metadata comes only from a consumer-supplied source or through scrty's confined outbound client, never from the WebAuthn library's own HTTP fetch;
    - since the model identifier and backup flags are stored, a consumer can apply a stricter policy to some users, such as administrators. The design settles how.
- **The same-channel rule holds.** A passkey never serves as the second factor of a passkey login, just as an emailed code never serves after an emailed magic link.
- **Required relying-party configuration.** The relying-party ID and allowed origins have no default, like the TOTP issuer, and a missing or malformed value is a construction error. The documentation states that changing the relying-party ID orphans every registered passkey.
- **Durable state.** A new security-state table for credentials (credential ID, public key, signature counter, flags, name, timestamps), with its store and conformance cases. Pending ceremonies need no table: they use the existing one-time token store. A random per-user WebAuthn user handle is mapped to the consumer's opaque user reference, which is never sent to an authenticator.
- **Placement.** WebAuthn parsing and verification come from `github.com/go-webauthn/webauthn`, kept in a nested `passkey` module so the core module gains no dependency. The ports and credential types live in the core, and no type of the library appears in scrty's public API.

## Capabilities

### New Capabilities

- `passkey-authentication`: registration and management of passkeys, passwordless login, passkey as an MFA method, user-verification and relying-party rules, user-handle mapping, signature-counter and clone handling, and the one-time ceremony challenge.

### Modified Capabilities

- `identity-model`: the `passkey` first-factor kind and its channel. The kind is not MFA-exempt.
- `http-security-chain`: the passkey registration and login endpoints in the chain.
- `security-state-stores`: the store contract for passkey credentials, including the signature counter, the backup flags and the suspended state, with its ambient-transaction rules. Pending ceremonies reuse the one-time token store contract unchanged.
- `schema-migrations`: the passkey tables in the security-state migration set.
- `store-conformance`: conformance cases for the passkey stores.
- `module-layout`: the new nested `passkey` module.
- `security-policy`: the MFA policies honour a second factor met at the first factor by a user-verified passkey login, recorded by the library, and refuse one merely asserted. The option requiring a separate second factor anyway.
- `sessions`: a session records that its second factor was met by the passkey login itself.
- `account-recovery`: passkeys join the authenticator reset through its port, and passwordless-only users are covered by its "no other way back in" check.
- `http-error-propagation`: status rows for the new refusals: a suspected clone, an authenticator refused by attestation policy, and a pending passkey.
- `rate-limiting`: the per-source throttle on the unauthenticated passwordless begin step.
- `email-notification`: the notices sent on a suspected clone and on registering a passkey, through the existing sending port.

The pending state and the confirm step are part of the new `passkey-authentication` capability, and use the check `recovery-codes` defines.

## Impact

- **Code:**
  - core: the `passkey` ports and types, `factor` gains a kind and channel, and the `httpsec` endpoints;
  - nested `passkey` module: the WebAuthn verifier;
  - `sqlstore`, `pgx` and `gorm`: the new stores;
  - `migrate`: new security-state tables.
- **Dependencies:** `github.com/go-webauthn/webauthn` in the nested `passkey` module only. It brings CBOR, JWT, TPM and UUID packages with it. The core module gains none.
- **Depends on:**
  - `mfa-multi-method`, which must land first, for the second-factor role;
  - `recovery-codes`, which must land first, for recovering an account whose passkeys are all lost, and for the saved codes and the "no other way back in" check that a first passkey can wait for.
- **Ordering:** the queue is `default-identity-store`, then `mfa-multi-method`, then `recovery-codes`, then this change, by the user's decision. It does not touch `default-identity-store`.

## Library Choice

`github.com/go-webauthn/webauthn` was chosen after a survey of the Go WebAuthn libraries, on standard conformance, maintenance and reputation.
- **Conformance:** it supports WebAuthn Level 3, including the credential record and the backup flags synced passkeys carry, and all eight attestation formats. Its README states it is conformance tested against the FIDO conformance tools. No published results or certification were found, so the design treats that as the maintainers' claim, not an established fact.
- **Maintenance** (figures read on 2026-09-28): it is the maintained continuation of the archived `duo-labs/webauthn`. It had more than 100 commits in the six months before this proposal, releases every few weeks, and 52 contributors. No known vulnerability is listed for it in OSV or GitHub's advisory database.
- **Reputation** (read on 2026-09-28): about 1,300 GitHub stars and close to 400 importing projects. It is the library other Go passkey projects build on.
- **Fit:** it verifies only, with no HTTP handling or sessions. It fetches the FIDO metadata service only when asked. A provider interface and a decoder over a caller-supplied blob let scrty fetch metadata through its confined outbound client, or not at all when attestation is `none`.
- **Alternatives rejected:**
  - `duo-labs/webauthn`, `koesie10/webauthn` and `fxamacker/webauthn` are archived or unmaintained.
  - `egregors/passkey` wraps this library in its own routes, sessions and user management, which would duplicate scrty's chain.
  - `islishude/webauthn` is too new to have users.
- **Risk:** it is still v0, and its README warns of breaking changes without notice. The risk is contained by keeping the library's types out of scrty's public API, so a breaking release touches one adapter inside the nested module. The version is pinned and upgraded deliberately.

## Open Questions

None open. Every question raised during exploration was decided by the user:
- passwordless login first, with a passkey also serving as a second factor;
- a user-verified passkey login satisfies the second factor, and is not an MFA exemption;
- the WebAuthn library, `go-webauthn/webauthn`, kept in a nested module;
- recovery through `recovery-codes`, with a first passkey waiting for saved codes where needed;
- WebAuthn responses as JSON through the library-owned reader;
- ceremony challenges as one-time tokens, spent on every attempt;
- a suspected clone refused and its credential suspended;
- no attestation by default.

## References

All sources below are **Researched**: they were consulted while exploring this change, on 2026-09-28, and are grouped by the decision they informed. No source is cited as primary documentation without being consulted. The library figures quoted under Library Choice were read live from the GitHub REST API and the OSV.dev API on that date, and will drift.

### Standard and protocol
- [Web Authentication: An API for accessing Public Key Credentials, Level 3 (W3C)](https://www.w3.org/TR/webauthn-3/): the ceremonies, user verification, backup flags, and challenges of at least 16 random bytes
- [Web Authentication, Level 2 (W3C)](https://www.w3.org/TR/webauthn-2/)
- [Clarity on challenge length, w3c/webauthn issue #1803](https://github.com/w3c/webauthn/issues/1803)
- [Server Requirements, WebAuthn Level 3 and CTAP 2.3 (FIDO Alliance)](https://fidoalliance.org/specs/fidoserver/fido-server-v2.3-rd-20260226.html)
- [Web Authentication API (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)

### Library choice
- [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn): the chosen library, with its README on conformance testing, Level 3 support, attestation formats and v0 stability
- [go-webauthn organization](https://github.com/go-webauthn)
- [webauthn package (pkg.go.dev)](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn): `SessionData`, the `Begin*` and `Finish*` functions, and the `Validate*` functions over parsed data
- [protocol package (pkg.go.dev)](https://pkg.go.dev/github.com/go-webauthn/webauthn/protocol): `ParseCredentialRequestResponseBytes` and `ParseCredentialCreationResponseBytes`
- [metadata package (pkg.go.dev)](https://pkg.go.dev/github.com/go-webauthn/webauthn/metadata): the optional MDS fetch, the `Provider` interface and the `Decoder` over a supplied blob
- [go-webauthn go.mod](https://raw.githubusercontent.com/go-webauthn/webauthn/master/go.mod): its dependencies and Go floor
- [OSV.dev vulnerability database](https://osv.dev): no known vulnerability for `go-webauthn/webauthn` or `duo-labs/webauthn`
- Alternatives surveyed and rejected:
  - [duo-labs/webauthn](https://github.com/duo-labs/webauthn), archived;
  - [koesie10/webauthn](https://github.com/koesie10/webauthn), archived;
  - [fxamacker/webauthn](https://github.com/fxamacker/webauthn), unmaintained;
  - [e3b0c442/warp](https://github.com/e3b0c442/warp), inactive;
  - [egregors/passkey](https://github.com/egregors/passkey) ([go-passkey on pkg.go.dev](https://pkg.go.dev/github.com/egregors/go-passkey)), a wrapper with its own routes and sessions;
  - [islishude/webauthn](https://github.com/islishude/webauthn), too new.
- [The best passkey SDKs and libraries (Corbado, dev.to)](https://dev.to/corbado/the-best-passkey-sdks-and-libraries-for-your-programming-language-framework-5hd0)

### A user-verified passkey login satisfies the second factor
- [About passkeys (GitHub Docs)](https://docs.github.com/en/authentication/authenticating-with-a-passkey/about-passkeys): "passkeys satisfy both password and 2FA requirements"
- [Signing in with a passkey (GitHub Docs)](https://docs.github.com/en/authentication/authenticating-with-a-passkey/signing-in-with-a-passkey)
- [Sign in with a passkey instead of a password (Google Account Help)](https://support.google.com/accounts/answer/13548313?hl=en): a passkey bypasses 2-Step Verification's second step, and can also be the second step
- [Allow users to skip passwords at sign-in (Google Workspace)](https://knowledge.workspace.google.com/admin/users/allow-users-to-skip-passwords-at-sign-in)
- [NIST SP 800-63B-4: Authenticators](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/): multi-factor cryptographic authenticators and their activation factor
- [NIST SP 800-63B-4: Authentication Assurance Levels](https://pages.nist.gov/800-63-4/sp800-63b/aal/): AAL2 needs two distinct factors, and syncable authenticators are not allowed at AAL3
- [Supplement to NIST SP 800-63B adds passkeys to AAL2 (Nat Sakimura)](https://nat.sakimura.org/2024/04/23/supplement-to-nist-sp800-63b-was-published-it-adds-passkey-to-aal2/)
- [NIST supplementary guidelines for passkeys, April 2024 (Authsignal)](https://www.authsignal.com/blog/articles/nist-supplementary-guidelines-for-passkeys-april-2024-part-1)

### Ceremony challenges are one-time tokens
- [HttpSessionPublicKeyCredentialRequestOptionsRepository (Spring Security API)](https://docs.spring.io/spring-security/reference/api/java/org/springframework/security/web/webauthn/authentication/package-summary.html): the challenge is kept server-side in the session by default
- [WebAuthnAuthenticationFilter (Spring Security API)](https://docs.spring.io/spring-security/site/docs/6.5.3/api/org/springframework/security/web/webauthn/authentication/WebAuthnAuthenticationFilter.html)
- [Passkeys with Spring Security 6.5 and MongoDB sessions (Kedos)](https://www.kedos.co.uk/p/news/passkeys-with-spring-security-6-5-and-mongodb-sessions)
- [Yubico java-webauthn-server](https://github.com/Yubico/java-webauthn-server) and [AssertionRequest API](https://developers.yubico.com/java-webauthn-server/JavaDoc/webauthn-server-core/2.8.2/com/yubico/webauthn/AssertionRequest.html): the request is serialised for temporary server-side storage
- [Passkeys (SimpleWebAuthn)](https://simplewebauthn.dev/docs/advanced/passkeys), [Usernameless flow: storing the challenge (discussion #321)](https://github.com/MasterKale/SimpleWebAuthn/discussions/321) and [Custom challenges](https://simplewebauthn.dev/docs/advanced/server/custom-challenges): the challenge is keyed by the session, expires, and is deleted after any attempt
- [GHSA-gjjc-pcwp-c74m (OneUptime advisory)](https://github.com/OneUptime/oneuptime/security/advisories/GHSA-gjjc-pcwp-c74m): a server that accepted a client-supplied challenge allowed replay
- [Server-side passkey registration (Google for Developers)](https://developers.google.com/identity/passkeys/developer-guides/server-registration)
- [Server-side passkey authentication (Google for Developers)](https://developers.google.com/identity/passkeys/developer-guides/server-authentication?authuser=9)

### A suspected clone is refused and its credential suspended
- [Web Authentication, Level 3 (W3C)](https://www.w3.org/TR/webauthn-3/): the signature counter and clone detection (§6.1.1), leaving the response to the relying party when verifying an assertion (§7.2), and the backup flags (§6.1.3)
- [webauthn package: Authenticator, CloneWarning and UpdateCounter (pkg.go.dev)](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#Authenticator): the library only sets `CloneWarning` and never fails a login, skips the check when both counters are 0, and requires the backup state to be written back on every login
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/): the CSP "SHALL suspend, invalidate, or destroy compromised authenticators … promptly following compromise detection", and notifications must explain how to repudiate
- [signCount is dead: why passkey clone detection doesn't work anymore (MojoAuth)](https://mojoauth.com/blog/signcount-is-dead-why-passkey-clone-detection-doesnt-work-anymore): synced passkeys report 0 on every login
- [Server-side passkey authentication: what the spec doesn't tell you (MojoAuth)](https://mojoauth.com/blog/server-side-passkey-authentication-what-the-spec-doesnt-tell-you)
- [Passkey has a theft detection feature, but Apple, Google and Microsoft broke it (U-Zyn Chua)](https://uzyn.com/2025/passkey-has-a-theft-detection-feature-but-big-tech-broke-it/)
- [Cross-device passkey sync explained (MojoAuth)](https://mojoauth.com/blog/cross-device-passkey-sync-icloud-google-1password)
- [State of passkey authentication in the wild: a census of the top 100K sites (arXiv)](https://arxiv.org/pdf/2602.15135)
- [SoK: Web authentication in the age of end-to-end encryption (arXiv)](https://arxiv.org/pdf/2406.18226)

### Attestation is not requested by default
- [Web Authentication, Level 3 (W3C)](https://www.w3.org/TR/webauthn-3/): conveyance preferences (§5.4.7), attestation privacy (§14.4.1), attestation limitations (§13.4.4)
- [Attestation: passkey relying-party implementation guidance (Yubico)](https://developers.yubico.com/Passkeys/Passkey_relying_party_implementation_guidance/Attestation/): "requiring attestation is an invasive policy", "err towards being more permissive", request and store for future reference, attestation for high-assurance scenarios
- [Passkeys developer guide for relying parties (Google for Developers)](https://developers.google.com/identity/passkeys/developer-guides) and [Server-side passkey registration](https://developers.google.com/identity/passkeys/developer-guides/server-registration)
- [Why do some platforms not support attestation for passkeys? (Corbado)](https://www.corbado.com/blog/passkey-providers/why-some-platforms-do-not-support-attestation-for-passkeys) and [Passkeys cheat sheet for developers (Corbado)](https://www.corbado.com/blog/passkeys-cheat-sheet): synced passkeys from Apple and Google carry no attestation
- [Where Google's passkey documentation ends (MojoAuth)](https://mojoauth.com/blog/where-googles-passkey-documentation-ends)
- [Details on Google's implementation of passkeys (FIDO dev list)](https://groups.google.com/a/fidoalliance.org/g/fido-dev/c/nhpxExcofb8)
- [Bootstrapping (passkeys.dev)](https://passkeys.dev/docs/use-cases/bootstrapping/)
- [NIST SP 800-63B-4: Authenticators](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/): AAL3 requires hardware-protected, non-exportable keys, and syncable authenticators are not allowed there
- [metadata package of go-webauthn (pkg.go.dev)](https://pkg.go.dev/github.com/go-webauthn/webauthn/metadata): the `Provider` interface and the `Decoder` over a supplied blob, which keep metadata out of the library's own HTTP
- Not re-verified on the research date: that some browsers ask the user's consent before sharing full attestation. It is recorded as the design's expectation, to be confirmed before it is documented as behaviour.

### Recovery and prevention
- [FIDO Passkeys (FIDO Alliance)](https://fidoalliance.org/passkeys/)
- [Customer support (Passkey Central, FIDO Alliance)](https://www.passkeycentral.org/resources-and-tools/customer-support): synced passkeys restore on a new device
- [Passkeys user journeys (Google for Developers)](https://developers.google.com/identity/passkeys/ux/user-journeys)
- [Device-bound vs. synced credentials: a comparative evaluation (arXiv)](https://arxiv.org/html/2501.07380v1)
- [What happens if you lose your passkey? (MojoAuth)](https://mojoauth.com/blog/what-happens-if-you-lose-your-passkey)
- The recovery flow itself is referenced in `recovery-codes`.
