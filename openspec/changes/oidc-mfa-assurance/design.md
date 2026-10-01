## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Contracts this change builds on and does not restate:**
  - `identity-model`: the `oidc` first-factor kind, its `federated` channel, and its exemption flag.
  - `security-policy`: the second-factor challenge policy and the MFA requirement policy. It includes these rules:
    - a login's own claim to have satisfied a second factor is never honoured at post-authentication;
    - a same-channel enrolment counts as no usable enrolment;
    - the exemption rule is replaceable (`WithMFAExemption`, accepted by both MFA policies).
  - `oidc-login`: strict ID token verification, the check-then-consume handoff redemption, the policy guards around it, and the callback success handler that replaces the handoff.
  - `sessions`: federated fields and the first factor are written in the creating write. Challenge state lives in library-owned fields, never in consumer data.
  - `multi-factor-auth`: the pending challenge, the verify endpoint, and the gate that blocks protected handlers while a challenge is pending.
- **Built on `passkey-authentication`.** That change adds the library-only proof that a login's second factor was met at its first factor, the session's met-by-first-factor marker, and the `passkey` kind and `public-key` channel. It modifies several of the requirement blocks this change modifies. It is applied and archived first, and this change's deltas are written against its post-change text (decision 8).
- **Established behaviour.** OIDC is exempt from both MFA policies purely by its kind. Both policies return allow for an exempt kind before any lookup, and neither reads a claim from the provider. "Require MFA for all" explicitly leaves OIDC exempt, on the premise that the provider handles the second factor. Existing tests pin that an enrolled user is logged in through OIDC without a challenge. No test pins the case of a required user with no enrolment logging in through OIDC under the default classification (decision 7).
- **What the code already has.**
  - The verifier decodes the whole ID token payload, so reading `amr` and `acr` needs no extra request. Nothing reads them today.
  - The authorize URL is built in `oidc`, so `acr_values` is added there, not in `httpsec`.
  - The handoff is a separate `HandoffManager`. The post-authentication policies run inside `Redeem`, through a `RedeemCheck` that today receives only the principal and password-change time. That check is where assurance must reach policy, so its argument widens (decision 4).
  - The first-factor vocabulary lives in package `factor`. `oidc` does not import `policy`, and `policy` does not import `oidc`.
  - The security-state migration is one file, edited in place before the first tag.

## Goals / Non-Goals

**Goals:**
- A user required to use MFA can no longer get a session through OIDC unless there is evidence of a second factor: either a verified provider assertion or scrty's own challenge.
- Assurance decisions use only signed, validated provider claims, matched exactly as configured. The library does not interpret provider-specific values.
- Every new behaviour has a default, an override, and construction-time validation.

**Non-Goals:**
- Authentication freshness (`auth_time`, `max_age`, `prompt=login`). An `amr` of `mfa` in a token minted from a long-lived provider SSO session is accepted. See Risks.
- The `claims` request parameter, essential claims, and the UserInfo endpoint.
- Re-authenticating at the provider mid-session (provider-side step-up).
- Changing the exemption of `api-key` logins.
- The enrolment path for required users who have no enrolment (`mfa-enrolment-path`).
- A built-in per-user assurance rule. Per-user rules go through the evaluator port (decision 2).

## Decisions

### 1. Per-provider assurance configuration is plain data

```go
type Assurance struct {
    AcceptedAMR []string       // exact, case-sensitive match on any one value
    AcceptedACR []string       // exact, case-sensitive match on the token's acr
    RequestACR  []string       // sent as acr_values; a request, never evidence
    Match       AssuranceMatch // MatchAny (default) or MatchAll
}
func WithProviderAssurance(provider string, a Assurance) ManagerOption // oidc
```

- **Default for a provider with no assurance option:** `AcceptedAMR = ["mfa"]`, no accepted `acr`, and no `acr_values`. `mfa` is the RFC 8176 value that asserts more than one authentication method. Single-method values such as `otp` or `hwk` are not accepted by default, because on their own they do not show that a second factor was used.
- **Override:** `WithProviderAssurance` replaces the whole configuration for that provider. Whether a field was configured, and whether it was configured empty, are told apart by a comma-ok read:
  - an `AcceptedAMR` configured empty means the provider's `amr` is never accepted;
  - a provider configured with neither accepted set never meets assurance, which is valid and means "always use the local second factor".
- **Matching:**
  - `MatchAny` (default): assurance is met when any configured criterion matches.
  - `MatchAll`: every configured criterion must match.
  - Both configured sets are provider assertions with the same trust, so either one is sufficient evidence by default.
- **`acr` is matched as a set, not as a minimum.** `acr` values are provider-defined and unordered in the standard. Ordering them would mean scrty interpreting provider data it does not own. A consumer who wants "silver or above" lists every value at or above silver.
  - **Alternative rejected:** an ordered ladder with a minimum. It is the same expressiveness with more configuration, and it invites the library to assume an order between values it does not know.
- **`acr_values`** is appended to the authorization redirect only when configured. It is a request the provider may ignore (OIDC Core calls it voluntary), so the returned token is always checked. Requesting an `acr` is never itself treated as evidence.
- **Construction checks** (configuration errors from `NewManager`):
  - an assurance option for an unregistered provider;
  - an empty string inside any list;
  - a `Match` value outside the defined set.

  Requesting `acr_values` while accepting no `acr` is valid, because a consumer may ask for a stronger context and verify it through `amr`.

### 2. Assurance is read only from the validated ID token

- **Source:** the `amr` and `acr` claims of the ID token that passed every check in `oidc-login`. Nothing else is read:
  - no UserInfo response (scrty never calls it);
  - no access token, query parameter or form field;
  - no value from a consumer's broker;
  - no value presented at redemption.

  The redemption endpoint reads assurance from the handoff record, which only the library writes.
- **Missing counts as not asserted.** An absent claim, an `amr` that is an empty array, an `amr` that is not an array of strings, and an `acr` that is not a non-empty string all mean nothing was asserted. The library never infers assurance from the provider's identity, from its discovery metadata (`acr_values_supported`), or from a previous login. Providers omit `amr` on silent and refresh-based authentication, so absence is common and must fail safe.
- **Malformed claims** write a sampled warning naming the provider and the claim name, never its value, under the existing `oidc.callback` sampler. The login continues with assurance not asserted; the claim does not make the token invalid. Rejecting the token would stop a provider with a quirky `amr` from logging anyone in, while treating the claim as absent already fails safe.
- **Stored as asserted.** The provider's `amr` values (in order, deduplicated) and its `acr` are kept verbatim. Match results are not stored as the source of truth (decision 4).
- **Override:** `WithAssuranceEvaluator(AssuranceEvaluator)` on the manager replaces the matching step. It is the port for per-user rules, such as "administrators require `hwk`".
  - It receives the request context, the user reference, the provider name, the verified issuer and the asserted values, never the raw token.
  - It returns met, not met, or an error. An error fails closed: the MFA policies deny with it as the reason.
  - The library still owns extraction, so a consumer evaluator cannot widen the trusted source.
  - **Alternative rejected:** a built-in per-user rule. It would need a new identity port to say which users need which values, and the evaluator already lets a consumer consult their own data.

### 3. What happens for a required user: challenge by default, refusal or exemption on request

The MFA requirement policy gains a federated-assurance mode. For the `federated` channel, the requirement no longer depends on the exemption flag of `oidc` (decision 9).

```go
func WithFederatedAssurance(mode FederatedAssuranceMode) MFARequirementOption // policy
// FederatedAssuranceChallenge (default), FederatedAssuranceRefuse, FederatedAssuranceExempt
```

For a login whose first factor has the `federated` channel and whose user is required:

| Assurance | Challenge (default) | Refuse | Exempt |
|---|---|---|---|
| met | allow; the requirement is satisfied | allow | allow |
| not met, user has a usable enrolment | challenge through the MFA challenge path | deny with an assurance-not-met reason | allow |
| not met, no usable enrolment | enrolment path when it admits OIDC, otherwise deny with enrolment-required | deny with an assurance-not-met reason | allow |
| evaluator or lookup error | deny | deny | allow |

- **Why challenge by default:**
  - It reuses a path that already exists end to end. Handoff redemption consumes the code and creates a session pending the challenge, the gate blocks protected handlers, and the verify endpoint resolves it.
  - The `federated` channel differs from every MFA method's channel, so the same-channel rule never applies.
  - Providers that do not emit `amr` (a common default) stay usable for required users who enrol locally.
  - It is the safe default the library-design rule asks for, and the user chose it.
- **The requirement policy raises the MFA challenge itself for unmet federated logins** in the post-authentication phase, because the second-factor challenge policy allows federated logins by default (decision 5). It therefore declares the MFA challenge, so the chain refuses to assemble without its enforcer.
- **Refuse** suits deployments where the provider must be the only MFA authority. A refusal does not consume the handoff code, is counted against the per-source limit like any refusal of a valid code, and maps to 403.
- **Exempt** is the established total exemption, kept as a named mode that a consumer chooses on purpose. Its godoc states the bypass in plain terms.
- **Override:** the mode option. `WithMFAExemption` remains the lower-level override. A consumer rule that marks `oidc` exempt still yields a total exemption before any federated evaluation, and the documentation says this is equivalent to `FederatedAssuranceExempt`.
- **Stateless authentication is unchanged.** A required user in that phase is still refused.
- **Alternative rejected:** refusal as the default. It breaks every required user of a provider that does not emit `amr`, and gives them no path in, even when they are enrolled locally.

### 4. Provider assurance is library-minted evidence, kept beside the session and re-matched per request

This is option B of the mechanism audit, refined. The alternatives and the evidence for the choice are under References.

- **Evidence, not a verdict.** The policy input gains a `FederatedAssurance` field of a public type with no public constructor, whose zero value asserts nothing. It carries the provider name, the verified issuer and the asserted `amr`/`acr`, readable through accessors. Only library code mints it:
  - the OIDC redemption, from the library-written handoff record;
  - per-request evaluation, from the session's library-owned fields.

  A consumer evaluating a policy directly cannot forge it. A plain field or claim on the input stays ignored, so the post-authentication honesty rule holds without exception.
- **Matching is a port the policy consults.** The MFA policies accept `WithFederatedAssuranceSource(FederatedAssuranceSource)`. The OIDC manager implements it from its provider configuration and evaluator. `policy` defines the port and `oidc` implements it, so `policy` never imports `oidc`.
- **The second-factor state is not set to satisfied** by provider assurance, and the passkey met-by-first-factor marker is not set either.
  - "Satisfied" keeps meaning that scrty's own verify endpoint succeeded, and the marker keeps meaning a library-verified passkey. Audit and consumer logic can tell all three apart.
  - NIST SP 800-63B-4 §5.1 holds that a session inherits, and never exceeds, the assurance of its authentication event. Mixing an outside assertion into the local satisfied state blurs that line.
  - Keycloak's open defect, where brokered logins never set the session's level, shows the cost of merging the two states.
- **Handoff record, handoff result and callback result** gain `AMR []string` and `ACR string`, written at issue alongside the federated fields.
- **The redemption check sees the record's assurance.** `RedeemCheck` becomes `func(ctx context.Context, c RedeemCandidate) error`, where `RedeemCandidate` carries the loaded principal, the password-change time, and the record's provider, issuer, `amr` and `acr`. This is a pre-tag signature change. The chain mints the evidence from the candidate inside the check. Its guard after redemption also refuses a consumer redeemer whose result names different assurance values than the check was handed, as it already does for a different user. A consumer's callback success handler receives them in `CallbackResult`. Its godoc says a consumer who creates sessions itself must pass them on, or the session carries no assurance.
- **Session** gains library-owned fields `FederatedAMR []string` and `FederatedACR string`, set through a creation option. They are written in the creating write, together with the first factor and provider, carried over on rotation, and never stored in consumer data. A consumer key cannot forge them, under the same rule as challenge state.
- **Per-request evaluation** re-matches the stored values against the provider's current configuration. It does not trust a stored "met" flag. This follows RFC 9470 and the per-request practice of Spring Security and ASP.NET Core. As a result:
  - tightening a provider's accepted set takes effect on existing sessions at their next request (met sessions become a per-request challenge, as the requirement policy already does for users flagged mid-session);
  - a provider removed from the registry never matches;
  - a session whose local second factor was satisfied stays allowed, as today.
- **Secrets at rest:** the values are not credentials. They are stored unsealed, unlike the ID token, which is a bearer artifact.
- **Alternatives rejected:**
  - *Reuse the passkey proof and create the session satisfied, re-matching per request (option A).* One proof would then carry two meanings: a library-verified authenticator that never becomes false, and a third-party assertion that must be re-matched. Re-matching would need a second code path anyway, and the satisfied state would no longer say who verified the factor.
  - *Reuse the proof and keep the login-time decision for the session's life (option C).* It freezes a decision made under configuration that may later be tightened, contrary to RFC 9470 and RFC 8176's warning that acceptable methods change over time.

### 5. Enrolled users who are not required keep today's behaviour by default

The second-factor challenge policy keeps allowing OIDC logins of enrolled, non-required users without a local challenge.

- **Why:** no guarantee is broken there. The user is not required, and the established behaviour carries no admitted defect for that case.
- **Mechanism:** the policy allows a `federated` first factor by its own default rule, no longer by the kind's exemption flag (decision 9), and consults no lookup for it.
- **Override:** `WithFederatedChallengeWhenUnmet(true)` on the second-factor challenge policy challenges such users when assurance is not met. It is named for that policy alone, so it does not govern the requirement policy.

### 6. Construction-time wiring checks

The following are configuration errors at construction:
- `WithFederatedChallengeWhenUnmet(true)` without a federated assurance source, at the challenge policy's construction.
- `FederatedAssuranceChallenge` without an MFA method is not a new error. It already fails as "require MFA for all with no methods". With a per-user lookup and no methods, the existing rule applies: a required user is denied with MFA-required, whatever the first factor. Making it an error under the default mode would reject a configuration that is valid today.
- OIDC login enabled on the chain while an MFA policy in Challenge or Refuse mode has no federated assurance source. Chain assembly asks the engine's policies, through an optional interface, whether they need a source and lack one, in the same way it already asks which challenges they declare.

An MFA policy with no source and no OIDC login on the chain is valid: no federated login ever reaches it.

### 7. Deliberate departures from the established design

Each item names what scrty does differently from the established behaviour, and why: **(a)** a settled scrty decision requires it, or **(b)** the established approach has a demonstrable defect.

1. **OIDC does not satisfy the MFA requirement by kind alone. Required users need verified provider assurance or a local second factor.**
   - (b) The established requirement states that a required user uses a second factor, including under "require MFA for all". Yet a required user with no enrolment, logging in through a provider that authenticated by password only, gets a session. The premise that the provider handles the second factor is never checked.
     - **Status: UNREPRODUCED, pending reproduction.** No existing test pins this case. The first task of this change writes it as a failing test: under the default configuration, with MFA required for all and no enrolment, an OIDC handoff redemption whose ID token carries no `amr` must be refused with enrolment-required and must not consume the code. If that test passes on the unchanged code, the claim is wrong, and this departure is removed.
   - (a) scrty's library-design rule: when safe and convenient disagree, the default is the safe one and the convenient one is an option. The total exemption survives as `FederatedAssuranceExempt`.
2. **Enrolling a required user through a session from an exempt OIDC login is no longer a supported path by default.** It follows from departure 1. That path is `mfa-enrolment-path`'s concern. Under Exempt mode the established path still works.
3. **The account-recovery way-back check no longer counts a linked identity by the OIDC kind's exemption alone.** It follows from departure 1: a linked identity counts only when its login would be admitted without a local second factor (decision 10).

Everything else is kept as established: the `api-key` exemption, the non-required enrolled user outcome, and the requirement policy's refusal order.

### 8. Sequencing after `passkey-authentication`

- `passkey-authentication` is applied and archived before this change is implemented. This change's deltas modify the requirement blocks as that change leaves them.
- Its proof requirement says the MFA policies "ignore every other field or claim when deciding whether the first factor met the second". This change narrows that sentence to name library-minted federated evidence as the one other input, and states that federated evidence is not that proof and never sets the marker.
- **Alternative rejected:** implementing this change first. It would mean rebasing an already-planned change of 35 tasks onto this one.

### 9. `oidc` is no longer exempt by kind; only `api-key` is

- `identity-model` narrows its wording: `oidc` reports the `federated` channel and is not exempt from an MFA requirement. Its MFA treatment is decided by the `federated` channel rules of `security-policy`: the mode for required users (decision 3) and the default allow for non-required users (decision 5).
- `api-key` stays the only exempt kind. The default exemption rule therefore stops short-circuiting OIDC, and a consumer rule that marks `oidc` exempt restores the total exemption.
- The enrolment-path allowlist is unchanged: OIDC stays off it by default. Its scenarios no longer need a consumer classification to make OIDC non-exempt.

### 10. The way-back check counts a linked identity only when its login would be admitted

- The account-recovery check counts a linked federated identity only when an OIDC login for that user would be admitted without a local second factor:
  - the requirement policy is in Exempt mode, or the consumer's exemption rule marks `oidc` exempt; or
  - the user is not required to use MFA.
- Provider assurance cannot be known before a login, so it is never assumed. This fails safe: the check may report no where a provider would have asserted `mfa`, which only makes the user keep another way back in.
- The decision is made by the requirement policy itself, so the two cannot disagree. The policy implements `policy.LoginAdmission` (`AdmitsWithoutLocalSecondFactor(ctx, user, kind) (bool, error)`), and `recovery.WayBackDeps.Admits` takes that method in place of today's `Exempt` rule. A failed requirement lookup returns an error, as every lookup failure in the check already does.
- **Default with no `Admits`:** a linked login counts only when its kind is exempt by `factor.Kind.MFAExempt`, which after decision 9 is `api-key` alone. A consumer who links OIDC identities and wants them counted wires the requirement policy's method. The godoc says so.

## Risks / Trade-offs

- [A provider's SSO session reuses an `mfa` assertion from hours ago] → Documented limit. Freshness (`auth_time`, `max_age`) is a non-goal and is recommended as a follow-up. Storing `auth_time` now was considered and deferred: before the first tag the migration is edited in place, so adding the column later costs nothing.
- [A provider lets a tenant administrator emit arbitrary `amr` values] → Provider configuration is trusted operator input, as `oidc-login` already states. The accepted sets are per provider, so a less trusted provider can be configured empty.
- [A consumer lists a single-method value such as `otp` and accepts single-factor logins] → Godoc on `AcceptedAMR` explains RFC 8176 semantics. The default accepts only `mfa`.
- [Required users of a provider that emits no `amr` are now challenged or refused at their next login] → Challenge is the default, so an enrolled user continues after a local code. Unenrolled required users are refused with enrolment-required, a documented consequence tied to `mfa-enrolment-path`. Exempt mode restores the old behaviour explicitly.
- [A consumer's callback success handler drops the assurance fields] → The session then carries no assurance, and required users are challenged or refused, which fails closed. Documented on the handler.
- [Re-evaluation on every request challenges live sessions after a configuration change] → Intended. It is the same step-up path used when a user is flagged mid-session.
- [A consumer evaluator is slow or fails] → It runs on every per-request evaluation of a federated session of a required user. Its failure denies. The godoc says it must be fast and side-effect free, like every refusal check.
- [Malformed claims are silently treated as absent] → Not silent: they produce a sampled warning with the provider and claim name.

## Migration Plan

Not applicable: nothing is tagged. The handoff and session columns are added in place to the security-state migration, owned by `schema-migrations`, before the first tag.

## Resolved Questions

Answered by the user on 2026-10-01:

- **The default mode:** `FederatedAssuranceChallenge`. `FederatedAssuranceExempt` stays available as an explicit opt-in, and `FederatedAssuranceRefuse` as an option.
- **Refuse versus challenge when assurance is not met:** challenge by default, refuse as an option.
- **Per provider or per user:** per provider in this change, per user through the evaluator port only.
- **`identity-model` wording:** a small `identity-model` delta (decision 9).
- **Sequencing with `passkey-authentication`:** passkey first (decision 8).
- **How assurance reaches policy:** decided by a standards and practice audit the user asked for: option B, refined (decision 4).
- **The way-back check:** counts a linked identity only when its login would be admitted (decision 10).

## References

### Decision 4: provider assurance as separate evidence, re-matched per request

**Researched (accessed 2026-10-01):**
- [NIST SP 800-63C-4](https://pages.nist.gov/800-63-4/sp800-63c.html): the RP determines the minimum xAL it accepts and assesses IdP assertions against it; FAL3 keeps an RP-verified authenticator distinct from the assertion.
- [NIST SP 800-63B-4, Session Management](https://pages.nist.gov/800-63-4/sp800-63b/session/): a session inherits, and is never higher than, the assurance of its authentication event; the RP is authoritative for reauthentication of federated sessions.
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html): step-up raises a session's assurance when a higher level is required.
- [RFC 9470, OAuth 2.0 Step-Up Authentication Challenge](https://www.rfc-editor.org/rfc/rfc9470.html): `acr` is evaluated per request against the resource's current requirements.
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): renew and log on privilege-level changes within a session.
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html): step-up for sensitive actions; says nothing about federated assertions.
- [Spring Security, Multi-Factor Authentication](https://docs.spring.io/spring-security/reference/servlet/authentication/mfa.html): each factor is recorded as its own authority, including the OAuth 2.0 login, and checked per request.
- [ASP.NET Core, Multi-factor authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/mfa?view=aspnetcore-10.0): `amr` is kept on the signed-in principal and checked per request by policy; providers differ in the values they send.
- [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/index.html): `acr` mapped to levels of authentication per realm and client.
- [Keycloak issue #25335](https://github.com/keycloak/keycloak/issues/25335): an open defect in which brokered logins never set the session's level of authentication; illustrates the cost of merging brokered and local assurance. Issue state drifts.

### Decisions 1–2: per-provider accepted values, ID-token-only source, absence fails safe

**Researched (accessed 2026-10-01):**
- [Auth0, Configure step-up authentication for web apps](https://auth0.com/docs/secure/multi-factor-authentication/step-up-authentication/configure-step-up-authentication-for-web-apps): check that `amr` is present and contains `mfa`; `amr` is absent after silent authentication and refresh.
- [coreos/go-oidc `IDToken`](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc#IDToken) and [zitadel/oidc `IDTokenClaims`](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/oidc#IDTokenClaims): Go relying-party libraries expose `amr`/`acr` as data and leave the decision to the relying party.

**Primary documentation:**
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html): `acr` and `amr` are optional ID token claims; `acr_values` is a voluntary request; the client checks an `acr` it requested.
- [RFC 8176, Authentication Method Reference Values](https://www.rfc-editor.org/rfc/rfc8176.html): `mfa` asserts multiple-factor authentication; relying on specific methods makes systems brittle as methods change.

### Decisions 3, 5, 7–10: modes, defaults, departures, sequencing and the way-back check

Reasoned from scrty's own settled specs and the established design, and from the user's answers recorded under Resolved Questions.
