## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Contracts this change builds on and does not restate:**
  - `identity-model`: the `oidc` first-factor kind, its `federated` channel, and its exemption flag.
  - `security-policy`: the second-factor challenge policy and the MFA requirement policy. It includes these rules:
    - a login's own claim to have satisfied a second factor is never honoured at post-authentication;
    - a same-channel enrolment counts as no usable enrolment;
    - the exemption rule is replaceable (`WithMFAExemption`).
  - `oidc-login`: strict ID token verification, the check-then-consume handoff redemption, the policy guards around it, and the callback success handler that replaces the handoff.
  - `sessions`: federated fields and the first factor are written in the creating write. Challenge state lives in library-owned fields, never in consumer data.
  - `multi-factor-auth`: the pending challenge, the verify endpoint, and the gate that blocks protected handlers while a challenge is pending.
- **Established behaviour.** OIDC is exempt from both MFA policies purely by its kind. Both policies return allow for an exempt kind before any lookup, and neither reads a claim from the provider. "Require MFA for all" explicitly leaves OIDC exempt, on the premise that the provider handles the second factor. Established tests pin two outcomes:
  - an enrolled user is logged in through OIDC without a challenge;
  - a required user with no enrolment is logged in through OIDC.

  The established documentation also suggests enrolling required users through a session from an exempt OIDC login.
- **What the verifier already has.** A verified ID token exposes all of its claims, so reading `amr` and `acr` needs no extra request.

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

## Decisions

### 1. Per-provider assurance configuration is plain data

```go
type Assurance struct {
    AcceptedAMR []string // exact, case-sensitive match on any one value
    AcceptedACR []string // exact, case-sensitive match on the token's acr
    RequestACR  []string // sent as acr_values; a request, never evidence
    Match       AssuranceMatch // MatchAny (default) or MatchAll
}
func WithProviderAssurance(provider string, a Assurance) ManagerOption
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
- **`acr_values`** is appended to the authorization redirect only when configured. It is a request the provider may ignore, so the returned token is always checked. Requesting an `acr` is never itself treated as evidence.
- **Construction checks** (configuration errors):
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
- **Missing counts as not asserted.** An absent claim, an `amr` that is an empty array, an `amr` that is not an array of strings, and an `acr` that is not a non-empty string all mean nothing was asserted. The library never infers assurance from the provider's identity, from its discovery metadata (`acr_values_supported`), or from a previous login.
- **Malformed claims** write a sampled warning naming the provider and the claim name, never its value, under the existing `oidc.callback` sampler. The login continues with assurance not asserted; the claim does not make the token invalid. Rejecting the token would stop a provider with a quirky `amr` from logging anyone in, while treating the claim as absent already fails safe.
- **Stored as asserted.** The provider's `amr` values (in order, deduplicated) and its `acr` are kept verbatim. Match results are not stored as the source of truth (see decision 4).
- **Override:** `WithAssuranceEvaluator(AssuranceEvaluator)` replaces the matching step, for example to consult a consumer's per-user rules. It receives the provider name, the verified issuer, and the asserted values only, never the raw token. The library still owns extraction, so a consumer evaluator cannot widen the trusted source.

### 3. What happens for a required user: challenge by default, refusal on request

The MFA requirement policy gains a federated-assurance mode, and the exemption flag of `oidc` no longer short-circuits it:

```go
func WithFederatedAssurance(mode FederatedAssuranceMode) MFARequirementOption
// FederatedAssuranceChallenge (recommended default), FederatedAssuranceRefuse, FederatedAssuranceExempt
```

For a login whose first factor has the `federated` channel and whose user is required:

| Assurance | Challenge (default) | Refuse | Exempt |
|---|---|---|---|
| met | allow; the requirement is satisfied | allow | allow |
| not met, user has a usable enrolment | challenge through the MFA challenge path | deny with an assurance-not-met reason | allow |
| not met, no usable enrolment | deny with enrolment-required | deny with an assurance-not-met reason | allow |

- **Why challenge by default:**
  - It reuses a path that already exists end to end. Handoff redemption consumes the code and creates a session pending the challenge, the gate blocks protected handlers, and the verify endpoint resolves it.
  - The `federated` channel differs from every MFA method's channel, so the same-channel rule never applies.
  - Providers that do not emit `amr` (a common default) stay usable for required users who enrol locally.
- **Refuse** suits deployments where the provider must be the only MFA authority. A refusal does not consume the handoff code, is counted against the per-source limit like any refusal of a valid code, and maps to 403.
- **Exempt** is the established total exemption, kept as a named mode that a consumer chooses on purpose. Its godoc states the bypass in plain terms.
- **Override:** the mode option. `WithMFAExemption` remains the lower-level override. A consumer rule that marks `oidc` exempt still yields a total exemption, and the documentation says this is equivalent to `FederatedAssuranceExempt`.
- **Post-authentication honesty rule.** At post-authentication, `security-policy` refuses to honour a login's claim of a satisfied second factor. Provider assurance is a separate input field, set only by the OIDC redemption path from the library-written handoff record. That rule therefore still holds for every client-influenced claim. The `security-policy` delta must word this distinction explicitly.
- **Stateless authentication is unchanged.** A required user in that phase is still refused.
- **Alternative rejected:** refusal as the default. It breaks every required user of a provider that does not emit `amr`, and gives them no path in, even when they are enrolled locally.

### 4. The session records the asserted assurance, and policy re-evaluates it

- **Handoff record and callback result** gain `AMR []string` and `ACR string`, written at issue alongside the federated fields. A consumer's callback success handler receives them in `CallbackResult`. Its godoc says a consumer who creates sessions itself must pass them on, or the session carries no assurance.
- **Session** gains library-owned fields `FederatedAMR []string` and `FederatedACR string`. They are written in the creating write, together with the first factor and provider, and are never stored in consumer data. A consumer key cannot forge them, under the same rule as challenge state.
- **Per-request evaluation** re-matches the stored values against the provider's current configuration. It does not trust a stored "met" flag. This means:
  - tightening a provider's accepted set takes effect on existing sessions at their next request (met sessions become a per-request challenge, as the requirement policy already does for users flagged mid-session);
  - a provider removed from the registry never matches.
- **The second-factor state is not set to satisfied** by provider assurance. "Satisfied" keeps meaning that scrty's own verify endpoint succeeded, so audit and consumer logic can tell the two apart. The policy input carries both facts separately.
- **Secrets at rest:** the values are not credentials, but they describe how the user authenticated. `secrets-at-rest` decides whether to seal them alongside the ID token; unsealed storage is acceptable.
- **Alternative rejected:** storing only a boolean result from login time. It freezes a decision made under configuration that may later be tightened, and it loses the evidence for audit.

### 5. Enrolled users who are not required keep today's behaviour by default

The second-factor challenge policy keeps allowing OIDC logins of enrolled, non-required users without a local challenge.

- **Why:** no guarantee is broken there. The user is not required, and the established behaviour carries no admitted defect for that case (see decision 7).
- **Override:** `WithFederatedChallengeWhenUnmet(true)` on the second-factor challenge policy challenges such users when assurance is not met. It is named for that policy alone, so it does not govern the requirement policy.

### 6. Construction-time wiring checks

The following are configuration errors at construction:
- `FederatedAssuranceChallenge` or `FederatedAssuranceRefuse` without the OIDC manager's assurance source wired into policy evaluation. Chain assembly checks this when both OIDC login and the MFA requirement policy are enabled.
- `FederatedAssuranceChallenge` without an MFA method. Every unmet login would be refused, which is a misconfiguration and not a policy; the consumer who wants that chooses Refuse.
- `WithFederatedChallengeWhenUnmet(true)` without OIDC login enabled.

### 7. Deliberate departures from the established design

Each item names what scrty does differently from the established behaviour, and why: **(a)** a settled scrty decision requires it, or **(b)** the established approach has a demonstrable defect.

1. **OIDC does not satisfy the MFA requirement by kind alone. Required users need verified provider assurance or a local second factor.**
   - (b) The established requirement states that a required user uses a second factor, including under "require MFA for all". Yet a required user with no enrolment, logging in through a provider that authenticated by password only, gets a session, and the established tests pin that outcome. The premise that the provider handles the second factor is never checked.
   - (a) scrty's library-design rule: when safe and convenient disagree, the default is the safe one and the convenient one is an option. The total exemption survives as `FederatedAssuranceExempt`.
   - Whether this becomes the default is left to the user; see Open Questions.
2. **Enrolling a required user through a session from an exempt OIDC login is no longer a supported path by default.** It follows from departure 1. That path is `mfa-enrolment-path`'s concern. Under Exempt mode the established path still works.

Everything else is kept as established: the `api-key` exemption, the non-required enrolled user outcome, and the requirement policy's refusal order.

## Risks / Trade-offs

- [A provider's SSO session reuses an `mfa` assertion from hours ago] → Documented limit. Freshness (`auth_time`, `max_age`) is a non-goal and is recommended as a follow-up.
- [A provider lets a tenant administrator emit arbitrary `amr` values] → Provider configuration is trusted operator input, as `oidc-login` already states. The accepted sets are per provider, so a less trusted provider can be configured empty.
- [A consumer lists a single-method value such as `otp` and accepts single-factor logins] → Godoc on `AcceptedAMR` explains RFC 8176 semantics. The default accepts only `mfa`.
- [Required users of a provider that emits no `amr` are now challenged or refused at their next login] → Challenge is the default, so an enrolled user continues after a local code. Unenrolled required users are refused with enrolment-required, a documented consequence tied to `mfa-enrolment-path`. Exempt mode restores the old behaviour explicitly.
- [A consumer's callback success handler drops the assurance fields] → The session then carries no assurance, and required users are challenged or refused, which fails closed. Documented on the handler.
- [Re-evaluation on every request challenges live sessions after a configuration change] → Intended. It is the same step-up path used when a user is flagged mid-session.
- [Malformed claims are silently treated as absent] → Not silent: they produce a sampled warning with the provider and claim name.

## Migration Plan

Not applicable: nothing is tagged. The handoff and session schema additions ship in the security-state migrations, owned by `schema-migrations`, before the first tag.

## Open Questions

These must be answered before the `oidc-login` and `security-policy` deltas are written, because they decide the default scenarios.

- **The default mode.** Should the default stay the established total exemption (`FederatedAssuranceExempt`), or become "required users must satisfy assurance" (`FederatedAssuranceChallenge`)?
  - **Recommendation: Challenge.** Keeping the established behaviour is the starting point. It is set aside here because of a demonstrable defect: a documented guarantee, that required users use a second factor, is not upheld on one login path, and tests pin the failing case. The library-design rule makes the safe choice the default and the convenient one an option.
  - **Cost:** required users of providers without `amr` must enrol locally, and the "enrol through an OIDC session" bootstrap needs Exempt mode or `mfa-enrolment-path`.
- **Refuse versus challenge when assurance is not met.** Recommendation: challenge by default and refuse as an option, for the reasons in decision 3. The alternative is refusal by default, which treats the provider as the only MFA authority.
- **Per provider only, or also per user?** This design configures assurance per provider and exposes `WithAssuranceEvaluator` for anything richer. Should scrty also ship a per-user rule, for example "administrators require `hwk`"? That would likely need a new identity port. Recommendation: per provider in this change, per user through the evaluator port only.
- **`identity-model` wording.** It says `oidc` is "exempt from an MFA requirement". Under the recommended default, OIDC is exempt only from the opportunistic challenge, not from the requirement. Should `identity-model` receive a delta narrowing that wording, or should `security-policy` alone carry the federated rule? Recommendation: a small `identity-model` delta, to keep the contracts consistent.
