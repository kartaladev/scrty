## Why

An OIDC login is currently exempt from the MFA requirement no matter what. The library assumes the provider handled the second factor, but it never checks. So a user who is required to use MFA, including under "require MFA for all", gets a session with no second factor anywhere if they log in through a provider that accepted only a password. The requirement fails silently on exactly the login path an attacker holding a stolen provider password would use.

This change lets each provider prove its assurance through its signed ID token, and closes the gap for required users.

## What Changes

- Add per-provider assurance configuration to `oidc-login`:
  - a set of accepted authentication method references (`amr`, RFC 8176 values such as `mfa`, `hwk`, `otp`);
  - a set of accepted authentication context class references (`acr`);
  - optional `acr_values` sent in the authorization request.
- Evaluate assurance only from the validated ID token. A missing, empty or malformed claim counts as not asserted. Nothing from the userinfo endpoint, the access token or the client is considered.
- Carry the asserted `amr` and `acr` values from the callback through the handoff code into the federated session, in the write that creates the session. Per-request policy can then decide on them without the ID token.
- Change how the MFA requirement treats OIDC logins in `security-policy`:
  - a required user's OIDC login satisfies the requirement only when the provider's asserted assurance meets that provider's configuration;
  - when it does not, the login is challenged for scrty's own second factor through the existing MFA challenge path, or refused where the consumer configures refusal.
- Keep the total exemption available as an explicit, documented mode that a consumer selects on purpose.
- **BREAKING (pre-tag):** the recommended default stops exempting required users' OIDC logins without assurance. The user chose this default on 2026-10-01, and it is recorded as a compatibility decision in design.md. Nothing is tagged yet.
- Users who are enrolled but not required keep today's behaviour by default: no local challenge after an OIDC login. A consumer can opt in to challenging them when assurance is not met.

Not in this change:
- Freshness of the provider's authentication (`auth_time`, `max_age`).
- The `claims` request parameter and essential-claim requests.
- Step-up re-authentication at the provider mid-session.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `oidc-login`: per-provider assurance configuration and its construction checks, `acr_values` in the authorization request, assurance read only from the verified ID token, assurance carried in the handoff record and the session's creating write, and a replacement of the requirement "OIDC logins are exempt from local MFA by default, as a stated limit".
- `security-policy`: the MFA requirement policy honours verified provider assurance for federated first factors, challenges or refuses when assurance is not met, keeps a total exemption as an explicit mode, and re-matches stored assurance per request. The second-factor challenge policy keeps allowing non-required federated logins by default.
- `identity-model`: `oidc` is no longer exempt from an MFA requirement by its kind; only `api-key` is.
- `sessions`: library-owned federated assurance fields, written in the creating write and carried over on rotation.
- `http-security-chain`: the login completion step carries library-minted federated evidence into policy and the session.
- `account-recovery`: a linked federated identity counts toward the way-back check only when its login would be admitted without a local second factor.
- `security-state-stores` and `schema-migrations`: the handoff and session records persist the asserted values on every backend.

## Impact

- **Code, core module:**
  - `oidc`: provider assurance configuration, claim extraction during ID token verification, and assurance fields on the callback result and handoff record;
  - `policy`: an assurance-aware MFA requirement decision for federated logins;
  - `session`: library-owned federated assurance fields;
  - `httpsec`: `acr_values` on the authorize redirect, and assurance passed into the post-authentication input at handoff redemption.
- **Persistence:** new columns on the handoff and session tables, stored unsealed because they are not credentials, owned by `security-state-stores` and `schema-migrations`. Conformance suites gain round-trip cases.
- **Sequenced after:** `passkey-authentication`, which is applied and archived first. Its deltas change the same requirement blocks, and its library-only proof is narrowed here (design.md, decision 8).
- **Depends on:** `oidc-login`, `identity-linking` (unchanged), `sessions`, `security-policy`, `identity-model` (first-factor kinds and channels), and `multi-factor-auth` for the challenge and verify path.
- **Consumers:** none yet. Nothing is tagged, so the default change is a recorded decision, not a compatibility break for anyone.
