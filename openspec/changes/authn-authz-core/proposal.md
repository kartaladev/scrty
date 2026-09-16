## Why

scrty has its foundation (module layout, identifiers, log sampling), but no security behaviour yet. Every login flow, HTTP integration and persistence adapter planned after this change needs the same core decisions made once, framework-free and testable on their own:
- who is this caller;
- may they do this;
- is their session still valid;
- does a deployment rule refuse, allow or challenge them;
- how often may a source fail;
- how is a single-use credential spent exactly once.

This change makes those decisions and pins their failure modes, so later changes wire them instead of re-deriving them.

## What Changes

- Add an **authentication** core: a manager that delegates to ordered providers, a username-and-password provider and a bearer-token provider.
  - An unknown user, a wrong password and an inactive account all return one uniform failure, with equalised password work.
  - A provider that reports success without a principal is treated as a failure.
- Add an **authorization** core: a delegating authorizer, per-resource privilege and ownership checks, and a centralized, ordered, first-match rule set with composable requirements.
  - A subject with no active role is denied, never a panic.
  - Loader errors are wrapped so the cause survives.
- Add **sessions**:
  - bearer identifiers drawn from `crypto/rand`;
  - idle and absolute expiry;
  - the first factor and challenge state recorded as session fields the library owns;
  - consumer data returned unchanged;
  - a store port, an in-memory store with a start-and-stop housekeeping ticker, and a sealing store wrapper for the provider ID token.
- Add a **security-policy** engine that evaluates rules by phase (pre-authentication, post-authentication, per-request, post-handler, stateless authentication) to allow, deny or challenge. Built-in policies:
  - account lockout;
  - idle timeout;
  - password age;
  - concurrent sessions;
  - the second-factor challenge;
  - the per-user or require-for-all MFA requirement, which fails closed when its lookup fails.

  It also adds an explicit, documented rule for a second factor on the same channel as the first. That rule refuses by default instead of completing silently on one factor. Refusal logs are sampled with a reporter.
- Add **rate limiting** that counts failures per source:
  - a limiter port and an in-memory limiter, with the per-replica limit documented and announced once;
  - canonical source keys, with IPv6 grouped by prefix and an unspecified address refused rather than pooled;
  - a source guard that exposes the check and failure-recording steps that redemption flows need;
  - pruning that can never disarm a limit.
- Add **one-time tokens**:
  - secrets hashed at rest;
  - scoped by purpose and bound to a subject;
  - expiry;
  - a side-effect-free check followed by an atomic consume, so callers can run refusal checks without spending the credential;
  - per-subject issuance counting, and a purge that cannot free issuance quota.

## Capabilities

### New Capabilities

- `authentication`: resolving presented credentials to a principal through ordered providers, with a uniform, non-enumerating failure contract.
- `authorization`: deciding whether a principal may act, through centralized rules, per-resource privilege checks and ownership checks.
- `sessions`: server-side sessions with unguessable identifiers, idle and absolute expiry, a recorded first factor and challenge state, a store contract and a sealing wrapper.
- `security-policy`: a phased allow/deny/challenge engine and its built-in deployment rules, including the MFA requirement and the same-channel second-factor rule.
- `rate-limiting`: bounding failed attempts per canonical source, with a replaceable limiter and an in-memory default.
- `one-time-tokens`: issuing, checking and atomically consuming short-lived, single-use, subject-bound credentials.

### Modified Capabilities

None. No specs have been archived yet.

## Impact

- **New code in the core module:** `authenticate`, `authorize`, `session`, `policy`, `ratelimit` and `onetime` packages. They have no framework, driver, scheduler or DI dependency.
- **Depends on other changes:**
  - `identity-model`: principal, user reference, user and role loaders, the MFA requirement lookup port, first-factor kinds with their channels and exemptions, and context carriers;
  - `password-encoding`: the password encoder and its default;
  - `token-issuance`: the token verifier;
  - `secrets-at-rest`: the cipher port the sealing session store uses;
  - `log-sampling` and `id-generation`, from project-foundation.
- **Consumed by later changes:**
  - `http-security`: interceptors, default chain assembly and status mapping of these sentinels;
  - `auth-methods`: MFA methods, magic link and API keys;
  - `oidc-brokering`: federated sessions and logout deletes;
  - `security-state-stores`: durable session, attempt and one-time-token stores;
  - `expiry-sweeping`: schedules the purge operations.
- **Consumers:** none yet. Nothing is tagged, so every default here is recorded as a decision, not a compatibility obligation.
