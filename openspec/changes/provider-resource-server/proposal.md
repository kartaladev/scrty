# Proposal: accept the provider's own access tokens on the chain

> **On hold (2026-11-18).** Decisions are pending: see `pending-decisions.md`. This document
> describes the bearer-reuse design (D1-A there), which may be superseded. Do not apply the change
> until those decisions are made.

## Why

A consumer that embeds scrty's OpenID Provider (`oidcprovider.Provider`) cannot accept the access
tokens that provider issues on its own API routes. `EnableBearerToken` accepts only first-party
tokens whose `jti` names a session. `Provider.VerifyAccessToken` returns the claims, but leaves the
audience check and the proof of key possession to its caller. The DPoP proof verification that
would do that check is internal to `httpsec`, and only the provider's UserInfo endpoint uses it.

A consumer is therefore left to re-implement RFC 9449 proof verification outside the library, or to
give up sender-constrained tokens. Neither is acceptable for a security library. The first consumer
to need this runs scrty as both provider and resource server in one process, behind one chain, with
every token DPoP-bound.

Checking that consumer's plan against v0.1.1 found three more gaps worth closing in the same
release:
- `DPoP.Require` applies to the whole chain, so it also forces proofs on browser form login.
- The password policy cannot carry a rule the consumer owns, such as letters and digits.
- An inactive account can never be told apart from a wrong password, even by a consumer who chooses
  to disclose it, as it already can for a locked account.

## What Changes

The decision of 2026-11-16 is to add no new chain option. Consumers keep one bearer surface:
`EnableBearerToken` learns to accept the provider's access tokens.

- **Provider verifier `Provider.AccessTokenVerifier(audience, opts...)`.** It returns a
  `token.Verifier` for the provider's own access tokens, JWT and opaque:
  - **Verification.** It checks them through `VerifyAccessToken`, so a revoked grant is refused at
    once, and it requires the audience.
  - **The audience.** The audience is an absolute URI without a fragment, by the same rule as
    `Client.Resources`, so a URN qualifies. It may not be the issuer. A bad audience is a
    construction error.
  - **Routing.** It claims a token by shape: an `at.`-prefixed opaque token, or a JWT typed `at+jwt`.
    `WithFirstPartyVerifier` routes every other token to the chain's first-party verifier. Without
    it, every other token is refused.
- **Grant-backed claims.** The claims it returns carry a mark that only scrty's own packages can set.
  The mark says that a live grant, rather than a session, vouches for the token, and it carries the
  verified token.
- **`EnableBearerToken` and grant-backed tokens.**
  - **Path.** For a grant-backed token it skips the session lookup and keeps everything else:
    1. the DPoP or certificate binding check;
    2. a reload of the user by the token's subject, refusing a missing or inactive user;
    3. the proof recorded last.
  - **Publication.** It publishes the caller with the token's granted scopes, so
    `authorize.HasAnyScope` works.
  - **Policy.** It runs the stateless policy phase under a new `access-token` first-factor kind.
  - **`Sessions`.** It may be nil only when the verifier is the provider's with no first-party route.
    Otherwise it stays required.
  - **Binding.** By default it refuses an unbound grant-backed token, whatever the chain's own
    `DPoP.Require`. `WithBearerUnboundGrantTokens` opts out. Browser form login is unaffected.
  - **Request shape.** With the provider's verifier, a second `Authorization` header or an
    `access_token` query parameter beside the header is refused as malformed.
  - **What it refuses at construction.** Grant-backed tokens under `WithBearerUsernameSubject`, and a
    first-party generator typed `at+jwt` beside the provider's verifier.
  - **Renewal.** The renewal endpoint refuses a grant-backed caller.
- **New accessor `httpsec.AccessTokenFromContext`.** It returns a copy of the verified provider token:
  client, scopes, audience, grant and binding.
- **New refusal sentinel `httpsec.ErrInvalidToken`** (401), joined with
  `authenticate.ErrAuthenticationFailed`. The chain challenges it with `error="invalid_token"`. Only a
  refused provider token returns it. First-party refusals are unchanged.
- **Password policy: consumer rules.** A new `password.WithRule` adds a rule the consumer owns,
  checked after the built-in lists and before the breach lookup. Its refusal is a password-rejected
  error that names the consumer's rule. The library still imposes no composition rule of its own.
- **Inactive-account disclosure, opt-in.**
  - The password provider keeps refusing an inactive account with the uniform failure, and now joins
    a new `authenticate.ErrAccountInactive` beneath it, as a lock already is. That join happens only
    after the password has verified.
  - By default the status stays 401. The new chain option `WithInactiveDisclosure` answers with the
    inactive refusal alone, as 403.
- **Release preparation for the next lockstep version.** This covers the changelog entry and the
  nested-module requirements, ready for the maintainer to tag, as `RELEASING.md` requires.

Not in this change:
- Remote issuers, JWKS fetching, token exchange and introspection-based verification. These stay with
  `bff-resource-server`.
- Accepting provider tokens under `EnableSessionBearer`. A chain runs one bearer mode, so a consumer
  who needs provider tokens uses `EnableBearerToken`.
- Making chain-wide `DPoP.Require` scopable per endpoint.
- Creating or pushing tags. That is the maintainer's step.

## Capabilities

### New Capabilities

- `oidc-provider-resource-server`: accepting the embedded provider's access tokens through the
  chain's bearer. It covers the provider's verifier (shape routing, audience, grant liveness), the
  grant-backed path through the bearer (binding, the default binding requirement, the live-user
  reload), publication of the caller and the token, refusals with their challenges, and dependency
  failures.

### Modified Capabilities

- `http-error-propagation`: adds the invalid-token sentinel, its 401 status, and its `invalid_token`
  challenge. Adds the inactive-account refusal and its 403 status under disclosure.
- `sender-constrained-tokens`: the bearer refuses an unbound grant-backed token by its own default,
  independently of chain-wide `Require`. That default never makes an issuing endpoint require a
  proof.
- `http-security-chain`: changes the bearer requirement. A grant-backed token authenticates against
  a live grant and a live user, with no session. `BearerTokenDeps.Sessions` may be nil only for a
  grant-backed-only verifier. Adds the construction refusals, the renewal refusal and
  `WithInactiveDisclosure`.
- `identity-model`: a user principal authenticated by an access token carries that token's granted
  scopes. A new first-factor kind, `access-token`, has no channel and is exempt from an MFA
  requirement, because the requirement was judged at the sign-in that made the grant.
- `password-policy`: the consumer may add rules of its own. Its refusals name the rule, and the
  library still imposes no composition rule.
- `authentication`: an inactive account's refusal stays the uniform failure, and is identifiable
  beneath it as inactive, after the password has verified.

## Impact

- **Code:**
  - `oidcprovider`: `AccessTokenVerifier` and `WithFirstPartyVerifier`.
  - `token` and an `internal` package: the grant-backed mark on `Claims`, and the `TypedGenerator`
    port.
  - `httpsec`:
    - the bearer's grant-backed path, `WithBearerUnboundGrantTokens`, `ErrInvalidToken` and its
      challenge, and `AccessTokenFromContext`;
    - the renewal refusal and `WithInactiveDisclosure`.
  - `authenticate`: `ErrAccountInactive` and the password provider's join.
  - `authenticate/factor`: the `access-token` kind.
  - `authenticate/password`: `WithRule` and `RuleFunc`.
  - Adapter tests in `httpsec/fibersec`, `httpsec/ginsec` and `test/httpsecconformance`.
- **API:** the change is additive. Two behaviours change:
  - `errors.Is(err, authenticate.ErrAccountInactive)` now holds beneath the uniform failure for an
    inactive account whose password verified.
  - `BearerTokenDeps.Sessions` may be nil in the one case stated above.
- **Dependencies:** none added.
- **Release:** the next lockstep version of all nine modules, `v0.2.0`.
- **Related changes:** `bff-resource-server` keeps the remote-issuer resource server, and does not
  overlap this change.
