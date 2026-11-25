# Proposal

## Why

With `browser-session`, a browser signs in to the consumer's own app through an `HttpOnly` cookie,
and no token reaches JavaScript. When that app then calls internal APIs on the user's behalf, it
needs something to send them, and today scrty gives it nothing: the chain hands out no token on a
cookie chain, and the provider's tokens from a federated sign-in are discarded after the exchange.
Each consumer would hand-roll token minting, lifetimes and refresh.

This change takes over the three questions the `bff-resource-server` draft left open about that
path. That draft is retired: its CSRF part landed in `close-security-gaps`, its resource-server part
on 2026-11-25, and its cookie session in `browser-session`.

**Status: blocked on Q2, Q3 and Q5 (design.md).** Specs and tasks follow once they are answered.

## What Changes

Candidate, if the draft's recommendations are adopted (Q2-B, Q3-A, Q5-B):

- **Outbound tokens for a signed-in request.** On a cookie chain, a handler can obtain a short-lived
  scrty access token for the request's session, with an API audience the consumer configures. The
  token is minted through the existing token issuance, never stored, and re-minted when it is within
  one minute of expiry. It never outlives the session's absolute deadline.
- **APIs verify it with the existing resource server.** Downstream APIs use
  `EnableResourceServer` against scrty's published key set, with the audience required. No new
  verification code.
- **No refresh tokens.** The session's idle and absolute expiry are the whole lifetime; revoking is
  deleting the session.
- **The consumer owns the proxy.** scrty documents the obligations: strip the session cookie before
  calling upstream, send only the token, and mark authenticated responses `Cache-Control: private,
  no-store`.
- **Override:** a consumer token source replaces minting, for APIs that must receive another
  issuer's token.

## Capabilities

### New Capabilities
- `token-forwarding` (name provisional, fixed once Q2 is answered): obtaining an access token for
  downstream APIs from a signed-in request, its audience, lifetime and renewal.

### Modified Capabilities
- None expected with the candidate answers. Q2-A or Q5-A would modify `oidc-login` (keeping and
  sealing the provider's tokens) and `sessions` (new sealed fields).

## Impact

- **Code (candidate):** `httpsec` (an option to enable outbound tokens and a context accessor),
  token issuance reused as is. No store change with Q5-B.
- **Docs:** a proxy-obligations section for consumers (Q3-A).
- **Depends on:** `browser-session` archived.
- **Dependencies:** none added with the candidate answers.
