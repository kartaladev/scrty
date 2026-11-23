# Proposal

## Why

A consumer that brokers a corporate SSO cannot keep its own accounts in step with it. The callback
throws away the upstream access token. The broker runs before the consumer can act. An identity
with no link is refused, or provisioned create-only. The consumer therefore cannot:

- read the upstream UserInfo,
- adopt an account it imported before go-live,
- refresh a user's data on every sign-in.

On top of that, an application that is itself the OpenID Provider for its own frontend needs a page
script to finish a federated sign-in: it redeems the handoff code and resumes the parked
authorization request. The frontend should see a plain OIDC code flow, with the brokering done on
the server.

## What Changes

- **Upstream token to the broker.** The callback keeps the upstream access token from the token
  response, in memory, for the one callback that received it. It hands the token to a broker that
  implements a new optional interface, wrapped in a value that cannot print or log the token. That
  value can fetch the provider's UserInfo:
  - through the confined outbound client;
  - with the response size bounded;
  - refusing a `sub` that differs from the ID token's.
  The token is never stored, logged, put in an error, or conveyed to the browser. A broker without
  the interface behaves exactly as today.
- **Sign-in hook on the library broker.** It is opt-in and set per provider. On every sign-in
  through that provider, after the ID token is verified, a consumer function receives three things:
  the verified identity, the upstream access, and the user the identity is already linked to. It
  returns a decision: one user, plus an optional apply step holding its writes. The library then
  checks the decision before anything is written:
  - an existing link to another user is refused, never re-pointed;
  - a missing or inactive user is refused;
  - by default, a second link from the same provider and issuer to one user is refused.
  It inserts the link, safely under concurrent sign-ins. Only then does it run the apply step and
  resolve the user through the link.
  A decision may also provision: it names a user that does not exist yet, and its apply step
  creates that user after the library has linked it.
  Combining the hook with just-in-time provisioning, claim mirroring or role sync for the same
  provider is a configuration error. Assurance is still read from the ID token alone.
- **Listing a user's links.** This is a new optional link-store capability. The memory, SQL, pgx and
  gorm link stores implement it. The existing link store contract is unchanged.
- **Server-side completion of a federated provider sign-in.** It is opt-in on the chain and
  needs a user loader. When a federated login started from the provider's own login page, carrying
  a parked request's handle, the callback does what a handoff redemption followed by a resume does,
  in the same order:
  1. check the handle;
  2. load the stored user;
  3. run the post-authentication policy;
  4. create the session and cancel held recoveries;
  5. run the per-request policy;
  6. resume and confirm.
  It then sets the provider's browser session and redirects the browser to the client with its
  authorization code, with no page script.
  - When a step is still owed (a second factor, an enrolment, a password change), the callback falls
    back to the existing handoff conveyance to the login page, which finishes the step and resumes
    as today.
  - Logins not tied to a parked request keep the handoff conveyance.
  - The provider exposes its login URL, read-only, for this.
- **Documentation.** The README covers:
  - the hook and the upstream access;
  - the standards-only frontend shape: the frontend is an OIDC client of the application's own
    provider, and brokering happens inside it;
  - the fallback.
  It does not claim that a consumer's frontend never talks to the upstream provider, since a
  consumer may hold its own upstream token for other APIs.

No breaking change: every addition is opt-in, and defaults are unchanged.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `oidc-login`:
  - the token response's access token is retained for the callback and offered to a broker that
    asks for it, never stored or logged;
  - UserInfo retrieval through the confined client with subject matching;
  - an optional pinned UserInfo endpoint;
  - the opt-in server-side completion of a federated provider sign-in, with handoff fallback, as a
    third conveyance beside the handoff and the callback success handler;
  - the redirect allowlist's carve-out for the provider's own login URL under completion.
- `identity-linking`:
  - the "never by email" requirement gains the consumer-hook carve-out;
  - an opt-in, per-provider sign-in hook that decides first and writes only after the library
    accepts;
  - library-owned link creation, conflict refusal and one link per user per provider by default;
  - an optional listing of a user's links;
  - configuration conflicts with just-in-time provisioning, claim mirroring and role sync.

## Impact

- `authenticate/oidc`:
  - exchange and token response handling;
  - `RelyingParty.Callback`;
  - new `Upstream` value and optional broker interface;
  - `Broker` options and resolution;
  - discovery metadata gains `userinfo_endpoint`, and `Provider` gains an optional pinned UserInfo
    endpoint.
- `httpsec`: OIDC login options and callback conveyance; use of `oidcprovider.Provider.Resume`, the
  browser-session cookie and the login completion step from the callback; construction checks
  pairing OIDC login with the OpenID Provider on one chain.
- `oidcprovider`: a read-only `LoginURL()` accessor. There is no behaviour change; the Go-API
  resume path is reused as documented.
- Link stores: an optional `ListByUser` in `authenticate/oidc` (memory), `store/sqlstore`,
  `store/pgxstore` and `store/gormstore`, plus the shared SQL query and the link-store conformance
  suite in `test/oidc`. No migration: the `user_id` index exists.
- `httpsec`: `OIDCDeps` gains an optional user loader, which completion requires.
- README sections "OIDC" and "OpenID Provider".
- Consumers: none affected unless they opt in.

## References

### Researched (accessed 2026-11-24)

- [keycloak-dev: User with multiple IdPs of the same type](https://groups.google.com/g/keycloak-dev/c/5-8obq588aU) and [Auth0: User account linking](https://auth0.com/docs/manage-users/user-accounts/user-account-linking.md): one link per user per identity provider is established practice, and e-mail-based auto-linking is a known takeover path. These support the one-link default. Secondary sources.

- [Red Hat build of Keycloak: Integrating identity providers](https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/22.0/html/server_administration_guide/identity_broker): a broker runs its own post-login steps (such as 2FA) after an upstream login, through a post-login flow. Supports the handoff fallback for an owed step.
- [Keycloak forum: External IdP + Keycloak OTP](https://forum.keycloak.org/t/external-idp-keycloak-otp/16842): community practice of a post-broker-login flow with OTP. Secondary source.
- [Auth0 community: MFA with SSO through an upstream IdP](https://community.auth0.com/t/end-users-forced-to-use-mfa-when-using-sso-with-upstream-idp/163790): broker-side MFA after an enterprise login unless the upstream asserted it. Secondary source.
- [Ory Kratos: Upstream MFA carry-over](https://www.ory.com/docs/kratos/social-signin/upstream-mfa): brokers honour upstream MFA only when it is asserted in tokens, and otherwise run their own.
- [NIST SP 800-63C-4](https://pages.nist.gov/800-63-4/sp800-63c.html): the RP sets the minimum assurance it accepts, and only the IdP knows the AAL it used. Supports keeping assurance from the verified ID token only. Search summary; the full text was not re-read.

### Primary documentation

- [OpenID Connect Core 1.0 §5.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo): the UserInfo request with a bearer access token, and the §5.3.2 rule that the UserInfo `sub` must match the ID token's.
- [RFC 6749 – OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) and [RFC 7636 – PKCE](https://www.rfc-editor.org/rfc/rfc7636): the code flow on both legs of the brokered sign-in.
- [RFC 9700 – OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700): no token in a front channel; the upstream token stays server-side.
- [RFC 9449 – DPoP](https://www.rfc-editor.org/rfc/rfc9449): the frontend's tokens from the application's own provider are unaffected.
