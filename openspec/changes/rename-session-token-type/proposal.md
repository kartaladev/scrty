# Proposal

## Why

scrty uses "first-party" with two meanings. `token.TypeFirstParty` names the token the chain issues
to its own users at sign-in, which stands for a session. `oidcprovider.Client.FirstParty` follows
the OAuth meaning: a client the provider's own organisation trusts, so consent is skipped. Both
apply at once on a chain that is also a provider, and the clash has already confused the design of
provider-issued access tokens on the chain. The token's meaning has no OAuth term. OWASP calls it a
session token, which also names what backs it.

## What Changes

- **BREAKING**: `token.TypeFirstParty` is renamed `token.TypeSessionToken`. The old name is removed
  with no alias. The wire value, `scrty+jwt`, is unchanged, so every token already issued still
  verifies.
- Unexported names that carry "first-party" for this token (`validateFirstPartyType` in `token`,
  `firstPartyRefused` in `httpsec`'s tests) are renamed to match.
- Godoc, test names, the README and the specs say "session token" for the token, and "the
  sign-in's sessions" for the sessions such tokens stand for, in place of "first-party token" and
  "first-party sessions".
- "First-party" in the OAuth sense stays as it is: `oidcprovider.Client.FirstParty`, the consent
  rules, and the test fixtures for first-party clients.
- The CHANGELOG records the break under *Changed* for the next release.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `token-issuance`: the token a generator issues by default is called the session token; type
  declaration, verifier and issuer requirements reworded. No behaviour changes.
- `oidc-provider-tokens`: the subject requirement names the chain's session tokens.
- `oidc-provider-userinfo`: the refusal list names a session token.
- `oidc-provider-logout`: the logout order names the sign-in's sessions.

## Impact

- **Public API**: `token.TypeFirstParty` removed; `token.TypeSessionToken` added with the same
  value. A consumer referencing the old name fails to compile, and the CHANGELOG states the
  one-line migration.
- **Code**: `token` (constant, defaults, the issuer's reserved-type check, godoc), and godoc and
  tests in `oidcprovider`, `httpsec`, `test/storetest`, `test/httpsecconformance` and
  `test/cmd/conformanceop`.
- **Docs**: `README.md`, `CHANGELOG.md`.
- **Wire, storage, behaviour**: none.
- **Related**: `provider-resource-server` (on hold) will use "session token" from the start.
