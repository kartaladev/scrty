## Why

Every authentication method, session, policy and HTTP interceptor scrty will ship needs the same four foundations, and they must agree before any of those packages exist:
- a shared vocabulary for who a caller is, and the ports a consumer implements to plug in their own users;
- password hashing that is safe by default;
- signed tokens whose verification cannot be talked out of its checks;
- signing keys that survive restarts, rotate, and shut down cleanly.

These are the places where authentication libraries most often fail silently:
- an issuer check that enforces the opposite of what was configured;
- keys that are lost on every restart;
- rotation goroutines that outlive shutdown;
- a verifier that accepts `alg: none`;
- a login that answers faster for unknown users.

scrty defines them first, with each of those failures written down as a requirement.

## What Changes

- Add the `identity` package:
  - principal, user details, assigned roles, resource privileges, organization and group types;
  - credential types;
  - carrying a principal through a request context.
- Add the `factor` package: first-factor kinds, their channels and their MFA exemption.
- Add the identity ports a consumer with their own user tables implements:
  - a user loader;
  - a role loader;
  - a user provisioner, whose create verb refuses a taken username by the write itself and whose separate update verb amends only named fields;
  - an MFA requirement lookup by user reference.
- Add the `password` package:
  - Argon2id as the default encoder, with bcrypt and scrypt;
  - replaceable parameters above a stated floor;
  - bcrypt never matching by truncation;
  - matching that costs the same whether or not it succeeds, so callers can equalize unknown-user logins with a decoy hash.
- Add the `token` package: JWT generation and verification on `lestrrat-go/jwx/v4`, with:
  - the algorithm pinned by the key, and `alg: none` rejected;
  - `kid` bound to the header;
  - `exp` required;
  - issuer and audience enforced when configured;
  - an injectable clock.
- Add the `signingkey` package:
  - key generation;
  - persistence through a key-store port, reloaded at construction;
  - scheduled rotation and housekeeping;
  - JWKS output;
  - start and stop that leave no goroutine behind.
- Add to the core module jwx v4 and `golang.org/x/crypto`.
- Raise the module's Go floor to 1.27, which jwx v4 forces: it reads and writes JSON through `encoding/json/v2`, which reaches the standard library in Go 1.27. On Go 1.26 it builds only under `GOEXPERIMENT=jsonv2`, a build-environment flag every consumer would otherwise inherit.

Not in this change:
- deciding logins, MFA or permissions (`authentication`, `security-policy`, `authorization`);
- durable key stores and sealing private keys (`security-state-stores`, `secrets-at-rest`);
- the default identity store (`default-identity-store`);
- serving the JWKS over HTTP (`http-security-chain`).

## Capabilities

### New Capabilities

- `identity-model`: the principal and user-details model, roles, privileges, organizations, credential types and first-factor kinds, and the contracts of the user loader, role loader, user provisioner and MFA requirement lookup.
- `password-encoding`: hashing and matching passwords with Argon2id (default), bcrypt or scrypt, parameter floors, the bcrypt length limit, and constant-work matching for unknown users.
- `token-issuance`: issuing and verifying signed JWTs: claims, key and algorithm selection, expiry, issuer, audience and failure reporting.
- `signing-keys`: generation, persistence and reload, rotation, housekeeping, JWKS output and the start/stop lifecycle of signing keys.

### Modified Capabilities

None. No specs exist yet.

## Impact

- **New code:** `identity/`, `factor/`, `password/`, `token/`, `signingkey/` in the core module. In the `test` module: the identity port conformance suite and an in-memory provisioner and loader.
- **Dependencies:** `github.com/lestrrat-go/jwx/v4` and `golang.org/x/crypto` in the core module. Neither is a framework, driver, scheduler or DI container, so the `module-layout` guard holds.
- **Go version:** the floor rises from 1.26 to 1.27 and the CI matrix follows. Nothing is tagged and there are no consumers, so this costs nothing now; after the first tag it would be a breaking change.
- **Later changes:**
  - `authn-authz-core` builds authentication, authorization, sessions and policy on these types;
  - `durable-persistence` implements the key store;
  - `default-identity-store` implements the identity ports;
  - `http-security` serves the JWKS and verifies bearer tokens;
  - `auth-methods` and `oidc-brokering` use the first-factor kinds and the provisioner.
- **Consumers:** none yet; nothing is tagged.
