# Proposal

## Why

Teams whose frontend is a React app want sign-in inside that app, in their own layout, rather than
on a separate scrty page. Today they reverse-engineer scrty's endpoints and error shapes, and each
team rebuilds the same forms and the same handling of a pending second factor. scrty's own pages
(`sign-in-pages`, `provider-pages`) do not help them, because they are served by the chain.

This change gives those teams an npm package of headless hooks and styled components that talk to
the same endpoints through a published, versioned contract, on the same cookie session and with the
same look as scrty's pages.

## What Changes

- **An endpoint contract**, so a client can rely on the endpoints without reading scrty's code:
  - a contract version;
  - an OpenAPI document of every browser-facing endpoint's requests, answers and problem types;
  - an opt-in discovery endpoint listing the contract version and the flows the chain has enabled.
- **The CSRF token for same-origin scripts:** an endpoint that answers the request's sign-in's CSRF
  token to a same-origin script, so the package can send `X-CSRF-Token` on unsafe requests.
- **`@kartaladev/scrty-react`** (npm):
  - headless hooks (`useSignIn`, `useMagicLink`, `usePasskey`, `useSecondFactor`, `useRecovery`,
    `useSessions`, `useSignOut`, `useScrty`);
  - styled components built on them, themed by the same `--scrty-*` variables as scrty's pages;
  - no credential is ever stored in JavaScript;
  - flows the chain does not offer, and contract versions the package does not support, are
    refused with a clear message instead of failing at the first request.

## Capabilities

### New Capabilities
- `endpoint-contract`: the versioned, published description of the chain's browser-facing
  endpoints, and the opt-in discovery endpoint.
- `react-components`: the behaviour of the npm package's hooks and components.

### Modified Capabilities
- `csrf-protection`: the sign-in's CSRF token becomes readable by same-origin scripts through an
  endpoint, beside the existing server-side accessor.

## Impact

- **Go:** `httpsec` (discovery endpoint, CSRF token endpoint, contract version constant); an
  OpenAPI document generated or maintained beside the endpoints, with a CI check that it matches the
  endpoint inventory.
- **npm:** a new package, its build, tests and release. Where it lives is open (design.md).
- **Supply chain:** the `supply-chain` rules extend to npm dependencies.
- **Depends on:** `browser-session` and `sign-in-pages` archived (the design tokens come from the
  pages).
