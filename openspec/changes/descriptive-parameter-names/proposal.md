# Proposal

## Why

Many exported signatures name a parameter with one letter, where a role name would read better. On 2026-11-09 a sweep of the published modules found 385 such signatures. A reader of the godoc sees `WithSessions(m *session.Sessions)`, `WithLoginLimiter(l ratelimit.Limiter)`, `New(c seal.Cipher, g id.Generator)` and `WithMFAChallengeTTL(d time.Duration)`. Each one has to be decoded from the type rather than read from the name. The maintainer asked for descriptive names, at least `sess` or, better, `sessions`, for readability.

## What Changes

- **Exported signatures get descriptive parameter names.** This covers every parameter of an exported function, of an exported method on an exported type, of an exported interface's methods and of an exported function type, across the nine published modules. Examples:
  - `sessions *session.Sessions` (not `m`)
  - `logger *slog.Logger` (not `l`)
  - `limiter ratelimit.Limiter` (not `l`)
  - `cipher seal.Cipher` (not `c`)
  - `ids id.Generator` (not `g`)
  - a duration named by its role, such as `ttl`, `window`, `interval`, `lifetime` or `timeout` (not `d`)
- **Go's established short names stay:**
  - `w http.ResponseWriter`, `r *http.Request`, `ctx context.Context`;
  - `t`/`b`/`tb` for testing types;
  - receivers;
  - `_` for an unused parameter.
- **Godoc follows the new names.** Godoc that refers to a renamed parameter is updated in the same edit. The README and the `Example` functions in each module use descriptive variable names for the same types.
- **A layout test keeps it that way.** It fails, naming the file, the function and the parameter, when an exported signature in a published module gives a parameter a one-letter name outside the established set.

There is no **BREAKING** change: Go parameter names are not part of a package's API, so no caller changes.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

None. No observable behaviour changes; the change sets `skip_specs: true`.

## Impact

- **Code:** the parameter names in about 30 packages across all nine published modules. Most are in `httpsec` (106 signatures), `oidcprovider`, `recovery`, `authenticate/*`, `session` and the stores. Godoc mentioning those parameters changes too, as do the `Example` functions and `README.md`.
- **Tests:** a new layout test in the root module's `layout_test.go`.
- **Order (revised 2026-11-09):** this change is merged to `main` before `harden-chain-boundary` cuts its private-fork branch. Both changes touch the same `httpsec` files. Landing the renames first means the security fix is written against the new names, and the advisory's pull request has nothing on `main` to conflict with. The renames ship in `v0.1.1` with the security fix; they need no release of their own.
